#!/usr/bin/env python3
# Tool for mapping relationship between EFI programs and NVRAM Key Values
# Created by : PN-TESTER

import argparse
import os
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BANNER = r"""
 _______ ___ ___ ______ _______ _______              
|    |  |   |   |   __ \   _   |   |   | _____ _____ 
|       |   |   |      <       |       ||  _  |  _  |
|__|____|\_____/|___|__|___|___|__|_|__||__|__|   __|
                                              |__|   
Created By : PN-TESTER
"""

DEBUG = False   # set to True via --debug flag

#color helpers

try:
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    C_HEAD = Fore.CYAN  + Style.BRIGHT
    C_OK   = Fore.GREEN + Style.BRIGHT
    C_WARN = Fore.YELLOW
    C_ERR  = Fore.RED   + Style.BRIGHT
    C_RST  = Style.RESET_ALL
except ImportError:
    C_HEAD = C_OK = C_WARN = C_ERR = C_RST = ""


# data structures

@dataclass
class VarStore:
    guid: str
    var_store_id: int
    attributes: int
    size: int
    name: str

@dataclass
class HiiSetting:
    widget_type: str
    prompt: str
    help_text: str
    question_flags: int
    question_id: int
    var_store_id: int
    var_offset: int
    flags: int
    size: int          # bits
    min_val: int
    max_val: int
    step: int
    var_store: Optional[VarStore] = None
    current_value: Optional[int] = None


# helpers

def u8(b: bytes, o: int) -> int:  return b[o]
def u16(b: bytes, o: int) -> int: return struct.unpack_from("<H", b, o)[0]
def u32(b: bytes, o: int) -> int: return struct.unpack_from("<I", b, o)[0]
def u64(b: bytes, o: int) -> int: return struct.unpack_from("<Q", b, o)[0]

def guid_str(b: bytes, o: int) -> str:
    a, bv, c = struct.unpack_from("<IHH", b, o)
    d = b[o+8:o+10].hex().upper()
    e = b[o+10:o+16].hex().upper()
    return f"{a:08X}-{bv:04X}-{c:04X}-{d}-{e}"


# HII String package parsing
#
# EFI_HII_PACKAGE_HEADER  (4 bytes, little-endian u32):
#   bits[23:0]  = Length  (includes this header)
#   bits[31:24] = Type
#
# EFI_HII_STRING_PACKAGE_HDR (after the 4-byte pkg header):
#   HdrSize          u32   @ +0
#   StringInfoOffset u32   @ +4
#   LanguageWindow   u16[16] @ +8  (32 bytes)
#   LanguageName     u16   @ +40
#   Language         null-terminated ASCII @ +42
#
# After header: SIBT blocks (block_type u8, then type-specific data)

SIBT_END             = 0x00
SIBT_STRING_SCSU     = 0x10
SIBT_STRING_SCSU_FONT= 0x11
SIBT_STRINGS_SCSU    = 0x12
SIBT_STRINGS_SCSU_FONT=0x13
SIBT_STRING_UCS2     = 0x14
SIBT_STRING_UCS2_FONT= 0x15
SIBT_STRINGS_UCS2    = 0x16
SIBT_STRINGS_UCS2_FONT=0x17
SIBT_DUPLICATE       = 0x20
SIBT_SKIP2           = 0x21
SIBT_SKIP1           = 0x22
SIBT_EXT1            = 0x30
SIBT_EXT2            = 0x31
SIBT_EXT4            = 0x32


def _read_null_ucs2(data: bytes, pos: int) -> Tuple[str, int]:
    chars = []
    while pos + 1 < len(data):
        cp = u16(data, pos); pos += 2
        if cp == 0: break
        chars.append(chr(cp))
    return "".join(chars), pos


def _read_null_scsu(data: bytes, pos: int) -> Tuple[str, int]:
    chars = []
    while pos < len(data):
        b = data[pos]; pos += 1
        if b == 0: break
        chars.append(chr(b) if b < 0x80 else "?")
    return "".join(chars), pos


def _find_sibt_start(payload: bytes) -> int:
    null_pos = payload.find(0, 42)
    if null_pos < 0:
        return -1
    return null_pos + 1


def _is_valid_string_pkg_hdr(payload: bytes) -> bool:
    if len(payload) < 46:
        return False
    hdr_size = u32(payload, 0)
    if hdr_size < 4 or hdr_size > 0x10000:
        return False
    for k in range(42, min(42 + 64, len(payload))):
        b = payload[k]
        if b == 0:
            return k > 42
        if not (0x20 <= b < 0x7F):
            return False
    return False


def parse_string_package(data: bytes, pkg_offset: int, pkg_len: int) -> Optional[Dict[int, str]]:
    if pkg_offset + pkg_len > len(data):
        return None
    payload = data[pkg_offset + 4: pkg_offset + pkg_len]

    if not _is_valid_string_pkg_hdr(payload):
        return None

    sibt_start = _find_sibt_start(payload)
    if sibt_start < 0:
        return None

    pos = sibt_start
    sid = 1
    string_map: Dict[int, str] = {0: ""}

    itr = 0
    while pos < len(payload) and itr < 0x20000:
        itr += 1
        block_type = payload[pos]; pos += 1

        if block_type == SIBT_END:
            break
        elif block_type == SIBT_STRING_UCS2:
            text, pos = _read_null_ucs2(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_UCS2_FONT:
            pos += 1
            text, pos = _read_null_ucs2(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU:
            text, pos = _read_null_scsu(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU_FONT:
            pos += 1
            text, pos = _read_null_scsu(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_DUPLICATE:
            sid += 1
        elif block_type == SIBT_SKIP1:
            if pos >= len(payload): break
            sid += payload[pos]; pos += 1
        elif block_type == SIBT_SKIP2:
            if pos + 2 > len(payload): break
            sid += u16(payload, pos); pos += 2
        elif block_type == SIBT_EXT1:
            if pos + 2 > len(payload): break
            pos += 1
            blen = payload[pos]; pos += 1
            pos += max(0, blen - 3)
        elif block_type == SIBT_EXT2:
            if pos + 3 > len(payload): break
            pos += 1
            blen = u16(payload, pos); pos += 2
            pos += max(0, blen - 4)
        elif block_type == SIBT_EXT4:
            if pos + 5 > len(payload): break
            pos += 1
            blen = u32(payload, pos); pos += 4
            pos += max(0, blen - 6)
        else:
            break

    return string_map if len(string_map) > 1 else None



# HII Form package / IFR opcode parsing

IFR_OP_FORM        = 0x01
IFR_OP_SUBTITLE    = 0x02
IFR_OP_TEXT        = 0x03
IFR_OP_ONE_OF      = 0x05
IFR_OP_CHECKBOX    = 0x06
IFR_OP_NUMERIC     = 0x07
IFR_OP_PASSWORD    = 0x08
IFR_OP_ONE_OF_OPT  = 0x09
IFR_OP_SUPPRESS_IF = 0x0A
IFR_OP_LOCKED      = 0x0B
IFR_OP_ACTION      = 0x0C
IFR_OP_RESET_BTN   = 0x0D
IFR_OP_FORM_SET    = 0x0E
IFR_OP_REF         = 0x0F
IFR_OP_NO_SUBMIT   = 0x10
IFR_OP_INCONS_IF   = 0x11
IFR_OP_GRAYOUT_IF  = 0x19
IFR_OP_DATE        = 0x1A
IFR_OP_TIME        = 0x1B
IFR_OP_STRING_OP   = 0x1C
IFR_OP_DISABLE_IF  = 0x1E
IFR_OP_ORDERED     = 0x23
IFR_OP_VARSTORE    = 0x24
IFR_OP_VARSTORE_NV = 0x25
IFR_OP_VARSTORE_EFI= 0x26
IFR_OP_VARSTORE_DEV= 0x27
IFR_OP_END         = 0x29
IFR_OP_DEFAULT     = 0x5B
IFR_OP_DEFAULTSTORE= 0x5C
IFR_OP_GUID        = 0x5F
IFR_OP_WARNING_IF  = 0x63

_SIZE_BITS = {0x00: 8, 0x01: 8, 0x02: 16, 0x03: 32, 0x04: 64}


def _parse_min_max_step(opdata: bytes, flags_off: int) -> Tuple[int, int, int, int]:
    if flags_off >= len(opdata):
        return 8, 0, 1, 0
    flags     = opdata[flags_off]
    size_bits = _SIZE_BITS.get(flags & 0x0F, 8)
    base      = flags_off + 1

    if size_bits == 8:
        if base + 3 > len(opdata): return size_bits, 0, 0xFF, 0
        return size_bits, opdata[base], opdata[base+1], opdata[base+2]
    elif size_bits == 16:
        if base + 6 > len(opdata): return size_bits, 0, 0xFFFF, 0
        return size_bits, u16(opdata,base), u16(opdata,base+2), u16(opdata,base+4)
    elif size_bits == 32:
        if base + 12 > len(opdata): return size_bits, 0, 0xFFFFFFFF, 0
        return size_bits, u32(opdata,base), u32(opdata,base+4), u32(opdata,base+8)
    elif size_bits == 64:
        if base + 24 > len(opdata): return size_bits, 0, 0xFFFFFFFFFFFFFFFF, 0
        return size_bits, u64(opdata,base), u64(opdata,base+8), u64(opdata,base+16)
    return size_bits, 0, 0, 0


def _is_valid_form_package(data: bytes, offset: int, pkg_len: int) -> bool:
    payload_start = offset + 4
    if payload_start + 2 > offset + pkg_len:
        return False
    op      = data[payload_start]
    hdr_b   = data[payload_start + 1]
    op_len  = hdr_b & 0x7F
    scope   = bool(hdr_b & 0x80)
    return op == IFR_OP_FORM_SET and op_len >= 24 and scope


def parse_form_package(data: bytes, pkg_offset: int, pkg_len: int,
                       strings: Dict[int, str]) -> List[str]:
    lines: List[str] = []
    scope_depth = 0
    pos = pkg_offset + 4
    end = pkg_offset + pkg_len

    def S(sid: int) -> str:
        return strings.get(sid, f"<str#{sid}>")

    while pos < end - 1:
        op      = data[pos]
        hdr_b   = data[pos + 1]
        op_len  = hdr_b & 0x7F
        scope   = bool(hdr_b & 0x80)

        if op_len < 2 or pos + op_len > end:
            pos += 1
            continue

        opdata = data[pos + 2: pos + op_len]

        if op == IFR_OP_END and scope_depth > 0:
            scope_depth -= 1

        indent = "\t" * scope_depth
        line: Optional[str] = None

        if op == IFR_OP_FORM_SET and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            tstr = S(u16(opdata, 16))
            hstr = S(u16(opdata, 18))
            line = f'{indent}FormSet Guid: {g}, Title: "{tstr}", Help: "{hstr}"'

        elif op == IFR_OP_FORM and len(opdata) >= 4:
            fid  = u16(opdata, 0)
            tstr = S(u16(opdata, 2))
            line = f'{indent}Form FormId: 0x{fid:X}, Title: "{tstr}"'

        elif op == IFR_OP_SUBTITLE and len(opdata) >= 5:
            pstr = S(u16(opdata, 0))
            hstr = S(u16(opdata, 2))
            flg  = opdata[4]
            line = f'{indent}Subtitle Prompt: "{pstr}", Help: "{hstr}", Flags: 0x{flg:X}'

        elif op == IFR_OP_TEXT and len(opdata) >= 6:
            pstr = S(u16(opdata, 0))
            hstr = S(u16(opdata, 2))
            tstr = S(u16(opdata, 4))
            line = f'{indent}Text Prompt: "{pstr}", Help: "{hstr}", Text: "{tstr}"'

        elif op == IFR_OP_VARSTORE and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            vsid = u16(opdata, 16)
            size = u16(opdata, 18)
            name = opdata[20:].rstrip(b'\x00').decode('ascii', errors='replace')
            line = f'{indent}VarStore Guid: {g}, VarStoreId: 0x{vsid:X}, Size: 0x{size:X}, Name: "{name}"'

        elif op == IFR_OP_VARSTORE_EFI and len(opdata) >= 26:
            vsid  = u16(opdata, 0)
            g     = guid_str(opdata, 2)
            attrs = u32(opdata, 18)
            size  = u16(opdata, 22)
            name  = opdata[24:].rstrip(b'\x00').decode('ascii', errors='replace')
            line  = (f'{indent}VarStoreEfi Guid: {g}, VarStoreId: 0x{vsid:X}, '
                     f'Attributes: 0x{attrs:X}, Size: 0x{size:X}, Name: "{name}"')

        elif op == IFR_OP_ONE_OF and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}OneOf Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')

        elif op == IFR_OP_CHECKBOX and len(opdata) >= 12:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            cflags = u8(opdata, 11)
            dflt   = "Enabled" if (cflags & 0x01) else "Disabled"
            mfgd   = "Enabled" if (cflags & 0x02) else "Disabled"
            line = (f'{indent}CheckBox Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{cflags:X}, Default: {dflt}, MfgDefault: {mfgd}')

        elif op == IFR_OP_NUMERIC and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}Numeric Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')

        elif op == IFR_OP_ONE_OF_OPT and len(opdata) >= 7:
            ostr   = S(u16(opdata, 0))
            oflags = opdata[2]
            val_hex = opdata[4:12].hex().upper()
            dflt   = ", Default"    if (oflags & 0x10) else ""
            mfgd   = ", MfgDefault" if (oflags & 0x20) else ""
            line = f'{indent}OneOfOption Option: "{ostr}", Value: 0x{val_hex}{dflt}{mfgd}'

        elif op == IFR_OP_DEFAULTSTORE and len(opdata) >= 4:
            nstr  = S(u16(opdata, 0))
            defid = u16(opdata, 2)
            line  = f'{indent}DefaultStore Name: "{nstr}", DefaultId: 0x{defid:X}'

        elif op == IFR_OP_DEFAULT and len(opdata) >= 3:
            defid = u16(opdata, 0)
            dtype = opdata[2]
            line  = f'{indent}Default DefaultId: 0x{defid:X}, Type: 0x{dtype:X}'

        elif op == IFR_OP_ACTION and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}Action Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')

        elif op == IFR_OP_REF and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            fid    = u16(opdata, 11) if len(opdata) >= 13 else 0
            line   = (f'{indent}Ref Prompt: "{pstr}", Help: "{hstr}", '
                      f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                      f'FormId: 0x{fid:X}')

        elif op in (IFR_OP_DATE, IFR_OP_TIME, IFR_OP_STRING_OP) and len(opdata) >= 11:
            name_map = {IFR_OP_DATE: "Date", IFR_OP_TIME: "Time", IFR_OP_STRING_OP: "String"}
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}{name_map[op]} Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')

        elif op == IFR_OP_SUPPRESS_IF: line = f'{indent}SuppressIf'
        elif op == IFR_OP_GRAYOUT_IF:  line = f'{indent}GrayOutIf'
        elif op == IFR_OP_DISABLE_IF:  line = f'{indent}DisableIf'
        elif op == IFR_OP_NO_SUBMIT:   line = f'{indent}NoSubmitIf'
        elif op == IFR_OP_INCONS_IF:   line = f'{indent}InconsistentIf'
        elif op == IFR_OP_END:         line = f'{indent}End'

        if line is not None:
            lines.append(line)

        if scope and op != IFR_OP_END:
            scope_depth += 1

        pos += op_len

    return lines



# Top-level scanner

PKG_TYPE_FORMS  = 0x02
PKG_TYPE_STRING = 0x04


def find_packages(data: bytes) -> Tuple[List[Tuple[int,int,Dict[int,str]]], List[Tuple[int,int]]]:
    string_pkgs: List[Tuple[int,int,Dict[int,str]]] = []
    form_pkgs:   List[Tuple[int,int]]               = []
    n = len(data)
    i = 0
    while i < n - 4:
        raw   = u32(data, i)
        ptype = (raw >> 24) & 0xFF
        plen  =  raw & 0x00FFFFFF

        if plen >= 4 and i + plen <= n:
            if ptype == PKG_TYPE_STRING and plen >= 50:
                smap = parse_string_package(data, i, plen)
                if smap is not None:
                    string_pkgs.append((i, plen, smap))
                    i += plen
                    continue

            elif ptype == PKG_TYPE_FORMS and plen >= 6:
                if _is_valid_form_package(data, i, plen):
                    form_pkgs.append((i, plen))
                    i += plen
                    continue

        i += 1

    return string_pkgs, form_pkgs


def extract_ifr(efi_path: str) -> str:
    data = Path(efi_path).read_bytes()
    print(f"[*] Scanning {len(data):,} bytes for HII packages...")

    string_pkgs, form_pkgs = find_packages(data)
    print(f"[+] Found {len(string_pkgs)} string package(s), {len(form_pkgs)} form package(s)")

    if not form_pkgs:
        print(f"\n{C_ERR}[!] No form packages found.{C_RST}")
        sys.exit(1)

    if not string_pkgs:
        print(f"{C_WARN}[!] No string packages found — settings will show as <str#N>{C_RST}")

    best_strings: Dict[int, str] = {}
    if string_pkgs:
        best_strings = max(string_pkgs, key=lambda x: len(x[2]))[2]
        print(f"[+] Using string package with {len(best_strings)} strings")

    all_lines: List[str] = []
    for idx, (off, plen) in enumerate(form_pkgs):
        lines = parse_form_package(data, off, plen, best_strings)
        all_lines.extend(lines)
        if DEBUG:
            print(f"    Form package {idx}: offset={off:#x}, length={plen:#x}, lines={len(lines)}")

    return "\n".join(all_lines)



# VarStore + setting parsing


_RE_VARSTORE = re.compile(
    r'VarStore(?:Efi)?\s+Guid:\s*([0-9A-Fa-f\-]{36})'
    r',\s*VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r'(?:,\s*Attributes:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Size:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Name:\s*"([^"]*)")?',
    re.IGNORECASE,
)

_RE_SETTING = re.compile(
    r'(OneOf|CheckBox|Numeric|Action)\s+Prompt:\s*"([^"]*)"'
    r'(?:,\s*Help:\s*"([^"]*)")?'
    r',\s*QuestionFlags:\s*0x([0-9A-Fa-f]+)'
    r',\s*QuestionId:\s*0x([0-9A-Fa-f]+)'
    r',\s*VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r',\s*VarOffset:\s*0x([0-9A-Fa-f]+)'
    r',\s*Flags:\s*0x([0-9A-Fa-f]+)'
    r'(?:,\s*Size:\s*(\d+))?'
    r'(?:,\s*Min:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Max:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Step:\s*0x([0-9A-Fa-f]+))?',
    re.IGNORECASE,
)


def parse_varstores(ifr_text: str) -> Dict[int, VarStore]:
    stores: Dict[int, VarStore] = {}
    for m in _RE_VARSTORE.finditer(ifr_text):
        guid  = m.group(1).upper()
        vsid  = int(m.group(2), 16)
        attrs = int(m.group(3), 16) if m.group(3) else 0x7
        size  = int(m.group(4), 16) if m.group(4) else 0
        name  = m.group(5) or ""
        stores[vsid] = VarStore(guid=guid, var_store_id=vsid,
                                attributes=attrs, size=size, name=name)
    return stores


def grep_settings(ifr_text: str, terms: List[str]) -> List[HiiSetting]:
    results: List[HiiSetting] = []
    seen: Set[Tuple] = set()
    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1)
        prompt    = m.group(2)
        help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16)
        q_id      = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16)
        vs_off    = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0

        if terms and terms != [""] and not any(t.lower() in (prompt + " " + help_text).lower() for t in terms):
            continue
        key = (vs_id, vs_off)
        if key in seen:
            continue
        seen.add(key)
        results.append(HiiSetting(
            widget_type=widget, prompt=prompt, help_text=help_text,
            question_flags=q_flags, question_id=q_id,
            var_store_id=vs_id, var_offset=vs_off,
            flags=flags, size=size, min_val=min_v, max_val=max_v, step=step,
        ))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# NVRAM parsing  (VSS variable store)
# ─────────────────────────────────────────────────────────────────────────────

VAR_HDR_MAGIC = 0x55AA

def _find_all_nvram_stores(fw: bytes) -> List[Tuple[int, int]]:
    """
    Find every EFI variable store in a firmware / NVRAM image.
    Returns list of (offset, size) for ALL valid candidates.

    FIX (v2): Previously only the *largest* store was returned, which caused
    the tool to select the FTW/spare area (biggest by allocation) instead of
    the actual variable store (most live entries).  We now return every valid
    candidate and let the caller pick the best one based on live-variable count.

    A valid store candidate satisfies:
      • byte at offset+20 == 0x5A  (EFI_HII_VARIABLE_STORE format marker)
      • byte at offset+21 == 0xFE  (healthy/valid state)
      • u32 at offset+16 is a sane size (0x400 < size < 0x800000)
      • at least one 0xAA55 variable header exists within the first 64 bytes
        of the store data area (after the 28-byte store header)
    """
    n = len(fw)
    store_candidates = []
    i = 0
    while i < n - 28:
        if fw[i + 20] == 0x5A and fw[i + 21] == 0xFE:
            size = u32(fw, i + 16)
            if 0x400 < size < 0x800000 and i + size <= n:
                aa55_near = fw.find(b'\xaa\x55', i + 28, i + 92)
                if aa55_near >= 0:
                    store_candidates.append((i, size))
        i += 1

    return store_candidates   # ALL stores — caller selects the best one


def _guid_str_to_bytes(gs: str) -> bytes:
    parts = gs.replace("-", "")
    a = int(parts[0:8],  16)
    b = int(parts[8:12], 16)
    c = int(parts[12:16],16)
    d = bytes.fromhex(parts[16:20])
    e = bytes.fromhex(parts[20:32])
    return struct.pack("<IHH", a, b, c) + d + e


def _probe_var_header(nvram: bytes, guid_pos: int):
    """
    Locate the variable header that owns the GUID found at *guid_pos* by
    probing all three known EFI variable header layouts:

      Layout A  AuthVar   (60-byte header): GUID at +44, Name at +60
                  Used by: Intel/standard authenticated-variable stores.

      Layout B  VSS2/AMD  (36-byte header): GUID at +20, Name at +36   ← NEW
                  Used by: AMD/Lenovo platforms (e.g. ThinkPad with Phoenix
                  BIOS on Ryzen).  Header structure:
                    +00 StartId    u16  (0x55AA)
                    +02 State      u8
                    +03 Reserved   u8
                    +04 Reserved2  u32  (platform-specific; often a counter)
                    +08 Attributes u32
                    +0C NameSize   u32
                    +10 DataSize   u32
                    +14 VendorGuid (16 bytes)   ← offset 20
                    +24 Name (UCS-2)            ← offset 36

      Layout C  VSS legacy (32-byte header): GUID at +16, Name at +32
                  Used by: older/simpler UEFI implementations.

    Returns (hdr_offset, name_start_offset) or (None, None).
    """
    for guid_off_in_hdr, name_off_in_hdr in ((44, 60), (20, 36), (16, 32)):
        hdr = guid_pos - guid_off_in_hdr
        if hdr >= 0 and nvram[hdr] == 0xAA and nvram[hdr + 1] == 0x55:
            return hdr, hdr + name_off_in_hdr
    return None, None


def _search_nvram_region(nvram: bytes, target: bytes, var_offset: int,
                          size_bytes: int, var_name: str,
                          live_result, deleted_result):
    """Search one NVRAM region, updating live/deleted results. Returns (live, deleted)."""
    n = len(nvram)
    search_pos = 0
    while search_pos < n - 16:
        guid_pos = nvram.find(target, search_pos)
        if guid_pos < 0:
            break
        search_pos = guid_pos + 1

        hdr, name_start = _probe_var_header(nvram, guid_pos)
        if hdr is None:
            continue
        state = nvram[hdr + 2]

        pos = name_start
        name_chars = []
        while pos + 1 < n:
            lo, hi = nvram[pos], nvram[pos + 1]
            pos += 2
            if lo == 0 and hi == 0:
                break
            name_chars.append(chr(lo) if hi == 0 else "?")
        found_name = "".join(name_chars)

        if var_name and found_name != var_name:
            continue

        data_off = pos
        if data_off + var_offset + size_bytes > n:
            continue

        raw = nvram[data_off + var_offset: data_off + var_offset + size_bytes]
        fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
        try:
            val = struct.unpack(fmt, raw)[0]
        except struct.error:
            continue

        if state == 0x3F:
            live_result = val
        elif deleted_result is None:
            deleted_result = val

    return live_result, deleted_result


def find_nvram_value(nvram, guid_str_val: str, var_offset: int, size_bits: int,
                     var_name: str = "") -> Optional[int]:
    target     = _guid_str_to_bytes(guid_str_val)
    size_bytes = max(1, size_bits // 8)

    live_result    = None
    deleted_result = None

    for region in (nvram if isinstance(nvram, list) else [nvram]):
        live_result, deleted_result = _search_nvram_region(
            region, target, var_offset, size_bytes, var_name,
            live_result, deleted_result)
        if live_result is not None:
            break

    return live_result if live_result is not None else deleted_result


def write_nvram_value(nvram_path: str, guid_str_val: str, var_name: str,
                      var_offset: int, size_bits: int, new_value: int) -> bool:
    nvram = Path(nvram_path).read_bytes()
    target = _guid_str_to_bytes(guid_str_val)
    size_bytes = max(1, size_bits // 8)
    n = len(nvram)

    live_pos    = None
    deleted_pos = None

    search_pos = 0
    while search_pos < n - 16:
        guid_pos = nvram.find(target, search_pos)
        if guid_pos < 0:
            break
        search_pos = guid_pos + 1

        hdr, name_start = _probe_var_header(nvram, guid_pos)
        if hdr is None:
            continue
        state = nvram[hdr + 2]

        pos = name_start
        name_chars = []
        while pos + 1 < n:
            lo, hi = nvram[pos], nvram[pos + 1]
            pos += 2
            if lo == 0 and hi == 0:
                break
            name_chars.append(chr(lo) if hi == 0 else "?")

        if "".join(name_chars) != var_name:
            continue

        data_off = pos
        write_off = data_off + var_offset
        if write_off + size_bytes > n:
            continue

        if state == 0x3F:
            live_pos = write_off
        elif deleted_pos is None:
            deleted_pos = write_off

    target_off = live_pos if live_pos is not None else deleted_pos
    if target_off is None:
        return False

    fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
    packed = struct.pack(fmt, new_value)
    buf = bytearray(nvram)
    buf[target_off: target_off + size_bytes] = packed
    Path(nvram_path).write_bytes(bytes(buf))
    return True



# Reverse lookup

def reverse_lookup(ifr_text: str, stores: Dict[int, VarStore],
                   guid: str, key_name: str) -> List[HiiSetting]:
    guid = guid.upper()
    matching_vsids = {
        vsid for vsid, vs in stores.items()
        if vs.guid.upper() == guid and vs.name == key_name
    }
    if not matching_vsids:
        return []
    results: List[HiiSetting] = []
    seen: Set[Tuple] = set()
    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1)
        prompt    = m.group(2)
        help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16)
        q_id      = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16)
        vs_off    = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0
        if vs_id not in matching_vsids:
            continue
        key = (vs_id, vs_off)
        if key in seen:
            continue
        seen.add(key)
        s = HiiSetting(widget_type=widget, prompt=prompt, help_text=help_text,
                       question_flags=q_flags, question_id=q_id,
                       var_store_id=vs_id, var_offset=vs_off,
                       flags=flags, size=size, min_val=min_v, max_val=max_v, step=step)
        s.var_store = stores.get(vs_id)
        results.append(s)
    return results


# printing tables

def _col_w(rows: List[List[str]], headers: List[str]) -> List[int]:
    w = [len(h) for h in headers]
    for row in rows:
        for i, c in enumerate(row):
            if i < len(w):
                w[i] = max(w[i], len(c))
    return w

def _hdr(text: str) -> str:
    return f"\n{C_HEAD}{text}{C_RST}\n{'─' * len(text)}"

def _box(title: str, lines: List[str]) -> None:
    width = max(len(title) + 4, max((len(l) for l in lines), default=0) + 4)
    bar   = "─" * width
    print(f"\n{C_HEAD}┌{bar}┐")
    pad   = width - len(title) - 2
    print(f"│ {title}{' ' * pad} │")
    print(f"├{bar}┤{C_RST}")
    for l in lines:
        pad = width - len(l) - 2
        print(f"  {l}")
    print(f"{C_HEAD}└{bar}┘{C_RST}")

def print_table(headers: List[str], rows: List[List], title: str = "") -> None:
    rs  = [[str(c) for c in row] for row in rows]
    w   = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    table_lines = [fmt.format(*headers), sep] + [fmt.format(*row) for row in rs]
    if title:
        _box(title, table_lines)
    else:
        for l in table_lines:
            print(l)
    print()

def _fmt_value(val: Optional[int], size_bits: int) -> str:
    if val is None:
        return "NOT FOUND"
    size_bytes = max(1, size_bits // 8)
    hex_digits = size_bytes * 2
    return f"0x{val:0{hex_digits}X}"


def print_settings_table(settings: List[HiiSetting], stores: Dict[int, VarStore],
                          title: str = "SETTINGS") -> None:
    rows = []
    for i, s in enumerate(settings):
        vs = stores.get(s.var_store_id)
        store_name = vs.name if vs else f"0x{s.var_store_id:X}"
        setting_name = s.prompt if len(s.prompt) <= 44 else s.prompt[:43] + "\u2026"
        val_str = _fmt_value(s.current_value, s.size)
        rows.append([str(i + 1), setting_name, store_name,
                     f"0x{s.var_offset:X}", val_str])
    headers = ["#", "Setting", "Store", "Offset", "Value"]
    rs = [[str(c) for c in row] for row in rows]
    w  = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    table_lines = [fmt.format(*headers), sep]
    for row in rs:
        line = fmt.format(*row)
        val = row[4]
        if val == "NOT FOUND":
            line = line.replace(val, f"{C_WARN}{val}{C_RST}", 1)
        else:
            line = line.replace(val, f"{C_OK}{val}{C_RST}", 1)
        table_lines.append(line)
    _box(title, table_lines)
    print()


def print_varstore_map(settings: List[HiiSetting], stores: Dict[int, VarStore]) -> None:
    rows = []
    seen: Set[int] = set()
    for s in settings:
        if s.var_store_id in seen:
            continue
        seen.add(s.var_store_id)
        vs = stores.get(s.var_store_id)
        if vs:
            rows.append([vs.name, vs.guid, f"0x{vs.size:X}"])
        else:
            rows.append([f"0x{s.var_store_id:X}", "?", "?"])
    print_table(["Store", "GUID", "Size"], rows, title="VARSTORE  →  GUID")


# Extra EFI scanner

def scan_extra_varstores(paths: List[str]) -> Dict[int, VarStore]:
    empty_strings: Dict[int, str] = {}
    combined: Dict[int, VarStore] = {}

    for path in paths:
        if not os.path.isfile(path):
            print(f"{C_WARN}[!] Extra EFI not found, skipping: {path}{C_RST}")
            continue
        data = Path(path).read_bytes()
        _, form_pkgs = find_packages(data)
        if not form_pkgs:
            if DEBUG: print(f"{C_WARN}[!] No form packages in: {path}{C_RST}")
            continue
        for off, plen in form_pkgs:
            lines = parse_form_package(data, off, plen, empty_strings)
            ifr_chunk = "\n".join(lines)
            stores = parse_varstores(ifr_chunk)
            combined.update(stores)
        if DEBUG:
            print(f"[+] Extra EFI {os.path.basename(path)}: {len(form_pkgs)} form pkg(s), {len(combined)} VarStore(s) so far")

    return combined


# MAIN

def _load_ifr_and_stores(efi: str, extra_efi: List[str], dump_ifr: Optional[str]):
    ifr_text = extract_ifr(efi)
    if dump_ifr:
        Path(dump_ifr).write_text(ifr_text, encoding="utf-8")
        if DEBUG:
            print(f"[+] IFR text saved to: {dump_ifr}")

    stores = parse_varstores(ifr_text)

    if extra_efi:
        extra = scan_extra_varstores(extra_efi)
        before = len(stores)
        stores.update(extra)
        if DEBUG:
            print(f"[+] {before} VarStore(s) in EFI + {len(extra)} from extras = {len(stores)} total.")
    else:
        efi_dir  = os.path.dirname(os.path.abspath(efi))
        efi_name = os.path.basename(efi)
        siblings = [os.path.join(efi_dir, f) for f in os.listdir(efi_dir)
                    if f != efi_name and f.endswith(".efi")
                    and os.path.isfile(os.path.join(efi_dir, f))]
        if siblings:
            extra = scan_extra_varstores(siblings)
            before = len(stores)
            stores.update(extra)
            if DEBUG and len(stores) > before:
                print(f"[+] Merged {len(stores)-before} additional VarStore(s) from siblings.")

    return ifr_text, stores


def main() -> None:
    epilog = """
EXAMPLE USAGE:\n
  Mode 1 — Map EFI settings to NVRAM variables (search by keyword):
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms VT-d,IOMMU
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --modify
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --set 2 0x1
    nvramap.py -mode 1 -efi Setup.efi -firmware firmware.bin -terms DMA --set 2 0x1

  Mode 2 — Map NVRAM variables to EFI settings (reverse lookup by GUID + key):
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid FB3B9ECE-4ABA-4933-B49D-B4D67D892351 -key HpDmarOptions
    nvramap.py -mode 2 -efi Setup.efi -firmware firmware.bin -guid FB3B9ECE-4ABA-4933-B49D-B4D67D892351 -key HpDmarOptions --modify
"""
    ap = argparse.ArgumentParser(
        prog="nvramap.py",
        description=(
            "NVRAMap — UEFI NVRAM Mapper & Editor\n"
            "\n"
            "  Parses HII form data from any UEFI EFI module and maps firmware\n"
            "  settings to their NVRAM variable store locations. Supports reading\n"
            "  and writing live values in raw NVRAM binary blobs.\n"
            "\n"
            "  Mode 1: Map EFI Settings  →  NVRAM Variables  (search by keyword)\n"
            "  Mode 2: Map NVRAM Variables  →  EFI Settings  (reverse, by GUID+key)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    req = ap.add_argument_group("required arguments")
    req.add_argument("-mode", required=True, choices=["1", "2"],
                    metavar="MODE",
                    help="Operation mode: 1 = EFI→NVRAM  |  2 = NVRAM→EFI")
    req.add_argument("-efi",  required=True, metavar="FILE",
                    help="Path to EFI module containing HII form data")
    req.add_argument("-nvram", default=None, metavar="FILE",
                    help="Path to raw NVRAM binary blob")
    req.add_argument("-firmware", default=None, metavar="FILE",
                    help="Path to full firmware dump (NVRAM store located automatically)")

    m1 = ap.add_argument_group("mode 1 options")
    m1.add_argument("-terms", "-t", default=None, metavar="TERMS",
                    help="Comma-separated search terms  e.g. VT-d,IOMMU,DMA")
    m1.add_argument("-all", action="store_true",
                    help="Dump every setting in the EFI (no search filter)")

    m2 = ap.add_argument_group("mode 2 options")
    m2.add_argument("-guid", default=None, metavar="GUID",
                    help="VarStore GUID  e.g. FB3B9ECE-4ABA-4933-B49D-B4D67D892351")
    m2.add_argument("-key",  default=None, metavar="NAME",
                    help="NVRAM variable name  e.g. HpDmarOptions")

    opt = ap.add_argument_group("options")
    opt.add_argument("--modify", action="store_true",
                    help="Interactive edit mode — select and modify values after display")
    opt.add_argument("--set", nargs=2, metavar=("INDEX", "VALUE"),
                    help="Non-interactive write: set setting [INDEX] to VALUE (0x.. or decimal)")
    opt.add_argument("--extra-efi", nargs="+", default=[], metavar="FILE",
                    help="Additional EFI files to scan for VarStore GUID definitions")
    opt.add_argument("--dump-ifr", default=None, metavar="FILE",
                    help="Save full extracted IFR text to FILE")
    opt.add_argument("--dump-var", default=None, metavar="GUID",
                    help="Debug: dump all raw NVRAM entries for a given GUID")
    opt.add_argument("--debug", action="store_true",
                    help="Verbose parsing output")

    args = ap.parse_args()

    global DEBUG
    DEBUG = args.debug

    print(BANNER)

    if not args.nvram and not args.firmware:
        ap.error("one of -nvram or -firmware is required")
    if args.nvram and args.firmware:
        ap.error("-nvram and -firmware are mutually exclusive")

    if args.mode == "1" and not args.terms and not getattr(args, 'all', False):
        ap.error("Mode 1 requires either -terms KEYWORD or -all")
    if args.mode == "2" and (not args.guid or not args.key):
        ap.error("Mode 2 requires both -guid and -key")

    if not os.path.isfile(args.efi):
        sys.exit(f"{C_ERR}[!] File not found: -efi {args.efi}{C_RST}")

    fw_bytes    = None
    nvram_off   = 0
    nvram_size  = 0

    if args.firmware:
        if not os.path.isfile(args.firmware):
            sys.exit(f"{C_ERR}[!] File not found: -firmware {args.firmware}{C_RST}")
        fw_bytes = bytearray(Path(args.firmware).read_bytes())
        stores_found = _find_all_nvram_stores(bytes(fw_bytes))
        if not stores_found:
            sys.exit(f"{C_ERR}[!] NVRAM variable store not found in firmware image{C_RST}")

        # ── Select best store: the one with the most live (state=0x3F) variables ──
        def _count_live(fw, off, sz):
            return sum(1 for i in range(off, off + sz - 4)
                       if fw[i] == 0xAA and fw[i+1] == 0x55 and fw[i+2] == 0x3F)

        nvram_regions = sorted(
            stores_found,
            key=lambda t: _count_live(bytes(fw_bytes), t[0], t[1]),
            reverse=True
        )
        nvram_bytes = [bytes(fw_bytes[off:off+size]) for off, size in nvram_regions]
        print(f"[+] Firmware: {len(fw_bytes):,} bytes")
        print(f"[+] Found {len(nvram_regions)} NVRAM store(s) (sorted by live-variable count):")
        for off, size in nvram_regions:
            lv = _count_live(bytes(fw_bytes), off, size)
            print(f"    0x{off:X}  size=0x{size:X}  live_vars={lv}")
    else:
        if not os.path.isfile(args.nvram):
            sys.exit(f"{C_ERR}[!] File not found: -nvram {args.nvram}{C_RST}")
        raw_nvram = Path(args.nvram).read_bytes()

        # ── When given a raw NVRAM blob that may contain multiple stores
        #    (e.g. a .vbd file exported from UEFITool), auto-detect all stores
        #    and search across them in live-variable-count order. ──
        sub_stores = _find_all_nvram_stores(raw_nvram)
        if len(sub_stores) > 1:
            def _count_live_bytes(data, off, sz):
                return sum(1 for i in range(off, off + sz - 4)
                           if data[i] == 0xAA and data[i+1] == 0x55 and data[i+2] == 0x3F)
            sub_stores = sorted(sub_stores,
                                key=lambda t: _count_live_bytes(raw_nvram, t[0], t[1]),
                                reverse=True)
            nvram_bytes  = [raw_nvram[off:off+sz] for off, sz in sub_stores]
            nvram_regions = sub_stores
            print(f"[+] NVRAM blob: {len(raw_nvram):,} bytes")
            print(f"[+] Detected {len(sub_stores)} embedded store(s) (sorted by live-variable count):")
            for off, sz in sub_stores:
                lv = _count_live_bytes(raw_nvram, off, sz)
                print(f"    0x{off:X}  size=0x{sz:X}  live_vars={lv}")
        else:
            nvram_bytes  = raw_nvram
            nvram_regions = None
            print(f"[+] NVRAM: {len(raw_nvram):,} bytes")

    # Load IFR
    ifr_text, stores = _load_ifr_and_stores(args.efi, args.extra_efi, args.dump_ifr)

    print("[+] Performing analysis...\n")

    if args.dump_var:
        _do_dump_var(nvram_bytes, args.dump_var.upper())

    if args.mode == "1":
        if getattr(args, 'all', False):
            settings = grep_settings(ifr_text, [""])
            title = "MODE 1  —  EFI Settings → NVRAM  (all)"
        else:
            terms = [t.strip() for t in args.terms.split(",") if t.strip()]
            settings = grep_settings(ifr_text, terms)
            title = f"MODE 1  —  EFI Settings → NVRAM  ({args.terms})"
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found{C_RST}")
        for s in settings:
            s.var_store = stores.get(s.var_store_id)

    else:  # mode 2
        settings = reverse_lookup(ifr_text, stores, args.guid, args.key)
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found for GUID={args.guid}  Key={args.key}{C_RST}")
        title = f"MODE 2  —  NVRAM → EFI Settings  |  {args.key}  ({args.guid})"

    for s in settings:
        vs = stores.get(s.var_store_id)
        if vs and vs.guid and vs.guid != "?":
            s.current_value = find_nvram_value(
                nvram_bytes, vs.guid, s.var_offset, s.size, var_name=vs.name)

    print_varstore_map(settings, stores)
    print_settings_table(settings, stores, title=title)


    # Modification logic
    do_modify = args.modify
    set_arg   = args.set

    def _parse_val(raw_val: str) -> int:
        raw_val = raw_val.strip()
        if raw_val.lower().startswith("0x"):
            return int(raw_val, 16)
        return int(raw_val)

    def _apply_change(idx: int, new_val: int, patched) -> bool:
        s  = settings[idx]
        vs = stores.get(s.var_store_id)
        if not vs:
            print(f"  {C_ERR}No VarStore for setting {idx+1}.{C_RST}")
            return False
        target = _guid_str_to_bytes(vs.guid)
        size_bytes = max(1, s.size // 8)

        regions = patched if isinstance(patched, list) else [patched]

        for region in regions:
            n = len(region)
            live_off    = None
            deleted_off = None
            search_pos  = 0

            while search_pos < n - 16:
                guid_pos = bytes(region).find(target, search_pos)
                if guid_pos < 0:
                    break
                search_pos = guid_pos + 1

                hdr, name_start = _probe_var_header(bytes(region), guid_pos)
                if hdr is None:
                    continue
                state = region[hdr + 2]

                pos = name_start
                name_chars = []
                while pos + 1 < n:
                    lo, hi = region[pos], region[pos + 1]; pos += 2
                    if lo == 0 and hi == 0: break
                    name_chars.append(chr(lo) if hi == 0 else "?")
                if "".join(name_chars) != vs.name:
                    continue

                write_off = pos + s.var_offset
                if write_off + size_bytes > n:
                    continue

                if state == 0x3F:
                    live_off = write_off
                elif deleted_off is None:
                    deleted_off = write_off

            target_off = live_off if live_off is not None else deleted_off
            if target_off is not None:
                fmt_s = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
                region[target_off: target_off + size_bytes] = struct.pack(fmt_s, new_val)
                s.current_value = new_val
                return True

        print(f"  {C_ERR}Variable not found in NVRAM buffer.{C_RST}")
        return False

    if isinstance(nvram_bytes, list):
        patched = [bytearray(r) for r in nvram_bytes]
    else:
        patched = bytearray(nvram_bytes)
    changes: List[str] = []

    if set_arg:
        try:
            idx     = int(set_arg[0]) - 1
            new_val = _parse_val(set_arg[1])
        except (ValueError, IndexError):
            sys.exit(f"{C_ERR}Invalid --set arguments.{C_RST}")
        if not (0 <= idx < len(settings)):
            sys.exit(f"{C_ERR}Index {idx+1} out of range (1–{len(settings)}).{C_RST}")
        if _apply_change(idx, new_val, patched):
            s = settings[idx]
            changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}")
            print(f"  {C_OK}Set [{idx+1}] {s.prompt} = {_fmt_value(new_val, s.size)}{C_RST}")

    elif do_modify:
        print("  Modify mode — select a setting by number, 'done' to save, 'q' to quit without saving.")
        print()
        while True:
            print_settings_table(settings, stores, title="Current Values")
            try:
                raw = input("  >> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                raw = "q"

            if raw in ("q", "quit"):
                print("  Aborted — no changes written.")
                return
            if raw in ("done", "d", ""):
                break

            try:
                idx = int(raw) - 1
            except ValueError:
                print("  Enter a number.\n"); continue
            if not (0 <= idx < len(settings)):
                print(f"  Out of range (1–{len(settings)}).\\n"); continue

            s  = settings[idx]
            vs = stores.get(s.var_store_id)
            cur = _fmt_value(s.current_value, s.size)
            print(f"\n  [{idx+1}] {s.prompt}")
            print(f"       Current : {cur}")
            print(f"       Range   : 0x{s.min_val:X} – 0x{s.max_val:X}")
            try:
                raw_val = input("  New value (hex 0x.. or decimal, blank to skip): ").strip()
                if not raw_val:
                    print("  Skipped.\n"); continue
                new_val = _parse_val(raw_val)
            except (ValueError, EOFError, KeyboardInterrupt):
                print("  Cancelled.\n"); continue
            if not (s.min_val <= new_val <= s.max_val):
                print(f"  {C_WARN}Warning: outside valid range.{C_RST}")
            if _apply_change(idx, new_val, patched):
                changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}")
                print(f"  {C_OK}New Value: {_fmt_value(new_val, s.size)}{C_RST}\n")

    # Save patched file
    if changes:
        # Determine source file and regions
        if args.firmware:
            src_p = Path(args.firmware)
            out_path = src_p.parent / (src_p.stem + "_patched" + src_p.suffix)
            for (off, size), region in zip(nvram_regions, patched):
                fw_bytes[off:off + size] = region
            out_path.write_bytes(bytes(fw_bytes))
        else:
            src_p = Path(args.nvram)
            out_path = src_p.parent / (src_p.stem + "_patched" + src_p.suffix)
            if isinstance(nvram_regions, list):
                # Multi-store .vbd: write back each patched region into the original blob
                buf = bytearray(Path(args.nvram).read_bytes())
                for (off, size), region in zip(nvram_regions, patched):
                    buf[off:off + size] = region
                out_path.write_bytes(bytes(buf))
            else:
                out_path.write_bytes(bytes(patched))

        print(f"\n{C_OK}  Saved → {out_path}{C_RST}")
        print(f"  Changes applied:")
        for c in changes:
            print(f"    {c}")
        print()


def _do_dump_var(nvram, dump_guid: str) -> None:
    try:
        target = _guid_str_to_bytes(dump_guid)
    except Exception:
        print(f"{C_ERR}Invalid GUID: {dump_guid}{C_RST}")
        return

    regions = nvram if isinstance(nvram, list) else [nvram]

    print(_hdr(f"NVRAM VAR DUMP  {dump_guid}"))
    match_n = 0
    for region in regions:
        n = len(region)
        search = 0
        while search < n - 16:
            gi = region.find(target, search)
            if gi < 0: break
            search = gi + 1
            match_n += 1

            hdr = gi
            while hdr > max(0, gi - 256):
                if region[hdr] == 0xAA and region[hdr+1] == 0x55: break
                hdr -= 1

            print(f"\n  Match {match_n}:  GUID@{gi:#x}  AA55@{hdr:#x}")
            chunk = region[hdr:hdr+80]
            for row in range(0, len(chunk), 16):
                hp = " ".join(f"{chunk[row+k]:02X}" for k in range(16) if row+k < len(chunk))
                print(f"    {hdr+row:08X}:  {hp}")

            p = gi + 16
            name_chars = []
            while p + 1 < n:
                lo, hi = region[p], region[p+1]; p += 2
                if lo == 0 and hi == 0: break
                name_chars.append(chr(lo) if hi == 0 else "?")
            name = "".join(name_chars)
            print(f"\n  Key: '{name}'   data @ {p:#x}")

            next_hdr = n
            for np in range(p+2, min(p+0x10000, n-1)):
                if region[np] == 0xAA and region[np+1] == 0x55:
                    next_hdr = np; break
            db = region[p:next_hdr]
            print(f"  Data ({len(db):#x} bytes):")
            print("  off:  " + "  ".join(f"{k:02X}" for k in range(16)))
            print("  ----  " + "  ".join("--" for _ in range(16)))
            for row in range(0, min(len(db), 64), 16):
                vs = "  ".join(f"{db[row+k]:02X}" for k in range(16) if row+k < len(db))
                print(f"  {row:04X}:  {vs}")

    if match_n == 0:
        print("  GUID not found.")
    print()


if __name__ == "__main__":
    main()
