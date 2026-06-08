# Map EFI Program Settings to NVRAM Key Values
This tool allows the operator to map possible control values in NVRAM to a given setting managed by an EFI program. The setting value can then be modified to control the underlying feature.
There are two analysis modes:
- Mode 1 : Map EFI program settings to NVRAM variables and values
- Mode 2 : Map NVRAM variable to EFI program settings
  
The tool is vendor agnostic and works against most modern UEFI implementations. The intended usage is to allow the user to quickly find and modify values related to important security settings when conducting physical penetration tests against UEFI firmware dumps. Once a setting is mapped, it's value can be overwritten and the resultant patched NVRAM can be flashed back onto the target computer's EEPROM chip to control firmware behaviour without requiring access to the pre-boot GUI or triggering a BitLocker recovery. Inspired by [research](https://www.mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios/) published by [Craig Blackie](https://github.com/craigsblackie), this tool extracts IFR data from the target EFI module, parses it for relevant settings, then resolves each setting's VarStoreId to it's corresponding NVRAM GUID and Key name, before parsing the provided NVRAM or firmware dump to extract and display the values at the correct offsets. Each live value is mapped to the option string it represents in the IFR data and shown under the status column. This technique enables fast analysis of EFI modules or NVRAM Variable Stores. 

To use this tool, extract the firmware from target EEPROM chip. You may specify extracted NVRAM or EFI programs to improve performance, or simply point NVRAMap at the full firmware dump and chose an analysis mode to begin automatic relationship discovery. In automatic mode, it may take a few minutes to perform full mapping. For modifications, simply use the ```--modify``` flag to launch the interactive editor. This mode will show additional information about targetted settings such as help strings and a list of valid options.

# Demo (mode 1 - EFI Settings to NVRAM analysis)
![](https://github.com/PN-Tester/NVRAMap/blob/main/Mode_1.PNG)
*The above image shows automatic discovery of where DMA Protection and Intel Virtualization settings are controlled*

# Demo (mode 2 - NVRAM to EFI Settings analysis)
![](https://github.com/PN-Tester/NVRAMap/blob/main/Mode_2.PNG)
*The above image shows discovery of what settings the target NVRAM variable data controls*

# Demo (Modifying values)
![](https://github.com/PN-Tester/NVRAMap/blob/main/Mode_Modify.PNG)
*The above image shows modification of pre-boot DMA Protection setting*

# Usage
```
usage: nvramap.py [-h] -mode MODE [-efi FILE] [-nvram FILE] [-firmware FILE] [-terms TERMS] [-all] [-guid GUID] [-key NAME] [--modify] [--set INDEX VALUE] [--extra-efi FILE [FILE ...]] [--dump-ifr FILE]
                  [--dump-var GUID] [--list-hii] [--debug-fw] [--debug]

NVRAMap — UEFI NVRAM Mapper & Editor

  When -efi is omitted and only -firmware is given, all UEFI Firmware
  Volumes are scanned automatically for EFI module discovery. 
  This may take several minutes.

options:
  -h, --help            show this help message and exit

required arguments:
  -mode MODE            Operation mode: 1 = EFI→NVRAM | 2 = NVRAM→EFI
  -efi FILE             EFI module with HII data (optional when -firmware is given)
  -nvram FILE           Raw NVRAM binary blob (optional when -firmware is given)
  -firmware FILE        Full firmware dump (NVRAM + HII modules located automatically)

mode 1 options:
  -terms TERMS, -t TERMS
                        Comma-separated search terms e.g. VT-d,IOMMU,DMA
  -all                  Dump every setting (no filter)

mode 2 options:
  -guid GUID            GUID of the VarStore you want to map
  -key NAME             Name of the NVRAM Key you want to map

options:
  --modify
  --set INDEX VALUE
  --extra-efi FILE [FILE ...]
  --dump-ifr FILE
  --dump-var GUID
  --list-hii            List all HII-bearing EFI modules found in firmware and exit
  --debug-fw            Print detailed firmware structure scan (FVs, sections, decomp results) and exit
  --debug               Verbose parsing output

EXAMPLE USAGE:

  Mode 1 — Map EFI settings to NVRAM variables (search by keyword):
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms VT-d,IOMMU
    nvramap.py -mode 1 -firmware firmware.bin -terms DMA
    nvramap.py -mode 1 -firmware firmware.bin -all

  Mode 2 — Map NVRAM variables to EFI settings (reverse lookup by GUID + key):
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid <GUID> -key <NAME>
    nvramap.py -mode 2 -firmware firmware.bin -guid <GUID> -key <NAME>

  Diagnostics:
    nvramap.py -mode 1 -firmware firmware.bin --list-hii
    nvramap.py -mode 1 -firmware firmware.bin --debug-fw

```

# Explanation
Originally, my methodology for mapping NVRAM data to the functionality it controlled involved targeted diffing of firmware dumps that matched the desired configuration state for further research. As expected, this method is time consuming and not suitable for large scale fuzzing or discovery of UEFI functionality. Then, security researcher [Craig Blackie](https://github.com/craigsblackie) at MDSEC sent me an [article he wrote](https://www.mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios/) where he describes using [IFRExtractor](https://github.com/LongSoft/IFRExtractor-RS) to determine control variables for Pre-Boot DMA Protection in Dell firmware. His methodology involved extracting the Setup.efi program from the firmware dump and analyzing its IFR structures to identify the NVRAM variable store associated with various UI actions (like choosing setting values). In his article, he manually performs the mapping operation through a combination of UEFITools and output from the extractor, arriving at precise offsets in the setup NVRAM variable that control the behaviour of pre-boot DMA countermeasures. I was curious if this technique could be automated and used to map the relationship between arbitrary EFI programs and NVRAM in a vendor agnostic scanner. NVRAMap is the result of this questioning. The present program will use extracted IFR data from the specified EFI program to map the settings it manages to NVRAM GUIDs and Keys. It will then automatically parse the specified NVRAM dump and map the detected settings to their assigned values. This can occur forward, or in reverse, in situations where an operator has an NVRAM section they are interested in but do not know what the data controls. Finally, the program can be used to modify the discovered setting values, creating a patched NVRAM file in the same directory which can later be used for flashing a target computer's EEPROM via universal programmer.
