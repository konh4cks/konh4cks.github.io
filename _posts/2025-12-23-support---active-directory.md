---
title: Support - Active Directory
date: 2025-12-23 00:00:00 +0000
categories: [HackTheBox Writeups, Windows]
tags: [hackthebox, windows]
---


```
sudo nmap -sVC -A -T4 $target       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-13 10:59 EET
Nmap scan report for 10.129.58.63 (10.129.58.63)
Host is up (0.048s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-13 09:00:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
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
|   date: 2025-11-13T09:00:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   45.40 ms 10.10.14.1 (10.10.14.1)
2   45.76 ms 10.129.58.63 (10.129.58.63)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.33 seconds
```

```
enum4linux -ng $target | tee enum4linux.log 
```
![[Pasted image 20251113111442.png]]

```
smbmap -H $target -u 'guest' -p ''
```
![[Pasted image 20251113113340.png]]

```
smbmap -H $target -u 'guest' -p '' -r support-tools
```
![[Pasted image 20251113113148.png]]

Download file:
```
smbmap -H $target -u 'guest' -p '' --download "support-tools/UserInfo.exe.zip"
```

```
netexec smb $target -u 'guest' -p '' --rid-brute
```
![[Pasted image 20251113113231.png]]

```
netexec smb $target -u 'guest' -p '' --rid-brute | grep -i 'sidtypeuser' | awk '{print$6}' | cut -d '\' -f2 | tee userlist2.txt

Administrator
Guest
krbtgt
DC$
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

