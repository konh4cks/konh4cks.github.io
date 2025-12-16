```
┌──(ares㉿legion)-[~]
└─$ sudo nmap -sV -A -T4 $target        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-07 10:53 EET
Stats: 0:00:25 elapsed; 0 hosts completed (1 up), 1 undergoing Traceroute
Traceroute Timing: About 32.26% done; ETC: 10:53 (0:00:00 remaining)
Nmap scan report for 10.10.11.143 (10.10.11.143)
Host is up (0.052s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=11/7%OT=22%CT=1%CU=34936%PV=Y%DS=2%DC=T%G=Y%TM=690DB39
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:04%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%
OS:II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=108%GCD=1%
OS:ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT
OS:11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1=7120%W2=7120%W3=7
OS:120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M552NNSNW7%CC=Y%Q
OS:=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL
OS:=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   52.60 ms 10.10.14.1 (10.10.14.1)
2   52.66 ms 10.10.11.143 (10.10.11.143)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.63 seconds

```

```
ffuf -c -u 'http://$target/FUZZ' -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -r
ffuf -c -u 'http://$target/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -r
ffuf -u 'http://$target' -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 100 -H "Host: FUZZ.$target"
subfinder -d $target 
feroxbuster -u http://$target -e -q -n --no-state -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ferox_light.txt
gospider -s https://$target -c 10 -d 2 --blacklist "\.(jpg|jpeg|gif|css|png|ttf|woff|pdf|svg|txt)" | tee crawl.txt
waymore -i $target -mode -B
```

Add to /etc/hosts
![[Pasted image 20251107111706.png]]

```
wpscan --url http://office.paper -e vt,tt,u,ap


[i] User(s) Identified:

[+] prisonmike
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] nick
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] creedthoughts
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)


```

```
wpscan --url http://office.paper -U users.txt --passwords /usr/share/wordlists/rockyou.txt 
```
No results

![[Pasted image 20251107114859.png]]

Vulnerable to:
https://github.com/rhbb/CVE-2019-17671

![[Pasted image 20251107114949.png]]

Chat with bot > @recyclops help
![[Pasted image 20251107115821.png]]
![[Pasted image 20251107120633.png]]
![[Pasted image 20251107120716.png]]
![[Pasted image 20251107122205.png]]

SSH into dwight with creds:
```

find / -type f -perm -04000 -ls 2>/dev/null
^C
[dwight@paper ~]$ find / -type f -perm -04000 -ls 2>/dev/null
  8808796     40 -rwsr-xr-x   1  root     root        38680 May 11  2019 /usr/bin/fusermount
  9137365     80 -rwsr-xr-x   1  root     root        79496 Aug 18  2021 /usr/bin/chage
  8927896     84 -rwsr-xr-x   1  root     root        84104 Aug 18  2021 /usr/bin/gpasswd
  8927899     44 -rwsr-xr-x   1  root     root        43424 Aug 18  2021 /usr/bin/newgrp
  8931938     52 -rwsr-xr-x   1  root     root        50320 Jul 21  2021 /usr/bin/mount
  8931953     52 -rwsr-xr-x   1  root     root        50160 Jul 21  2021 /usr/bin/su
  8931956     36 -rwsr-xr-x   1  root     root        33544 Jul 21  2021 /usr/bin/umount
  9189665     68 -rwsr-xr-x   1  root     root        65904 Nov  8  2019 /usr/bin/crontab
  8988797     36 -rwsr-xr-x   1  root     root        33600 Apr  6  2020 /usr/bin/passwd
 10008560     36 -rws--x--x   1  root     root        33688 Jul 21  2021 /usr/bin/chfn
 10009158     28 -rws--x--x   1  root     root        25320 Jul 21  2021 /usr/bin/chsh
 10009623     64 -rwsr-xr-x   1  root     root        61688 May 11  2019 /usr/bin/at
  9716917    164 ---s--x--x   1  root     root       165488 Oct 25  2021 /usr/bin/sudo
  9454437     36 -rwsr-xr-x   1  root     root        34560 May 11  2019 /usr/bin/fusermount3
 13107699     12 -rwsr-xr-x   1  root     root        12136 Nov  8  2021 /usr/sbin/grub2-set-bootflag
 13285751     12 -rwsr-xr-x   1  root     root        12176 May  7  2021 /usr/sbin/pam_timestamp_check
 13285753     40 -rwsr-xr-x   1  root     root        37760 May  7  2021 /usr/sbin/unix_chkpwd
 13022988     48 -rws--x--x   1  root     root        45904 Aug 27  2021 /usr/sbin/userhelper
 13704484    196 -rwsr-xr-x   1  root     root       200408 Jul 30  2021 /usr/sbin/mount.nfs
   585816     20 -rwsr-xr-x   1  root     root        18016 May 11  2019 /usr/lib/polkit-1/polkit-agent-helper-1
 13285491     64 -rwsr-x---   1  root     dbus        63656 May  8  2021 /usr/libexec/dbus-1/dbus-daemon-launch-helper
  9189747     20 -rwsr-xr-x   1  root     root        16792 Dec 21  2021 /usr/libexec/qemu-bridge-helper
  9190025     60 -rwsr-x---   1  root     973         58584 Sep 10  2021 /usr/libexec/cockpit-session
  4750147    164 -rwsr-x---   1  root     sssd       163984 Dec 21  2021 /usr/libexec/sssd/krb5_child
  4627603     96 -rwsr-x---   1  root     sssd        97544 Dec 21  2021 /usr/libexec/sssd/ldap_child
  4750150     28 -rwsr-x---   1  root     sssd        25040 Dec 21  2021 /usr/libexec/sssd/proxy_child
  4627609     56 -rwsr-x---   1  root     sssd        55440 Dec 21  2021 /usr/libexec/sssd/selinux_child
  5742379     24 -rwsr-xr-x   1  root     root        21080 Feb  2  2021 /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
  9455310     16 -rwsr-xr-x   1  root     root        12520 Jun 10  2021 /usr/libexec/Xorg.wrap
  
[dwight@paper ~]$ /usr/lib/polkit-1 --version

[dwight@paper polkit-1]$ rpm -qa polkit
polkit-0.115-6.el8.x86_64
```

Vulnerable to:
https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus
https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

![[Pasted image 20251107124354.png]]
