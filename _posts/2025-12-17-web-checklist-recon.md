---
title: Web Checklist - Recon
date: 2025-12-17 00:00:00 +0000
categories: [Bug Bounty]
tags: [bug bounty, exploitation, web security, checklist]
---

---

## Finding Subdomains

```bash
subfinder -d example.com -all -recursive -o subs_subfinder.txt
assetfinder --subs-only example.com > subs_assetfinder.txt
findomain -t example.com | tee subs_findomain.txt

amass enum -passive -d example.com | awk -F']' '{print $NF}' | sort -u > subs_amass.txt
amass enum -active -d example.com | awk -F']' '{print $NF}' | sort -u >> subs_amass.txt
```

---

## Public Sources (Manual / Custom)

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u > subs_crtsh.txt

curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |
 sed -E 's_https?://__;s/\/.*//;s/:.*//' | sed 's/^www\.//' | sort -u > subs_wayback.txt

curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=10000" |
 jq -r '.results[]?.page?.domain' | sort -u > subs_urlscan.txt

curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/example.com/passive_dns" |
 jq -r '.passive_dns[]?.hostname' | sort -u > subs_alienvault.txt
```

> Make sure to configure all API keys.

---

## GitHub Subdomain Scraping

```bash
github-subdomains -d domain.com -t <github_token>
```

---

## Shodan‑Powered Subdomain Finder

```bash
# Single domain
shosubgo -d target.com -s YourAPIKEY

# Multiple domains from file
shosubgo -f domains.txt -s YourAPIKEY
```

### Bookmarklet – IP Extraction

```javascript
javascript:(function(){var e=document.querySelectorAll('strong'),i=[];e.forEach(function(e){i.push(e.innerHTML.replace(/["']/g,''))});var t=i.join('\n'),a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(t);a.download='ip.txt';document.body.appendChild(a);a.click();})();
```

### Bookmarklet – Domain + IP Extraction

```javascript
javascript:(function(){var e=document.querySelectorAll('strong'),i=[],d=[];e.forEach(function(e){var t=e.innerHTML.replace(/["']/g,'').trim();/^(\d{1,3}\.){3}\d{1,3}$/.test(t)?i.push(t):/^(?!\d+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(t)&&d.push(t)});var s='IPs:\n'+i.join('\n')+'\n\nDomains:\n'+d.join('\n'),a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(s);a.download='domains.txt';document.body.appendChild(a);a.click();})();
```

```bash
cat ip.txt | nuclei -tags grafana -bs 50 -c 50 -es info
```

---

## Subdomain Permutation & DNS Resolution

```bash
subfinder -d example.com | alterx | dnsx > subs_perm.txt
echo example.com | alterx -enrich | dnsx > subs_perm_enrich.txt
echo example.com | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx > subs_perm_wordlist.txt
```

---

## Merge & Deduplicate

```bash
cat *.txt | sort -u > merged_subdomains.txt
```

---

## Discover Live Hosts (httpx)

```bash
cat merged_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subs_alive.txt

httpx -l merged_subdomains.txt \
 -ports 3306,5432,6379,27017,15672,9090 \
 -o alive_ports.txt
```

---

## ASN & IP Discovery

```bash
asnmap -d example.com | dnsx -silent -resp-only > asn_ips.txt
```

### Amass Intel

```bash
amass intel -org "nasa"
amass intel -active -cidr 159.69.129.82/32
amass intel -active -asn <ASN>
```

---

## Harvesting IPs Linked to Domains

```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=<api>" | jq -r '.. | .ip_address? // empty'

curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty'

curl -s "https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000" | jq -r '.results[]?.page?.ip // empty'
```

---

## Brute‑Forcing Subdomains

```bash
ffuf -u "https://FUZZ.target.com" -w wordlist.txt -mc 200,301,302
```

---

## Directory & File Bruteforce

```bash
ffuf -w directory-list.txt -u https://example.com/FUZZ -fc 400,401,403,404 -recursion -e .html,.php,.txt -t 100
```

---

## Visual Recon (Aquatone)

```bash
cat ip.txt | aquatone
cat ip.txt | aquatone -ports 80,443,8000,8080,8443
```

---

## Port Scanning

```bash
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt
nikto -h alive_subdomains.txt -output nikto_results.txt
```

---

## URL Crawling

### Active

```bash
katana -u subs_alive.txt -d 3 -js -o urls_crawled_katana.txt
cat subs_alive.txt | hakrawler -depth 3 -plain | sort -u > urls_crawled_hakrawler.txt
```

### Passive

```bash
cat subs_alive.txt | gau | waybackurls | urldedupe > urls_crawled_gau_wayback.txt
urlfinder -d example.com | sort -u > urls_crawled_urlfinder.txt
```

### Merge

```bash
cat urls_crawled_*.txt | sort -u > allurls.txt
```

---

## Parameter Extraction

```bash
grep '=' allurls.txt | urldedupe > params.txt
grep -E '\\?[^=]+=.+$' allurls.txt
```

---

## Sensitive File Discovery

```bash
cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5" 
 
cat allurls.txt | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"  
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

---

## Hidden Paramater Discovery 

```bash
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w burp-parameter-names.txt -t 10 --rate-limit 10
```



---

## JavaScript Recon

```bash
cat subdomains_alive.txt | gau > urls_gau.txt
cat subdomains_alive.txt | waybackurls > urls_wayback.txt
katana -u subdomains_alive.txt -d 3 -ps > urls_katana.txt
hakrawler -url subdomains_alive.txt -depth 3 -plain > urls_hakrawler.txt
```

```bash
cat urls_gau.txt urls_wayback.txt urls_katana.txt urls_hakrawler.txt | sort -u > allurls_js.txt
```

```bash
grep -E "\.js$" allurls_js.txt | sort -u > jsfiles_all.txt
```

```bash
cat jsfiles_all.txt | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 > jsfiles_alive.txt
```

```bash
cat jsfiles_alive.txt | xargs -n1 -P20 python3 /path/to/LinkFinder.py -i - -o js_endpoints_linkfinder.txt
```

```bash
cat jsfiles_alive.txt | xargs -n1 -P20 python3 /path/to/jsfinder.py -i - -o js_endpoints_jsfinder.txt
```

```bash
cat js_endpoints_linkfinder.txt js_endpoints_jsfinder.txt | sort -u > js_endpoints_all.txt
```

```bash
cat jsfiles_alive.txt | xargs -n1 -P20 curl -s | grep -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|password|ftp password|jdbc|db|sql|secret|config|admin|json|gcp|htaccess|.env|ssh key|access key|secret token|oauth_token|oauth_token_secret" > js_sensitive_keys.txt
```

```bash
cat jsfiles_alive.txt | nuclei -t /home/spy/tools/nuclei-templates/http/exposures/ -c 30 > js_nuclei_exposures.txt
```


