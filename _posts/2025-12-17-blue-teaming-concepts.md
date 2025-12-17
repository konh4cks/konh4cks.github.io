---
title: Blue Teaming - Concepts
date: 2025-12-17 00:00:00 +0000
categories: [Information Security]
tags: [blue team, information security, concepts, soc]
---

## SOC Center Definition

SOC center is the first line of defense and should be based on the below strategies

- Single management and reporting structure
- Complete awareness of both the business objectives and the IT environment
- Enough budget to invest in people and technology.
- Training and supporting SOC analysts
- Establishing area of operation which could be any Information security standard along with the corporate policy.
- Creating the SOC charter and mission

## SOC Charter

SOC charter sets the overall strategy of the SOC center and how it will operate.

## What does the SOC do?

- Security monitoring of the environment and responding to the alarms and threats.
- Performing incident response and patch management.
- Vulnerability analysis and management.
- Forensics whether performed in-house or with a third-party.
- Reporting
- Malware analysis
- Intrusion detection and prevention.
- Threat Hunting
- Cyber Threat Intelligence
- Internal Training

## Building a SOC

- Choosing the SOC location should take into consideration the space which should accommodate twice the planned/current members of the SOC team
- Integrating the SOC function into the existing IT process. This includes the notifications, change management and updates.
- Plan for SOC team acquisition and training.
- Conduct an inventory for the current data sources for future logging into the SIEM. This may include syslog, SNMP traps, firewall logs, etc.
- Identify the applications that support business processes and their mappings to the server. Also identify system owners and data custodians in different departments. This will establish a clear vision on whom to contact during the incident response event. This also includes identifying all network and security devices such as firewalls, IDS, IPS and other technology devices and assets.
- Plan for three years ahead of data storage for logging needs.

## Reasons to request Funding For a SOC Center

- Regulatory compliance with local laws and compliance frameworks.
- The need to keep and store log data.
- Without access to logs that go back in time, issues can't be found and accountability can't be achieved.

## Common SOC Metrics

The below metrics are common to measure the success and progress of your SOC.

- MTT for data sources: The measure time to detect that there is an issue in the data source and how long does it take to fix it?
- Average time to sweep and check the enterprise's endpoints for security issues should decrease over time and the percentage of completed scanned endpoints should increase.
- Number of high severity alerts that are not reviewed by 8 or 24 hours. If it is taking too long to respond/review alerts then consider adding more trained staff.
- The number of false positive alarms should decrease overtime and this is accomplished by tuning the notification rules in the platform.
- The measure time to detect an incident after reviewing an alarm.
- The measure time from the detection to the containment phase of an incident.
- The measure time to expel and push out the intruder off the network.
- Number of incidents closed and opened.

## SOC Training

- Product-specific training and skills
- Vendor neutral training such as IT and security certifications.
- Internal dedicated training.

## SOC Analyst Skills

- Understanding the cyber kill chain or the steps the attacker takes starting from the recon and finishing with actions on objectives.
- Understanding the incident handling process
- Familiarity with the organization's networks, assets and data sources.
- Firm IT background including networking, operating system and hardware devices.
- Understanding Firewalls, IDS and IPS systems and how they work and operate and their rulesets.
- PCAP collection and analysis
- Forensics Skills
- OWASP TOP 10
- Scripting in PowerShell, PHP, Perl, Python, BASH, etc.

## SOC Maturity Frameworks

### The CMMI

Th Carnegie Mellon Capability Maturity Integration is a framework that helps newly-established SOC's to mature and grow into a more systematic and organized SOC. You can apply the CMMI on multiple SOC processes such as improving the maturity of data source (collecting logs), alarm processing  

## Turnover Shift Checklist

The turnover shift checklist is a checklist that is written by your SOC team to define what analysts do per shift. The below list should cover turnover items from prior shift:

- Key Events
- Status of ongoing incidents
- Data issues
- Staff issues
- system issues  
    Other items to be covered:
- Review of yesterday's alerts
- Review new alerts that are added/instrumented to the system
- Review data sources leaving the system/ coming into the system.

## Examples of SOC Defense Strategies

- To help in minimizing and preventing **phishing attacks**, you would use a tool such as `dnstwist` to scan for all domains that look like your domain and either buy them or if they are owned/bought by others you would then block/filter them on the network level should an attacker use them as part of phishing campaigns. Also create a search query in your SIEM solution to find hits to these domains.
- Make sure `sysmon` is installed on important endpoints and workstations in order to collect detailed **process logs** (commandline, parent process). Additionally create a SIEM alert when an office application or an email program executed command prompt. This indicates that a user may have clicked/downloaded a malicious attachment.
- Always monitor for **process creation** events with detailed tracking. You can enable auditing on Windows to collect `command line` for this event ID `4688`. On the SIEM, you may then create a search query that lists all events with this ID and build a whitelist of good known applications.
- Monitor for events related to **presence indicators** (login, logout, screen lock, screen unlock), service state changes and and local group management. These events can be used and monitored to detect if an endpoint is used outside business hours, new accounts created, service status changes. All these may indicate persistent attempts and lateral moves. To better detect persistence attempts, you would monitor the output of a command that lists the `autoruns`. You can feed the output of this command into your SIEM. Example command is `autorunsc`
- Monitor for **brute force authentication failures** on publicly-exposed services.
- Monitor for **authentication anomalies** which include using service accounts for interactive logon, service accounts used from non-authorized source system, user logon outside working hours, user authentication from multiple source systems.
- Monitor for **data exfiltration** indicators which include HTTP(s)/ Mismatch, outbound FTP from source systems that don't require it such as an outbound FTP traffic from a printer, use of file storage cloud services not dictated by a company business case or using public information sharing webistes (pastebin).
- Monitor for **signature matching** to known vulnerabilities
- Monitor for **service failures** such as backup failures or AV failures.
- Monitor for **Insider Threats indicators** which are use of USB drives, authentication baseline violations, authentication failures against file sharing servers, intranet Sharepoint,,etc.
- Monitor **Abnormal Email activity** which includes emails with large attachments, malicious sent email by users which indicates an AV failure or an internal workstation compromise, email traffic to and from blacklisted email addresses (can be retrieved from threat intelligence feeds and added to your SIEM monitoring data).

## Vulnerability Management

### Definition

Vulnerability management is an ongoing, proactive, and frequently automated activity that protects computer systems, networks, and enterprise solutions from cyberattacks and data breaches. Consequently, it is a vital component of an overall security program. By discovering, evaluating, and correcting potential security flaws, businesses can help avoid attacks and mitigate their effects if they occur.

### Vulnerability Scanning

The process of utilizing a computer program (vulnerability scanner)to find vulnerabilities in networks, computer infrastructure, or applications.  
**Identifying Assets**  
The next step is to identify the systems that will be covered by the vulnerability scans. Some organizations choose to cover all systems in their scanning process, whereas others scan systems differently (or not at all) depending on the classification of data stored on these systems, whether the system is internal or exposed to the internet, services running on the system and the nature of the system ( used for production, development or testing).  
**Determining the scanning frequency**  
You can designate a schedule that meets their security, compliance, and business requirements. You should also configure these scans to provide automated alerting when they detect new vulnerabilities using email reports.  
Overall consider the below factors for scanning frequency

- The organization’s risk appetite is its willingness to tolerate risk within the environment. If an organization is extremely risk averse, it may choose to conduct scans more frequently to minimize the amount of time between when a vulnerability comes into existence and when it is detected by a scan.
- Regulatory requirements, such as PCI DSS or FISMA, may dictate a minimum frequency for vulnerability scans. These requirements may also come from corporate policies.
- Technical constraints may limit the frequency of scanning. For example, the scanning system may only be capable of performing a certain number of scans per day and organizations may need to adjust scan frequency to ensure that all scans complete successfully.
- Business constraints may prevent the organization from conducting resource-intensive vulnerability.  
    **Active vs Passive Scanning**  
    Most vulnerability scanning tools perform active vulnerability scanning, meaning that the  
    tool actually interacts with the scanned host to identify open services and check for possible  
    vulnerabilities. Active scanning does provide high-quality results, but those results come with  
    some drawbacks such as noisy scans easily detected by system admins and IDS/IPS. Additionally active scanning may inadvertently exploit vulnerabilities thus interfering with the function of a production system. Passive vulnerability scanning takes a different approach that supplements active scans. Instead of probing systems for vulnerabilities, passive scanners monitor the network, similar to the technique used by intrusion detection systems. But instead of watching for intrusion attempts, they look for the telltale signatures of outdated systems and applications. Passive scanning only capable of detecting vulnerabilities that are reflected in network traffic. They’re not a replacement for active  
    scanning, but they are a very strong complement to periodic active vulnerability scans.  
    **Scanning Scope**  
    The scope of a vulnerability scan describes the extent of the scan such as the systems covered by the scan and what kind of tests will be performed against discovered systems. Most important step is making sure that the scans won't disrupt the function of the systems that are about to be tested and scanned.  
    **Stealth vs Noisy Scan**  
    Noisy scans use TCP which simply initiates a TCP connection to the target system and probe it for vulnerabilities which attracts the attention of security solutions and system admins. Although it might be appropriate for advertised scanning, it often doesn’t work well for a penetration test.  
    Using stealth scans better approximates the activity of a skilled attacker, resulting in a more realistic penetration test.  
    **Credentialed Scans**  
    In a credentialed scan, we can provide the scanner with credentials that allow the scanner to connect to the target server and retrieve configuration information. This information can then be used to determine whether a vulnerability exists, improving the scan’s accuracy over non-credentialed alternatives. For example, if a vulnerability scan detects a potential issue that can be corrected by an operating system update, the credentialed scan can check whether the update is installed on the system before reporting a vulnerability.  
    **Commercial Vulnerability scanners**
- Nesus: Full Vulnerability Scanner
- Nexpose: Full Vulnerability Scanner
- Acunetix: Full Vulnerability Scanner
- Qualys: Full Vulnerability Scanner  
    **Open Source Vulnerability scanners**
- OWASP ZAP: Web Application Scanner
- OpenVas: Web Application Scanner
- Nikto: Web Application Scanner
- Wapiti: Web Application Scanner
- SQLmap: Database Vulnerability Scanner

### Vulnerability Exploitation

Once you have conducted your initial survey of a target, including mapping out a full list of  
targets and probing them to identify potential vulnerabilities and weaknesses, the next step  
is to analyze that data to identify which targets you will prioritize, what exploits you will  
attempt, and how you will access systems and devices that you have compromised. In most cases, you will target the most vulnerable systems for initial exploits to gain a foothold that may provide further access.  
Not every vulnerability has exploit code released, and even when exploit  
code is released, it can vary in quality and availability.

### Vulnerability Remediation

Some of the most important factors in the remediation prioritization decision-making  
process are listed here:

- Criticality of the Systems and Information Affected by the Vulnerability measured by confidentiality, integrity and availability.
- Difficulty of Remediating the Vulnerability in terms of resources, cost and time required.
- Severity of the Vulnerability: The more severe an issue is, the more important it is to correct that issue. You can use the scoring system CVE for this factor.
- Exposure of the Vulnerability which depends on the availability of a public exploit and whether the impacted server is internal or external in the network.  
    All the remediation and fixes should be implemented in a virtual environment or sandbox to avoid unintended disruptions to the affected production system.

### Vulnerability Classification

Vulnerability classification is standardized into what's called Common Vulnerabilities and Exposures. CVE identifier consisting of the CVE prefix, the year the CVE ID was given, and the sequence number.  
Furthermore, the CVE description includes the affected product name, the affected versions, the product manufacturer, the vulnerability's nature, the overall impact, the access an attacker would need to exploit the vulnerability, and the crucial code inputs required.  
**Common Vulnerability Scoring System (CVSS)**  
CVSS is a scoring system that rates the severity of vulnerabilities and identifies their characteristics. It assigns severity scores to all defined vulnerabilities, which is used to prioritize mitigation efforts and the required resources based on the severity. The range of possible scores is 0 to 10, with 10 representing the most severe.  
You can search for vulnerabilities and their impact along with CVSS score in the links below

```
https://nvd.nist.gov/
https://www.cvedetails.com/
```

**Interpreting the CVSS Vector**  
An example of a CVSS vector is shown below

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

This vector contains nine components. The first section, CVSS:3.0, simply informs that the vector was composed using CVSS version 3. The next  
eight sections correspond to each of the eight CVSS metrics below:

```
■■ Attack Vector: Network (score: 0.85)
■■ Attack Complexity: Low (score: 0.77)
■■ Privileges Required: None (score: 0.85)
■■ User Interaction: None (score: 0.85)
■■ Scope: Unchanged
■■ Confidentiality: High (score: 0.56)
■■ Integrity: None (score: 0.00)
■■ Availability: None (score: 0.00)
```

**Mapping qualitative and numeric scores**  

### Vulnerability Management Life Cycle

Life Cycle of a vulnerability management programs consists of the below steps

```
1- Discover
2- Prioritize
3- Assess
4- Reporting
5- Remediation
6- Verification and Monitoring

```

The **Discover step** includes compiling a list of all the environment's resources/assets, including the applications, services, operating systems, and configurations, to identify vulnerabilities. This step can be accomplished using any vulnerability scanner by adding the assets you want to scan and then start the scanning.  
The **Prioritize step** includes grouping and assigning a risk-based priority to the assets (identified during the discovery phase) based on how crucial they are to the business. This can significantly assist the organization in determining which groups require special attention and thus will aid in the decision-making process when distributing resources. For example, Asset vulnerabilities leading to data breaches and DB access are rated as **Top** risk priority since the breach of sensitive organization records would damage the organization's reputation and may also have legal or regulatory consequences.  
The **Assess step** includes creating a risk baseline by evaluating your assets to determine how severe each is. The process lets organizations decide which risks to eliminate based on factors such as their classification, criticality level, and vulnerability level. In the longer run, assessments help organizations establish a consistent baseline.  
The **Remediation Step** includes fixing the vulnerabilities discovered earlier, beginning with the most severe ones. The identified vulnerabilities should be reported to the concerned stakeholders for remediation. A few approaches are available to organizations for dealing with known vulnerabilities and configuration errors. **Remedial action, such as thoroughly addressing or patching vulnerabilities, is the best course of action**. If complete remediation is not feasible, businesses might mitigate, which entails lowering the risk of exploitation or minimising the potential harm. Finally, security engineers can acknowledge their vulnerability, for instance, when the risk involved is low, and choose to do nothing.

### Vulnerability Management Frameworks

**NIST Cyber Security Framework**  
The fundamental components of the NIST Cybersecurity Framework are broken down into five areas applicable to vulnerability management that help to achieve the cybersecurity objectives of an organization.  
**Identify**: What assets and processes require security?  
**Protect:** Put the right security measures in place to protect the organisation's assets.  
**Detect:** Implement adequate procedures to detect cybersecurity events.  
**Respond**: Develop methods for mitigating the effects of cybersecurity incidents.  
**Recover**: Implement the proper procedures for restoring capabilities and services impacted by cybersecurity incidents.

### Relevant Regulatory Standards for Vulnerability Management

#### PCI-DSS

**Definition**  
PCI DSS prescribes specific security controls for merchants who handle credit card transactions  
and service providers who assist merchants with these transactions. This standard  
includes what are arguably the most specific requirements for vulnerability scanning of  
any standard.  
**Some terms from The standard**

- Organizations must run both internal and external vulnerability scans (PCI DSS requirement 11.2).
- Organizations must run scans on at least a quarterly basis and “after any significant change in the network (such as new system component installations, changes in network topology, firewall rule modifications, product upgrades)” (PCI DSS requirement 11.2).
- Internal scans must be conducted by qualified personnel (PCI DSS requirement 11.2.1).
- Organizations must remediate any high-risk vulnerabilities and repeat scans to confirm that they are resolved until they receive a “clean” scan report (PCI DSS requirement 11.2.1).
- External scans must be conducted by an Approved Scanning Vendor (ASV) authorized by PCI SSC (PCI DSS requirement 11.2.2).

#### Federal Information Security Management Act (FISMA)

**Definition**  
The Federal Information Security Management Act of 2002 (FISMA) requires that government agencies and other organizations operating systems on behalf of government agencies comply with a series of security standards. The specific controls required by these standards depend on whether the government designates the system as low impact, moderate impact, or high impact.  
Some Requirements  
A. Scans for vulnerabilities in the information system and hosted applications and when new vulnerabilities potentially affecting the system/application are identified and reported;  
B. Employs vulnerability scanning tools and techniques that facilitate interoperability among tools and automate parts of the vulnerability management process by using standards for:

1. Enumerating platforms, software flaws, and improper configurations;
2. Formatting checklists and test procedures; and
3. Measuring vulnerability impact;  
    C. Analyzes vulnerability scan reports and results from security control assessments;  
    D. Remediates legitimate vulnerabilities in accordance with an organizational assessment of risk; and  
    E. Shares information obtained from the vulnerability scanning process and security control assessments to help eliminate similar vulnerabilities in other information systems (i.e. systemic weaknesses or deficiencies).

### Server and Endpoint Vulnerabilities

**Missing Patches**  
One of the most common alerts from a vulnerability scan is that one or more systems on the network are running an outdated version of an operating system or application and require security patch(es).  
**Unsupported Operating Systems and Applications**  
Once the vendor announces the final end of  
support for a product/OS, those who continue running the outdated software put themselves  
at a significant risk of attack. The vendor will not investigate or correct security flaws that arise in the product after that date. Those continuing to run the unsupported product/OS are on their own from a security perspective. For example, Windows server 2013, Windows XP, Linux Debian Stretch, etc are all no longer supported products.  
**Buffer Overflows**  
Buffer overflow attacks occur when an attacker manipulates a program into placing more data into an area of memory than is allocated for that program’s use. The goal is to overwrite other information in memory with instructions that may be executed by a different process running on the system.  
**Privilege Escalation**  
Privilege escalation attacks seek to increase the level of access that an attacker has to a target  
system. They exploit vulnerabilities that allow the transformation of a normal user account  
into a more privileged account, such as the root superuser account.  
**Arbitrary Code Execution**  
Arbitrary code execution vulnerabilities allow an attacker to run software of their choice on  
the targeted system. This can be a catastrophic event, particularly if the vulnerability allows  
the attacker to run the code with administrative privileges. Remote code execution vulnerabilities  
are an even more dangerous subset of code execution vulnerabilities because the  
attacker can exploit the vulnerability over a network connection without having physical or  
logical access to the target system.  
**Firmware Vulnerabilities**  
Firmware often contains the device’s  
operating system and/or configuration information which is just like any other code subject to bugs and vulnerabilities. For example, spectre and meltdown exploit a feature of the microprocessors' chips known as speculative execution to allow processes to gain access to information reserved for other processes.  
**Insecure Protocol Use**  
These protocols don't use encryption to protect usernames, passwords, and the content sent over an open network, exposing the users of the protocol to eavesdropping attacks. Examples are Telnet and FTP.  
**Debug Modes**  
Debug modes typically provide detailed information on the inner workings of an application and server as  
well as supporting databases. Although this information can be useful to developers, it can inadvertently assist an attacker seeking to gain information about the structure of a database, authentication mechanisms used by an application, or other details. For this reason, vulnerability scans do alert on the presence of debug mode on scanned servers.

#### Network Vulnerabilities

**Missing Firmware Updates**  
Vulnerability scans may also detect security problems in network devices that require firmware updates from the manufacturer to correct. These vulnerabilities result in reports similar to the operating system missing patches.  
**Outdated SSL/TLS Versions**  
SSL is no longer considered secure and should not be used on production systems. The same  
is true for early versions of TLS. Vulnerability scanners may report that web servers are using  
these protocols so any connections making  
use of these outdated versions of SSL and TLS may be subject to eavesdropping attacks. Network devices on the network should be using only newer protocols, such as TLS version 1.2.  
**Insecure Cipher Use**  
Some ciphers used by SSL/TLS contain vulnerabilities that render them insecure because of their susceptibility to eavesdropping attacks. For example RC4 is an insecure cryptographic cipher and should not be used by the servers or network devices in secure communications.  
**Certificate Issues**  
Vulnerability scans may detect issues with the certificates presented by servers that support SSL and/or TLS. Common certificate problems are listed below

- Mismatch Between the Name on the Certificate and the Name of the Server.
- Expiration of the Digital Certificate.
- Unknown Certificate Authority (CA).  
    **Internal IP Disclosure**  
    Servers that are not properly configured may leak their private IP addresses to remote systems.  
    This can occur when the system includes its own IP address in the header information returned in the response to an HTTP request. The server is not aware that NAT is in use, so it uses the private address in its response. Attackers and penetration testers can use this information to learn more about the internal configuration of a firewalled network.  
    **VPN Issues**  
    This includes out of date VPN software and the use of insecure ciphers.

#### Virtualization Vulnerabilities

**VM Escape**  
It happens when an attacker is able to pivot and move between different virtualized machines starting from a single host they got access to.

## Incident Response

### Preparation

In the wake of an incident, your client will give you the news that a suspicious activity is taking place on a machine in their system.  
The preparation phase involves preparing the following

```
- One laptop with kali linux, windows and SIFT installed where you can switch between systems at boot
- A bunch of external hard drives 
- Bootable USB keys for linux and windows OS
- Another set of USB keys for forensic tools both on linux and windows.
- Toolkit containing tools such as screwdrivers
- USB adapters of all kinds
- Ethernet cables
- Physical write blocker for forensic copies.
```

### Gathering Details

Gather details about the incident from the staff who noticed it. Collect documents about the system architecture and network topology in addition to the contact details of the IT department. It's also important to understand the role of the machine that was under the attack to make a preliminary assessment about the nature of the situation.

### Conducting the investigation

Never do the following below:

```
- Its important not to perform any operation on the machine before you do a full memory and disk copy according to forensic standards. Forensic standards state that a full bit by bit copy of the RAM and disk should be performed in addition to any available snapshots.

- Never use any of the tools on the infected machine while its in live state.
```

[Two scenarios are possible]  
1- The machine is an endpoint machine and not a public facing server  
2- The machine is a public facing server for business operations

#### The machine is an endpoint machine and not a public facing server

#### Perform full forensic analysis

The steps below are taken in order to conduct full forensic analysis

```
1- Full bit by bit copy of the RAM should be performed in addition to any available snapshots.
2- A usb key with forensic tools to grap open files, running processes, network connections,etc should be available to start the live forensics. Make sure all artifacts are hashed and timestamped so that evidence will be admissible in court and also make sure to document all steps taken in the forensic analysis so that you make an admissible chain of custody.
3- Full physical disk copy. On Linux that corresponds to /dev/sda and on windows it corresponds to \\.\PHYSICALDRIVE0/. The physical copy can be taken after shutting down the computer by unplugging the power cable.Physical copies are taken bit by bit using a software such as FTK Imager or Encase. Make sure you connect the hard drive to external write blocker to preserve the integrity while connecting it to your investigation computer using a USB cable.
4- Once RAM is copied and once artifacts are collected, you can use the USB on a clean machine prepared for this purpose.
5- Make sure to have backups copies of the collected data stored in additional USB keys.
6- Start the analysis with the live captured data. System configs, network configs,etc.
```

Regarding [step 2] Dumplt is preferable to have for RAM acquisition. You can use this tool to take a memory dump of the machine as well.  
[About Live System Forensics]  
Don't perform any live machine forensics untill you take a bit by bit copy of the physical Disk and RAM using acquisition and imaging tools. The output of live forensic tools such as netstat,process hacker,etc is not reliable on an infected machine. Some malwares and rootkits operate on the kernel mode which means they can alter the state of any process or tool installed on the operating system. That's why we do a bit by bit copy then we do live system forensics using our own tools installed on an external USB. To reveal malware behaviour, we compare the output of the analysis between the two methods to decide whether the malware was tampering with OS data.  
[Artifcats to collect when doing live forensic]

```
1- System info
2- network configs
3- Users
4- Active and listening connections
5- Running processes
6- Jouranl events
```

These artifacts are stored in a USB drive and copied into another three USB drives. Don't connect the USB into a production machine. Remember to use a freshly installed machine for only analysis purposes.  
[How to spot a suspicious process]

```
1- Process running with wrong parent process. Example would be the authentication manager lsass.exe running as a child process of explorer.exe

2- Process executable running from suspicious locations such as c:\temp or c:\users\

3- Misspelled processes. 

4- Process with long command line containing weird or encoded characters and URLs.
```

[#Note](https://publish.obsidian.md/#Note) What if the machine infected is a virtual machine part of a Hyper-V or ESXi Node?  
In the above case, we follow the below steps

```
1- Use Vsphere client to connect to the main ESXi node and list all the available virtual machines
2- Copy The VMDK file which is a full copy of the hard drive of the targeted virtual machine
3- Suspened the virtual machine to create a snapshot file VMSS that you can merge with the paging file VMEM.
```

To achieve step 3 above, issue the below command

```
vmss2core-sb.exe -W8 "machine.vmem" "machine.vmss"
```

The output of the above command is a memory dump you can inspect with Volatility.

##### Cut Internet access on the machine

##### Eradication and Recovery

After you have discovered how the incident occured and created your infection timeline, you have two set of steps to follow for the eradication. [#The](https://publish.obsidian.md/#The) below steps can be taken in order if the attacker managed to get access only to one machine which is the infected machine

```
- Identify backdoors first. Could be reverse shells or bind shells. Reverse shells can be found easily in firewall logs. Just look for a pattern of an outgoing connection to a recurring IP address. For bind shells, it is usually a listening point or active listening connection therefore nmap scan of the infected machine should reveal all open listening ports. Correlate nmap scan results with netstat issued on the machine to look for common points or discrepanies. If you find a weird listening port, then see if it's listed to start on boot which raises the chacnes of it being a bind shell.Lastly shut down the port and disable the service that was running on it.
- Look for files modified around the time of the incident with two hours difference.
-Revoke any unauthorized account created
-Patch all vulnerabilities that caused privileged escalation or foothold access
-Reset passwords for all accounts in the machine
-Perform full rootkit and antivirus scan. In some instances, you may need to fully resotre from a previous safe state or do a full format
- If you have discovered IOCs, then look them up on all machines and domain controllers. Use powershell to retrieve events containing one of the IOCs so you can decide on which machines need eradication and recovery.Also lookup firewalls and network devices with C2C2 addresses to find which machines on the network communicated with the attacker's C2C.
- Create a blacklist of C2C IPs and block it using the firewall.
- Create and Install fresh windows copies for infected machines.Be very careful when copying important documents before installing fresh windows copies. Exculde dangerous extension from you backup such as the below ones
.cs','*.ps1','*.psm','*.exe','*.com','*.dll','*.vbs','*.vbe','*.js','*.hta','*.msi','*.msp','*.csh','*.cpl','*.bat
- Reset all users' passwords especially in Windows Active directory including the KRBTGT and DSRM account twice.
- Clone AD into a new clean windows server domain controller.
```

#### The machine is a public facing server for business operations

##### Perform full forensic analysis

The steps below are taken to conduct full forensic analysis

```
1- Full bit by bit copy of the RAM should be performed in addition to any available snapshots.
2- A usb key with forensic tools to grap open files, running processes, network connections,etc should be available to start the live forensics. Make sure all artifacts are hashed and timestamped so that evidence will be admissible in court and also make sure to document all steps taken in the forensic analysis so that you make an admissible chain of custody.
3- Full physical disk copy. On Linux that corresponds to /dev/sda and on windows it corresponds to \\.\PHYSICALDRIVE0/. The physical copy can be taken after shutting down the computer by unplugging the power cable.Physical copies are taken bit by bit using a software such as FTK Imager or Encase. Make sure you connect the hard drive to external write blocker to preserve the integrity while connecting it to your investigation computer using a USB cable.
4- Once RAM is copied and once artifacts are collected, you can use the USB on a clean machine prepared for this purpose.
5- Make sure to have backups copies of the collected data stored in additional USB keys.
6- Start the analysis with the live captured data. System configs, network configs,etc.
```

Regarding [step 2] Dumplt is preferable to have for RAM acquisition. You can use this tool to take a memory dump of the machine as well.

##### Interact with the machine using telnet,ssh,RDP,etc

##### Extract all traffic inbound to the target machine in the last 72 hours

Logs are firewall logs, machine logs, windows event logs, syslogs,etc.  
[#Focus](https://publish.obsidian.md/#Focus) on system logs such as failed logins, access violations,etc  
[#In](https://publish.obsidian.md/#In) network logs, focus on traffic coming to the infected machine, file transfer logs, http logs,etc.  
[#Enumerate](https://publish.obsidian.md/#Enumerate) tasks current and scheduled ones and pay special focus on those create by unknown users.

#### Have one of the sys admins with you all the time in case you needed credentials or explanation on something

#### Find out how the incident occured

This includes a premilinary analysis of the below

```
1- Find if there are newly created account on the machine
2- Try to inspect all tasks/jobs ran by the unrecognized account
3- Find the root cause of how the attacker managed to get access. This includes inspecting files that were modified around the time of the incident, inspecting tasks/jobs created by the unrecognized account, investigating startups,etc.
4- Don't disable the attacker's account untill you found the root cause and performed the full forensic analysis.
```

##### Create an infection time line

After you found the root cause of the hack, create an infection timeline outlining with timestap the steps taken starting from the first malicious action [privilege escalation] untill the moment when the team declared an incident [weird event happened like CPU overload].

##### Containment and Eradication

After you have discovered how the incident occured and created your infection timeline, you have two set of steps to follow for the eradication. [#The](https://publish.obsidian.md/#The) below steps can be taken in order if the attacker managed to get access only to one machine which is the infected machine

```
- Identify backdoors first. Could be reverse shells or bind shells. Reverse shells can be found easily in firewall logs. Just look for a pattern of an outgoing connection to a recurring IP address. For bind shells, it is usually a listening point or active listening connection therefore nmap scan of the infected machine should reveal all open listening ports. Correlate nmap scan results with netstat issued on the machine to look for common points or discrepanies. If you find a weird listening port, then see if it's listed to start on boot which raises the chacnes of it being a bind shell.Lastly shut down the port and disable the service that was running on it.
- Look for files modified around the time of the incident with two hours difference.
-Revoke any unauthorized account created
-Patch all vulnerabilities that caused privileged escalation or foothold access
-Reset passwords for all accounts in the machine
-Perform full rootkit and antivirus scan. In some instances, you may need to fully resotre from a previous safe state or do a full format
- Create a blacklist of C2C IPs and block it using the firewall.
- Create and Install fresh windows copies for infected machines.Be very careful when copying important documents before installing fresh windows copies. Exculde dangerous extension from you backup such as the below ones
.cs','*.ps1','*.psm','*.exe','*.com','*.dll','*.vbs','*.vbe','*.js','*.hta','*.msi','*.msp','*.csh','*.cpl','*.bat
- Reset all users' passwords especially in Windows Active directory including the KRBTGT and DSRM account twice.
- Clone AD into a new clean windows server domain controller.

```

[#One](https://publish.obsidian.md/#One) step I omitted from the above steps which is cutting internet access on the machine. Obviously if the infected machines is either a mainframe or a business critical machine where it handles most of your business operations such as serving content or services to clients, then cutting internet access immediately may not be a wise choise.  
[#If](https://publish.obsidian.md/#If) the attacker hacked the subject machine after compromising another machine or account then the below steps are taken in order:

```
- Repeat steps 1 and 2 and 3 from the above scenario witout taking any action like shutting down the port or revoking an account access. We don't want to draw the attacke's attention untill we are able to neutralize the first root cause
- Start collecting data on the root cause. If the attacker managed to get access to the hacked machine via a hacked account or hacked machine then start collecting information about that machine very first. Make sure you follow privacy laws and take approvals from legal and HR to keep the evidence admissible.
- Gather the ip addresses and computer names of the infected machines and put them in a group you create in the firewall. Then start filtering the firewall logs for all communications between the infected machines including the DC or the public facing server. Filter for traffic on port 135 RCP and Ports 5985-5986 for Winrm to be able to spot the first machine from which the attacker established the first foothold and pivoted into other infected machines. Establish baselines of traffic before, during and after the incident to see the trends.
```

##### Establishing new firewall rules and logging configs

Just as the incident occured, you knew how it occured and what artifacts the attacker left. Make sure to do the following

```
- Create a firewall or IDS rule to raise an alert once a connection is attempted against the backdoor port
- Raise an alert using syslog or windows event logs whenever an account belonging to the attacker or used by the attacker was under the attempet of being accessed.
- Create a honeypot with interesting files and raise an alert upon a connection is made to it.
- Create an alert for any login made outside business hours.
```

### Analysis and lessons learned

In this stage of IR, we create a report outlining the following

```
Total Assets Impacted by the incident
Type of data leaked if any
```

## Recommended Security Controls

### Access Control and Account Management

- Restricting administrative privileges for end users. This simple control applies to organizations of any size. Restricting privileges and following the principle of least privilege are easy to implement and scale.
- Randomizing local administrator passwords on every system makes it so that the compromise of a single local admin credential doesn’t allow widespread access to every other asset in the network. This can be achieved through Microsoft’s Local Administrator Password Solution (LAPS) if you are using MS-AD
- Strong password policy (15 characters or more). Complex passwords use a mix of character types. Strong passwords use a mix of character types and have a minimum password length of at least eight characters.
- MFA (Multi factor authentication) everywhere you can possibly implement.
- Account lockout policies thwart some password attacks, such as brute force attacks and dictionary attacks. Accounts will typically have lockout policies preventing users from guessing the password. If a user enters the wrong password too many times (such as three or five times), the system locks the user’s account.
- Changing default credentials. Many applications and devices have default passwords. These should be changed before putting the application or device into service.
- Disablement policy. Disable user accounts as soon as possible when employees leave the organization. Additionally, it’s common to disable default accounts (such as the Guest account mentioned previously) to prevent them from being used. Disabling is preferred over deleting the account, at least initially. If administrators delete the account, they also delete any encryption and security keys associated with the account.
- Prevent users from using shared or generic accounts.
- Time-based logins (sometimes referred to as time-of-day restrictions) ensure that users can only log on to computers during specific times. If a user tries to log on to a system outside the restricted time, the system denies access to the user.
- Implement accounts auditing to check users' rights and permissions and ensure they match their job requirements and need to know.

### Network Security

- `Network segmentation` between hosts, including client isolation so workstations can’t talk to other workstations is another great control to have in place. If the attacker can’t pivot from one workstation to another, it’s going to be hard to escalate privileges in the domain.
- `Implement a Firewall`. There’s very little reason for many ports to be able to communicate outside of your organization. Most modern firewalls can also assist with creating rules that block malformed application requests. Additionally, a firewall works great for blocking known bad addresses and other artifacts based on signatures and other techniques.
- `Spam filter on mail gateways`

### Logging

- `Logging`. Without logging, we do not have a foundation to detect, alert, hunt, contextualize, and respond to events that occur throughout an organization.
- `Enable Windows Event` Forwarding to centrally collect logs from your Windows environment. Windows Event Forwarding is built into Windows and makes for a pretty good log aggregator.

### Host and Endpoint Security

- `Application Control`: Implement Application control/application whitelisting. For example, Microsoft has Software Restriction Policies, AppLocker, and Device Guard. Just by doing simple things like blocking PowerShell from regular users and blocking non-code-signed binaries in user profile directories can have a huge impact on your infections and thwart a number of attacks.
- `App whitelisting and Blacklisting`: App whitelisting seems to work well. Locking down systems to only allow the bare minimum and regularly auditing the list to ensure it doesn’t grow or end up out of date helps stop attackers by killing their tools, whether they are using imported ones or are trying to use built-in ones. If the whitelisting app also does reporting, then it is even better, as a report will be a good indicator that something bad is happening on a machine.
- Make sure systems are hardened by disabling unnecessary ports and services and uninstalling not needed software.
- `Configuration Management`: Implement Configuration management which is a process of managing and deploying secure configurations, often includes system images, to multiple systems. One of the most common methods of deploying systems is with images starting with a master image. An image is a snapshot of a single system that we deploy to multiple other systems. Image can sometimes be created them with templates (Operating systems with pre-defined configurations) or with other tools to create a secure baseline. Then integrity measurements can be used to discover when a system deviates from the baseline.
- `Patch Management`: Patch management ensures that systems and applications stay up to date with current patches. This is one of the most efficient ways to reduce operating system and application vulnerabilities because it protects systems from known vulnerabilities. Patch management includes a group of methodologies and consists of identifying, downloading, testing, deploying, and verifying patches.

### Administrative Controls

- `Security Awareness`: Security awareness training can be one of the easiest and most important controls that bolsters the overall security posture of an organization. Educate and empower users to practice good cyber hygiene.
- `Vulenrability Management`: Monthly vulnerability assessment. This will assist the organization’s technology leaders in prioritizing the most critical vulnerabilities. Using a vulnerability scanner can do wonders for finding the easy wins for attackers. Many of these are very affordable. They will help sort out missing patches, default passwords, and known vulnerabilities in commercial off-the shelf software, etc., that are so often used as the initial foothold by attackers.
- `Outsourcing`:For a small business, the simplest way to achieve security this is to outsource. Depending on the scope, if a small organization cannot afford to maintain these people, they should outsource the task to a third party.
- `Disaster Recover and Backup Planning`: Test your recovery strategy on a regular basis. Whether it’s accidental or due to a ransomware attack, the loss of data can threaten the viability of small and medium businesses even more than large enterprises.
- `Change Management`: Change management defines the process for any type of system modifications or upgrades, including changes to applications. Change management ensures that changes to IT systems do not result in unintended outages and provides an accounting structure or method to document all changes.

### Physical Security

- `Securing Doors Access with Cards`: Proximity cards are small credit card-sized cards that activate when they are close to a proximity card reader. Many organizations use these for access points, such as the entry to a building or the entry to a controlled area within a building.
- `Door Locks`: Door access systems include physical locks, cipher locks, and biometrics. Biometric locks can provide both the identification and authentication of users to track who entered a secure area and when they entered.
- `Cable Locks`: Cable locks are effective threat deterrents for small equipment such as laptops and some workstations. When used properly, they prevent losses due to theft of small equipment.
- `Security Guards`
- `CCTV`
- `Sensors`:Sensors monitor the environment and can detect changes. They can detect motion, noise, moisture, temperature changes, and more.
- `Fencing, lighting, and alarms`: Fencing, lighting, and alarms all provide physical security. They are often used together to provide layered security. Motion detection methods are also used with these methods to increase their effectiveness. Infrared detectors detect movement by objects of different temperatures.
- `Air Gap`:An air gap is a physical security control that ensures that a computer or network is physically isolated from another computer or network. Cables to one network never touch cables to another network, but instead, there is a gap of air between the cables.
- `Faraday Cage`: A Faraday cage is typically a room that prevents radio frequency (RF) signals from entering into or emanating beyond a room. It includes electrical features that cause RF signals that reach the boundary of the room to be reflected back. This prevents signals from emanating outside the Faraday cage and protects equipment in the cage from damage from external signals such as lightning. A Faraday cage can also be a small enclosure.

### Establishing Security Policy

**Definition**  
Security policies are written documents that lay out a security plan within a company. They are one of many administrative controls used to reduce and manage risk. When created early enough, they help ensure that personnel implement security throughout the life cycle of various systems in the company. When employees follow the policies and procedures, they help prevent incidents, data loss, and theft.  
**Acceptable Use Policy**  
It often describes the purpose of computer systems and networks, how users can access them, and the responsibilities of users when they access the systems. The AUP may include statements informing users that systems are in place monitoring their activities.  
**Mandatory vacation**  
Mandatory vacation policies help detect when employees are involved in malicious activity, such as fraud or embezzlement. As an example, employees in positions of fiscal trust, such as stock traders or bank employees, are often required to take an annual vacation of at least five consecutive workdays. For embezzlement actions of any substantial size to succeed, an  
employee would need to be constantly present to manipulate records and respond to different inquiries. On the other hand, if a policy forces an employee to be absent for at least five consecutive workdays, someone else would be required to answer any queries during the employee’s absence. This increases the likelihood of discovering illegal activities by employees. It also acts as an effective deterrent.  
**Separation of duties**  
Separation of duties prevents any single person or entity from controlling all the functions of a critical or sensitive process by dividing the tasks between employees. This helps prevent potential fraud, such as if a single person prints and signs checks.  
**The principle of Least privilege**  
Least privilege specifies that individuals or processes are granted only those rights and permissions needed to perform their assigned tasks or functions. By implementing the least privilege policy, it limits potential losses if any  
individual or process is compromised.  
**Job rotation**  
Job rotation policies require employees to change roles regularly. Employees might change roles temporarily, such as for three to four weeks, or permanently. This helps ensure that employees cannot continue with fraudulent activity indefinitely.  
**Clean desk space**  
A clean desk space policy requires users to organize their areas to reduce the risk of possible data theft. It reminds users to secure sensitive data and may include a statement about not writing down passwords.  
**Background checks, Onboarding and Offboarding**  
Background checks investigate the history of an individual prior to employment and, sometimes, during employment. They may include  
criminal checks, credit checks, and an individual’s online activity. Onboarding is the process of granting new employees access to resources.  
Offboarding removes this access often by disabling or deleting a user’s account. Offboarding also includes collecting everything issued to the  
employee.  
**NDA**  
A non-disclosure agreement (NDA) is used between two entities to ensure that proprietary data is not disclosed to unauthorized entities. Many organizations use an NDA to prohibit employees from sharing proprietary data either while they are employed or after leaving the organization. It’s common to remind employees of an existing NDA during offboarding or an exit interview.  
**Supply chain and third party vendor policies**  
Supply chain and vendor policies typically provide guidance on how to limit access given to vendors. An SLA (service-level agreement) is an agreement between a company and a vendor that stipulates performance expectations, such as minimum  
uptime and maximum downtime levels. A memorandum of understanding (MOU) expresses an understanding between two or more parties indicating their intention to work together toward a common goal. A measurement systems analysis (MSA) evaluates the processes and tools used to make measurements.  
**Incident Response Policy**  
An incident response policy defines a security  
incident and incident response procedures. Incident response procedures start with preparation to prepare for and prevent incidents. Preparation  
helps prevent incidents such as malware infections. Personnel review the policy periodically and in response to lessons learned after incidents.

## Attacks Detection Strategies

### DNS Tunneling

A technique used by attackers especially advanced persistent groups to exfilterate data through DNS queries. Attackers prefer this method because DNS can't be blocked. DNS Tunneling attack detection methods

```
1- Examine long DNS queries usually they come in TXT query type. Wireshark or any packet analyzer can be used.

2- Look also for uncommon DNS query types.

3- DNS tunneling usually use bot traffic and algorithms so while looking into the packers, pay attention to any consisten and repeated long algorithm characters in DNS queries.

4- Examine the destination host or server to which the suspected traffic is sent. If the host or server doesn't receive othe traffic, it means the sole purpose of it is to receive tunneling traffic.
```