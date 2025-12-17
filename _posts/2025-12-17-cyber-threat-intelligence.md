---
title: Cyber Threat Intelligence
date: 2025-12-17 00:00:00 +0000
categories: [Information Security]
tags: [threat intelligence, information security, cti]
---

## Cyber Threat Intelligence

### Definition

From blue team perspective, it's the collection and analysis of tactics, techniques and procedures used by attackers to build detections.  
From read team perspectives, it's the emulation of adversaries TTPs and analysis of blue team's ability to build detections based in IOCs and TTPs.  
[#EX](https://publish.obsidian.md/#EX)  
Red team collects TTPs from threat intelligence frameworks and related to a certain hacking group to create tools and emulate this hacking group's behaviour in an engagement.

In cyber threat intelligence, we aim to answer the below questions with the help of threat intelligence

- Who’s attacking you?
- What are their motivations?
- What are their capabilities?
- What artefacts and indicators of compromise (IOCs) should you look out for?

### How to gather threat intelligence

- **Internal:**
    - Vulnerability assessments and incident response reports.
    - Cyber awareness training reports.
    - System logs and events.
- **Community:**
    - Web forums.
    - Dark web communities for cybercriminals.
- **External**
    - Threat intel feeds (Commercial & Open-source)
    - Online marketplaces.
    - Public sources include government data, publications, social media, financial and industrial assessments.

### Lifecycle Phases of Cyber threat intelligence

#### Direction

Defining the goals and objectives by preparing the below:

- Information assets and business processes that require defending.
- Potential impact to be experienced on losing the assets or through process interruptions.
- Sources of data and intel to be used towards protection.
- Tools and resources that are required to defend the assets.

#### Collection

Analysts start gathering the data by using commercial, private and open-source resources available. Due to the volume of data analysts usually face, it is recommended to automate this phase to provide time for triaging incidents.

#### Processing

Raw logs, vulnerability information, malware and network traffic usually come in different formats and may be disconnected when used to investigate an incident. This phase ensures that the data is extracted, sorted, organised, correlated with appropriate tags and presented visually in a usable and understandable format to the analysts. SIEMs are valuable tools for achieving this and allow quick parsing of data.

#### Analysis

Once the information aggregation is complete, security analysts must derive insights. Decisions to be made may involve:

- Investigating a potential threat through uncovering indicators and attack patterns.
- Defining an action plan to avert an attack and defend the infrastructure.
- Strengthening security controls or justifying investment for additional resources.

#### Dissemination

Different organisational stakeholders will consume the intelligence in varying languages and formats. For example, C-suite members will require a concise report covering trends in adversary activities, financial implications and strategic recommendations. At the same time, analysts will more likely inform the technical team about the threat IOCs, adversary TTPs and tactical action plans.

#### Feedback

The final phase covers the most crucial part, as analysts rely on the responses provided by stakeholders to improve the threat intelligence process and implementation of security controls. Feedback should be regular interaction between teams to keep the lifecycle working.

### Threat Intelligence Frameworks

Threat intelligence frameworks collect TTPs and categorize them according to

```bash
1.  Threat Group
2.  Kill Chain Phase
3.  Tactic
4.  Objective/Goal
```bash
#### MITRE ATT&CK

**Link**  
[https://attack.mitre.org/](https://attack.mitre.org/)  
**Definition**  
MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a comprehensive, globally accessible knowledge base of cyber adversary behaviour and tactics. Developed by the MITRE Corporation, it is a valuable resource for organizations to understand the different stages of cyber attacks and develop effective defences.  
**How it works**  
The ATT&CK framework is organized into a matrix that covers various tactics (high-level objectives) and techniques (methods used to achieve goals). The framework includes descriptions, examples, and mitigations for each technique, providing a detailed overview of threat actors' methods and tools.  
**Use Cases**  
`Identifying potential attack paths based on your infrastructure`  
Based on your assets, the framework can map possible attack paths an attacker might use to compromise your organization. For example, if your organization uses Office 365, all techniques attributed to this platform are relevant to your threat modelling exercise.  
`Developing threat scenarios`  
MITRE ATT&CK has attributed all tactics and techniques to known threat groups. This information can be leveraged to assess your organization based on threat groups identified to be targeting the same industry.  
`Prioritizing vulnerability remediation`  
The information provided for each MITRE ATT&CK technique can be used to assess the significant impact that may occur if your organisation experiences a similar attack. Given this, your security team can identify the most critical vulnerabilities to address.

#### DREAD Framework

**Definition**  
The DREAD framework is a risk assessment model developed by Microsoft to evaluate and prioritize security threats and vulnerabilities.

DREAD offers a more numerical and calculated approach to threat analysis than STRIDE or MITRE ATT&CK, making it excellent for clearly prioritizing threats.  
**How it works**  
We can explain how Dread works by explaining the acronyms that compose its name  
`Damage`  
How bad would an attack be?  
The potential harm that could result from the successful exploitation of a vulnerability. This includes data loss, system downtime, or reputational damage.  
`Reproducibility`  
How easy is it to reproduce the attack?  
The ease with which an attacker can successfully recreate the exploitation of a vulnerability. A higher reproducibility score suggests that the vulnerability is straightforward to abuse, posing a greater risk.  
`Exploitability`  
How much work is it to launch the attack?  
The difficulty level involved in exploiting the vulnerability considering factors such as technical skills required, availability of tools or exploits, and the amount of time it would take to exploit the vulnerability successfully.  
`Affected Users`  
How many people will be impacted?  
The number or portion of users impacted once the vulnerability has been exploited.  
`Discoverability`  
How easy is it to discover the vulnerability?  
The ease with which an attacker can find and identify the vulnerability considering whether it is publicly known or how difficult it is to discover based on the exposure of the assets (publicly reachable or in a regulated environment).  
**Putting it into practice**  
The DREAD Framework is typically used for  
Qualitative Risk Analysis, rating each category from  
one to ten based on a subjective assessment and  
interpretation of the questions above. Moreover, the  
average score of all criteria will calculate the overall  
DREAD risk rating.  
`Damage`

```
0 – Indicates no damage caused to the organization
5 – Information disclosure said to have occurred
8 – Non-sensitive user data has been compromised
9 – Non-sensitive administrative data has been compromised
10 – The entire information system has been destructed. All data and applications are inaccessible
```bash
`Reproducibility`

```bash
0 – Difficult to replicate the attack
5 – Complex to replicate the attack
7.5 – Easy to replicate the attack
10 – Very easy to replicate the attack
```bash
`Exploitability`

```
2.5 – Indicates that advanced programming and networking skills needed to exploit the vulnerability
5 – Available attack tools  needed to exploit the vulnerability
9 – Web application proxies are needed to exploit the vulnerability
10 – Indicates the requirement of a web browser  needed to exploit the vulnerability
```bash
`Affected Users`

```bash
0 –  no users  affected
2.5 – Indicates chances of fewer individual users  affected
6 –  Few users affected
8 – Administrative users affected
10 – All users affected
```bash
`Discoverability`

```
2.5 – Indicates it’s hard to discover the vulnerability
5 – HTTP requests can uncover the vulnerability
8 – Vulnerability  found in the public domain
10 – Vulnerability found in  web address bar or form
```bash
#### PASTA

**Definition**  
PASTA, or Process for Attack Simulation and Threat Analysis, is a structured, risk-centric threat modelling framework designed to help organizations identify and evaluate security threats and vulnerabilities within their systems, applications, or infrastructure. PASTA provides a systematic, seven-step process that enables security teams to understand potential attack scenarios better, assess the likelihood and impact of threats, and prioritise remediation efforts accordingly.

PASTA is an excellent framework for aligning threat modelling with business objectives. Unlike other frameworks, PASTA integrates business context, making it a more holistic and adaptable choice for organisations  
**Components**

1. `Define the Objectives`  
    Establish the scope of the threat modelling exercise by identifying the systems, applications, or networks being analysed and the specific security objectives and compliance requirements to be met.
2. `Define the Technical Scope`  
    Create an inventory of assets, such as hardware, software, and data, and develop a clear understanding of the system's architecture, dependencies, and data flows.
3. `Decompose the Application`  
    Break down the system into its components, identifying entry points, trust boundaries, and potential attack surfaces. This step also includes mapping out data flows and understanding user roles and privileges within the system.
4. `Analyze the Threats`  
    Identify potential threats to the system by considering various threat sources, such as external attackers, insider threats, and accidental exposures. This step often involves leveraging industry-standard threat classification frameworks or attack libraries.
5. `Vulnerabilities and Weaknesses Analysis`  
    Analyze the system for existing vulnerabilities, such as misconfigurations, software bugs, or unpatched systems, that an attacker could exploit to achieve their objectives. Vulnerability assessment tools and techniques, such as static and dynamic code analysis or penetration testing, can be employed during this step.
6. `Analyze the Attacks`  
    Simulate potential attack scenarios and evaluate the likelihood and impact of each threat. This step helps determine the risk level associated with each identified threat, allowing security teams to prioritize the most significant risks.
7. `Risk and Impact Analysis`  
    Develop and implement appropriate security controls and countermeasures to address the identified risks, such as updating software, applying patches, or implementing access controls. The chosen countermeasures should be aligned with the organisation's risk tolerance and security objectives.

#### TIBER(Threat Intelligence-based Ethical Red Teaming)-EU

**Link**  
[https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)

#### OST Map

**Link**  
[https://www.intezer.com/ost-map/](https://www.intezer.com/ost-map/)

#### TAXII

**Link**  
[https://oasis-open.github.io/cti-documentation/taxii/intro](https://oasis-open.github.io/cti-documentation/taxii/intro)

#### STIX

**Link**  
[https://oasis-open.github.io/cti-documentation/stix/intro](https://oasis-open.github.io/cti-documentation/stix/intro)

#### STRIDE

**Definition and Components**  
The STRIDE framework is a threat modelling methodology also developed by Microsoft, which helps identify and categorize potential security threats in software development and system design.

STRIDE shines in its structure and methodology, allowing for a systematic review of threats specific to software systems.

**Components**  
`Spoofing`  
Unauthorized access or impersonation of a user or system.  
[#Examples](https://publish.obsidian.md/#Examples)

- Sending an email as another user.
- Creating a phishing website mimicking a legitimate one to harvest user credentials.  
    `Tampering`  
    Unauthorized modification or manipulation of data or code.  
    [#Examples](https://publish.obsidian.md/#Examples)
- Updating the password of another user.
- Installing system-wide backdoors using an elevated access.  
    `Repudiation`  
    Ability to deny having acted, typically due to insufficient auditing or logging.  
    [#Examples](https://publish.obsidian.md/#Examples)
- Denying unauthorised money-transfer transactions, wherein the system lacks auditing.
- Denying sending an offensive message to another person, wherein the person lacks proof of receiving one.  
    `Information Disclosure`  
    Unauthorized access to sensitive information, such as personal or financial data.  
    [#Examples](https://publish.obsidian.md/#Examples)
- Unauthenticated access to a misconfigured database that contains sensitive customer information.
- Accessing public cloud storage that handles sensitive documents.  
    `Denial of Service`  
    Disruption of the system's availability, preventing legitimate users from accessing it.  
    [#Examples](https://publish.obsidian.md/#Examples)
- Flooding a web server with many requests, overwhelming its resources, and making it unavailable to legitimate users.
- Deploying a ransomware that encrypts all system data that prevents other systems from accessing the resources the compromised server needs.  
    `Elevation of Privilege`  
    Unauthorized elevation of access privileges, allowing threat actors to perform unintended actions.  
    [#Examples](https://publish.obsidian.md/#Examples)
- Creating a regular user but being able to access the administrator console.
- Gaining local administrator privileges on a machine by abusing unpatched systems.

#### The Diamond Model

**Definition and Components**  
The Diamond Model is composed of four core features: adversary, infrastructure, capability, and victim to help analyze intrusions and give insights on the threat actor.  
An `adversary` is also known as an attacker, enemy, cyber threat actor, or hacker. The adversary is the person who stands behind the cyberattack. Cyberattacks can be an intrusion or a breach.  
It is difficult to identify an adversary during the first stages of a cyberattack. Utilizing data collected from an incident or breach, signatures, and other relevant information can help you determine who the adversary might be.  
`Victim` is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions.  
`Capability` is also known as the skill, tools, and techniques used by the adversary in the event. The capability highlights the adversary’s tactics, techniques, and procedures (TTPs).  
`Capability Capacity` is all of the vulnerabilities and exposures that the individual capability can use.   
`Adversary Arsenal` is a set of capabilities that belong to an adversary. The combined capacities of an adversary's capabilities make it the adversary's arsenal.  
`Infrastructure`is also known as software or hardware. Infrastructure is the physical or logical interconnections that the adversary uses to deliver a capability or maintain control of capabilities. For example, a command and control centre (C2) and the results from the victim (data exfiltration).  
_Type 1 Infrastructure_ is the infrastructure controlled or owned by the adversary.   
_Type 2 Infrastructure_ is the infrastructure controlled by an intermediary. Sometimes the intermediary might or might not be aware of it. This is the infrastructure that a victim will see as the adversary. Type 2 Infrastructure has the purpose of obfuscating the source and attribution of the activity. Type 2 Infrastructure includes malware staging servers, malicious domain names, compromised email accounts, etc.  
`Service Providers` are organizations that provide services considered critical for the adversary availability of Type 1 and Type 2 Infrastructures, for example, Internet Service Providers, domain registrars, and webmail providers.

#### The Unified Kill Chain

**Definition and Components**  
Unified kill chain is used to describe the methodology/path attackers such as hackers or APTs use to approach and intrude a target.  
**Components**  
The UKC states that there are 18 phases to an attack: Everything from reconnaissance to data exfiltration and understanding an attacker's motive. These phases have been grouped together as the figure below shows  

#### The Cyber Kill Chain

**Definition**  
The Cyber Kill Chain helps in understanding and protecting against ransomware attacks, security breaches as well as Advanced Persistent Threats (APTs). We can use the Cyber Kill Chain to assess your network and system security by identifying missing security controls and closing certain security gaps based on your company's infrastructure.  
**Phases of an attack in Cyber kill chain**  
_Reconnaissance_  
_Reconnaissance_ is discovering and collecting information on the system and the victim. The reconnaissance phase is the planning phase for the adversaries. **OSINT** (Open-Source Intelligence) also falls under reconnaissance.  
_Weaponization_  
In this phase, the attacker prepares the infrastructure necessary to perform the attack. Examples are below:

```bash
- Creating an infected Microsoft Office document containing a malicious macro or VBA scripts.

- Creating a malicious payload or a very sophisticated worm, implant it on the USB drives, and then distribute them in public. An example of the virus. 

- Creating a Command and Control (C2) server for executing the commands on the victim's machine or deliver more payloads. 

- Creating Backdoors
```bash
_Delivery_  
Its the phase where the attacker decides to choose the method for transmitting the payload or the malware.  
Examples of delivery can be:

```
- Phishing email
- USB Drop Attack: Distributing infected USB drives in public places like coffee shops, parking lots, or on the street.
- Watering hole attack. A watering hole attack is a targeted attack designed to aim at a specific group of people by compromising the website they are usually visiting and then redirecting them to the malicious website of an attacker's choice.
```bash
_Exploitation_  
Its the phase where the attacker could exploit software, system, or server-based vulnerabilities to escalate the privileges or move laterally through the network.  
The attacker could exploit vulnerabilities by incorporating the exploit with the payload in the weaponization phase or simply after gaining access to the target system.  
_Installation_  
Its the phase where the attacker's aim is to reaccess the system at a later time or in case he loses the connection to it or if he got detected and got the initial access removed, or if the system is later patched. He will no longer have access to it. That is when the attacker needs to install a backdoor. A persistent backdoor will let the attacker access the system he compromised in the past.  
_Command and Control_  
The stage where the compromised endpoint would communicate with an external server set up by an attacker to establish a command & control channel. After establishing the connection, the attacker has full control of the victim's machine.  
The objective here is to control the victim machine by sending command and instructions to the victim machine which in turn executes them and sends the output back to the attacker's C2 server.  
_Actions on objectives_  
In this stage, the attacker executes the strategic goal of his entire plan. The actions can be:

```bash
- Harvesting and dumping the credentials from users.
- Perform privilege escalation
- Lateral movement through the company's environment.
- Collect and exfiltrate sensitive data.
- Deleting the backups and shadow copies. 
-   Overwrite or corrupt data.
```bash
### Information Sharing and Analysis Centers (ISACs)

Used to share and exchange various Indicators of Compromise (IOCs) to obtain threat intelligence

### TTP

An acronym for Tactics, Techniques, and Procedures.

```
The Tactic is the adversary's goal or objective.
The Technique is how the adversary achieves the goal or objective.
The Procedure is how the technique is executed.
```bash
### Threat Intelligence Types

**Strategic**  
Assist senior management make informed decisions specifically about the security budget and strategies.  
**Tactical**  
Interacts with the TTPs and attack models to identify adversary attack patterns.  
**Operational**  
Interact with IOCs and how the adversaries operationalize.

### Steps to create threat intelligence campaign

```bash
1.  Identify framework and general kill chain
2.  Determine targeted adversary
3.  Identify adversary's TTPs and IOCs
4.  Map gathered threat intelligence to a kill chain or framework
5.  Draft and maintain needed engagement documentation
6.  Determine and use needed engagement resources (tools, C2 modification, domains, etc.)
```bash
### Threat modelling

Threat modelling is a systematic approach to **identifying, prioritizing, and addressing potential security threats** across the organization. By simulating possible attack scenarios and assessing the existing vulnerabilities of the organisation's interconnected systems and applications, threat modelling enables organisations to develop proactive security measures and make informed decisions about resource allocation.Threat modelling aims to reduce an organisation's overall risk exposure by identifying vulnerabilities and potential attack vectors, allowing for adequate security controls and strategies.

#### Creating a Threat Modeling Plan

**Defining the scope**  
Identify the specific systems, applications, and networks in the threat modelling exercise.  
**Asset Identification**  
Develop diagrams of the organization's architecture and its dependencies. It is also essential to identify the importance of each asset based on the information it handles,  such as customer data, intellectual property, and financial information.  
**Identify Threats**  
Identify potential threats that may impact the identified assets, such as cyber attacks, physical attacks, social engineering, and insider threats.  
**Map to MITRE ATT&CK or any threat modeling/intelligence framework**  
Map the identified threats to the corresponding tactics and techniques in the MITRE ATT&CK Framework. For each mapped technique, utilise the information found on the corresponding ATT&CK technique page, such as the description, procedure examples, mitigations, and detection strategies, to gain a deeper understanding of the threats and vulnerabilities in your system.  
**Analyze Vulnerabilities and Prioritize Risks**   
Analyze the vulnerabilities based on the potential impact of identified threats in conjunction with assessing the existing security controls. Given the list of vulnerabilities, risks should be prioritized based on their likelihood and impact.  
**Develop and Implement Countermeasures**  
Design and implement security controls to address the identified risks, such as implementing access controls, applying system updates, and performing regular vulnerability assessments.  
**Monitor and Evaluate**  
Continuously test and monitor the effectiveness of the implemented countermeasures and evaluate the success of the threat modelling exercise. An example of a simple measurement of success is tracking the identified risks that have been effectively mitigated or eliminated.

#### Threat Modeling Team

**Security Team**  
The overarching team of red and blue teams. This team typically lead the threat modelling process, providing expertise on threats, vulnerabilities, and risk mitigation strategies. They also ensure security measures are implemented, validated, and continuously monitored.  
**Development Team**  
The development team is responsible for building secure systems and applications. Their involvement ensures that security is always incorporated throughout the development lifecycle.|  
**IT and Operations Team**  
IT and Operations teams manage the organization's infrastructure, including networks, servers, and other critical systems. Their knowledge of network infrastructure, system configurations and application integrations is essential for effective threat modelling.  
**Governance, Risk and Compliance Team**  
The GRC team is responsible for organization-wide compliance assessments based on industry regulations and internal policies. They collaborate with the security team to align threat modelling with the organisation's risk management objectives.|  
**Business Stakeholders**  
The business stakeholders provide valuable input on the organisation's critical assets, business processes, and risk tolerance. Their involvement ensures that the efforts align with the organization's strategic goals.  
**End Users**  
As direct users of a system or application, end users can provide unique insights and perspectives that other teams may not have, enabling the identification of vulnerabilities and risks specific to user interactions and behaviours.