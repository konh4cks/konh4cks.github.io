---
title: Cyber Security Management - Concepts
date: 2025-12-17 00:00:00 +0000
categories: [Information Security]
tags: [information security, management, governance, risk]
---

## Implementing Information Security Programs

### Using Cybersecurity Frameworks

- NIST’s Cybersecurity Framework (CSF) NIST 800/30 (For risk assessment)and NIST 800/53
- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment  
    • NIST SP 800-37: Risk Management Framework for  
    Information Systems and Organizations
- NIST 800-53 Security Controls and Traceability Matrix (SCTM)
- Cyber Kill Chain
- ISO 27001.

### Metrics to use to measure the success of the information security program

- Measure the percentage of increased incidents: Finding more stuff doesn’t inherently mean your security is getting lax; it could very well be an indication of security process improvements.
- Applying employee training to actual business use cases: SANS courses aren’t just expensive weeklong vacations. Make your people come back and debrief what they learned and then share that knowledge with the team.
- Number of detections in place
- Number of false positives: false positives are an indicator that monitoring is either too sensitive or not monitoring the correct indicators. Post any new implementation, there should be some false positives as heuristics learn the environment, but that should be a trend line that continually goes down as well.
- Number of benign true positives (a true alert, but internal employee)
- Number of true positives: If an attacker makes it past all of the defenses and is not detected, that is a true positive. As far as metrics go, those need to trend as closely to zero as is possible.
- Number of preventions in place
- Number of times preventions worked
- Amount of time spent responding to alerts manually
- % of out of date systems: Firmware, software, and operating system patches should be tracked and part of the program requirements as they contribute to a large number of security incidents.
- Threats Detected: The one metric that is likely to continually go up is threats detected and threats stopped. Whether it’s visitors stopped for not having a badge or being escorted, or malicious web traffic halted, real-time threat indicators are most likely to trend upward and good for demonstrating to management the nature of the challenge we are facing.
- Mean time to response/remediate (MTTR): How long does it take to go from alerting/detection to response and remediation?
- the number of incidents you see over time should go down as the organization matures and gets better. The number of vulnerabilities seen during passive and active scanning activities should be also going down as the organization gets more mature. Also, internal user awareness training should be considered as should the rate of success of, say, phishing tests to help bring the awareness levels up to make not only the security and blue team a success, but the organization as a whole a success.

## Implementing an Incident Response Program

### Important Factors and Elements

- Project management
- Case management: Where are you putting your team’s findings and investigation notes? Is everyone on the same page?
- Executive sponsorship and stakeholder buy-in
- Process: The IR process should be clearly defined: What is the IR process for the program? Is an incident clearly defined? What are the key areas of responsibilities between individual contributors and leaders?
- Education: The incident response program will be able to set standards of education and ongoing training for personnel to stay up-to-date on the changing threat landscape.
- Network security monitoring and analysis
- Threat hunting
- Cyber-threat intel analysis
- Live host analysis
- Malware analysis
- Disk forensic analysis
- Security log analysis
- Security event coordination/analysis
- Key management/leadership/“soft” skills
- Critical thinking/analysis.

## Data Governance

Data governance is critically important and works in concert with asset management and risk management. An organization has to understand what data is important to the business and why. Once that is understood and properly modeled, smart decisions can be made related to business risks and planning, additional security controls, reduction and protection strategies, and overall impacts. It’s also critically important to understand what data is actually regulated and what is assumed to be regulated but in fact isn’t.  
The data retention policy is the most important document in the policy arsenal for reducing a data footprint. It is virtually impossible to expect or rely on the end-user community to police their own data.  
Organizations should put forth as much effort as is feasible to understand where their data is stored, the classification of the data, which people/applications have access, and the flow of data through business processes. From there you can make continuously informed decisions about changing processes, opportunities, and what you want your overall footprint to be.  
Implementing appropriate IAM controls along with DLP. Finally, We would not hold on to data longer than we need to. Oftentimes enterprises don’t set retention policies appropriately. The more data you unnecessarily hold on to, the more risk you have.

### Laws and Frameworks for Data Governance

**Health Insurance Portability and Accountability Act (HIPAA)**  
HIPAA mandates that organizations protect health information. This includes any information related to the health of an individual that might be held by doctors, hospitals, or any health facility. It also applies to any information held by an organization related to health plans offered to employees.  
**Gramm-Leach Bliley Act (GLBA)**  
This is also known as the Financial Services Modernization Act and includes a Financial Privacy Rule. This rule requires financial institutions to provide consumers with a privacy notice explaining what information they collect and how it is used.  
**Sarbanes-Oxley Act (SOX)**  
SOX requires that executives within an organization take individual responsibility for the accuracy of financial reports. It also includes specifics related to auditing and identifies penalties to individuals for noncompliance.  
**General Data Protection Regulation (GDPR)**  
This European Union (EU) directive mandates the protection of privacy data for individuals who live in the EU. It applies to any organization that collects and maintains this data, regardless of the location of the organization.

### Information Security Governance

Information security governance represents an organization's established structure, policies, methods, and guidelines designed to guarantee the privacy, reliability, and accessibility of its information assets. Information security governance includes the below processes

- **Strategy**: Developing and implementing a comprehensive information security strategy that aligns with the organisation's overall business objectives.
- **Policies and procedures**: Preparing policies and procedures that govern the use and protection of information assets.
- **Risk management**: Conduct risk assessments to identify potential threats to the organisation's information assets and implement risk mitigation measures.
- **Performance measurement**: Establishing metrics and key performance indicators (KPIs) to measure the effectiveness of the information security governance program.
- **Compliance**: Ensuring compliance with relevant regulations and industry best practices.

## Risk Management

### Definitions

**Risk management** is the practice of identifying, monitoring, and limiting risks to a manageable level. It doesn’t eliminate risks but instead  
identifies methods to limit or mitigate them.  
**Risk** is the possibility or likelihood of a threat exploiting a vulnerability resulting in a loss.  
**Risk Mitigation** reduces the chances that a threat will exploit a vulnerability. You reduce  
risks by implementing controls (also called countermeasures and safeguards).  
**Risk Avoidance** An organization can avoid a risk by not providing a service or not participating in a risky activity such as disconnecting a machine from the internet.  
**Risk Acceptance** When the cost of a control outweighs a risk, an organization will often accept the risk.  
**Risk Transference** is transferring the risk to another entity or at least shares the risk with another entity. The most common method is by purchasing insurance. Another method is by outsourcing or contracting a third party.  
**Inherent risk** refers to the risk that exists before controls are in place to manage the risk.  
**Residual risk** is the amount of risk that remains after managing or mitigating risk to an acceptable level.  
**Risk appetite** refers to the amount of risk an organization is willing to accept. This varies between organizations based on their goals and strategic objectives.  
**Risk register** is a comprehensive document listing known information about risks such as the risk owner. It typically includes risk scores along with recommended security controls to reduce the risk scores. A risk matrix plots risks onto a graph or chart, and a risk heat map uses color-coding to plot the risks.  
**Threat** is any circumstance or event that  
has the potential to compromise confidentiality, integrity, or availability. Threats can be classified into three main categories: human-made, technical, or natural.  
**Vulnerability** is a weakness. It can be a weakness in the hardware, the software, the configuration, or even the users operating the system. If a threat (such as an attacker) exploits a vulnerability, it can result in a security incident.  
**Asset** An asset is an economic resource owned or controlled by an individual, company, or government. Assets include cash and cash equivalents, accounts receivable, investments, stock, equipment, real estate, and intellectual property. An asset in information systems refers to any valuable resource or component (tangible or intangible) that an organization relies upon to achieve its objectives. These assets are critical for successfully operating and managing the organization’s information processes.  
**Security incident** is an adverse event or series of  
events that can negatively affect the confidentiality, integrity, or availability of an organization’s information technology (IT) systems and data. This  
includes intentional attacks, malicious software (malware) infections, accidental data loss, and much more.

### Risk Assessment Frameworks

#### NIST SP 800-30

A risk assessment methodology developed by the National Institute of Standards and Technology (NIST). It involves identifying and evaluating risks, determining the likelihood and impact of each risk, and developing a risk response plan. Based on this framework, the risk assessment comprises of the below steps

##### Frame Risks

First, we must establish the context within which all risk activities occur.  
When we frame risk we try to define the folloing  
**Risk Assumptions**: What are the assumptions about threats and vulnerabilities? What is the likelihood of occurrence? What would be the impact and consequences?  
**Risk Constraints**: What are the constraints on assessing, responding, and monitoring risks?  
**Risk Tolerance**: What are the acceptable levels of risk? What is the acceptable degree of risk uncertainty?  
**Priorities and Trade-offs**: What are the high-priority business functions? What are the trade-offs among the different types of faced risks?

##### Assess risk

In this step we identify, analyze, and evaluate potential risks and their likelihood and impact. This step is crucial to help decide on a proper response later. In this step we try to define the below  
**Threats**: What are the threats that you need to consider?  
**Vulnerabilities**: What are the vulnerabilities that you have to deal with  
**Impact**: What would be the impact if a threat exploited a vulnerability?  
**Likelihood**: What is the likelihood of this vulnerability being exploited?

##### Risk Analysis

Risk can be analyzed using two approaches, namely

- **Qualitative Risk Analysis**, where we assign ratings to risks. The ratings can be a qualitative adjective, such as high, medium, and low. Alternatively, it can be something symbolic, such as red, yellow, and green.

The below is the risk assessment matrix using in qualitative risk analysis  

- **Quantitative Risk Analysis**, where we assign monetary values and use that as a basis for decision-making. In conducting the quantitative risk analysis, we aim to calculate the values defined below
- `Single Loss Expectancy (SLE)` is the loss incurred due to the realization of a threat represented as a monetary value.
- `Asset Value` is the monetary valuation of an asset
- `Exposure Factor (EF)` is the percentage of loss a realized threat can cause to an asset.
- `Annualised Loss Expectancy (ALE)` is the loss the company expects to lose per year due to the threat.
- `Annualised Rate of Occurrence (ARO)` is the expected number of times this threat is realised yearly, i.e., frequency per year.

And below are the equations we can use to find them

```
SLE= AssetValue × EF
ALE = SLE× ARO
```

##### Respond to risk

We take the steps necessary to mitigate the likelihood or impact of the risk. When responding to risks we have the below options

- `Avoid Risk`: If a company decides to eliminate the activity that leads to the risk, that would be risk avoidance. A bank might decide that all employees’ computers cannot access the Internet to protect its systems against all online threats. An organization might instruct its employees to work exclusively using the workstations on its premises to prevent data from being stolen.
- `Transfer Risk`: A company might consider the risk too high to handle, so it decides to purchase insurance. That would be risk transference or risk sharing. A publishing house might buy insurance against fire, for instance.
- `Mitigate Risk`: A company might invest in countermeasures to reduce risk to an acceptable level; this would be risk mitigation. To protect against computer viruses, a company might install antivirus on all its computers instead of blocking access to the Internet and gluing the USB ports. Mitigating risks will at the end involves implementing safeguards but before we implement them we should consider whether it's worth the investment by applying the below equations

```
ValueofSafeGuard = ALEbeforeSafeguard - AELafterSafeGuard - AnnualCostOfSafeguard
```

The value calculated from above was positive then an implementation of the safeguard is cost effective and the benefits outweigh the risks and if it's negative then the opposite applies.

- `Accept Risk`: Sometimes, the countermeasure cost exceeds the loss incurred if the risk is realized.

##### Monitor risk

Finally, we continue tracking and evaluating the effectiveness of risk responses, identifying new risks, and ensuring that our risk management activities are effective. Monitoring is an ongoing process, as many criteria might change over time.

#### Facilitated Risk Analysis Process (FRAP)

A risk assessment methodology that involves a group of stakeholders working together to identify and evaluate risks. It is designed to be a more collaborative and inclusive approach to risk analysis.

#### Operationally Critical Threat, Asset, and Vulnerability Evaluation (OCTAVE)

A risk assessment methodology that focuses on identifying and prioritizing assets based on their criticality to the organization’s mission and assessing the threats and vulnerabilities that could impact those assets.

#### Failure Modes and Effect Analysis (FMEA)

A risk assessment methodology commonly used in engineering and manufacturing. It involves identifying potential failure modes for a system or process and then analyzing the possible effects of those failures and the likelihood of their occurrence.

### Supply Chain Risk Management

Supply chain risk management includes managing the risk associated with dealing with vendors and service providers especially when you choose to transfer the risk to a third part. The risk can be divided into

- **Risk associated with hardware**: Depending on the importance of the target, a threat actor can add a hardware Trojan to an electronic device. As with software Trojans, the purpose is to provide unauthorised functionality.
- **Risk associated with software**: Software Trojans require access to the software to plant it. In the worst-case scenario, the attacker would succeed in adding the Trojan directly to the source code.
- **Risk associated with services**: The risk can range from downtime to data breaches. A company must ensure that the service provider has a good security program before using its service.

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

## Information Security Regulations

Information security regulation refers to legal and regulatory frameworks that govern the use and protection of information assets. Regulations are designed to protect sensitive data from unauthorized access, theft, and misuse. Compliance with regulations is typically mandatory and enforced by government agencies or other regulatory bodies.  
**General Data Protection Regulation (GDPR)**  
GDPR is a regulation propagated by the European Union that sets strict requirements for how organizations handle and protect and  secure the personal data of EU citizens and residents.  
GDPR consists of the below components

```
- Prior approval must be obtained before collecting any personal data.
- Personal data should be kept to a minimum and only collected when necessary.
- Adequate measures are to be adopted to protect stored personal data.
```

The fines and penalties imposed on non-compliant companies and organizations include two tiers of fines:

```
- Tier 1: More severe violations, including unintended data collection, sharing data with third parties without consent, etc. Maximum penalty amounting to 4% of the organization's revenue or 20 million euros (whichever is higher).
- Tier 2: Less severe violations, including data breach notifications, cyber policies, etc. The maximum fine for Tier 2 is 2% of the organization's revenue or 10 million euros (whichever is higher).
```

**Health Insurance Portability and Accountability Act (HIPAA)**  
A US-based official law to maintain the sensitivity of health-related information of citizens.  
**Payment Card Industry Data Security Standard (PCI-DSS**  
Set technical and operational requirements to ensure the secure handling, storage, processing, and transmission of cardholder data by merchants, service providers, and other entities that handle payment cards.  
**Gramm-Leach-Bliley Act (GLBA)**  
Financial companies must be sensitive to their customers' nonpublic personal information (NPI), including implementing information security programs, providing privacy notices, and disclosing information-sharing practices.

## Information Security Frameworks

Information security framework is a set of documents that outline how security and governance are handled and achieved in the organization. Implementing an information security framework is part of implementing an information security program. A framework has the below components:

- **Policies**: A formal statement that outlines an organization's goals, principles, and guidelines for achieving specific objectives.
- **Standards**:A document establishing specific requirements or specifications for a particular process, product, or service.
- **Guidelines**: A document that provides recommendations and best practices (non-mandatory) for achieving specific goals or objectives.
- **Procedures**: Set of specific steps for undertaking a particular task or process.
- Baselines: A set of minimum security standards or requirements that an organization or system must meet.

### ISO27001

“Information Security Management,” provides  
information on information security management system (ISMS) requirements. Organizations that implement the ISMS requirements can go through a three-stage certification process, indicating they are ISO 27001 compliant.

### ISO 27701

ISO 27701, “Privacy Information Management System (PIMS),” is based on ISO 27001, and it outlines a framework for managing and protecting Personally Identifiable Information (PII).  
It provides organizations with guidance to comply with global privacy standards, such as the European Union General Data Protection Regulation (EU GDPR).

### Governance and Risk Compliance (GRC) framework

This framework revolves around governance, risk management and compliance with regulations. Main components are below:

- **Governance Component**: Involves guiding an organisation by setting its direction through information security strategy,  which includes policies, standards, baselines, frameworks, etc., along with establishing appropriate monitoring methods to measure its performance and assess the outcomes.
- **Risk Management Component**: Involves identifying, assessing, and prioritising risks to the organisation and implementing controls and mitigation strategies to manage those risks effectively. This includes monitoring and reporting on risks and continuously evaluating and refining the risk management program to ensure its ongoing effectiveness.
- **Compliance Component**: Ensuring that the organisation meets its legal, regulatory, and industry obligations and that its activities align with its policies and procedures. This includes developing and implementing compliance programs, conducting regular audits and assessments, and reporting on compliance issues to stakeholders.  
    `Steps to create a GRC Program`

```
- Define the scope and objectives: This step involves determining the scope of the GRC program and defining its goals. For example, a company can implement a GRC program for its customer data management system. The objective might be to reduce cyber risks to 50% in the next 12 months while maintaining the trust of its customers. 

- Conduct a risk assessment: In this step, the organisation identifies and assesses its cyber risks. For example, a risk assessment might reveal that the customer data management system is vulnerable to external attacks due to weak access controls or outdated software. The organisation can then prioritize these risks and develop a risk management strategy.

- Develop policies and procedures: Policies and procedures are developed to guide cyber security practices within the organisation. For example, the company might establish a password policy to ensure the usage of strong passwords. They might also implement logging and monitoring system access procedures to detect suspicious activity.

- Establish governance processes: Governance processes ensure the GRC program is effectively managed and controlled. For example, the organisation might establish a security steering committee that meets regularly to review security risks and make decisions about security investments and priorities. Roles and responsibilities are defined to ensure everyone understands their role in the program.

- Implement controls: Technical and non-technical controls are implemented to mitigate risks identified in risk assessment. For example, the company might implement firewalls, Intrusion Prevention System (IPS), Intrusion Detection System (IDS), and Security Information and Event Management (SIEM) to prevent external attacks and impart employee training to improve security awareness and reduce the risk of human error.

- Monitor and measure performance: Processes are established to monitor and measure the effectiveness of the GRC program. For example, the organisation can track metrics and compliance with security policies. This information is used to identify areas for improvement and adjust the program as needed.

- Continuously improve: The GRC program is constantly reviewed and improved based on performance metrics, changing risk profiles, and stakeholder feedback. For example, suppose the organisation experiences a security incident. In that case, it might conduct a post-incident analysis to identify the root cause and make changes to prevent a similar incident from happening again.
```