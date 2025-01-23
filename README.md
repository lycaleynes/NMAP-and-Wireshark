<h1>NMAP and Wireshark</h1>

<h2>Description</h2>

<p>In the changing field of cybersecurity, we need to continually identify new threats to your network as evidenced in the network itself and the traffic on that network. We need to know how to run network mapping and monitoring software to find vulnerabilities and anomalies that could impact the security of your network in order to recommend sound solutions.</p>

<p>For this project, I used the virtual world at the “Performance Assessment Lab” web link from my school and accessed the files and lab environment necessary to run both Nmap and Wireshark on the network associated with this task. I also recommended solutions to address any issues I have found.</p>

<h2>Network Topology</h2>

<p align="center">
<img src="https://i.imgur.com/KDThErQ.jpeg" height="80%" width="80%" alt="Network Topology"/>

<p>This network topology is a star topology with a central node labeled "localhost," which acts as the hub. Several nodes are connected directly to this central hub via dashed lines, representing their network connections. Each connected node is identified by its IP address, with six nodes in total: 10.168.27.1, 10.168.27.132, 10.168.27.20, 10.168.27.14, 10.168.27.10, and 10.168.27.15.</p>

<h2>Summary of Vulnerabilities and Implications</h2>

<h3>Outdated OpenSSH Version on Multiple Hosts</h3>

<p align="center">
<img src="https://i.imgur.com/mzdrrdS.png" height="80%" width="80%" alt="NMAP"/>
<br />
<img src="https://i.imgur.com/OhThrAi.png" height="80%" width="80%" alt="NMAP"/>
<br />
<img src="https://i.imgur.com/XXdRh8u.png" height="80%" width="80%" alt="NMAP"/>

<p>Multiple hosts within the network are running an outdated version of OpenSSH. Specifically, the hosts with IP addresses 10.168.27.14, 10.168.27.20, and 10.168.27.132 are operating on OpenSSH 5.5p1 Debian 6+squeeze5. This version, released around 2010, is significantly outdated and is susceptible to known vulnerabilities such as CVE-2016-0777 and CVE-2016-0778. These vulnerabilities allow attackers to extract private SSH keys from the server's memory using the roaming feature, potentially leading to unauthorized access and privilege escalation (OpenSSH, 2016). Moreover, Debian 6 ("Squeeze") has reached its end-of-life, meaning it no longer receives security updates, further exacerbating the risk.</p>

<h3>Vulnerable SMB Services on Windows Server 2008 R2</h3>

<p align="center">
<img src="https://i.imgur.com/u6VA1TX.png" height="80%" width="80%" alt="NMAP"/>
<br />

<p>The server at IP address 10.168.27.10 is running Microsoft Windows Server 2008 R2 with SMB services active on ports 139/TCP and 445/TCP. This configuration is vulnerable to the EternalBlue exploit (CVE-2017-0144), which allows remote attackers to execute arbitrary code via crafted packets, leading to potential full system compromise (Microsoft, 2017). This vulnerability was famously exploited by the WannaCry ransomware, which encrypted data and demanded payment, causing widespread disruption globally. The exploitation could also enable attackers to propagate through the network, targeting other devices and increasing the scale of the attack.</p>

<h3>Unsecured FTP Service Using FileZilla Server</h3>

<p align="center">
<img src="https://i.imgur.com/RA6suxq.png" height="80%" width="80%" alt="NMAP"/>
<br />

<p>The host at IP address 10.168.27.15 is running an unsecured FTP service using FileZilla Server. Without specific version details, it's challenging to pinpoint exact vulnerabilities; however, older versions of FileZilla Server have been associated with vulnerabilities like directory traversal (CVE-2017-16023) and denial of service issues (National Vulnerability Database, 2017). Additionally, FTP inherently transmits data, including credentials, in plain text, making it susceptible to interception and man-in-the-middle attacks. This could lead to unauthorized access to sensitive files, credential theft, and even the distribution of malware through the compromised server.</p>

<h2>Wireshark Anomalies</h2>

<h3>Weak Password Transmission Over FTP</h3>

<p align="center">
<img src="https://i.imgur.com/7bmiqYU.png" height="80%" width="80%" alt="Wireshark"/>
<br />

<p>In packet range 213819 to 213821, a weak password transmission was observed during an FTP exchange. The client sent the command PASS 3.55.1, and the server responded with 230 Logged on, indicating successful authentication. This vulnerability is identified in CVE-1999-0612, which describes the risks associated with plaintext FTP authentication.</p>

<h3>Improper IGMP Handling Leading to Potential Denial of Service</h3>

<p align="center">
<img src="https://i.imgur.com/EwxuupM.png" height="80%" width="80%" alt="Wireshark"/>
<br />

<p>In packet ranges 214730 to 214742 and 219142 to 219149, multiple IGMPv3 Membership Reports were observed, where the host 10.16.80.243 repeatedly joins and leaves multicast groups 224.0.0.251 and 224.0.0.22. This behavior relates to CVE-2017-1000410, where improper handling of IGMP traffic could lead to a denial of service.</p>

<h3>Unencrypted LDAP Simple Bind Transmission</h3>

<p align="center">
<img src="https://i.imgur.com/NoAQaXq.png" height="80%" width="80%" alt="Wireshark"/>
<br />

<p>In packet range 151078 to 151086, a simple bind request using LDAP was captured, where credentials were transmitted in plaintext without encryption. This issue is aligned with CVE-2017-8563, where Microsoft disabled simple bind in Windows Server and Active Directory over unencrypted channels due to the high-security risks involved.</p>

<h2>Implications of each Wireshark Anomaly</h2>

<h3>Weak Password Transmission Over FTP</h3>

<p>Since FTP transmits data, including passwords, in plaintext, this transmission is vulnerable to interception. A malicious actor could use packet-sniffing tools to capture these credentials, making the exchange susceptible to man-in-the-middle attacks. FTP transmits sensitive credentials like the USER and PASS commands without encryption, allowing attackers to intercept and exploit the data using tools such as Wireshark.</p>

<h3>Improper IGMP Handling Leading to Potential Denial of Service</h3>

<p>The rapid joining and leaving of groups can lead to unnecessary network overhead, potentially indicating issues with multicast group management or inefficient handling by the network. If left unresolved, such behavior can cause instability in the multicast configuration or network equipment. The repeated joining and leaving of multicast groups can exhaust resources on network devices, resulting in outages or severe performance degradation.</p>

<h3>Unencrypted LDAP Simple Bind Transmission</h3>

<p>Simple Bind sends sensitive information such as usernames and passwords without using encryption mechanisms like TLS or SSL, making it highly vulnerable to interception. Without encryption, attackers can capture the transmitted credentials and potentially gain unauthorized access to the directory service. Simple Bind requests in this capture suggest similar risks, where sensitive credentials are exposed during transmission without encryption, potentially leading to credential leakage.</p>

<h2>Recommended Solutions</h2>

<h3>Outdated OpenSSH Version on Multiple Hosts</h3>

<p>For the hosts at IP addresses 10.168.27.14, 10.168.27.20, and 10.168.27.132 running an outdated version of OpenSSH (5.5p1 Debian 6+squeeze5), it is crucial to upgrade OpenSSH to the latest stable release. Updating to a newer version will patch known vulnerabilities, such as CVE-2016-0777 and CVE-2016-0778, and provide enhanced security features (OpenSSH, 2023). Disabling the insecure roaming feature by adding UseRoaming no to the SSH client configuration file (ssh_config) addresses vulnerabilities exploited in these CVEs (OpenSSH, 2016).</p>

<p>Upgrading the operating system from Debian 6 ("Squeeze") to a currently supported version, such as Debian 11 "Bullseye," is also advised. Supported operating systems receive regular security updates and patches, reducing vulnerability exposure (Debian Project, 2021). Implementing a regular patch management process ensures that all software and operating systems are up to date, minimizing security risks associated with outdated software (NIST, 2019).</p>

<h3>Vulnerable SMB Services on Windows Server 2008 R2</h3>

<p>Applying all critical security updates is recommended for the server at IP address 10.168.27.10 running Microsoft Windows Server 2008 R2 with SMB services active on ports 139/TCP and 445/TCP, particularly those addressing CVE-2017-0144 (Microsoft, 2017). Installing these patches mitigates the risk of remote code execution exploits like EternalBlue. Disabling the SMBv1 protocol is essential, as it is outdated and contains multiple security vulnerabilities. This can be accomplished using PowerShell commands or the Windows Features interface (NSA, 2017).</p>

<p>Upgrading to a supported version of Windows Server, such as Windows Server 2019 or 2022, ensures the system receives regular security updates and improvements (Microsoft, 2021). Implementing network segmentation to isolate critical systems limits the potential spread of infections within the network (NIST, 2020).</p>

<h3>Unsecured FTP Service Using FileZilla Server</h3>

<p>For the host at IP address 10.168.27.15 running an unsecured FTP service with FileZilla Server, upgrading to the latest version of FileZilla Server is advisable, as it includes security patches and improvements (FileZilla Project, 2023). Transitioning to secure protocols such as FTPS (FTP over SSL/TLS) or SFTP (Secure File Transfer Protocol) encrypts data in transit, protecting credentials and file contents from interception (IETF, 2006). Strong authentication mechanisms, like key-based or multi-factor authentication, enhance security by requiring additional verification factors beyond just a password (NIST, 2017). Encrypting data at rest and in transit safeguards sensitive information from unauthorized access and interception (ISO/IEC, 2013).</p>

<h3>Weak Password Transmission Over FTP</h3>

<p>Enforcing strong password policies is important to address the weak password transmission observed during the FTP exchange (packet range 213819 to 213821). This involves requiring complex passwords that are regularly updated (NIST, 2017). Implementing encrypted protocols like SFTP or FTPS ensures that credentials are not transmitted in plaintext, protecting them from interception (IETF, 2006). Monitoring network traffic using intrusion detection systems helps detect unsecured credential transmissions and prompts immediate remediation (Scarfone & Mell, 2007).</p>

<h3>Improper IGMP Handling Leading to Potential Denial of Service</h3>

<p>To mitigate risks associated with the observed IGMPv3 Membership Reports (packet ranges 214730 to 214742 and 219142 to 219149), updating the firmware and software of all network devices to the latest versions is recommended. Manufacturers often release updates to fix known vulnerabilities and improve IGMP handling (Cisco Systems, 2018). Implementing IGMP snooping on switches helps manage multicast traffic efficiently and reduces unnecessary network overhead (IEEE, 2011). Monitoring and limiting IGMP traffic using network monitoring tools prevents potential denial-of-service attacks by controlling the flow of IGMP messages (Juniper Networks, 2019).</p>

<h3>Unencrypted LDAP Simple Bind Transmission</h3>

<p>For the Simple Bind requests observed in the LDAP capture (packet range 151078 to 151086), enforcing the use of LDAP over SSL/TLS (LDAPS) is essential. This encrypts data in transit and prevents interception of credentials (Microsoft, 2017). Configuring the directory service to reject Simple Bind requests that are not over an encrypted channel ensures that clients use secure methods for authentication. Training users and administrators on the importance of secure protocols and proper configuration reduces the likelihood of implementing insecure practices (SANS Institute, 2018). Conducting regular security audits helps detect and remediate insecure configurations promptly (ISO/IEC, 2013).</p>

<h2>References</h2>

- Cisco Systems. (2018). Cisco IOS and IOS XE Software IGMPv3 Denial of Service Vulnerability. Retrieved from [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180905-igmp](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180905-igmp)
- Debian Project. (2021). Debian Releases. Retrieved from [https://www.debian.org/releases/](https://www.debian.org/releases/)
- FileZilla Project. (2023). FileZilla Server Downloads. Retrieved from [https://filezilla-project.org/download.php?type=server](https://filezilla-project.org/download.php?type=server)
- IEEE. (2011). IEEE Standard for Local and Metropolitan Area Networks—Bridges and Bridged Networks. Retrieved from [https://standards.ieee.org/standard/802_1Q-2011.html](https://standards.ieee.org/standard/802_1Q-2011.html)
- International Organization for Standardization. (2013). ISO/IEC 27002:2013 Information Technology – Security Techniques – Code of Practice for Information Security Controls. Retrieved from [https://www.iso.org/standard/54533.html](https://www.iso.org/standard/54533.html)
- Internet Engineering Task Force. (2006). SSH Transport Layer Protocol (RFC 4253). Retrieved from [https://tools.ietf.org/html/rfc4253](https://tools.ietf.org/html/rfc4253)
- Juniper Networks. (2019). Understanding IGMP Snooping and Filtering. Retrieved from [https://www.juniper.net/documentation/en_US/junos/topics/concept/igmp-snooping-filtering-overview.html](https://www.juniper.net/documentation/en_US/junos/topics/concept/igmp-snooping-filtering-overview.html)
- Microsoft. (2017). LDAP Data Signing and LDAP Channel Binding. Retrieved from [https://docs.microsoft.com/windows-server/security/kerberos/ldap-signed-communications](https://docs.microsoft.com/windows-server/security/kerberos/ldap-signed-communications)
- Microsoft. (2017). Microsoft Security Bulletin MS17-010 - Critical. Retrieved from [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Microsoft. (2017). Security Update for Microsoft Windows SMB Server (4013389). Retrieved from [https://docs.microsoft.com/security-updates/securitybulletins/2017/ms17-010](https://docs.microsoft.com/security-updates/securitybulletins/2017/ms17-010)
- Microsoft. (2021). Windows Server Release Information. Retrieved from [https://docs.microsoft.com/windows-server/get-started/windows-server-release-info](https://docs.microsoft.com/windows-server/get-started/windows-server-release-info)
- National Institute of Standards and Technology. (2017). Digital Identity Guidelines (NIST SP 800-63-3). Retrieved from [https://doi.org/10.6028/NIST.SP.800-63-3](https://doi.org/10.6028/NIST.SP.800-63-3)
- National Institute of Standards and Technology. (2019). Security and Privacy Controls for Information Systems and Organizations (NIST SP 800-53 Rev. 5). Retrieved from [https://doi.org/10.6028/NIST.SP.800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5)
- National Institute of Standards and Technology. (2020). Zero Trust Architecture (NIST SP 800-207). Retrieved from [https://doi.org/10.6028/NIST.SP.800-207](https://doi.org/10.6028/NIST.SP.800-207)
- National Vulnerability Database. (1999). CVE-1999-0612. Retrieved from [https://nvd.nist.gov/vuln/detail/CVE-1999-0612](https://nvd.nist.gov/vuln/detail/CVE-1999-0612)
- National Vulnerability Database. (2017). CVE-2017-16023. Retrieved from [https://nvd.nist.gov/vuln/detail/CVE-2017-16023](https://nvd.nist.gov/vuln/detail/CVE-2017-16023)
- National Vulnerability Database. (2018). CVE-2017-1000410. Retrieved from [https://nvd.nist.gov/vuln/detail/CVE-2017-1000410](https://nvd.nist.gov/vuln/detail/CVE-2017-1000410)
- NSA Cybersecurity Directorate. (2017). Mitigating SMB v1 Vulnerabilities. Retrieved from [https://media.defense.gov/2017/May/12/2001745760/-1/-1/0/SMB_V1_VULNERABILITIES_20170512.PDF](https://media.defense.gov/2017/May/12/2001745760/-1/-1/0/SMB_V1_VULNERABILITIES_20170512.PDF)
- OpenSSH. (2016). Security Advisory: CVE-2016-0777 and CVE-2016-0778. Retrieved from [https://www.openssh.com/txt/release-7.1p2](https://www.openssh.com/txt/release-7.1p2)
- OpenSSH. (2016). Security Advisory: ssh client information leak (CVE-2016-0777 and CVE-2016-0778). Retrieved from [https://www.openssh.com/txt/release-7.1p2](https://www.openssh.com/txt/release-7.1p2)
- OpenSSH. (2023). OpenSSH Release Notes. Retrieved from [https://www.openssh.com/releasenotes.html](https://www.openssh.com/releasenotes.html)
- SANS Institute. (2018). Security Awareness Planning Kit. Retrieved from [https://www.sans.org/security-awareness-training/resources/security-awareness-planning-kit](https://www.sans.org/security-awareness-training/resources/security-awareness-planning-kit)
- Scarfone, K., & Mell, P. (2007). Guide to Intrusion Detection and Prevention Systems (IDPS) (NIST SP 800-94). Retrieved from [https://doi.org/10.6028/NIST.SP.800-94](https://doi.org/10.6028/NIST.SP.800-94)
