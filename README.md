<h1>Nmap</h1>

<h2>Description</h2>

<p>In the evolving field of cybersecurity, identifying new threats within a network is crucial to maintaining security. Network mapping tools like Nmap (Network Mapper) help in detecting vulnerabilities and anomalies that could expose a system to potential attacks.</p>

<p>For this project, I utilized a virtual machine provided by my school to access the necessary files and lab environment, allowing me to run Nmap scans on the network. These scans revealed critical security concerns, such as outdated OpenSSH versions, vulnerable SMB services, and an unsecured FTP server. By analyzing network topology, open ports, and service versions, I was able to recommend security improvements such as software updates, protocol hardening, and access control measures to mitigate risks.</p>

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

<h2>Recommended Solutions</h2>

<h3>Outdated OpenSSH Version on Multiple Hosts</h3>

<p>For the hosts at IP addresses 10.168.27.14, 10.168.27.20, and 10.168.27.132 running an outdated version of OpenSSH (5.5p1 Debian 6+squeeze5), it is crucial to upgrade OpenSSH to the latest stable release. Updating to a newer version will patch known vulnerabilities, such as CVE-2016-0777 and CVE-2016-0778, and provide enhanced security features (OpenSSH, 2023). Disabling the insecure roaming feature by adding UseRoaming no to the SSH client configuration file (ssh_config) addresses vulnerabilities exploited in these CVEs (OpenSSH, 2016).</p>

<p>Upgrading the operating system from Debian 6 ("Squeeze") to a currently supported version, such as Debian 11 "Bullseye," is also advised. Supported operating systems receive regular security updates and patches, reducing vulnerability exposure (Debian Project, 2021). Implementing a regular patch management process ensures that all software and operating systems are up to date, minimizing security risks associated with outdated software (NIST, 2019).</p>

<h3>Vulnerable SMB Services on Windows Server 2008 R2</h3>

<p>Applying all critical security updates is recommended for the server at IP address 10.168.27.10 running Microsoft Windows Server 2008 R2 with SMB services active on ports 139/TCP and 445/TCP, particularly those addressing CVE-2017-0144 (Microsoft, 2017). Installing these patches mitigates the risk of remote code execution exploits like EternalBlue. Disabling the SMBv1 protocol is essential, as it is outdated and contains multiple security vulnerabilities. This can be accomplished using PowerShell commands or the Windows Features interface (NSA, 2017).</p>

<p>Upgrading to a supported version of Windows Server, such as Windows Server 2019 or 2022, ensures the system receives regular security updates and improvements (Microsoft, 2021). Implementing network segmentation to isolate critical systems limits the potential spread of infections within the network (NIST, 2020).</p>

<h3>Unsecured FTP Service Using FileZilla Server</h3>

<p>For the host at IP address 10.168.27.15 running an unsecured FTP service with FileZilla Server, upgrading to the latest version of FileZilla Server is advisable, as it includes security patches and improvements (FileZilla Project, 2023). Transitioning to secure protocols such as FTPS (FTP over SSL/TLS) or SFTP (Secure File Transfer Protocol) encrypts data in transit, protecting credentials and file contents from interception (IETF, 2006). Strong authentication mechanisms, like key-based or multi-factor authentication, enhance security by requiring additional verification factors beyond just a password (NIST, 2017). Encrypting data at rest and in transit safeguards sensitive information from unauthorized access and interception (ISO/IEC, 2013).</p>

<h2>References</h2>

- Debian Project. (2021). Debian Releases. Retrieved from [https://www.debian.org/releases/](https://www.debian.org/releases/)
- FileZilla Project. (2023). FileZilla Server Downloads. Retrieved from [https://filezilla-project.org/download.php?type=server](https://filezilla-project.org/download.php?type=server)
- Microsoft. (2017). Microsoft Security Bulletin MS17-010 - Critical. Retrieved from [https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- Microsoft. (2017). Security Update for Microsoft Windows SMB Server (4013389). Retrieved from [https://docs.microsoft.com/security-updates/securitybulletins/2017/ms17-010](https://docs.microsoft.com/security-updates/securitybulletins/2017/ms17-010)
- Microsoft. (2021). Windows Server Release Information. Retrieved from [https://docs.microsoft.com/windows-server/get-started/windows-server-release-info](https://docs.microsoft.com/windows-server/get-started/windows-server-release-info)
- National Vulnerability Database. (2017). CVE-2017-16023. Retrieved from [https://nvd.nist.gov/vuln/detail/CVE-2017-16023](https://nvd.nist.gov/vuln/detail/CVE-2017-16023)
- NSA Cybersecurity Directorate. (2017). Mitigating SMB v1 Vulnerabilities. Retrieved from [https://media.defense.gov/2017/May/12/2001745760/-1/-1/0/SMB_V1_VULNERABILITIES_20170512.PDF](https://media.defense.gov/2017/May/12/2001745760/-1/-1/0/SMB_V1_VULNERABILITIES_20170512.PDF)
- OpenSSH. (2016). Security Advisory: CVE-2016-0777 and CVE-2016-0778. Retrieved from [https://www.openssh.com/txt/release-7.1p2](https://www.openssh.com/txt/release-7.1p2)
- OpenSSH. (2023). OpenSSH Release Notes. Retrieved from [https://www.openssh.com/releasenotes.html](https://www.openssh.com/releasenotes.html)
- OpenSSH. (2016). Security Advisory: ssh client information leak (CVE-2016-0777 and CVE-2016-0778). Retrieved from [https://www.openssh.com/txt/release-7.1p2](https://www.openssh.com/txt/release-7.1p2)
- OpenSSH. (2023). OpenSSH Release Notes. Retrieved from [https://www.openssh.com/releasenotes.html](https://www.openssh.com/releasenotes.html)
- SANS Institute. (2018). Security Awareness Planning Kit. Retrieved from [https://www.sans.org/security-awareness-training/resources/security-awareness-planning-kit](https://www.sans.org/security-awareness-training/resources/security-awareness-planning-kit)
- Scarfone, K., & Mell, P. (2007). Guide to Intrusion Detection and Prevention Systems (IDPS) (NIST SP 800-94). Retrieved from [https://doi.org/10.6028/NIST.SP.800-94](https://doi.org/10.6028/NIST.SP.800-94)
