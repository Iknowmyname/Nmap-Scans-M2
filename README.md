# Nmap-Scans-M2




<h2>

 </h2>

<h2>Description</h2>
This project is split into three repositories where this repository will provide the documentation of performing necessary Nmap scans to identify the vulnerabilities(CVEs) which are present in the targeted virtual machine. The Kali Linux distro is utilized to perform the network scans. Nmap is a powerful open source security auditing and network scanning tool which is pre-installed in the Kali Linux distro. The VMware Workstation Player is used to run the virtual machines.
<br />
<br />


<h2>Virtual Machines Used</h2>

- <b>Kali Linux</b> 
- <b>[Metasploitable2https://github.com/joshmadakor1/4chan-Image-Analysis-Middleware-C964)</b> (Vulnerable Virtual Machine)


<br />
<br />

<h2>Performing Port Scans</h2>








<h3>TCP SYN Scan</h3>

```bash
$ nmap -sS 192.168.74.133

```

<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

The TCP SYN Scan is the most widely used scan with Nmap. A TCP SYN packet will be sent to the vulnerable virtual machine's ports and if the port is open it will respond with a SYN-ACK packet back as an acknowledgement to say that the port is open. This scan does not establish a full TCP connection as Nmap will send a RST packet to erase the connection which makes it a quicka and stealthy scan.
Service and Version Detection Scan


<details>
    <summary><b>TCP_SYN output</b></summary>

    Nmap scan report for 192.168.74.133
     Host is up (0.0025s latency).
     Not shown: 977 closed tcp ports (reset)
     PORT     STATE SERVICE
     21/tcp   open  ftp
     22/tcp   open  ssh
     23/tcp   open  telnet
     25/tcp   open  smtp
     53/tcp   open  domain
     80/tcp   open  http
     111/tcp  open  rpcbind
     139/tcp  open  netbios-ssn
     445/tcp  open  microsoft-ds
     512/tcp  open  exec
     513/tcp  open  login
     514/tcp  open  shell
     1099/tcp open  rmiregistry
     1524/tcp open  ingreslock
     2049/tcp open  nfs
     2121/tcp open  ccproxy-ftp
     3306/tcp open  mysql
     5432/tcp open  postgresql
     5900/tcp open  vnc
     6000/tcp open  X11
     6667/tcp open  irc
     8009/tcp open  ajp13
     8180/tcp open  unknown

    ...
    ...
</details>
<br />
<br />



<h3>UDP Scan</h3>

```bash
$ nmap -sU 192.168.74.133

```

<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

The UDP scan will report the state of each scanned UDP port where the status can be either "Open", "Closed" or "Filtered". If the status of a port is displayed as filtered then it indicates the presence of a firewall which is filtering the packets sent.

<br />
<br />

<details>
    <summary><b>UDP_Scan output</b></summary>

    Nmap scan report for 192.168.74.133
     Host is up (0.0025s latency).
     Not shown: 977 closed tcp ports (reset)
     PORT     STATE SERVICE
     21/tcp   open  ftp
     22/tcp   open  ssh
     23/tcp   open  telnet
     25/tcp   open  smtp
     53/tcp   open  domain
     80/tcp   open  http
     111/tcp  open  rpcbind
     139/tcp  open  netbios-ssn
     445/tcp  open  microsoft-ds
     512/tcp  open  exec
     513/tcp  open  login
     514/tcp  open  shell
     1099/tcp open  rmiregistry
     1524/tcp open  ingreslock
     2049/tcp open  nfs
     2121/tcp open  ccproxy-ftp
     3306/tcp open  mysql
     5432/tcp open  postgresql
     5900/tcp open  vnc
     6000/tcp open  X11
     6667/tcp open  irc
     8009/tcp open  ajp13
     8180/tcp open  unknown

    ...
    ...
</details>
<br />
<br />


<h2>Service and Version Detection</h2>  

```bash
$ nmap -sV 192.168.74.133

```


<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

This scan is done to determine the services running on the open ports and also the version of those servies. By determining the version of the services ,the age of the software and potential vulnerabilities associated with that version can be identified.

<details>
    <summary><b>UDP_Scan output</b></summary>

    Nmap scan report for 192.168.74.133
     Host is up (0.0025s latency).
     Not shown: 977 closed tcp ports (reset)
     PORT     STATE SERVICE
     21/tcp   open  ftp
     22/tcp   open  ssh
     23/tcp   open  telnet
     25/tcp   open  smtp
     53/tcp   open  domain
     80/tcp   open  http
     111/tcp  open  rpcbind
     139/tcp  open  netbios-ssn
     445/tcp  open  microsoft-ds
     512/tcp  open  exec
     513/tcp  open  login
     514/tcp  open  shell
     1099/tcp open  rmiregistry
     1524/tcp open  ingreslock
     2049/tcp open  nfs
     2121/tcp open  ccproxy-ftp
     3306/tcp open  mysql
     5432/tcp open  postgresql
     5900/tcp open  vnc
     6000/tcp open  X11
     6667/tcp open  irc
     8009/tcp open  ajp13
     8180/tcp open  unknown

    ...
    ...
</details>
<br />
<br />

For instance, the output shows an open ftp port with the service version of vsftpd 2.3.4. 

<br />
<br />

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>

A quick search on this partcular service version will show that it is vulnerable to a backdoor command execution exploit. This vulnerability has a CVSS of 10.0 which is critical and could lead to severe consequences if not remediated immediately.

<br />
<br />

<h2>Scanning with NSE Scripts </h2>

<br />
<br />

<h4>SQL Injection Vulnerability Scan</h4>

```bash
$ nmap --script http-sql-injection -p 80,443 192.168.74.133

```

<br />

Output: 

```bash

PORT    STATE  SERVICE
80/tcp  open   http
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.74.133:80/mutillidae/index.php?page=credits.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=user-poll.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=site-footer-xss-discussion.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=documentation%2Fhow-to-access-Mutillidae-over-Virtual-Box-network.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=text-file-viewer.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=capture-data.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=php-errors.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=usage-instructions.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?do=toggle-hints%27%20OR%20sqlspider&page=home.php
|     http://192.168.74.133:80/mutillidae/index.php?page=source-viewer.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=show-log.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=notes.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=add-to-your-blog.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=documentation%2Fvulnerabilities.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=framing.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=credits.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=text-file-viewer.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=view-someones-blog.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=change-log.htm%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=installation.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=source-viewer.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=secret-administrative-pages.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?do=toggle-security%27%20OR%20sqlspider&page=home.php
|     http://192.168.74.133:80/mutillidae/index.php?page=add-to-your-blog.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=user-info.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/?page=login.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=register.php%27%20OR%20sqlspider
|     http://192.168.74.133:80/mutillidae/index.php?page=captured-data.php%27%20OR%20sqlspider
|   Possible sqli for forms:
|     Form at path: /mutillidae/index.php, form's action: index.php. Fields that might be vulnerable:
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|       choice
|_      initials
443/tcp closed https



```




<br />
<br />



The SQL injection script is used to scan for any SQLi vulnerabilities as from the previous TCP SYN scan it showed the MySQL port status as "OPEN". The output of the scan shows several SQL queries which are vulnerable to SQL injections. The index.php of the web address also contains a SQLi vulnerability which would allow attackers to exploit and gain access to vital parts of the machine server. 

Cross Site Request Forgery Scan

```bash
$ nmap -sV --script http-csrf 192.168.74.133

```

<br />
<br />

Output:

```bash

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.74.133
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.74.133:80/dvwa/
|     Form id: 
|     Form action: login.php
|     
|     Path: http://192.168.74.133:80/dvwa/login.php
|     Form id: 
|     Form action: login.php
|     
|     Path: http://192.168.74.133:80/twiki/TWikiDocumentation.html
|     Form id: 
|     Form action: http://TWiki.org/cgi-bin/passwd/TWiki/WebHome
|     
|     Path: http://192.168.74.133:80/twiki/TWikiDocumentation.html
|     Form id: 
|     Form action: http://TWiki.org/cgi-bin/passwd/Main/WebHome
|     
|     Path: http://192.168.74.133:80/twiki/TWikiDocumentation.html
|     Form id: 
|     Form action: http://TWiki.org/cgi-bin/edit/TWiki/
|     
|     Path: http://192.168.74.133:80/twiki/TWikiDocumentation.html
|     Form id: 
|     Form action: http://TWiki.org/cgi-bin/view/TWiki/TWikiSkins
|     
|     Path: http://192.168.74.133:80/twiki/TWikiDocumentation.html
|     Form id: 
|     Form action: http://TWiki.org/cgi-bin/manage/TWiki/ManagingWebs
|     
|     Path: http://192.168.74.133:80/mutillidae/index.php?page=html5-storage.php
|     Form id: idform
|     Form action: index.php?page=html5-storage.php
|     
|     Path: http://192.168.74.133:80/mutillidae/index.php?page=text-file-viewer.php
|     Form id: id-bad-cred-tr
|_    Form action: index.php?page=text-file-viewer.php
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      40791/tcp   mountd
|   100005  1,2,3      50629/udp   mountd
|   100021  1,3,4      38182/udp   nlockmgr
|   100021  1,3,4      57488/tcp   nlockmgr
|   100024  1          39511/udp   status
|_  100024  1          51977/tcp   status
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
514/tcp  open  tcpwrapped
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.74.133
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.74.133:8180/admin/
|     Form id: username
|     Form action: j_security_check;jsessionid=BD605641BE10D84A9A74E4A209C87955
|     
|     Path: http://192.168.74.133:8180/jsp-examples/cal/login.html
|     Form id: 
|     Form action: cal1.jsp
|     
|     Path: http://192.168.74.133:8180/jsp-examples/error/error.html
|     Form id: 
|_    Form action: err.jsp
|_http-server-header: Apache-Coyote/1.1
MAC Address: 00:0C:29:E5:7E:AE (VMware)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel



```

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>

Several CSRF vulnerabilities were detected by scanning with the http-csrf script. 


<h2>Scanning with Vulners Script</h2>

```bash
$ sudo nmap -sV -p0-65535 --script vulners 192.168.74.133

```

<br />
<br />

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>

The sV flag is used for this particular scan as the vulners script would require information regarding the version of the service to determine the CVE based on the corresponding version. This script leverages the vulnerability database from Vulners.com to detect the known vulnerabilities. The output shows the vulnerabilities detected and also provides a link to the CVE in order to assess and determine the severity of the CVE.




<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
