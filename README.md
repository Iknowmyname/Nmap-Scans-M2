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


<h2>Performing Port Scans</h2>

TCP SYN Scan

<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

The TCP SYN Scan is the most widely used scan with Nmap. A TCP SYN packet will be sent to the vulnerable virtual machine's ports and if the port is open it will respond with a SYN-ACK packet back as an acknowledgement to say that the port is open. This scan does not establish a full TCP connection as Nmap will send a RST packet to erase the connection which makes it a quicka and stealthy scan.
Service and Version Detection Scan

<h3>UDP Scan</h3>

<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

The UDP scan will report the state of each scanned UDP port where the status can be either "Open", "Closed" or "Filtered". If the status of a port is displayed as filtered then it indicates the presence of a firewall which is filtering the packets sent.

<br />
<br />
<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/Service%20%26%20Version%20Detection%20Scan.PNG" height="65%" width="65%" alt="sV"/>
</p>

This scan is done to determine the services running on the open ports and also the version of those servies. By determining the version of the services ,the age of the software and potential vulnerabilities associated with that version can be identified.

For instance, the output shows an open ftp port with the service version of vsftpd 2.3.4. 

<br />
<br />

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>

A quick search on this partcular service version will show that it is vulnerable to a backdoor command execution exploit.


<h2>Scanning with NSE Scripts </h2>

SQL Injection Vulnerability Scan

<br />
<br />

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>


Cross Site Request Forgery Scan

<br />
<br />

<p align="center">
<img src="https://github.com/Iknowmyname/Nmap-Scans-M2/blob/main/vsftpd%202.3.4%20CVE.PNG" height="65%" width="65%" alt="sV"/>
</p>

Several CSRF vulnerabilities were detected by scanning with the http-csrf script. 

# Output
CVEScannerV2 will show all CVEs related to every _service-version_ discovered.

<details>
    <summary><b>cvescannerv2.nse output</b></summary>

    PORT      STATE    SERVICE        VERSION
    22/tcp    open  ssh                  OpenSSH 7.1 (protocol 2.0)
    | cvescannerv2:
    |   product: openssh
    |   version: 7.1
    |   vupdate: *
    |   cves: 27
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2008-3844       	9.3  	-    	No        	No
    |   	CVE-2016-8858       	7.8  	7.5  	No        	No
    |   	CVE-2016-6515       	7.8  	7.5  	Yes       	No
    |   	CVE-2016-1908       	7.5  	9.8  	No        	No
    |   	CVE-2016-10009      	7.5  	7.3  	Yes       	No
    |   	CVE-2015-8325       	7.2  	7.8  	No        	No
    |   	CVE-2016-10012      	7.2  	7.8  	No        	No
    |   	CVE-2016-10010      	6.9  	7.0  	Yes       	No
    |   	CVE-2020-15778      	6.8  	7.8  	No        	No
    |_  	CVE-2019-6111       	5.8  	5.9  	Yes       	No
    ...
    ...
    3306/tcp  open  mysql                MySQL 5.5.20-log
    | cvescannerv2:
    |   product: mysql
    |   version: 5.5.20
    |   vupdate: *
    |   cves: 541
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2012-2750       	10.0 	-    	No        	No
    |   	CVE-2016-6662       	10.0 	9.8  	Yes       	No
    |   	CVE-2012-3163       	9.0  	-    	No        	No
    |   	CVE-2020-14878      	7.7  	8.0  	No        	No
    |   	CVE-2013-1492       	7.5  	-    	No        	No
    |   	CVE-2014-0001       	7.5  	-    	No        	No
    |   	CVE-2018-2562       	7.5  	7.1  	No        	No
    |   	CVE-2014-6500       	7.5  	-    	No        	No
    |   	CVE-2014-6491       	7.5  	-    	No        	No
    |_  	CVE-2012-0553       	7.5  	-    	No        	No
    ...
    ...
</details>

<p align="center">
<img src="https://i.imgur.com/UeNTKzL.png" height="65%" width="65%" alt="Image Analysis Dataflow"/>
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
