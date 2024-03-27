---
title: "Metasploit bits"
date: 2023-08-25
tags: [Metasploit, MetasploitFramework]
---
> Metasploit documentation: https://docs.metasploit.com
> Related CheatSheet: [Metasploit](Notes/CheatSheets/Metasploit.md)
## Metasploit architecture

### Modules

Ruby script files, one for each exploit

Stored usally in:
- `/usr/share/metasploit-framework/modules`
- `$HOME/.msf4/modules`

**Modules sources**:
- https://www.exploit-db.com
- https://www.rapid7.com/db/
- GitHub dork : `MetasploitModule path:*.rb OR MetasploitModule path:*.rc*`

### Plugins

Adds extra functionalities to metasploit

Stored usually in:
- `/usr/share/metasploit-framework/plugins`
- `$HOME/.msf4/plugins`

#### Example from [docs.metasploit.com](https://docs.metasploit.com/docs/using-metasploit/intermediate/how-to-use-plugins.html#capture-plugin)

**Capture Plugin**

```bash
msf6 > load capture
[*] Successfully loaded plugin: Credential Capture
msf6 > captureg start --ip 192.168.159.128
Logging results to /home/smcintyre/.msf4/logs/captures/capture_local_20220325104416_589275.txt
Hash results stored in /home/smcintyre/.msf4/loot/captures/capture_local_20220325104416_612808
[+] Authentication Capture: DRDA (DB2, Informix, Derby) started
[+] Authentication Capture: FTP started
[+] HTTP Client MS Credential Catcher started
[+] HTTP Client MS Credential Catcher started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: MSSQL started
[+] Authentication Capture: MySQL started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: PostgreSQL started
[+] Printjob Capture Service started
[+] Authentication Capture: SIP started
[+] Authentication Capture: SMB started
[+] Authentication Capture: SMTP started
[+] Authentication Capture: Telnet started
[+] Authentication Capture: VNC started
[+] Authentication Capture: FTP started
[+] Authentication Capture: IMAP started
[+] Authentication Capture: POP3 started
[+] Authentication Capture: SMTP started
[+] NetBIOS Name Service Spoofer started
[+] LLMNR Spoofer started
[+] mDNS Spoofer started
[+] Started capture jobs
msf6 >
```

### Tools

Metasploit tools are scripts usually developed by third parties that aids during pentest, CTFs and such

The source are stored usually in:
- `/usr/share/metasploit-framework/tools`


> [!INFO] Scripts 
> Metasploit scripts are now deprecated and modules should be used instead

### Metasploit architecture in Exegol

Metasploit is not installed in the same way as the ParrotOS is inside [Exegol](https://github.com/ThePorgs/Exegol)

- [Modules](###Modules) and [Plugins](###Plugins) are stored inside `/root/.msf4/`
- Binaries - such as `msfconsole`, `msfdb` or `msfvenom` - are stored in `/opt/metasploit-framework/bin/`

## Metasploit Payloads

### Singles

Contains exploit + entire shellcode => Self-contained
More stable but bigger than the others
### Stagers

Works with [Stages](###Stages) to typically set up a network connection beteen the attacker and victim
Designed to be small and reliable
Metasploit uses the best stager and less-preferred as fallbacks
### Stages

Component downloaded by the [Stagers](###Stagers) w/o size limits such as meterpreter (see [Meterpreter](##Meterpreter) for more info about this attack payload) and others

### Common Payload Types

**Windows**

|**Payload**|**Description**|
|---|---|
|`generic/custom`|Generic listener, multi-use|
|`generic/shell_bind_tcp`|Generic listener, multi-use, normal shell, TCP connection binding|
|`generic/shell_reverse_tcp`|Generic listener, multi-use, normal shell, reverse TCP connection|
|`windows/x64/exec`|Executes an arbitrary command (Windows x64)|
|`windows/x64/loadlibrary`|Loads an arbitrary x64 library path|
|`windows/x64/messagebox`|Spawns a dialog via MessageBox using a customizable title, text & icon|
|`windows/x64/shell_reverse_tcp`|Normal shell, single payload, reverse TCP connection|
|`windows/x64/shell/reverse_tcp`|Normal shell, stager + stage, reverse TCP connection|
|`windows/x64/shell/bind_ipv6_tcp`|Normal shell, stager + stage, IPv6 Bind TCP stager|
|`windows/x64/meterpreter/$`|Meterpreter payload + varieties above|
|`windows/x64/powershell/$`|Interactive PowerShell sessions + varieties above|
|`windows/x64/vncinject/$`|VNC Server (Reflective Injection) + varieties above|

**Automatic payload selection**

> [!TIP] Metasploit sets automatically a payload for an exploit. This is the preference list that Metasploit uses to select a payload if there isn't one set for the exploit : 
> 
>- windows/meterpreter/reverse_tcp
>- java/meterpreter/reverse_tcp
>- php/meterpreter/reverse_tcp
>- php/meterpreter_reverse_tcp
>- ruby/shell_reverse_tcp
>- cmd/unix/interact
>- cmd/unix/reverse
>- cmd/unix/reverse_perl
>- cmd/unix/reverse_netcat_gaping
>- windows/meterpreter/reverse_nonx_tcp
>- windows/meterpreter/reverse_ord_tcp
>- windows/shell/reverse_tcp
>- generic/shell_reverse_tcp

## Metasploit database

> `msfconsole` has built-in support for PostgreSQL db
### Setup

```bash {title="Init metasploit database"}
❯ sudo msfdb init
```

```bash {title="Connect to the MSF DB"}
❯ sudo msfdb run
```

### Reinitiate the DB

```bash
❯ msfdb reinit
❯ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4
# Or if your on exegol
❯ cp /opt/metasploit-framework/config/database.yml /root/.msf4
❯ sudo servcie postgresql restart
❯ msfconsole -q
```

### Workspaces

Having the msfdb set up allows the creatoion of Workspaces.
Workspaces are pretty useful when dealing with large amount of hosts and data linked to them.

```bash {title="Display available workspaces"}
msf6> workspace

* default
```

We can add or delete a workspace with `workspace -a` and `workspace -d`
#### Importing nmap Scan Results

> [!INFO]- `XML` content is prefered over plaintext
> - Generate `xml` scan reports with nmap using `nmap -oX`
> - Generate all report types with `nmap -oA`

```bash
msf6 > db_import host_scan.xml

[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.10.9'
[*] Importing host 192.168.10.21
[*] Successfully imported ~/host_scan.xml


msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
192.168.10.21             Unknown                    device         


msf6 > services

Services
========

host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
192.168.10.21  135    tcp    msrpc         open   Microsoft Windows RPC
<SNIP>
```
#### Using nmap inside msfconsole

```bash
msf6 > db_nmap -sC -sV -Pn --min-rate 10000 -T 5 192.168.10.21
```

#### Export msfdb contents

```bash
msf6 > db_export -f xml session_backup.xml
```

#### Display stored creds

During interactions with target hosts, gathered creds are stored inside the db.
We can list, add manually, delete and match credentials with ports

```bash
msf6 > creds -h

With no sub-command, list credentials. If an address range is
given, show only credentials with logins on hosts within that
range.

Usage - Listing credentials:
  creds [filter options] [address range]

Usage - Adding credentials:
  creds add uses the following named parameters.
    user      :  Public, usually a username
    password  :  Private, private_type Password.
    ntlm      :  Private, private_type NTLM Hash.
    Postgres  :  Private, private_type Postgres MD5
    ssh-key   :  Private, private_type SSH key, must be a file path.
    hash      :  Private, private_type Nonreplayable hash
    jtr       :  Private, private_type John the Ripper hash type.
    realm     :  Realm, 
    realm-type:  Realm, realm_type (domain db2db sid pgdb rsync wildcard), defaults to domain.

Examples: Adding
   # Add a user, password and realm
   creds add user:admin password:notpassword realm:workgroup
   # Add a user and password
   creds add user:guest password:'guest password'
   # Add a password
   creds add password:'password without username'
   # Add a user with an NTLMHash
   creds add user:admin ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A
   # Add a NTLMHash
   creds add ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A
   # Add a Postgres MD5
   creds add user:postgres postgres:md5be86a79bf2043622d58d5453c47d4860
   # Add a user with an SSH key
   creds add user:sshadmin ssh-key:/path/to/id_rsa
   # Add a user and a NonReplayableHash
   creds add user:other hash:d19c32489b870735b5f587d76b934283 jtr:md5
   # Add a NonReplayableHash
   creds add hash:d19c32489b870735b5f587d76b934283

General options
  -h,--help             Show this help information
  -o <file>             Send output to a file in csv/jtr (john the ripper) format.
                        If the file name ends in '.jtr', that format will be used.
                        If file name ends in '.hcat', the hashcat format will be used.
                        CSV by default.
  -d,--delete           Delete one or more credentials

Filter options for listing
  -P,--password <text>  List passwords that match this text
  -p,--port <portspec>  List creds with logins on services matching this port spec
  -s <svc names>        List creds matching comma-separated service names
  -u,--user <text>      List users that match this text
  -t,--type <type>      List creds that match the following types: password,ntlm,hash
  -O,--origins <IP>     List creds that match these origins
  -R,--rhosts           Set RHOSTS from the results of the search
  -v,--verbose          Don't truncate long password hashes

Examples, John the Ripper hash types:
  Operating Systems (starts with)
    Blowfish ($2a$)   : bf
    BSDi     (_)      : bsdi
    DES               : des,crypt
    MD5      ($1$)    : md5
    SHA256   ($5$)    : sha256,crypt
    SHA512   ($6$)    : sha512,crypt
  Databases
    MSSQL             : mssql
    MSSQL 2005        : mssql05
    MSSQL 2012/2014   : mssql12
    MySQL < 4.1       : mysql
    MySQL >= 4.1      : mysql-sha1
    Oracle            : des,oracle
    Oracle 11         : raw-sha1,oracle11
    Oracle 11 (H type): dynamic_1506
    Oracle 12c        : oracle12c
    Postgres          : postgres,raw-md5

Examples, listing:
  creds               # Default, returns all credentials
  creds 1.2.3.4/24    # Return credentials with logins in this range
  creds -O 1.2.3.4/24 # Return credentials with origins in this range
  creds -p 22-25,445  # nmap port specification
  creds -s ssh,smb    # All creds associated with a login on SSH or SMB services
  creds -t NTLM       # All NTLM creds
  creds -j md5        # All John the Ripper hash type MD5 creds

Example, deleting:
  # Delete all SMB credentials
  creds -d -s smb
```
