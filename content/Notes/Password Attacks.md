---
title: "About Password attacks"
date: 2023-08-29
tags: [Password, Attacks, Password Attacks]
---

> Related Cheatsheet : [Password Attacks](Notes/CheatSheets/Password%20Attacks.md)
> Some great documentation about Windows credential manipulation here: https://www.thehacker.recipes/ad/movement/credentials
## Credential storage in linux & windows environment
### Password encryption format in `/etc/shadow`

|**ID**|**Cryptographic Hash Algorithm**|
|---|---|
|`$1$`|[MD5](https://en.wikipedia.org/wiki/MD5)|
|`$2a$`|[Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))|
|`$5$`|[SHA-256](https://en.wikipedia.org/wiki/SHA-2)|
|`$6$`|[SHA-512](https://en.wikipedia.org/wiki/SHA-2)|
|`$sha1$`|[SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)|
|`$y$`|[Yescrypt](https://github.com/openwall/yescrypt)|
|`$gy$`|[Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1)|
|`$7$`|[Scrypt](https://en.wikipedia.org/wiki/Scrypt)|

See also : [Linux user authentification recap](https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf)

### Windows Authentication

![](Windows%20Authentication%20Process.png)

## Password Attack Methods 

### Dictionary

Pre-gen list of known passwords, acquired from either public sources or bought to some companies / threat actors.
For each password in the list, we compute its hash and compare it against the one to crack.
This method is usually the one used in CTFs since all of the pentesting environment bundles rockyou, which is a very famous wordlist.
This method can be also quite time consuming depending on multiple factors such has the length of the wordlist or the time needed to compute a password hash.
### Brute Force

Extremely slow process used if there is no available alternatives.
This method involves computing the hash of each combination possible for a specified ruleset.
A ruleset defines what a password is made of. One example of a ruleset can be that a password is only made of alphanumeric characters with minimum 8 characters  - thus matching this regex : `[a-zA-Z0-9]{8,}` -
### Rainbow Tables

Involve the use of a pre-computed list of password hashes and their plaintext version.
Also this method is really fast compared to the last two method, it's impossible to find the plaintext version of the hash if it's not already included in the table. Thus removing the possibility of applying mutations to the passwords we want to crack. 

## Windows Local Password Attack Methods

### SAM

|Registry Hive|Description|
|---|---|
|`hklm\sam`|Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.|
|`hklm\system`|Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.|
|`hklm\security`|Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.|

We can dump the sam database manually using reg.exe:

```powershell
reg save hklm\sam C:\Windows\Tasks\sam.save

reg.exe save hklm\system C:\Windows\Tasks\system.save

reg.exe save hklm\security C:\Windows\Tasks\security.save
```

Then after exfiltrating the dumps, we can use `impacket-secretsdump.py` against the dumps: 

```bash
❯ secretsdump.py -sam sam.save -security security.save -system ssytem.save LOCAL
```

Or, we can use `crackmapexec` to directly retrieve, decrypt and dump the SAM hash using:

```bash
❯ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

https://wiki.porchetta.industries/smb-protocol/obtaining-credentials/dump-sam

> [!NOTE] Hashes cannot be dumped without the `system bootkey` since it is used to encrypt & decrypt the `SAM` database

To crack those NT Hashes, we can put them into a file and run `hashcat` against it:

> [!INFO] `NT Hashes` hash type in `hashcat` is `1000`

```bash
❯ hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```
### LSASS

> **Local Security Authority Subsystem Service (LSASS)** is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens. It also writes to the Windows Security Log.

Attacking LSASS relies primarily on dumping the `lsass.exe` process in order to extract credentials that are stored in the memory of the program.
A dump of the process can be directly created from the Task Manager, by using various tools or directly from the command-line on the remote host.

> [!EXAMPLE]- Some great documentation about attacking LSASS process
> - https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass
> - https://en.hackndo.com/remote-lsass-dump-passwords/

### NTD.dit

> https://attack.mitre.org/techniques/T1003/003/


Ntds.dit is the main AD database file. NTDS stands for NT Directory Services. The DIT stands for Directory Information Tree. The Ntds.dit file on a particular domain controller contains all naming contexts hosted by that domain controller, including the Configuration and Schema naming contexts. A Global Catalog server stores the partial naming context replicas in the Ntds.dit right along with the full Domain naming context for its domain.
One a Windows system is joined to a domain, it will no longer default to referencing the SAM db to validate requests.

To make a copy of the `NTDS.dit` file, we need to be in the `Administrator group`, `Domain Admins group` or equivalent.

Multiple techniques to exfiltrate the NTDS database can be found on The Hacker Recipes here: https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds or we can directly cme to extract the contents of the NTDS.dit file. This method utilize VSS as described in the previous THR link to quickly capture and dump the contents of the db.

> [!TIP]
> A new tool called `ntdissector` made by the synactiv team was released in September, this tool is a swiss army knife for manipulating the `ndts.dit`.
> You can find more about this tool on [their blog](https://www.synacktiv.com/en/publications/introducing-ntdissector-a-swiss-army-knife-for-your-ntdsdit-files) and on the [tools repo](https://github.com/synacktiv/ntdissector/).
