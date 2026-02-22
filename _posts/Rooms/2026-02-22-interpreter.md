---
title: "HackTheBox - interpreter"
permalink: /CTFs/HTB-interpreter/
date: 2026-02-22
categories: [HackTheBox]
tags: [HackTheBox, hashcat, ssti]
math: true
mermaid: true
image:
  path: /assets/img/CTFs/interpreter/logo.jpg
---
# Enumeration
nmap:
```bash
# Nmap 7.95 scan initiated Sun Feb 22 03:00:02 2026 as: /usr/lib/nmap/nmap --privileged -sC -sV -T4 -oN nmap.scan -vv --max-rate=10000 10.129.2.161
Nmap scan report for 10.129.2.161
Host is up, received echo-reply ttl 63 (0.084s latency).
Scanned at 2026-02-22 03:00:15 EET for 23s
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDVuD7K78VPFJrRRqOF1sCo4+cr9vm+x+VG1KLHzsgeEp3WWH2MIzd0yi/6eSzNDprifXbxlBCdvIR/et0G0lKI=
|   256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILAfcF/jsYtk8PnokOcYPpkfMdPrKcKdjel2yqgNEtU3
80/tcp  open  http     syn-ack ttl 63 Jetty
|_http-favicon: Unknown favicon MD5: 62BE2608829EE4917ACB671EF40D5688
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
443/tcp open  ssl/http syn-ack ttl 63 Jetty
|_http-title: Mirth Connect Administrator
|_ssl-date: TLS randomness does not represent time
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=mirth-connect
| Issuer: commonName=Mirth Connect Certificate Authority
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-19T12:50:05
| Not valid after:  2075-09-19T12:50:05
| MD5:   c251:9050:6882:4177:9dbc:c609:d325:dd54
| SHA-1: 3f2b:a7d8:5c81:9ecf:6e15:cb6a:fdc6:df02:8d9b:1179
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBfagAwIBAgIHAs1vd37U6TANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQD
| DCNNaXJ0aCBDb25uZWN0IENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkx
| MjUwMDVaGA8yMDc1MDkxOTEyNTAwNVowGDEWMBQGA1UEAwwNbWlydGgtY29ubmVj
| dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQp
| Kv42F90HswreFnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS
| 0aH1zwFbRMgO6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1
| rMNQ3IO6bGCrzozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtaz
| A0E3ZhEau3izPfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6
| p0qEOVKuyD1ckPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFTh
| xxUCAwEAAaOCBEMwggQ/MIIDBAYDVR0jBIIC+zCCAveAggLzMIIC7zCCAdegAwIB
| AgIBATANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDDCNNaXJ0aCBDb25uZWN0IENl
| cnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkxMjUwMDVaGA8yMDc1MDkxOTEy
| NTAwNVowLjEsMCoGA1UEAwwjTWlydGggQ29ubmVjdCBDZXJ0aWZpY2F0ZSBBdXRo
| b3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx5tdSOdln2NVP
| 2ENEc4CQmkkY/1O64NLvBnWr+Zu8AWyzFRBiGceqIXnWIpKWO5xxSObqsMiS2uSL
| Cj3/sprvfX+mojkmrZvpIYDqTQoayWjdI/MAn76VBZrZ4tGyPKibM6msLC/PNeSV
| JtGneR0GtT1yB3VGYfSEOJeIJLa2+PcHERSg2b+xBsrsWmGqwTIwl6NG3MPczmUD
| xomVpz7EpMZFka4slmRT81W9lIpgXl/jVAgLFoZUQ0q7ta1E0WdfeWkjMf0qEF5s
| LSm4UjDRkq/+xR8eZ7K1NBQL+1sUlmyhnfJnTGfik13g0xfpH1WNWsaHbRi6G70M
| zQs51qrlAgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQEL
| BQADggEBAFB4ZKwCdqnPqNWZhEi4XRoQY0/5bG/td+XP8a3lyudHQR6+JG8W2/DG
| MreycjnadJCaMn/KfBHULtUgbnpsCSJHQG/xmBS9jeT8NUu2R87xKypU7F0r08A2
| T9bduARSWYAJLF8g3UVGhC1o5fU+t0j3zUVEGKHdlC2GioZV9Jg5e7BIo/iqrLcX
| D6QOBOi509oMLYN40ijI6Q4KT0x01oDemPuirqo6CVg4fKnVjBGdXeWGdsH9DZsK
| O5zpxT2DcNXtFn7WdI+0FlUn+1Az+rFzuQlDZfyUAxiYXtL4ZaOGYKNNjKCECquv
| pdO2OKdCcl6oCIBJfRGDnh2Q7FIqK5wwggEzBgNVHQ4EggEqBIIBJjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQpKv42F90Hswre
| Fnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS0aH1zwFbRMgO
| 6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1rMNQ3IO6bGCr
| zozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtazA0E3ZhEau3iz
| PfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6p0qEOVKuyD1c
| kPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFThxxUCAwEAATAN
| BgkqhkiG9w0BAQsFAAOCAQEAKEQK8YNzAWgPB07ydf05p277ISLa2T+rWzQ2cCPD
| amgc1lCOHK0pEdNMI2z4J+iNdeXiPpuBVgvKId6I8ETLdA7foFRGklv6W6t4MjMY
| Pte8+PPkhKdwRVLzEj/tae427Ar8daDCvyFK/IhunhugyxfywHNj665V+bqPLBGw
| bgiV7+CQKpNOeADBeGbZpEGfQb+U+RkLCpjq7don698TdeBIPcIErzDgS8PDZ217
| Y0o4EU9gaX6U42cpvD/LLZ+e87GRxBlm9ivRA8QAE+yqo8GZtWvYveLkg+7qNcWB
| nWXyOijePyLYSHl4QHn3F4nTx2bO16KspRrDZsmiZGyEIw==
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 22 03:00:38 2026 -- 1 IP address (1 host up) scanned in 35.89 seconds
```

> Full writeup after machine retiring.