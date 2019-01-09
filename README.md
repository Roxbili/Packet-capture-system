# 数据包捕获系统（数据包捕获+ARP欺骗）
## 环境
*python 2.x*  
*使用的库*：scapy库、tkinter库、scapy-http、scapy-ssl_tls  
**安装**：  
```
pip install scapy
pip install scapy-http
pip install pip install scapy-ssl_tls
```
**调用**：  
```
from Tkinter import *
from scapy.all import *
from scapy.layers.ssl_tls import *
from scapy.layers import http
```
## 实现
实现分为前端和后端两部分，前端部分在文件GUI_11中，后端部分在文件ARP_code中，后端实现数据包捕获以及ARP欺骗。  
## 运行
运行GUI_11文件即可。