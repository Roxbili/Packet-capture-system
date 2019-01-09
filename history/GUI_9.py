# -*- coding: UTF-8 -*-

import tkMessageBox
from Tkinter import *
from scapy.all import *
from ARP_code import(
    get_bag,
    ARP_creatpac,
    ARP_sendpac
)


### 子函数

# 开始抓包
def getTrue():
    global getbag_flag
    global typenum
    global bagcon
    global bagcontent

    print('Packet capture begin')
    getbag_flag = True
    bagnum = int(en.get())    # 获取需要抓包的个数

    # 清空上一次抓包信息
    typenum = []
    bagcon = []

    # 抓包设置
    f_mode = 0
    if var0.get() == True and var1.get() == False:
        f_mode = 1
    if var0.get() == False and var1.get() == True:
        f_mode = 2
    if var0.get() == True and var1.get() == True:
        f_mode = 3

    bagcontent = get_bag(bagnum, f_mode) # 子函数名get_bag
    if not len(bagcontent):
        tkMessageBox.showinfo("超时！", "没有抓到数据包")

    # 获取抓包每个类型的个数
    typenum.append( len(bagcontent[TCP]) )
    typenum.append( len(bagcontent[UDP]) )
    typenum.append( len(bagcontent[ICMP]) )
    typenum.append( bagnum - len(bagcontent[TCP]) - len(bagcontent[UDP]) - len(bagcontent[ICMP]) )
    # 获取数据包信息
    for i in range(bagnum):
        bagcon.append( bagcontent[i].summary() )

    # 删除现有信息，更新信息
    listb.delete(0, END)    # listb是显示不同种类包的个数
    for item in typenum:
        listb.insert(END, item)

    conb.delete(0, END)     # conb是捕捉到的包的简略信息
    for item in bagcon:
        conb.insert(END, item)

def ARPTrue():
    global pkt
    global ARP_content
    global endflag
    
    print('begin ARP')

    # 获得文本框中的数据
    interfacetype = en1.get()
    target_IP = en2.get()
    gateway_IP = en3.get()
    pattern_SELECT = en4.get()

    # 构造请求包
    if target_IP == 'None':
        target_IP = None
    pkt = ARP_creatpac(gateway_IP, target_IP, interfacetype, pattern_SELECT)

    # 检查是否结束
    for i in range(int(en5.get())):
        ARP_sendpac(pkt, interfacetype)

    msg.delete(0, END)
    msg.insert(END, '发送数据包结束')

def click_listbox(Event):
    w = Event.widget
    index = Event.widget.nearest(Event.y)   # 点击到第几条目
    print(index)
    info = bagcontent[index]
    a_window(info)

# 弹窗
def a_window(info):
    top2 = Toplevel()
    top2.title('详细信息')

    if 'Ether' in info:
        Label(top2, text = '###[ Ethernet ]###').grid(stick=W)
        Label(top2, text = 'dst: ' + str(info[Ether].dst)).grid(stick=W)
        Label(top2, text = 'src: ' + str(info[Ether].src)).grid(stick=W)
        Label(top2, text = 'type: ' + str(info[Ether].type)).grid(stick=W)
        Label(top2, text = '').grid()  # 空行

    if 'IP' in info:
        Label(top2, text = '###[ IP ]###').grid(stick=W)
        Label(top2, text = 'version: ' + str(info[IP].version)).grid(stick=W)
        Label(top2, text = 'ihl: ' + str(info[IP].ihl)).grid(stick=W)
        Label(top2, text = 'tos: ' + str(info[IP].tos)).grid(stick=W)
        Label(top2, text = 'len: ' + str(info[IP].len)).grid(stick=W)
        Label(top2, text = 'id: ' + str(info[IP].id)).grid(stick=W)
        Label(top2, text = 'flags: ' + str(info[IP].flags)).grid(stick=W)
        Label(top2, text = 'frag: ' + str(info[IP].frag)).grid(stick=W)
        Label(top2, text = 'ttl: ' + str(info[IP].ttl)).grid(stick=W)
        Label(top2, text = 'proto: ' + str(info[IP].proto)).grid(stick=W)
        Label(top2, text = 'chksum: ' + str(info[IP].chksum)).grid(stick=W)
        Label(top2, text = 'src: ' + str(info[IP].src)).grid(stick=W)
        Label(top2, text = 'dst: ' + str(info[IP].dst)).grid(stick=W)
        Label(top2, text = '\\options\\')
        Label(top2, text = '').grid()  # 空行

    if 'TCP' in info:
        Label(top2, text = '###[ TCP ]###').grid(stick=W)
        Label(top2, text = 'sport: ' + str(info[TCP].sport)).grid(stick=W)
        Label(top2, text = 'dport: ' + str(info[TCP].dport)).grid(stick=W)
        Label(top2, text = 'seq: ' + str(info[TCP].seq)).grid(stick=W)
        Label(top2, text = 'ack: ' + str(info[TCP].ack)).grid(stick=W)
        Label(top2, text = 'dataofs: ' + str(info[TCP].dataofs)).grid(stick=W)
        Label(top2, text = 'reserved: ' + str(info[TCP].reserved)).grid(stick=W)
        Label(top2, text = 'flags: ' + str(info[TCP].flags)).grid(stick=W)
        Label(top2, text = 'window: ' + str(info[TCP].window)).grid(stick=W)
        Label(top2, text = 'chksum: ' + str(info[TCP].chksum)).grid(stick=W)
        Label(top2, text = 'urgptr: ' + str(info[TCP].urgptr)).grid(stick=W)
        Label(top2, text = 'options: ' + str(info[TCP].options)).grid(stick=W)
        Label(top2, text = '').grid()  # 空行

        if 'HTTP' in info:
            Label(top2, text = '###[ HTTP ]###').grid(stick=W)
            if 'HTTP Request' in info:
                Label(top2, text = '###[ HTTP Request ]###').grid(stick=W)
                Label(top2, text = 'Method: ' + str(info[TCP].payload.Method)).grid(stick=W)
                Label(top2, text = 'Path: ' + str(info[TCP].payload.Path)).grid(stick=W)
                Label(top2, text = 'Http-Version: ' + str(info[TCP].payload.Http-Version)).grid(stick=W)
                Label(top2, text = 'Host: ' + str(info[TCP].payload.Host)).grid(stick=W)
                Label(top2, text = 'User-Agent: ' + str(info[TCP].payload.User-Agent)).grid(stick=W)
                Label(top2, text = 'Accept: ' + str(info[TCP].payload.Accept)).grid(stick=W)
                Label(top2, text = 'Accept-Language: ' + str(info[TCP].payload.Accept-Language)).grid(stick=W)
                Label(top2, text = 'Accept-Charset: ' + str(info[TCP].payload.Accept-Charset)).grid(stick=W)
                Label(top2, text = 'Referer: ' + str(info[TCP].payload.Referer)).grid(stick=W)
                Label(top2, text = 'Authorization: ' + str(info[TCP].payload.Authorization)).grid(stick=W)
                Label(top2, text = 'Expect: ' + str(info[TCP].payload.Expect)).grid(stick=W)
                Label(top2, text = 'From: ' + str(info[TCP].payload.From)).grid(stick=W)
                Label(top2, text = 'If-Match: ' + str(info[TCP].payload.If-Match)).grid(stick=W)
                Label(top2, text = 'If-Modified-Since: ' + str(info[TCP].payload.If-Modified-Since)).grid(stick=W)
                Label(top2, text = 'If-None-Match: ' + str(info[TCP].payload.If-None-Match)).grid(stick=W)
                Label(top2, text = 'If-Range: ' + str(info[TCP].payload.If-Range)).grid(stick=W)
                Label(top2, text = 'If-Unmodified-Since: ' + str(info[TCP].payload.If-Unmodified-Since)).grid(stick=W)
                Label(top2, text = 'Max-Forwards: ' + str(info[TCP].payload.Max-Forwards)).grid(stick=W)
                Label(top2, text = 'Proxy-Authorization: ' + str(info[TCP].payload.Proxy-Authorization)).grid(stick=W)
                Label(top2, text = 'Range: ' + str(info[TCP].payload.Range)).grid(stick=W)
                Label(top2, text = 'TE: ' + str(info[TCP].payload.TE)).grid(stick=W)
                Label(top2, text = 'Cache-Control: ' + str(info[TCP].payload.Cache-Control)).grid(stick=W)
                Label(top2, text = 'Connection: ' + str(info[TCP].payload.Connection)).grid(stick=W)
                Label(top2, text = 'Date: ' + str(info[TCP].payload.Date)).grid(stick=W)
                Label(top2, text = 'Pragma: ' + str(info[TCP].payload.Pragma)).grid(stick=W)
                Label(top2, text = 'Trailer: ' + str(info[TCP].payload.Trailer)).grid(stick=W)
                Label(top2, text = 'Transfer-Encoding: ' + str(info[TCP].payload.Transfer-Encoding)).grid(stick=W)
                Label(top2, text = 'Upgrade: ' + str(info[TCP].payload.Upgrade)).grid(stick=W)
                Label(top2, text = 'Via: ' + str(info[TCP].payload.Via)).grid(stick=W)
                Label(top2, text = 'Warning: ' + str(info[TCP].payload.Warning)).grid(stick=W)
                Label(top2, text = 'Keep-Alive: ' + str(info[TCP].payload.Keep-Alive)).grid(stick=W)
                Label(top2, text = 'Allow: ' + str(info[TCP].payload.Allow)).grid(stick=W)
                Label(top2, text = 'Content-Encoding: ' + str(info[TCP].payload.Content-Encoding)).grid(stick=W)Expires
                Label(top2, text = 'Content-Language: ' + str(info[TCP].payload.Content-Language)).grid(stick=W)
                Label(top2, text = 'Content-Length: ' + str(info[TCP].payload.Content-Length)).grid(stick=W)
                Label(top2, text = 'Content-Location: ' + str(info[TCP].payload.Content-Location)).grid(stick=W)
                Label(top2, text = 'Content-MD5: ' + str(info[TCP].payload.Content-MD5)).grid(stick=W)
                Label(top2, text = 'Content-Range: ' + str(info[TCP].payload.Content-Range)).grid(stick=W)
                Label(top2, text = 'Content-Type: ' + str(info[TCP].payload.Content-Type)).grid(stick=W)
                Label(top2, text = 'Expires: ' + str(info[TCP].payload.Expires)).grid(stick=W)
                Label(top2, text = 'Last-Modified: ' + str(info[TCP].payload.Last-Modified)).grid(stick=W)
                Label(top2, text = 'Cookie: ' + str(info[TCP].payload.Cookie)).grid(stick=W)
                Label(top2, text = 'Additional-Headers: ' + str(info[TCP].payload.Additional-Headers)).grid(stick=W)

            elif 'HTTP Response' in info:
                Label(top2, text = '###[ HTTP Response ]###').grid(stick=W)
                Label(top2, text = 'Status-Line: ' + str(info[TCP].payload.Status-Line)).grid(stick=W)
                Label(top2, text = 'Accept-Ranges: ' + str(info[TCP].payload.Accept-Ranges)).grid(stick=W)
                Label(top2, text = 'Age: ' + str(info[TCP].payload.Age)).grid(stick=W)
                Label(top2, text = 'E-Tag: ' + str(info[TCP].payload.E-Tag)).grid(stick=W)
                Label(top2, text = 'Location: ' + str(info[TCP].payload.Location)).grid(stick=W)
                Label(top2, text = 'Proxy-Authenticate: ' + str(info[TCP].payload.Proxy-Authenticate)).grid(stick=W)
                Label(top2, text = 'Retry-After: ' + str(info[TCP].payload.Retry-After)).grid(stick=W)
                Label(top2, text = 'Server: ' + str(info[TCP].payload.Server)).grid(stick=W)
                Label(top2, text = 'Vary: ' + str(info[TCP].payload.Vary)).grid(stick=W)
                Label(top2, text = 'WWW-Authenticate: ' + str(info[TCP].payload.WWW-Authenticate)).grid(stick=W)
                Label(top2, text = 'Cache-Control: ' + str(info[TCP].payload.Cache-Control)).grid(stick=W)
                Label(top2, text = 'Connection: ' + str(info[TCP].payload.Connection)).grid(stick=W)
                Label(top2, text = 'Date: ' + str(info[TCP].payload.Date)).grid(stick=W)
                Label(top2, text = 'Pragma: ' + str(info[TCP].payload.Pragma)).grid(stick=W)
                Label(top2, text = 'Trailer: ' + str(info[TCP].payload.Trailer)).grid(stick=W)
                Label(top2, text = 'Transfer-Encoding: ' + str(info[TCP].payload.Transfer-Encoding)).grid(stick=W)
                Label(top2, text = 'Upgrade: ' + str(info[TCP].payload.Upgrade)).grid(stick=W)
                Label(top2, text = 'Via: ' + str(info[TCP].payload.Via)).grid(stick=W)
                Label(top2, text = 'Warning: ' + str(info[TCP].payload.Warning)).grid(stick=W)
                Label(top2, text = 'Keep-Alive: ' + str(info[TCP].payload.Keep-Alive)).grid(stick=W)
                Label(top2, text = 'Allow: ' + str(info[TCP].payload.Allow)).grid(stick=W)
                Label(top2, text = 'Content-Encoding: ' + str(info[TCP].payload.Content-Encoding)).grid(stick=W)
                Label(top2, text = 'Content-Language: ' + str(info[TCP].payload.Content-Language)).grid(stick=W)
                Label(top2, text = 'Content-Length: ' + str(info[TCP].payload.Content-Length)).grid(stick=W)
                Label(top2, text = 'Content-Location: ' + str(info[TCP].payload.Content-Location)).grid(stick=W)
                Label(top2, text = 'Content-MD5: ' + str(info[TCP].payload.Content-MD5)).grid(stick=W)
                Label(top2, text = 'Content-Range: ' + str(info[TCP].payload.Content-Range)).grid(stick=W)
                Label(top2, text = 'Content-Type: ' + str(info[TCP].payload.Content-Type)).grid(stick=W)
                Label(top2, text = 'Expires: ' + str(info[TCP].payload.Expires)).grid(stick=W)
                Label(top2, text = 'Last-Modified: ' + str(info[TCP].payload.Last-Modified)).grid(stick=W)
                Label(top2, text = 'Additional-Headers: ' + str(info[TCP].payload.Additional-Headers)).grid(stick=W)
                
    if 'UDP' in info:
        Label(top2, text = '###[ UDP ]###').grid(stick=W)
        Label(top2, text = 'sport: ' + str(info[UDP].sport)).grid(stick=W)
        Label(top2, text = 'dport: ' + str(info[UDP].dport)).grid(stick=W)
        Label(top2, text = 'len: ' + str(info[UDP].len)).grid(stick=W)
        Label(top2, text = 'chksum: ' + str(info[UDP].chksum)).grid(stick=W)
        Label(top2, text = '').grid()  # 空行

    if 'DNS' in info:
        Label(top2, text = '###[ DNS ]###').grid(stick=W)
        Label(top2, text = 'id: ' + str(info[DNS].id)).grid(stick=W)
        Label(top2, text = 'qr: ' + str(info[DNS].qr)).grid(stick=W)
        Label(top2, text = 'opcode: ' + str(info[DNS].opcode)).grid(stick=W)
        Label(top2, text = 'aa: ' + str(info[DNS].aa)).grid(stick=W)
        Label(top2, text = 'tc: ' + str(info[DNS].tc)).grid(stick=W)
        Label(top2, text = 'rd: ' + str(info[DNS].rd)).grid(stick=W)
        Label(top2, text = 'ra: ' + str(info[DNS].ra)).grid(stick=W)
        Label(top2, text = 'z: ' + str(info[DNS].z)).grid(stick=W)
        Label(top2, text = 'ad: ' + str(info[DNS].ad)).grid(stick=W)
        Label(top2, text = 'cd: ' + str(info[DNS].cd)).grid(stick=W)
        Label(top2, text = 'rcode: ' + str(info[DNS].rcode)).grid(stick=W)
        Label(top2, text = 'qdcount: ' + str(info[DNS].qdcount)).grid(stick=W)
        Label(top2, text = 'ancount: ' + str(info[DNS].ancount)).grid(stick=W)
        Label(top2, text = '\\qd\\').grid(stick=W)
        Label(top2, text = ' |###[ DNS Question Record ]###').grid(stick=W)
        Label(top2, text = ' |  qname: ' + str(info[DNS].qd.qname)).grid(stick=W)
        Label(top2, text = ' |  qtype: ' + str(info[DNS].qd.qtype)).grid(stick=W)
        Label(top2, text = ' |  qclass: ' + str(info[DNS].qd.qclass)).grid(stick=W)
        Label(top2, text = 'an: ' + str(info[DNS].an)).grid(stick=W)
        Label(top2, text = 'ns: ' + str(info[DNS].ns)).grid(stick=W)
        Label(top2, text = 'ar: ' + str(info[DNS].ar)).grid(stick=W)
        Label(top2, text = '').grid()  # 空行

    if 'Raw' in info:
        Label(top2, text = '###[ Raw ]###').grid(stick=W)
        Label(top2, text = 'load: ' + str(info[Raw].load)).grid(stick=W)
        Label(top2, text = '').grid()  # 空行






if __name__ == "__main__":
    # 参数，为全局变量
    typenum = []
    typename = ['TCP', 'UDP', 'ICMP', 'Other']
    bagcon = []
    pkt = None
    bagcontent = None
    ARP_content = ''
    getbag_flag = False

    top = Tk()
    # 进入消息循环
    
    # 设置界面大小、名称、图标、垂直滚动条
    top.geometry('670x685')
    top.minsize(670,685)
    top.title("packet capture")
    # top.iconbitmap('e:\python.ico')
    





    # 空行调整格式
    inb = Label(top, text = "")
    inb.grid(row = 0, column = 0, sticky = E)

    # 输入抓包数量
    inb = Label(top, text = "请输入抓包数量：")
    inb.grid(row = 1, column = 0, sticky = E)
    
    en = Entry(top)
    en.grid(row = 1, column = 1, sticky = W)
    en.insert(0, '100')

    # 空行调整格式
    inb = Label(top, height=2, text = "(TCP/UDP复选框可捕获指定协议的数据包（可都选），若都不选则捕获所有可捕获数据包)")
    inb.grid(row = 3, columnspan = 6, sticky = E)

    # 滤波复选框的设置
    var0 = BooleanVar()
    var1 = BooleanVar()
    tcp_b = Checkbutton(top, text = "TCP", variable = var0)
    tcp_b.grid(row = 4, column = 0, sticky = E)
    udp_b = Checkbutton(top, text = "UDP", variable = var1)
    udp_b.grid(row = 4, column = 1, sticky = W)


    # 空行调整格式
    inb = Label(top, text = "")
    inb.grid(row = 10, column = 0, sticky = E)

    # 开始抓包按钮,command触发事件
    begin = Button(top, text = "开始捕获数据包", activebackground = 'gray', command = getTrue)
    begin.grid(row = 18, columnspan = 2)

    # 空行调整格式
    inb = Label(top, text = "")
    inb.grid(row = 19, column = 0, sticky = E)

    # 显示抓包每个类型的个数
    l1 = Label(top, text = '捕获数据包个数:')
    l1.grid(row = 20, sticky = E)

    listb = Listbox(top, height = 4, width = 7, bg = '#D9D9D9', bd = 0)
    for item in typename:
        listb.insert(END, item)
    listb.grid(row = 22, column = 0, sticky = E)

    listb = Listbox(top, height = 4, width = 15)
    listb.grid(row = 22, column = 1, sticky = W)

    # 输出数据包信息 bagcontent = get_bag(bagnum)
    # 需要水平拖动与竖直拖动
    l4 = Label(top, text = '数据包信息：')
    l4.grid(row = 25, sticky = W)

    # 加上滚动条
    scrollbar = Scrollbar(top)
    scrollbar.grid(row = 28, column = 9, sticky = W)

    conb = Listbox(top, height = 10, width = 80, bg = 'white', bd = 2, selectmode=BROWSE, yscrollcommand=scrollbar.set)
    conb.grid(columnspan=8, row = 28, column = 0)
    scrollbar.config(command=conb.yview)

    # 绑定点击事件
    conb.bind('<Button-1>', click_listbox)





    # 四个文本输入框
    # 接口（默认为wlo1）
    interface = Label(top, text = "请输入接口：")
    interface.grid(row = 30, column = 0, sticky = E)
    en1 = Entry(top)
    en1.grid(row = 30, column = 1, sticky = W)
    en1.insert(0, 'wlo1')
    # interfacetype = inttype.get()

    # 目标IP地址
    target = Label(top, text = "被欺骗主机的IP地址：")
    target.grid(row = 33, column = 0, sticky = E)
    en2 = Entry(top)
    en2.grid(row =33, column = 1, sticky = W)
    en2.insert(0, 'None')
    # target_IP = targetIP.get()

    # 网关IP地址
    gateway = Label(top, text = "毒化记录中的IP地址：")
    gateway.grid(row = 35, column = 0, sticky = E)
    en3 = Entry(top)
    en3.grid(row = 35, column = 1, sticky = W)
    # gateway_IP = gatewayIP.get()
    
    # 模式（req/rep）
    pattern = Label(top, text = "请选择模式：")
    pattern.grid(row = 40, column = 0, sticky = E)
    en4 = Entry(top)
    en4.grid(row = 40, column = 1, sticky = W)
    en4.insert(0, 'rep')
    # pattern_SELECT = patternIP.get()

    # 发送包的个数
    pattern = Label(top, text = "请输入需要发送的数据包的个数：")
    pattern.grid(row = 44, column = 0, sticky = E)
    en5 = Entry(top)
    en5.grid(row = 44, column = 1, sticky = W)
    en5.insert(0, '8')

    # 最终确认信息按钮，不勾选，确认后调用子函数ARP_creatpac
    ARP_def = Button(top, text = "  确  认  ", activebackground = 'gray', command = ARPTrue )
    ARP_def.grid(row = 46, column = 1, sticky = W)

    # 显示消息
    msg = Listbox(top, height = 1, bg = '#D9D9D9', bd = 0)
    msg.grid(row = 48, column = 1, sticky = W)

    # 退出按钮
    out = Button(top, text='Quit', command=top.quit, activebackground = 'gray')
    out.grid(columnspan = 2, sticky = E)

    top.mainloop()
    