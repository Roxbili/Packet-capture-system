# -*- coding: UTF-8 -*-

import tkMessageBox
from Tkinter import *
from scapy.all import *
from ARP_code import(
    get_bag,
    ARP_creatpac,
    ARP_sendpac
)
from scapy.layers.ssl_tls import *
from scapy.layers import http


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
    find_c = {'0': 'tcp', '1': 'udp', '2': 'port 80', '3': 'port 443'}
    factor = None
    c = [[0,c_tcp.get()] , [1,c_udp.get()], [2,c_http.get()], [3,c_https.get()]]


    for i, tof in c:
        if tof:
            if factor == None:
                factor = find_c[str(i)]
            else:
                factor = factor + ' or ' + find_c[str(i)]

    bagcontent = get_bag(bagnum, factor)

    print('Packet capture has done')

    if len(bagcontent) == 0:
        tkMessageBox.showinfo("超时！", "没有抓到数据包")
        return

    # 获取抓包每个类型的个数
    typenum.append( len(bagcontent[TCP]) )
    typenum.append( len(bagcontent[UDP]) )
    typenum.append( len(bagcontent[ICMP]) )
    typenum.append( bagnum - len(bagcontent[TCP]) - len(bagcontent[UDP]) - len(bagcontent[ICMP]) )
    # 获取数据包信息
    for i in range(len(bagcontent)):
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
    information = Listbox(top2).grid(sticky = W)
    show_msg(top2, info, information)    # 递归调用，显示包中所有的信息

def show_msg(top2, info, information):
    # Label(top2, text = '###[ ' + info.name + ' ]###').grid(stick=W)
    information.insert(END, '###[ ' + info.name + ' ]###')
    dict_one = info.fields
    for item in dict_one:
        if (type(dict_one[item]) is list) and (item != 'options'):
            show_msg(top2, dict_one[item][0])
        else:
            # Label(top2, text = item + ': ' + repr(dict_one[item]), wraplength=1000, justify='left').grid(stick=W)
            information.insert(END, item + ': ' + repr(dict_one[item]))
    # Label(top2, text = '').grid()  # 空行
    information.insert(END, '')

    if info.payload.name == 'NoPayload':
        return
    else:
        show_msg(top2, info.payload)





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
    en.insert(0, '10')

    # 空行调整格式
    inb = Label(top, height=2, text = "(TCP/UDP复选框可捕获指定协议的数据包（可都选），若都不选则捕获所有可捕获数据包)")
    inb.grid(row = 3, columnspan = 6, sticky = E)

    # 滤波复选框的设置
    c_tcp = BooleanVar()
    c_udp = BooleanVar()
    c_http = BooleanVar()
    c_https = BooleanVar()

    tcp_b = Checkbutton(top, text = "TCP", variable = c_tcp)
    tcp_b.grid(row = 4, column = 0, sticky = E)
    udp_b = Checkbutton(top, text = "UDP", variable = c_udp)
    udp_b.grid(row = 4, column = 1, sticky = W)
    http_b = Checkbutton(top, text = "HTTP", variable = c_http)
    http_b.grid(row = 4, column = 1, sticky = E)
    https_b = Checkbutton(top, text = "HTTPS", variable = c_https)
    https_b.grid(row = 4, column = 2, sticky = W)



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

    lista = Listbox(top, height = 4, width = 7, bg = '#D9D9D9', bd = 0)
    for item in typename:
        lista.insert(END, item)
    lista.grid(row = 22, column = 0, sticky = E)

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
    