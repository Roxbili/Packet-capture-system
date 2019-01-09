# -*- coding: UTF-8 -*-

from Tkinter import *
from scapy.all import *

# 子函数


if __name__ == "__main__":
    # 参数
    typenum = []
    typename = ['TCP', 'UDP', 'ICMP', 'Other']
    bagcon = []

    top = Tk()
    # 进入消息循环

    # 设置界面大小、名称、图标、垂直滚动条
    top.geometry('600x400')
    top.minsize(600,400)
    top.title("packet capture")
    # top.iconbitmap('e:\python.ico')

    # 输入抓包数量
    inb = Label(top, text = "请输入抓包数量：")
    inb.grid(row = 0, column = 0, padx = (600, 0))
    num = StringVar()
    num.set('100')
    entry = Entry(top, textvariable = num )
    entry.grid(row = 0, column = 1, padx = (0, 600))
    bagnum = int(num.get()) # 获取输入框的值并打印
    print(bagnum)

    # 开始抓包按钮,command触发事件
    begin = Button(top, text = "开始捕获数据包")
    begin.grid(row = 1, padx = (600, 0))

    # 开始抓包

    # 调用子函数获取信息
    # bagcontent = get_bag(bagnum) # 子函数名get_bag
    bagcontent = rdpcap('C:\Users\85746\Desktop\Course_Design\Packet_capture\demo.pcap')
    # 获取抓包每个类型的个数
    typenum.append( len(bagcontent[TCP]) )
    typenum.append( len(bagcontent[UDP]) )
    typenum.append( len(bagcontent[ICMP]) )
    typenum.append( bagnum - len(bagcontent[TCP]) - len(bagcontent[UDP]) - len(bagcontent[ICMP]) )

    # 显示抓包每个类型的个数
    l1 = Label(top, text = '捕获数据包个数:')
    l1.grid(row = 2, padx = (600, 0))

    listb = Listbox(top, height = 4, width = 7, bg = '#f0f0f0', bd = 0)
    for item in typename:
        listb.insert(END, item)
    listb.grid(row = 3, column = 0, padx = (700, 0))

    listb = Listbox(top, height = 4, width = 15)
    for item in typenum:
        listb.insert(END, item)
    listb.grid(row = 3, column = 1, padx = (0, 700))


    # 输出数据包信息 bagcontent = get_bag(bagnum)
    # 需要水平拖动与竖直拖动
    l4 = Label(top, text = '数据包信息：')
    l4.grid(row = 4)

    # for i in range(bagnum):
    #     # 显示bagcontent[i].summary()
    #     bagcom = bagcontent[i].summary()
    #     bagcomm = Label(top, text = bagcom)
    #     bagcomm.grid(row = (i + 4))
    for i in range(bagnum):
        bagcon.append( bagcontent[i].summary() )

    # 加上滚动条
    scrollbar = Scrollbar(top)
    scrollbar.grid(row = 5, column = 1, padx = (0, 400))

    conb = Listbox(top, height = 10, width = 100, bg = 'white', bd = 2, yscrollcommand=scrollbar.set)
    for item in bagcon:
        conb.insert(END, item)
    conb.grid(row = 5, column = 0)
    scrollbar.config(command=conb.yview)

    # scrollbary = Scrollbar(top)
    # scrollbary.grid(column = 2)

    # canvas = Canvas(top, width = 400, height = 100, bg = "white", bd = 2, relief = SUNKEN, yscrollcommand=scrollbary.set)
    # canvas.grid(row = 5, columnspan = 2 )

    # scrollbary.config(command = canvas.yview)

    # 四个文本输入框
    # 接口（默认为wlo1）
    interface = Label(top, text = "请输入接口：")
    interface.grid(row = 6, column = 0, padx = (600, 0))
    inttype = StringVar()
    inttype.set('wlo1')
    entry = Entry(top, textvariable = inttype )
    entry.grid(row = 6, column = 1, padx = (0, 600))
    interfacetype = inttype.get()
    print(interfacetype)
    # 目标IP地址
    target = Label(top, text = "请输入目标IP地址：")
    target.grid(row = 7, column = 0, padx = (600, 0))
    targetIP = StringVar()
    targetIP.set('None')
    entry = Entry(top, textvariable = targetIP )
    entry.grid(row = 7, column = 1, padx = (0, 600))
    target_IP = targetIP.get()
    print(target_IP)
    # 网关IP地址
    gateway = Label(top, text = "请输入网关IP地址：")
    gateway.grid(row = 8, column = 0, padx = (600, 0))
    gatewayIP = StringVar()
    gatewayIP.set('set')
    entry = Entry(top, textvariable = gatewayIP )
    entry.grid(row = 8, column = 1, padx = (0, 600))
    gateway_IP = gatewayIP.get()
    print(gateway_IP)
    # 模式（req/rep）
    pattern = Label(top, text = "请选择模式：")
    pattern.grid(row = 9, column = 0, padx = (600, 0))
    patternIP = StringVar()
    patternIP.set('req/rep')
    entry = Entry(top, textvariable = patternIP )
    entry.grid(row = 9, column = 1, padx = (0, 600))
    pattern_IP = patternIP.get()
    print(pattern_IP)
    # 最终确认信息



    # 退出按钮
    out = Button(top, text='Quit', command=top.quit)
    out.grid()

    top.mainloop()
    