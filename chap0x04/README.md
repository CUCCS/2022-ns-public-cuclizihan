# 网络拓扑搭建

将五个主机都连接到同一个网络中：

网关：

![图片加载失败](/image/network-1.png)

攻击者：

![图片加载失败](/image/network-2.png)

受害者：

![图片加载失败](/image/network-5.png)

其他主机：

![图片加载失败](/image/network-3.png)

![图片加载失败](/image/network-4.png)

|     主机    |    ip地址   | MAC地址 |
| ----------- | ----------- | -------- |
| gateway | 172.16.111.1 | 08:00:27:ca:5a:77 |
| attacker | 172.16.111.122 | 08:00:27:5e:db:60 |
| victim | 172.16.111.150 | 08:00:27:6b:bf:8c |

# 实验一：检测局域网中的异常终端

#### 在受害者主机上检查网卡的「混杂模式」是否启用

在我的kali主机上，网卡的表示形式是`eth0`而不是`enp0s3`，因此这里根据实际情况修改了一下语句：

![图片加载失败](/image/check_promiscuous%20mode.png)

#### 在攻击者主机上开启 scapy

![图片加载失败](/image/open_scapy.png)

#### 在 scapy 的交互式终端输入以下代码回车执行

首先查看受害者主机的ip地址：

![图片加载失败](/image/victim-ip.png)

在攻击者scapy终端上执行代码：

![图片加载失败](/image/scapy.png)

#### 回到受害者主机上开启网卡的『混杂模式』

![图片加载失败](/image/open_promisc.png)

上述输出结果里没有出现`PROMISC`字符串

输入`ip link show eth0`，输出结果里多出来了`PROMISC`：

![图片加载失败](/image/promisc.png)

#### 回到攻击者主机上的 scapy 交互式终端再次执行命令

执行`pkt = promiscping("受害者主机ip")`：

![图片加载失败](/image/resend.png)

#### 在受害者主机上手动关闭该网卡的「混杂模式」

![图片加载失败](/image/promisc_off.png)

# 实验二：手工单步“毒化”目标主机的 ARP 缓存

#### 获取当前局域网的网关 MAC 地址

在受害者主机输入`arp`查看当前网关的mac地址：

![图片加载失败](/image/gateway_mac.png)

#### 构造一个 ARP 请求，并查看报文详情

![图片加载失败](/image/arp.png)

#### 发送这个 ARP 广播请求

![图片加载失败](/image/send_arp_correct.png)

#### 伪造网关的 ARP 响应包

ARP 响应的目的 MAC 地址设置为攻击者主机的 MAC 地址

![图片加载失败](/image/send_fake_arp.png)

#### 恢复受害者主机的 ARP 缓存记录，伪装网关给受害者发送 ARP 响应

![图片加载失败](/image/restore_arp.png)

#### 在受害者主机上尝试 ping 网关

![图片加载失败](/image/ping_gateway.png)

静候几秒 ARP 缓存刷新成功，退出 ping

#### 查看受害者主机上 ARP 缓存

输入`ip neigh`

![图片加载失败](/image/arp_2.png)

# 实验问题

#### 1.ARP报文没有成功发送

##### 问题截图

最初发送arp报文的时候，并没有成功发送，也没有收到回复：

![图片加载失败](/image/send_arp.png)

##### 解决方法

发送时添加参数`iface="eth3"`后，发送成功：

![图片加载失败](/image/send_arp_correct.png)

#### 2.受害者主机上的ARP缓存中，网关MAC地址没有替换为攻击者的MAC地址

##### 问题截图

攻击者发送伪造的 ARP 响应数据包到受害者主机：

![图片加载失败](/image/problem_1.png)

![图片加载失败](/image/problem_2.png)

再到受害者主机上查看ARP缓存：

![图片加载失败](/image/problem_3.png)

网关MAC地址没有替换为攻击者的MAC地址

##### 解决方法

添加以太网头，`arpspoofed=Ether()/ARP(op=2, psrc="172.16.111.1", pdst="172.16.111.150", hwdst="08:00:27:5e:db:60")`，其他步骤相同:

![图片加载失败](/image/correct.png)

再到受害者主机上查看ARP缓存：

![图片加载失败](/image/succeed.png)

网关MAC地址已经替换为攻击者的MAC地址，问题解决。

# 参考资料

https://blog.csdn.net/yjh314/article/details/50848010

https://www.cnblogs.com/kerrycode/p/13709537.html

http://courses.cuc.edu.cn/course/90732/forum#/topics/348207?show_sidebar=false&scrollTo=topic-348207&pageIndex=1&pageCount=1&topicIds=348207,344841&predicate=lastUpdatedDate&reverse

https://www.jianshu.com/p/b4102e3e3e96