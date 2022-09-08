# 实验目的

·掌握 VirtualBox 虚拟机的安装与使用；

·掌握 VirtualBox 的虚拟网络类型和按需配置；

·掌握 VirtualBox 的虚拟硬盘多重加载；

# 实验要求

### 虚拟硬盘配置成多重加载，效果如下图所示

![图片加载失败](/image/20.png)

### 完成以下网络连通性测试；

- [x] 靶机可以直接访问攻击者主机

- [x] 攻击者主机无法直接访问靶机

- [x] 网关可以直接访问攻击者主机和靶机

- [x] 靶机的所有对外上下行流量必须经过网关

- [x] 所有节点均可以访问互联网

# 实验过程

### 安装虚拟机

##### 1.网关——debian的安装和

在虚拟介质管理中注册debian10，`为虚拟硬盘设置多重加载`：

![图片加载失败](/image/1.png)

##### 2.靶机——xp的安装和配置

注册虚拟介质：

![图片加载失败](/image/14.png)

新建虚拟电脑，并导入虚拟介质：

![图片加载失败](/image/15.png)

### 配置网络连接

根据拓扑配置网络连接。

网关Debian的网卡设置：

![图片加载失败](/image/21.png)

攻击者主机attacker-kali的ip地址：

![图片加载失败](/image/27.png)

靶机Victim-XP-1的ip地址：

![图片加载失败](/image/39.png)

靶机Victim-XP-2的ip地址：

![图片加载失败](/image/40.png)

靶机Victim-kali-1的ip地址：

![图片加载失败](/image/36.png)

靶机Victim-Debian-2的ip地址：

![图片加载失败](/image/38.png)

所有主机的网络设置如下表格：

| 主机名称 | 网络设置 | IP地址 |
|  ----   | ----     | ---- |
| Victim-XP-1  | intnet1 | 172.16.111.145   | 
| Victim-kali-1  | intnet1 | 172.16.111.150     |
| Victim-XP-2  | intnet2 | 172.16.222.133    |
| Victim-Debian-2 | intnet2 | 172.16.222.103  |
| attacker-kali  | NATnetwork | 10.0.2.4 |
| Gateway-Debian-1 | NATnetwork | 10.0.2.15/24 |
|                  | Host Only | 192.168.56.113/24 |
|                  | intnet1 | 172.16.111.1/24 |
|                  | intnet2 | 172.16.222.1/24 |

### 连通性测试

##### 1.靶机可以直接访问攻击者主机

靶机访问攻击者主机：

![图片加载失败](/image/32.png)

##### 2.攻击者主机无法直接访问靶机

攻击者主机无法直接访问靶机：

![图片加载失败](/image/33.png)

##### 3.网关可以直接访问攻击者主机和靶机

网关访问攻击者主机：

![图片加载失败](/image/30.png)

网关访问靶机（xp-1)：

![图片加载失败](/image/31.png)

##### 4.靶机的所有对外上下行流量必须经过网关

在debian上开启一个抓包，输入口令：`tcpdump -i enp0s9 -n`

![图片加载失败](/image/17.png)

在xp上ping百度的网址：

![图片加载失败](/image/18.png)

debian上看到了抓取的数据包：

![图片加载失败](/image/19.png)

靶机的所有对外上下行流量必须经过网关测试成功。

##### 5.所有节点均可以访问互联网

网关：

![图片加载失败](/image/34.png)

攻击者：

![图片加载失败](/image/35.png)

靶机：

![图片加载失败](/image/37.png)

# 实验问题

### 一、介质类型由普通更改为多重加载出错

##### 问题截图

![图片加载失败](/image/2.png)

##### 解决方法

1.释放硬盘

![图片加载失败](/image/5.png)

2.更改类型为多重加载

![图片加载失败](/image/6.png)

3.更改成功

![图片加载失败](/image/7.png)

4.重新选择虚拟硬盘

![图片加载失败](/image/8.png)

### 二、ssh连接root账户，输入密码后连接请求未通过

##### 问题截图

![图片加载失败](/image/11.png)

##### 解决方法

![图片加载失败](/image/13.png)

### 三、新建一个NAT网络

##### 解决方法

参考CSDN上的资料后，得知新建一个NAT网络的方法。

点击`管理-全局设定-网络`，然后点击`新建一个NAT网络`即可。

### 四、kali无法登录

##### 问题截图

![图片加载失败](/image/24.png)

##### 解决方法

出现引导界面时选择恢复模式advance options for kali GNU/Linux：

![图片加载失败](/image/25.png)

直接按‘e’，就进入编辑模式：

![图片加载失败](/image/26.png)

ro改成rw，在gz后加上init=/bin/bash，之后便可以进入命令行，输入`passwd`便可以重置密码：

![图片加载失败](/image/23.png)

### 五、靶机ping攻击者主机无法ping通

##### 问题截图

![图片加载失败](/image/29.png)

##### 解决方法

关闭xp系统的防火墙

![图片加载失败](/image/28.png)

# 参考资料

https://expoli.tech/articles/2021/06/07/1623066136894.html

https://blog.csdn.net/allway2/article/details/106961332

https://blog.csdn.net/dkfajsldfsdfsd/article/details/79403343

https://blog.csdn.net/qq_40647685/article/details/79894840

https://github.com/CUCCS/2021-ns-public-Zhang1933/tree/ch0x01/ch0x01

https://github.com/CUCCS/2021-ns-public-Daytoyecho/blob/chap0x01/chap0x01/chap0x01.md