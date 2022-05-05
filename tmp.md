# 网络扫描

1. 信息收集

（1） Solicit

DUID：LL，LLT
IPAddress
T1, T2, validtime, preftime
VendorClass？
DNS？
Domain？

（2） Solicit，Rebind

AAT（Address Asignment Type）：linear， random＋rebind，random

（3） Bisers（Ping，Rebind，Solicit）

PoolLimit

2. 扫描

（1） 被动扫描

T1 < Threshold ?

DUID：LL，LLT
LLA
GUA
VendorClass？

（2） 无状态扫描

Limit < Threshold ?

无状态扫描[masscan, zmap, etc]

（3） 机器学习扫描

机器学习扫描[Entropy/IP, 6gan, etc]

# 实验

1. 实验对象

服务端：Cisco路由器，TPLink路由器，Openwrt，Windows DHCP Server， ISC DHCP Server

客户端：Windows，Linux，Android，FreeBSD，MacOS，IOS

2. 服务端DUID类型，T1，AAT，PoolSize

服务端x(DUID类型vT1vAATvPoolSize)

| 服务端   | Cisco路由器 | TPLink路由器 | Openwrt      | Windows DHCP Server | ISC DHCP Server |
|----------|-------------|--------------|--------------|---------------------|-----------------|
| DUID类型 | LL          | LL           | LL           | LLT                 | LLT             |
| T1       | 43200(12h)  | 43200(12h)   | -1(infinity) | 345600(4d)          | 3600(1h)        |
| AAT      | random      | linear       | random       | random              | random+rebind   |
| PoolSize | manual      | N/A          | 8            | 64                  | manual          |

3. 客户端DUID类型，VendorClass

客户端x(DUID类型vVendorClass)

| 客户端      | Windows | Linux | Android | FreeBSD | MacOS | IOS |
|-------------|---------|-------|---------|---------|-------|-----|
| DUID类型    | LLT     | LLT   |         |         |       |     |
| VendorClass | yes     | no    |         |         |       |     |

4. 定界效果

（1） DeHCP

仿真实验，离线主机比例x窗口大小x定界准确率

| 窗口\离线主机比例 | 30% | 50% | 70% |
|-------------------|-----|-----|-----|
| 1                 |     |     |     |
| 2                 |     |     |     |
| 3                 |     |     |     |
| 4                 |     |     |     |

（2） Rebind

仿真实验，离线主机比例x定界准确率

| 主机离线比例 | 30% | 50% | 70% |
|--------------|-----|-----|-----|
| 准确率       |     |     |     |

（3） Solicit

仿真实验，请求次数x定界准确率

| 请求次数 | 32 | 64 | 128 | 256 |
|----------|----|----|-----|-----|
| 准确率   |    |    |     |     |

（4） Bisers

服务端x（定界准确率vDHCPv6报文发送数）

| 服务端 | cisco路由器 | openwrt | Windows DHCP Server | ISC DHCP Server |
|--------|-------------|---------|---------------------|-----------------|
| 准确率 | 99.2%       | 96.9%   | 99.1%               | 100%            |

5. 机器学习扫描效果

# 安全建议

1. 服务端避免信息泄露，避免可预测地址分配方式

（1） 随机生成DUID
（2） 随机分配地址，使用大地址池，随机生成方式避免被机器学习

2. 客户端避免信息泄露

（1） 随机生成DUID并定期更换
（2） 避免使用VendorClass

3. 交换机对DHCPv6报文做特殊处理

（1） 单播DHCPv6报文：只转发可信端口发送的多播DHCPv6报文
（2） 多播DHCPv6报文：只向可信端口转发多播DHCPv6报文
