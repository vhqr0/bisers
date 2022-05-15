# 摘要

网络扫描是资产管理与渗透测试的一个重要组成部分，然而IPv6网络因其庞大的
地址空间而被认为无法扫描。本文提出了一个针对DHCPv6管理的IPv6网络的扫描
方案，有效地解决了DHCPv6管理的IPv6网络的扫描问题。

# 引言

扫描网络中存活的主机是资产管理与渗透测试的一个重要组成部分。IPv4的32位
地址空间可以用masscan等无状态扫描工具在几小时内完成扫描，扫描一个常见
的8位或16位子网通常只要几分钟。网络管理员和安全工程师们已经习惯于用网
络扫描工具扫描出所有存活的主机，扫描这些主机开放了哪些服务，有哪些安全
隐患，然后进行安全维护或渗透测试。人们从未认为探测一个网络中存活的主机
是一个问题。然而对于IPv6而言，这个任务因其庞大的地址空间而变得不可完成。
随着IPv6的普及，寻找有效的IPv6网络扫描方法变得日益重要。

IPv6地址配置分为手动配置和自动配置，自动配置又分为无状态地址自动配置、
无状态DHCPv6地址配置和有状态DHCPv6地址配置。虽然无状态地址自动配置和无
状态DHCPv6已经足以方便的配置网络，但是这些方式难于管理。有状态DHCPv6地
址配置方式因为易于管理而被广泛使用，尤其是在大型网络中。

针对使用DHCPv6管理的IPv6网络，我们提出两类扫描方法。一类是被动扫描，通
过监听网络中多播的DHCPv6报文收集网络中的DHCPv6客户端信息。另一类是主动
扫描，我们提出一个DHCPv6地址池定界方案Bisers（BInary SEarch & Rebind &
Solicit），通过DHCPv6定界帮助缩小网络扫描的地址空间，有效地提高网络扫
描的效率。

## 相关工作

### DHCPv6被动扫描

DHCPv6客户端、中继发送给服务端的报文是多播的，一个DHCPv6报文从客户端经
过多个中继到达服务端所经过的所有局域网中的所有主机都会收到该报文。攻击
者可以通过嗅探DHCPv6报文收集网络中的资产信息，这是一种十分有效的被动扫
描：一方面，这些DHCPv6报文中除了地址，还包含丰富的信息：Stephen等人分
析了如何通过DUID跨网络识别和追踪一台设备[1]，Vendor Class选项可以帮助
攻击者识别设备的硬件和操作系统；另一方面，这种被动扫描相比于其它同类型
的方法更稳定。按照约定，DHCPv6客户端要在T1时间内续租地址。活跃的节点在
T1时间内必定发送Request、Renew、Confirm中的一个报文。攻击者可以先检查
服务端的T1值，然后可以期望在T1时间内收集到网络中所有的资产信息。

### DeHCP定界算法

Bergenholtz等人提出了一个DHCPv6定界算法DeHCP[2]：该算法基于部分DHCPv6
服务端实现未经仔细的安全考虑便沿用DHCPv4的实现方式使用线性分配地址，使
用二分搜索探测密集的地址空间的边界。

```
def ddelimit(l, u, h, w):
  return dllimit(l, h, w), dulimit(h, u, w)

def dllimit(l, u, w):
  host = (l + u) / 2
  if l >= u then return host
  if nd(host) then return dllimit(l, host-1, w)
  for i in range(host-w, host+w+1):
    if nd(i) then return dllimit(l, i-1, w)
  return dllimit(host+1, u, w)

def dulimit(l, u, w):
  host = (l + u) / 2
  if l >= u then return host
  if nd(host) then return dulimit(host+1, u, w)
  for i in range(host-w, host+w+1):
    if nd(host) then return dulimit(i+1, u, w)
  return dulimit(l,host-1, w)
```

DeHCP对使用线性分配地址的DHCPv6服务器十分有效，但是我们测试了常见的
DHCPv6服务端实现（见4节），发现虽然中国市场上常见的家用路由器实现都使
用线性分配地址，但是几个主流的商用路由器实现和主要的软件实现使用更安全
的随机分配地址，因此DeHCP的使用场景受到了更严格的限制。

## 主要工作

本研究的主要工作集中于对DHCPv6服务器信息的收集。我们从协议和具体实现上
分析我们可以利用DHCPv6协议收集DHCPv6服务器的哪些信息。DHCPv6服务器地址
池边界的探测是其中的一个重要部分，为弥补DeHCP定界算法仅适用于信息分配
地址的DHCPv6服务端实现的不足，我们提出了两个基于DHCPv6协议的定界算法，
综合这三个算法，我们给出了一个主动探测DHCPv6服务器地址分配类型并使用相
应算法定界的完善的DHCPv6定界方案：Bisers。DHCPv6服务器信息中T1和地址池
边界这两个属性是我们评估被动扫描和主动扫描的效率的标准。我们还具体分析
了常见的DHCPv6客户端实现，总结了通过被动扫描我们可以收集到附加信息。我
们给出了一个收集DHCPv6服务器信息及被动扫描在Linux平台的参考实现
[https://github.com/vhqr0/bisers]。

此外，本研究还从隐私的角度分析了DHCPv6协议的缺陷，并对使用DHCPv6管理的
IPv6网络的部署给出一些安全建议。

# 背景

DHCPv6协议是用来分配IPv6地址、前缀及其它网络参数的网络协议。使用DHCPv6
配置网络的主机需要向DHCPv6服务器租借并定期续租地址，因此使用DHCPv6管理
的网络相比于使用SLAAC的网络更易于管理。

DHCPv6服务端和客户端都有表示身份的唯一标识，称为DUID。最初的DHCPv6标准
有三种DUID生成方式，抛除不常见的厂商唯一ID标识，常见的方式有使用链路层
地址生成的LL方式和使用链路层地址和生成时的当前时间生成的LLT。人们很快
发现这两种生成方式带来的隐私问题，因此RFC6355提出了另一种DUID生成方式：
UUID。然而，目前几乎所有DHCPv6客户端实现和服务端实现仍使用LL或LLT。

DHCPv6客户端通过多播向DHCPv6服务端发送报文，如果需要则使用DUID指明要使
用哪个服务器。DHCPv6服务端通过单播向DHCPv6客户端发送报文。这种通信方式
带来严重的安全问题与隐私问题。

DHCPv6客户端首先通过Solicit报文发现网络中的DHCPv6服务器，DHCPv6服务器
收到该报文后响应Advertise报文，其中一般包含T1，T2与一个预分配的地址。
DHCPv6客户端选择其中一个服务器作为默认DHCPv6服务器，然后通过Request报
文向该服务器租借其预分配的地址，DHCPv6服务器响应Reply报文。除了租借新
的地址，新加入网络的DHCPv6客户端也可以通过Confirm报文请求之前使用的地
址。DHCPv6客户端需要在T1时间内再次发送Request报文续租地址，如果在T2时
间内无法续租，则使用Rebind报文向所有其它DHCPv6服务器请求租借相同的地址，
DHCPv6服务器响应Relpy报文通知其是否可以申请该地址。

# DHCPv6扫描方案

## 初步信息收集

我们可以像普通的DHCPv6客户端一样主动发送DHCPv6 Solicit报文获得DHCPv6服
务器响应的DHCPv6 Advertise报文。该报文中包含DHCPv6服务器的DUID及T1，还
包含例如网络前缀、DNS服务器、本地域名等网络参数。我们主要关注DHCPv6服
务器的DUID及T1。

DUID作为唯一身份标识可以用来追踪一台设备。此外，DUID本身还包含丰富的信
息。仅管已有UUID等更隐私的DUID生成方式，几乎所有DHCPv6服务端实现都使用
LLT或LL方式生成DUID。

T1决定了DHCPv6客户端续租地址的时间间隔。网络中所有DHCPv6客户端要么在T1
时间内发送Renew报文续租地址，要么在这段时间内加入网络，发送Request或
Confirm租借地址。因此，我们可以期望在T1时间内监听所有Renew、Request和
Confirm报文来收集到网络中所有DHCPv6客户端信息。

## 地址池探测

### Bisers地址池定界方案

在初步信息收集后，我们尝试探测一个用于主动扫描的地址区间。对于线性分配
地址的DHCPv6服务端实现而言，该区间应接近DHCPv6服务器分配的第一个地址和
最后一个地址。对于随机分配地址的DHCPv6服务端实现而言，该区间应该接近
DHCPv6服务器的地址池。

DeHCP定界算法适用于线性分配地址的DHCPv6服务端实现，然而大部分DHCPv6服
务端实现都使用随机分配地址。因此，我们首先提出了一个基于DHCPv6 Rebind
的定界算法。该算法基于DHCPv6标准中的一个缺陷，可以用少量DHCPv6 Rebind
报文精确定界。然而经过测试只有少数DHCPv6服务端实现完全按照标准实现，因
此我们又提出了一个更通用的基于DHCPv6 Solicit的定界算法。该算法通过发送
大量DHCPv6 Solicit报文得到的结果估算DHCPv6服务器地址池的边界。我们把
DHCPv6服务端的AAT（地址分配方式）分为三类：linear、random+rebind和
random分别对应以上三个DHCPv6定界算法。

现在，我们描述Bisers定界方案：首先用Solicit请求两个地址，如果两个地址
是相邻的，则认为DHCPv6服务器的AAT为linear，使用DeHCP定界算法定界；再通
过两个Rebind请求第一次Solicit得到的地址前后的地址，如果成功，则认为
DHCPv6服务器的AAT为random+rebind，使用基于Rebind的定界算法定界；否则
认为DHCPv6服务器的AAT为random，使用基于Solicit的定界算法定界。

```python
def bisers(w, n):
  h = solicit()
  if h + 1 == solicit() then return ddelimit(netmin(h), netmax(h), h, w)
  if rebind(h+1) or rebind(h-1) then return rdelimit(netmin(h), netmax(h), h)
  return sdelimit(h, n)
```

经过实际测试（见4节），该方案已覆盖常见的DHCPv6服务端实现。

### 基于Rebind的DHCPv6定界算法

参考RFC3315,当DHCPv6服务端收到Rebind报文时，首先在其数据库中寻找相应的
记录，若未发现，服务端应响应一个包含该地址的Reply报文，并根据该地址是
否符合其地址分配策略设置该相应的有效时间。基于这种机制，我们提出一种基
于DHCPv6 Rebind的DHCPv6服务端地址池边界二分搜索算法。考虑到在地址池中
某个地址已经被分配的情况下，我们用Rebind报文请求该地址，DHCPv6服务端会
认为这个地址不符合其地址分配策略，与处理地址池之外的地址的表现方式一致，
所以我们在探测一个地址是否在服务端的地址池中时，首先检查这个地址是否在
已请求到的地址缓存中，若失败，再用Rebind探测，若还失败，再用ping探测这
个地址是否被某个存活的节点占用。

```python
def rdelimit(l, u, h):
  return rllimit(l, h), rulimit(h, u)

def rllimit(l, u):
  host = (l + u) / 2
  if l >= u then return host
  if cached(host) or rebind(host) or ping(host)
    then return rllimit(l, host-1)
    else return rllimit(host+1, u)

def rulimit(l, u):
  host = (l + u) / 2
  if l >= u then return host
  if cached(host) or rebind(host) or ping(host)
    then return rulimit(host+1, u)
    else return rulimit(l, host-1)
```

不难看出，当搜索空间限制在64位子网内时，该算法可以通过不超过128次
Rebind请求，在几秒钟的时间内完成精确地DHCPv6定界，前提是服务端实现遵循
RFC3315的规范诚实地向Rebind请求反映自己的地址池信息。

该算法考虑到已经被分配的地址，但是仍有不足：可能有节点请求到地址后便无
法被探活，或者服务端配置中显式排除掉一些地址。这导致我们探测的地址池中
存在一些漏点，但是在庞大的地址池中分散的取不超过128个点碰撞到这些漏点
的概率很低，而且可以通过多次探测避免。

虽然在理论上很完美，但是实际测试（见4节）时发现只有一个常见的DHCPv6服
务端实现：ISC DHCP Server：类UNIX系统中著名的dhcpd，可以用Rebind探测地
址池，其它实现都避免了在响应Rebind时泄露地址池信息。因此，我们又提出了
另一种不那么完美但是普遍有效的算法。

### 基于Solicit的DHCPv6定界算法

我们提出了一种基于DHCPv6 Solicit的DHCPv6定界算法，通过不断发起Solicit
请求记录请求到的地址的最小值与最大值，把这两个值当作边界。

这是一个很简单的算法，但难以评估其有效性。DHCPv6服务端实现使用的‘随
机’分配地址是怎样的随机？我们简单假设这种‘随机’是在统计学上随机的。
以服务端在统计学上随机地生成地址，且请求次数n远小于地址池地大小为前提，
我们把如何评估该算法归化为以下数学问题：

给定区间[a,b]，在该区间中随机生成n个数，取其中的最小值和最大值a',b'，
求期望E(b'-a')。

这是一个次序统计量的期望问题，其解为((n-1)/(n+1))(b-a)。随着请求次数n
的增加，伪地址池占地址池的比例为(n-1)/(n+1)趋向于1。而服务端分配的地址
在地址池中是随机的，我们可以期望在伪地址池中扫描到同样比例的地址。不难
验证，当请求次数为100时，伪地址池的准确率超过98%。

我们可以继续改进该算法：假设得到的伪地址池为[a',b']，可以求得a,b的期望
为a'-delta,b'+delta，其中delta=(b'-a')/(n-1)。我们可以把
[a'-delta,b'+delta]当作更准确的伪地址池。

```python
def sdelimit(h, n):
  l = u = h
  for _ in range(n):
    a = solicit()
    l = min(a, l)
    u = max(a, u)
  delta = (l-u)/n
  return l-delta, u+delta
```

经过实际测试（见4节），该算法在几个使用随机分配地址的DHCPv6服务端实现
中都十分有效。

## 扫描实施

我们可以利用前面收集到的信息在扫描开始前预先评估被动扫描和主动扫描的工
作量。

DHCPv6服务器的T1决定被动扫描需要的时间。经过实际测试，除了一个特殊的
DHCPv6服务端实现：Openwrt使用无限的续租时间之外，其它DHCPv6服务端实现
的T1值都是可接受的：DHCPv6服务端实现的默认T1值最长为Windows DHCP
Server的四天，Cisco和TPLINK的路由器默认为十二小时，ISC DHCP Server只要
一小时。

被动扫描除了扫描效果准确稳定以外，还能收集到丰富的附加信息。附加信息中
最有价值的信息是DUID和VendorClass。正如前面所讨论的，DUID可以用于追踪
一台设备，DUID本身也可能包含有用的信息。可能收集到的VendorClass信息还
可以用于判断一台设备的操作系统。经过实际测试，Linux和Windows的DHCPv6客
户端实现都使用LLT方式生成DUID，且Windows的DHCPv6客户端实现还附带
Windows的VendorClass。

基于DHCPv6的被动扫描也有缺陷：网络管理员可以设置一个很大的T1值来增长网
络嗅探的周期；换机也可以使用类似DHCP Snooping的技术对DHCPv6报文作特殊
处理，不向非信任端口转发DHCPv6请求报文来避免这种嗅探。此外，如果DHCPv6
服务器使用线性地址分配或使用很小的地址池，主动扫描的效果可能远好于被动
扫描。

DHCPv6服务器的地址池大小决定主动扫描需要扫描的地址空间。如果这个地址空
间足够小，我们可以使用Zmap、masscan等无状态扫描工具扫描这个地址空间。
一般而言，使用线性地址分配的DHCPv6服务端实现的地址空间和网络的规模在一
个数量级，只有使用随机地址分配和大到不可扫描的地址池才能避免主动扫描。

最差的情况，如果DHCPv6服务器T1值很大或多播的DHCPv6报文被交换机过滤，且
DHCPv6使用大地址池的随机地址分配方式分配地址，我们无使用过上述两种扫描
方式。在这种情况下，我们还可以向DHCPv6服务器申请大量地址作为数据集，使
用Entropy/IP等基于机器学习的扫描方法扫描网络。

# 实验及分析

## 实验对象

我们选择以下DHCPv6服务端实现作为测试对象。家用路由器实现：TPLINK；商用
路由器实现：Cisco；软件实现：Openwrt、ISC DHCP Server、Windows DHCP
Server。我们选择以下DHCPv6客户端实现作为测试对象：ISC DHCP Client、
Windows DHCP Client。

其中，TPLINK路由器测试使用2020年生产的TL-XDR1860型号的真实路由器，
Cisco路由器测试使用的IOS镜像版本为15.2，Openwrt测试使用的版本为19.07，
ISC DHCP Server测试使用的版本为4.4.1，Windows DHCP Server测试使用的版
本Windows Server 2016，ISC DHCP Client测试使用的版本为4.4.1，Windows
DHCP Clinet测试使用的版本为Windows 10 1809。

## 服务端参数

我们先分析各服务端实现的参数，主要关注其的DUID生成方式、默认T1、地址分
配方式和默认地址池大小。

| 服务端   | Cisco      | TPLINK     | Openwrt      | Windows    | ISC           |
|----------|------------|------------|--------------|------------|---------------|
| DUID类型 | LL         | LL         | LL           | LLT        | LLT           |
| T1       | 43200(12h) | 43200(12h) | -1(infinity) | 345600(4d) | 3600(1h)      |
| AAT      | random     | linear     | random       | random     | random+rebind |
| PoolSize | manual     | N/A        | 8            | 64         | manual        |

可以看到服务端DUID类型均为LL或LLT，这方便攻击者收集网络的额外信息。对
于被动扫描，除了Openwrt不使用续租，和Windows DHCP Server需要四天之外，
其它服务端实现如果使用默认值则只需要几个小时便可扫描完成。对于主动扫描，
使用线性地址分配的TPLINK路由器和Openwrt软路由都可以快速扫描完成，而强
制使用64位地址池的Windows DHCP Server则无法扫描，手动配置地址池的Cisco
路由器和ISC DHCP Server是否可以方便地扫描取决于网络管理员的配置。

## 客户端参数

我们再分析各客户端实现的参数，主要关注其DUID生成方式及VendorClass。

| 客户端      | Windows | Linux |
|-------------|---------|-------|
| DUID类型    | LLT     | LLT   |
| VendorClass | yes     | no    |

可以看到，两个DHCPv6客户端实现的DUID都使用LLT方式生成，因此我们可以期
望通过被动扫描的方式获取目标主机初次加入网络的时间。此外，我们还可以通
过VendorClass识别Windows设备。

## 定界效果

我们引入准确率作为衡量一个定界算法效果的指标：假设真实的地址池为[a, b]，
定界算法得到的地址池为[a', b']，则准确率为 1 - (|a' - a| + |b' - b|) /
(b - a)。

我们先通过仿真实验模拟真实环境，测试三个算法在不同环境、不同参数下的准
确率。模拟环境的地址分配方式在测试DeHCP时为线性，否则为随机，地址池大
小为48位，网络规模为1000，如果有必要，我们将分别模拟30%、50%、70%的离
线主机比例。

DeHCP定界算法：

| 窗口\离线主机比例 | 30%   | 50%    | 70%    |
|-------------------|-------|--------|--------|
| 1                 | 99.8% | 91.16% | 53%    |
| 2                 | 99.8% | 93.96% | 83.22% |
| 3                 | 99.8% | 98.54% | 94.86% |
| 4                 | 99.8% | 99.7%  | 98.7%  |

基于Rebind的定界算法：

| 主机离线比例 | 30%  | 50%  | 70%  |
|--------------|------|------|------|
| 准确率       | 100% | 100% | 100% |

基于Solicit的定界算法：

| 请求次数 | 32     | 64     | 128    | 256    |
|----------|--------|--------|--------|--------|
| 准确率   | 96.34% | 97.93% | 98.97% | 99.49% |

DeHCP定界算法在离线主机比例高达70%的环境下也有不错的效果，我们选择3作
为默认的窗口大小。在庞大的地址池里可以少到忽略不计的漏点很难对基于
Rebind的定界算法产生影响。基于Solicit的定界算法不受离线主机比例的影响，
且当请求次数为32时已有不错的效果，我们选择64作为默认的请求次数。

我们再在实际环境中测试Bisers对不同DHCPv6服务端实现的准确率。对于使用线
性地址分配的TPLINK路由器，我们直接在有数十台设备的真实环境中测试。对于
其它实现，如果需要手动配置地址池，则使用24位的地址池大小，否则使用默认
的地址池大小，然后预先申请1000个地址再测试。

| 服务端 | Cisco | TPLINK | Openwrt | Windows | ISC  |
|--------|-------|--------|---------|---------|------|
| 准确率 | 99.2% | 100%   | 96.9%   | 99.1%   | 100% |

可以看到，我们提出的Bisers定界方案对目前主流的DHCPv6服务端实现普遍有效。

# 安全建议

1. 为防范被动扫描，交换机应提供类似于DHCP Snooping的技术对多播的DHCPv6
   报文作特殊处理，只向可信的端口转发这些报文。为DHCPv6服务器设置一个
   足够大的T1也可以增加被动扫描的时间周期。
2. 为防范主动扫描，DHCPv6服务器应使用随机分配地址，且使用的地址池应大
   到不可扫描。
3. 针对扫描的附加信息，DHCPv6客户端应避免通过DUID和VendorClass泄露信息。
   DUID应使用UUID等不包含具体信息的方式生成，且为避免追踪应定时更换。

# 总结及进一步工作

我们提出了一个扫描由DHCPv6管理的IPv6网络的方案，包含被动扫描和主动扫描
两种方法。作为主动扫描的一个重要部分，我们提出了一个完善的DHCPv6定界方
案，对几乎所有DHCPv6服务端实现都可以快速地完成准确地定界，但其对于主动
扫描的帮助取决于DHCPv6服务器的配置。我们还总结了通过DHCPv6协议可以收集
到哪些附加信息，DHCPv6协议在设计和实现上的隐私缺陷，以及如何避免这些缺
陷。

进一步的工作有两个方向，一个是研究基于机器学习的扫描方法对使用随机分配
地址的DHCPv6服务端实现的有效性，另一个是研究被动扫描使用DHCPv6中继的网
络。

# 参考文献

[1] S. Groat, M. Dunlop, R. Marchany, J. Tront, What DHCPv6 says about
you // Proceedings of the World Congress on Internet Security
(WorldCIS), London, UK, 2011: 146-151

[2] E. Bergenholtz, A. Moss, D. Ilie, E. Casalicchio, Finding a needle
in a haystack: A comparative study of IPv6 scanning methods //
Proceedings of the International Symposium on Networks, Computers and
Communications (ISNCC), New York, USA, 2019
