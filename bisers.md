# 摘要

Bisers：一种高效的DHCPv6地址池边界探测方案

Bisers: An efficient DHCPv6 address pool boundary detection solution

本文提出了两个DHCPv6定界算法，并且结合一个已经提出的定界算法，提出了一
种高效的DHCPv6地址池定界方案。该方案对目前主流的DHCPv6服务端实现都可以
在几秒钟内准确地定界。DHCPv6定界可以直接帮助IPv6网络扫描，也可能有更多
应用。

In this paper, two DHCPv6 delimitation algorithms are proposed, and
combined with an already proposed delimitation algorithm, an efficient
DHCPv6 address pool delimitation solution is proposed. This solution
can accurately delimit the current mainstream DHCPv6 server
implementations within a few seconds. DHCPv6 delimitation can directly
help IPv6 network scanning, and may have more applications.

# 引言

扫描网络中存活的主机是资产管理与渗透测试的一个重要组成部分。IPv4看似庞
大的32位地址空间可以用Zmap、masscan等无状态扫描工具在几小时内扫描完成，
扫描一个常见的8位或16位的子网只要几分钟。网络管理员和安全工程师们已经
习惯于用网络扫描工具扫描出所有存活的主机，扫描这些主机开放了哪些服务，
有哪些安全隐患，然后进行安全维护或渗透测试。 在过去IPv4盛行的时代人们
从未认为探测一个网络中有多少存活的主机是一个问题。然而对于IPv6而言，这
个任务因其庞大的地址空间而变得无比艰巨。随着IPv6的普及，寻找有效的IPv6
网络扫描方法变得日益重要。

IPv6地址配置分为手动配置和自动配置，自动配置又分为SLAAC（StateLess
Address AutoConfiguration）无状态地址自动配置、无状态DHCPv6和有状态
DHCPv6。虽然SLAAC和无状态DHCPv6已经足以方便地配置网络，但是管理困难。
有状态DHCPv6因其易于管理而被广泛使用，尤其是在大型网络中。

针对使用DHCPv6管理的IPv6网络，DHCPv6定界方法可以帮助缩小网络扫描的地址
空间，有效地提高网络扫描的效率：假设我们可以快速探测DHCPv6服务器的地址
池的边界，对该IPv6网络的扫描就缩小到对该地址池的扫描，之后可以用邻居发
现协议扫描地址池内存活的地址。

## 相关工作

### DHCPv6被动扫描

DHCPv6客户端、中继发送给服务端的报文是多播的，一个DHCPv6报文从客户端经
过多个中继到达服务端所经过的所有局域网中的所有主机都会收到该报文。攻击
者可以通过嗅探DHCPv6报文收集网络中的资产信息，这是一种十分有效的被动扫
描：一方面，这些DHCPv6报文中除了地址，还包含丰富的信息：DUID、源MAC地
址可以帮助攻击者跨网络识别和追踪一台设备，Vendor Class选项可以帮助攻击
者识别设备的硬件和操作系统；另一方面，这种被动扫描相比于其它同类型的方
法更稳定。按照约定，DHCPv6客户端要在T1时间内续租地址。活跃的节点在T1时
间内必定发送Request、Renew、Confirm中的一个报文。攻击者可以先检查服务
端的T1值，然后可以期望在T1时间内收集到网络中所有的资产信息。更多内容可
以参考Stephen等人的工作[ref: dhcpv6sniff]。

基于DHCPv6的被动扫描也有缺陷：有些DHCPv6客户端实现默认的T1值长达数天，
其它实现也支持网络管理员设置一个很大的T1值来增长网络嗅探的周期；此外，
交换机也可以使用类似DHCP Snooping的技术对DHCPv6报文作特殊处理，不向非
信任端口转发DHCPv6请求报文来避免这种嗅探。

### DeHCP

Bergenholtz等人提出了一个DHCPv6定界算法DeHCP[ref: dehcp]：该算法基于部
分DHCPv6服务端实现未经仔细的安全考虑便沿用DHCPv4的实现方式使用线性分配
地址，使用二分搜索探测密集的地址空间的边界。

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
DHCPv6服务端实现（见3节），发现虽然中国市场上常见的家用路由器实现都使
用线性分配地址，但是几个主流的商用路由器实现和主要的软件实现使用更安全
的随机分配地址，因此DeHCP的使用场景受到了更严格的限制。

## 主要工作

为改进DeHCP无法探测使用随机分配地址的DHCPv6服务端实现的地址池的不足，
本研究首先提出了两个适用于这些实现的DHCPv6定界算法，分别为基于DHCPv6
Rebind的精确定界算法和更通用的基于DHCPv6 Solicit的模糊定界算法。之后，
我们综合了以上三个DHCPv6定界算法，提出了一个高效的且适用于几乎所有常见
的DHCPv6服务端实现的DHCPv6地址池探测方案：Bisers（Binary search &
rebind & solicit）。我们给出了一个该方案在Linux平台的参考实现
[https://github.com/vhqr0/bisers]。

# Bisers

## 基于Rebind的DHCPv6定界算法

参考RFC3315,当DHCPv6服务端收到Rebind报文时，首先在其数据库中寻找相应的
记录，若未发现，服务端应响应一个包含该地址的Reply报文，并根据该地址是
否符合其地址分配策略设置该相应的有效时间。基于这种机制，我们提出一种基
于DHCPv6 Rebind的DHCPv6服务端地址池边界二分搜索算法。考虑到在地址池中
某个地址已经被分配的情况下，我们用Rebind报文请求该地址，DHCPv6服务端会
认为这个地址不符合其地址分配策略，与处理地址池之外的地址的表现方式一致，
所以我们在探测一个地址是否在服务端的地址池中时，首先检查这个地址是否在
已请求到的地址缓存中，若失败，再用Rebind探测，若还失败，再用邻居发现协
议探测这个地址是否被某个存活的节点占用。

```python
def rdelimit(l, u, h):
  return rllimit(l, h), rulimit(h, u)

def rllimit(l, u):
  host = (l + u) / 2
  if l >= u then return host
  if cached(host) or rebind(host) or nd(host)
    then return rllimit(l, host-1)
    else return rllimit(host+1, u)

def rulimit(l, u):
  host = (l + u) / 2
  if l >= u then return host
  if cached(host) or rebind(host) or nd(host)
    then return rulimit(host+1, u)
    else return rulimit(l, host-1)
```

该算法考虑到已经被分配的地址，但是仍有不足：可能有节点请求到地址后便无
法被探活，或者服务端配置中显式排除掉一些地址。这导致我们探测的地址池中
存在一些漏点，但是在庞大的地址池中分散的取不超过128个点碰撞到这些漏点
的概率很低，而且可以通过多次探测避免。

不难看出，当搜索空间限制在64位子网内时，该算法可以通过不超过128次
Rebind请求，在几秒钟的时间内完成精确地DHCPv6定界，前提是服务端实现遵循
RFC3315的规范诚实地向Rebind请求反映自己的地址池信息。

虽然在理论上很完美，但是实际测试（见3节）时发现只有一个常见的DHCPv6服
务端实现：ISC DHCP Server：类UNIX系统中著名的dhcpd，可以用Rebind探测地
址池，其它实现都避免了在响应Rebind时泄露地址池信息。因此，我们又提出了
另一种不那么完美但是普遍有效的算法。

## 基于Solicit的DHCPv6定界算法

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

经过实际测试（见3节），该算法在几个使用随机分配地址的DHCPv6服务端实现
中都十分有效。

## Bisers

综合利用三个DHCPv6定界算法，我们提出了一个完善的DHCPv6地址池探测方案
bisers： 首先，通过连续申请两次地址检测DHCPv6服务器是否使用线性分配地
址，如果是则使用DeHCP定界。如果不是则再尝试通过用Rebind请求首次分配的
地址附近的地址检测DHCPv6服务器是否可以用Rebind探测地址池信息，如果是则
使用基于Rebind的算法定界。如果不是则使用基于Solicit的算法定界。

```python
def bisers(w, n):
  h = solicit()
  if h + 1 == solicit() then return ddelimit(netmin(h), netmax(h), h, w)
  if rebind(h+1) or rebind(h-1) then return rdelimit(netmin(h), netmax(h), h)
  return sdelimit(h, n)
```

经过实际测试（见3节），该方案已覆盖常见的DHCPv6服务端实现。

# 实验及分析

## 实验设计

我们选择以下DHCPv6服务端实现作为测试对象。家用路由器实现：TP-Link；商
用路由器实现：Cisco；软件实现：ISC DHCP Server、Windows DHCP Server、
odhcpd/openwrt。

对这些实现，我们首先介绍测试使用的版本和实验环境。然后进行初步分析，检
查地址配置方式（线性、随机或者？）和对Rebind请求的处理。最后对所有使用
随机分配地址的实现测试基于Solicit的定界算法，并对其中可以用Rebind探测
地址池的实现测试基于Rebind的定界算法并与前者比较。

我们使用三个度量评价一个定界算法：发送报文的数量，准确率和扫描准确率。
首先，我们把探测的边界与真实的边界的差占真实地址池大小的比率作为不同地
址池大小的定界效果的一个统一度量，即准确率；其次，我们还引入扫描准确率，
考虑到这样的情况：在某些不使用统计学随机分配地址的实现中，假设其分配的
地址向地址池的中点集中，会造成我们探测到的地址池偏小，边界准确率偏低，
但并不代表其扫描效果更差。我们预先申请大量地址，然后统计这些地址查在探
测到的地址池中的占这些地址的比例作为扫描准确率。扫描准确率将真实地反映
定界算法应用在网络扫描中的效果。

## 初步分析

TP-Link家用无线路由器是中国家用无线路由器市场的代表，我们测试使用2020
年生产的TL-XDR1860型号的真实路由器。经过测试，该路由器的DHCPv6服务端实
现使用线性分配地址。

Cisco商用路由器是全球商用路由器市场的代表，我们测试使用的Cisco IOS镜像
的版本为15.2，测试环境是使用EVE-NG模拟的虚拟网络。经过测试，该路由器的
DHCPv6服务端实现使用随机分配地址，对于伪造的Rebind请求，响应的Reply不
包含IAAddress选项。

odhcpd：广泛使用的软路由系统openwrt内置的DHCP服务器软件，我们测试使用
的openwrt版本为19.07。经过测试，该软件实现使用随机分配地址，对于伪造的
Rebind请求，odhcpd不会接受请求的地址并分配新的地址。在测试时我们还发现
odhcpd与其它实现的不同：首先，odhcpd有防止DOS攻击的机制，收到大量请求
时会停止服务一端时间，导致我们在每一次DHCPv6请求后睡眠1秒绕过DOS攻击检
测，大幅延长了定界的时间；其次，我们发现odhcpd无法配置地址池，接口ID在
0x10c~0xff3间随机生成，且不缓存响应Solicit分配的地址。当基于Solicit的
定界算法的请求次数超过64次时，我们总是可以得到精确的边界与请求次数对应
的边界，因此我们不再深入测试此实现。

ISC DHCP Server：类UINX系统下使用最广泛的著名的dhcpd，我们测试使用的版
本为4.4.1。经过测试，该软件实现使用随机分配地址，会向Rebind请求诚实地
反映地址池信息。

Windows DHCP Server：Windows Server内置的DHCP服务器软件，我们测试使用
的Windows Server版本为2016。经过测试，该软件实现使用随机分配地址，不会
响应伪造Rebind请求。

## 实验

我们首先测试基于Solicit的DHCPv6定界算法。对于ISC DHCP Server、Windows
DHCP Server、Cisco路由器这三个DHCPv6服务端实现，我们测试不同请求次数：
32、64、96、128和160的定界算法的准确率和扫描准确率，结果如下：

准确率：

| 请求次数 | ISC DHCP Server | Windows DHCP Server | Cisco |
|----------|-----------------|---------------------|-------|
| 32       | 0.954           | 0.971               | 0.961 |
| 64       | 0.984           | 0.991               | 0.992 |
| 96       | 0.988           | 0.993               | 0.993 |
| 128      | 0.989           | 0.995               | 0.994 |
| 160      | 0.991           | 0.997               | 0.994 |

扫描准确率：

| 请求次数 | ISC DHCP Server | Windows DHCP Server | Cisco |
|----------|-----------------|---------------------|-------|
| 32       | 0.982           | 0.969               | 0.967 |
| 64       | 0.998           | 0.991               | 0.996 |
| 96       | 0.998           | 0.993               | 0.997 |
| 128      | 0.997           | 0.995               | 0.998 |
| 160      | 0.997           | 0.998               | 0.998 |

观察到基于Solicit的DHCPv6定界算法当请求次数超过64次就已经有可观的准确
率和扫描准确率。

我们再测试基于Rebind的DHCPv6定界算法。在本文测试的几个DHCPv6服务端实现
中仅ISC DHCP Server可以测试。经过几次测试，基于Rebind的DHCPv6定界算法
用86~87个DHCPv6 Rebind报文就可以精确地定界，准确率和扫描准确率都为100%。

## 实验分析

我们把测试的DHCPv6服务端实现按实验结果分为三类：首先是TP-Link路由器，
使用线性分配地址，Bisers对于该类实现使用DeHCP定界，其效果已在相关工作
中充分讨论；然后是ISC DHCP Server，使用随机分配地址，是测试中唯一一个
可以用Rebind定界的实现，可以用基于Rebind的定界算法通过少量报文精确定界；
最后是odhcpd、Windows DHCP Server和Cisco路由器，使用随机分配地址，且不
可以用Rebind定界。Bisers对于这些实现使用基于Solicit的定界算法，虽然无
法精确定界，但请求次数为64时已经相当准确，且发送的报文的数量要少于基于
Rebind的定界算法。

综合以上结论，Bisers已覆盖本研究测试的几个常见的DHCPv6服务端实现，且探
测使用的报文少，探测时间除了有DOS保护的odhcpd需要几分钟，其它实现只需
要几秒钟，探测到的边界的准确率和测试准确率高于98%。

# 总结及进一步工作

我们提出了一个DHCPv6地址池探测方案，对几乎所有的DHCPv6服务端实现上都可
以快速地完成准确的DHCPv6定界，但是否可能成为DHCPv6服务器的一个弱点还要
看其使用的地址池的大小，如果低于32位，则扫描这个网络并不比扫描整个IPv4
网络困难。因此，我们强烈建议网络管理员在有安全需求的场景中使用的地址池
的大小不要低于48位。

需要指出的是，我们简单假设DHCPv6服务端地址生成是在统计学上随机的，关于
基于Solicit的DHCPv6定界方法对使用符合其它的概率分布模型的地址生成方式
的DHCPv6服务端实现的有效性以及可能带来的安全隐患还可以做进一步研究；此
外，关于DHCPv6定界在网络扫描之外的应用也有待研究。

# 参考文献

[1] S. Groat, M. Dunlop, R. Marchany, J. Tront, What DHCPv6 says about
you // Proceedings of the World Congress on Internet Security
(WorldCIS), London, UK, 2011: 146-151

[2] E. Bergenholtz, A. Moss, D. Ilie, E. Casalicchio, Finding a needle
in a haystack: A comparative study of IPv6 scanning methods //
Proceedings of the International Symposium on Networks, Computers and
Communications (ISNCC), New York, USA, 2019
