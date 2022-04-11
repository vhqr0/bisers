#include <endian.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>

#include <linux/if_ether.h>

#include <pcap.h>

void help() {
  puts("Usage: ddhcp6 [-i INTERFACE] [-v] [-t TIMEOUT] [-c COUNT]");
  puts("              {-h | -r | -s[COUNT] | -n}");
  puts("-h, --help          show this  message");
  puts("-i, --interface     specified interface, default via pcap");
  puts("-v, --verbose       specified debuginfo during delimit");
  puts("-t, --timeout       specified timeout, default to 100 (ms)");
  puts("-c, --count         specified delimit times, default to 1");
  puts("-r, --rebind        delimit by rebind");
  puts("-s, --solicit       delimit by solicit, default deeps to 200");
  puts("-n, --no-delimit    no delimit, just solicit once (default)");
}

const char *iface = NULL, *addr = NULL;
int verbose = 0, timeout = 100, count = 1, solicit_count = 200;
enum { rebind, solicit, solicit_once } mode = solicit_once;
char errbuf[PCAP_ERRBUF_SIZE] = {0}, ntopbuf[INET6_ADDRSTRLEN];

void parseargs(int argc, char **argv) {
  pcap_if_t *alldevs, dev;
  int opt, optind;
  struct option options[] = {{"help", no_argument, NULL, 'h'},
                             {"interface", required_argument, NULL, 'i'},
                             {"verbose", no_argument, NULL, 'v'},
                             {"timeout", required_argument, NULL, 't'},
                             {"count", required_argument, NULL, 'c'},
                             {"rebind", no_argument, NULL, 'r'},
                             {"solicit", optional_argument, NULL, 's'},
                             {"no-delimit", no_argument, NULL, 'n'}};

  while ((opt = getopt_long(argc, argv, "hi:vt:c:rs::n", options, &optind)) >
         0) {
    switch (opt) {
    case 'h':
      help();
      exit(0);
    case 'i':
      iface = optarg;
      break;
    case 'v':
      verbose = 1;
      break;
    case 't':
      timeout = atoi(optarg);
      break;
    case 'c':
      count = atoi(optarg);
      break;
    case 'r':
      mode = rebind;
      break;
    case 's':
      mode = solicit;
      if (optarg)
        solicit_count = atoi(optarg);
      break;
    case 'n':
      mode = solicit_once;
      break;
    default:
      fprintf(stderr, "unknown option: %c\n", opt);
      exit(-1);
    }
  }
  if (!iface) {
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
      fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
      exit(-1);
    }
    if (!alldevs) {
      fprintf(stderr, "no dev found\n");
      exit(-1);
    }
    dev = *alldevs;
    iface = dev.name;
  }
}

/* sall:   lladdress (iface index)
 * sockfd: handler to send pkt
 * pkt:    packet
 * ethhdr: eth header pointer to pkt
 * ip6hdr: ip6 header pointer to pkt
 * buf:    ip6 payload pointer to pkt
 * mtu:    pkt max size
 * cap:    buf max size
 * cur:    buf current size
 */

#define HDRSIZE (sizeof(struct ethhdr) + sizeof(struct ip6_hdr))

struct sockaddr_ll sall;
int sockfd, mtu, cap, cur;
uint8_t *pkt = NULL, *buf = NULL;
struct ethhdr *ethhdr = NULL;
struct ip6_hdr *ip6hdr = NULL;

void ddsend_init() {
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket failed");
    exit(-1);
  }
  if (ioctl(sockfd, SIOCGIFINDEX, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFINDEX failed");
    exit(-1);
  }
  memset(&sall, 0, sizeof(sall));
  sall.sll_ifindex = ifr.ifr_ifindex;
  if (ioctl(sockfd, SIOCGIFMTU, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFMTU failed");
    exit(-1);
  }
  mtu = ifr.ifr_mtu;
  if (mtu < 1280) {
    fprintf(stderr, "interface mtu too small: %d\n", mtu);
    exit(-1);
  }
  pkt = (uint8_t *)malloc(mtu);
  memset(pkt, 0, mtu);
  ethhdr = (struct ethhdr *)pkt;
  ip6hdr = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
  buf = pkt + HDRSIZE;
  cap = mtu - HDRSIZE;
  cur = 0;
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFHWADDR failed");
    exit(-1);
  }
  memcpy(ethhdr->h_source, ifr.ifr_hwaddr.sa_data, 6);
  ethhdr->h_proto = htons(ETH_P_IPV6);
  ip6hdr->ip6_src.s6_addr[0] = 0xfe;
  ip6hdr->ip6_src.s6_addr[1] = 0x80;
  memcpy(ip6hdr->ip6_src.s6_addr + 8, ethhdr->h_source, 3);
  ip6hdr->ip6_src.s6_addr[8] ^= 2;
  ip6hdr->ip6_src.s6_addr[11] = 0xff;
  ip6hdr->ip6_src.s6_addr[12] = 0xfe;
  memcpy(ip6hdr->ip6_src.s6_addr + 13, ethhdr->h_source + 3, 3);
  ip6hdr->ip6_vfc = 0x60;
  ip6hdr->ip6_hlim = 0xff;
}

/* send pkt
 * target mac:     mac
 * target ip:      prefix+id
 * payload length: cur
 * next header:    nxt
 * payload:        buf
 */

#define NXT_UDP 0x11
#define NXT_ICMP 0x3a

void ddicmp6cksum();
void ddudpcksum();

void ddsend(uint64_t mac, uint64_t prefix, uint64_t id, uint8_t nxt) {
  mac = htobe64(mac);
  memcpy(ethhdr->h_dest, ((uint8_t *)&mac) + 2, 6);
  ((uint64_t *)&ip6hdr->ip6_dst.s6_addr)[0] = htobe64(prefix);
  ((uint64_t *)&ip6hdr->ip6_dst.s6_addr)[1] = htobe64(id);
  ip6hdr->ip6_plen = htons(cur);
  ip6hdr->ip6_nxt = nxt;
  switch (nxt) {
  case NXT_ICMP:
    ddicmp6cksum();
    break;
  case NXT_UDP:
    ddudpcksum();
    break;
  }
  if (sendto(sockfd, pkt, cur + HDRSIZE, 0, (struct sockaddr *)&sall,
             sizeof(sall)) < 0) {
    perror("send failed");
    exit(-1);
  }
}

/* udp checksum
 * ip6 src || ip6 udp || nxt(2) || plen(2) || buf
 */
void ddudpcksum() {
  uint32_t sum = 0;
  uint16_t *p = (uint16_t *)buf;
  int c = cur;

  for (int i = 0; i < 8; i++)
    sum += htons(*(((uint16_t *)ip6hdr->ip6_src.s6_addr) + i));
  for (int i = 0; i < 8; i++)
    sum += htons(*(((uint16_t *)ip6hdr->ip6_dst.s6_addr) + i));
  sum += NXT_UDP;
  sum += cur;

  while (c > 1) {
    sum += htons(*p++);
    c -= 2;
  }

  if (c)
    sum += *(uint8_t *)p << 8;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += sum >> 16;

  ((struct udphdr *)buf)->check = ntohs(~sum);
}

/* icmpv6 checksum
 * buf || ip6 src || ip6 dst || plen(4) || nxt(4)
 */
void ddicmp6cksum() {
  uint32_t sum = 0;
  uint16_t *p = (uint16_t *)buf;
  int c = cur + 40;

  memcpy(buf + cur, ip6hdr->ip6_src.s6_addr, 16);
  memcpy(buf + cur + 16, ip6hdr->ip6_dst.s6_addr, 16);
  buf[cur + 34] = cur >> 8;
  buf[cur + 35] = cur;
  buf[cur + 39] = NXT_ICMP;

  while (c > 1) {
    sum += ntohs(*p++);
    c -= 2;
  }

  if (c)
    sum += *(uint8_t *)p << 8;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += sum >> 16;

  ((struct icmp6_hdr *)buf)->icmp6_cksum = htons(~sum);
}

/* pcap:           pcap capture handler
 * pfd:            pcap handler selectable fd
 * ddselect_flag:  flag should be set by callback to break select loop
 * nafilter:       pcap filter for neighbor advertise
 * dhcpfilter:     pcap filter for dhcp reply
 */

#define NAFILTER "icmp6[icmp6type]==icmp6-neighboradvert"
#define DHCPFILTER "ip6 and udp src port 547 and udp dst port 546"

pcap_t *pcap = NULL;
int pfd, ddselect_flag = 0;
struct bpf_program nafilter, dhcpfilter;

void ddselect_init() {
  if (!(pcap = pcap_open_live(iface, mtu, 0, -1, errbuf))) {
    fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
    exit(-1);
  }
  if (*errbuf)
    fprintf(stderr, "pcap_open_live warnning: %s\n", errbuf);
  if (pcap_setnonblock(pcap, 1, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(-1);
  }
  if ((pfd = pcap_get_selectable_fd(pcap)) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_get_selectable_fd failed");
    exit(-1);
  }
  if (pcap_compile(pcap, &nafilter, NAFILTER, 1, 0) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_compile failed");
    exit(-1);
  }
  if (pcap_compile(pcap, &dhcpfilter, DHCPFILTER, 1, 0) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_compile failed");
    exit(-1);
  }
}

void ddselect_set_filter(struct bpf_program *filter) {
  if (pcap_setfilter(pcap, filter) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_setfilter failed");
    exit(-1);
  }
}

/* pcap capture with callback until ddselect_flag is set or timeout */
void ddselect(pcap_handler callback) {
  fd_set rfds;
  struct timeval tv;

  ddselect_flag = 0;
  tv.tv_sec = 0;
  tv.tv_usec = timeout << 10;

  while (!ddselect_flag && (tv.tv_usec || tv.tv_sec)) {
    FD_ZERO(&rfds);
    FD_SET(pfd, &rfds);
    switch (select(pfd + 1, &rfds, NULL, NULL, &tv)) {
    case 1:
      pcap_dispatch(pcap, 1, callback, NULL);
      break;
    case -1:
      perror("select failed");
      exit(-1);
      break;
    }
  }
}

/* ddnd send neighbor solicit, and set ddnd_id to discovery id,
 * ddnd_callback check the neighbor advertise and set ddselect_flag to 1.
 */

uint64_t ddnd_id;

void ddnd_callback(u_char *user, const struct pcap_pkthdr *h,
                   const u_char *bytes) {
  struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(bytes + sizeof(struct ethhdr));
  struct nd_neighbor_advert *nahdr =
      (struct nd_neighbor_advert *)(bytes + HDRSIZE);

  if (h->caplen < HDRSIZE + sizeof(struct nd_neighbor_advert) ||
      be64toh(*((uint64_t *)(nahdr->nd_na_target.s6_addr + 8))) != ddnd_id)
    return;

  ddselect_flag = 1;
}

/* alive check via neighbor discovery, discovery address: dprefix + did */
int ddnd(uint64_t dprefix, uint64_t did) {
  uint64_t mac = 0x3333ff000000 + (did & 0xffffff);
  uint64_t prefix = 0xff02000000000000;
  uint64_t id = 0x1ff000000 + (did & 0xffffff);
  struct nd_neighbor_solicit *nshdr = (struct nd_neighbor_solicit *)buf;

  memset(buf, 0, cap);
  nshdr->nd_ns_type = ND_NEIGHBOR_SOLICIT;
  ((uint64_t *)&nshdr->nd_ns_target.s6_addr)[0] = htobe64(dprefix);
  ((uint64_t *)&nshdr->nd_ns_target.s6_addr)[1] = htobe64(did);
  cur = sizeof(struct nd_neighbor_solicit);
  buf[cur++] = 1;
  buf[cur++] = 1;
  memcpy(buf + cur, ethhdr->h_source, 6);
  cur += 6;
  ddnd_id = did;
  ddselect_set_filter(&nafilter);
  ddsend(mac, prefix, id, NXT_ICMP);
  ddselect(ddnd_callback);
  return ddselect_flag;
}

/* dhcp_cache:   cache for allocated addr
 * cduid:        client id option
 * sduid:        server id option
 * trid, iaid:   dhcp solicit/rebind id
 * dhcpip:       dhcp server address
 * dhcpaip:      dhcp allocated address, dhcpprefix + dhcpaid
 * solicited:    if have solicited, we want track the same server
 */

#define DHCP_CACHE_SIZE 128
uint64_t dhcp_cache[DHCP_CACHE_SIZE];
int dhcp_cache_cur = 0;

#define DUID_MAX_LEN 128
uint8_t cduid[DUID_MAX_LEN], sduid[DUID_MAX_LEN];
int cduidlen, sduidlen;

uint32_t trid, iaid;
struct in6_addr dhcpip, dhcpaip;
uint64_t dhcpprefix, dhcpaid;
uint32_t dhcpt1, dhcpt2, dhcppreferedtime, dhcpvalidtime;

int solicited = 0;

/* check dhcp advertise and set dhcp delimit parameters.  cduid is
 * initialized by ddsolicit, trid/iaid is randomized generated every
 * time call ddsolicit and ddrebind.  ddsolicit_callback check
 * serverid option and set sduid, and, check iana option and set
 * dhcpprefix, t1, t2, validtime and preferedtime.  the solicited
 * address shoud append to dhcp_cache.
 */
void ddsolicit_callback(u_char *user, const struct pcap_pkthdr *h,
                        const u_char *bytes) {
  struct ip6_hdr *ip6hdr =
      (struct ip6_hdr *)((uint8_t *)bytes + sizeof(struct ethhdr));
  struct udphdr *udphdr = (struct udphdr *)((uint8_t *)bytes + HDRSIZE);
  uint8_t *c = (uint8_t *)bytes + HDRSIZE + sizeof(struct udphdr);
  int cr = h->caplen - HDRSIZE - sizeof(struct udphdr), cl;
  int fcid = 0, fsid = 0, fiana = 0;

  if (cr < 4 || ip6hdr->ip6_nxt != NXT_UDP || c[0] != 2 ||
      memcmp(c + 1, &trid, 3))
    return;
  memcpy(dhcpip.s6_addr, ip6hdr->ip6_src.s6_addr, 16);
  c += 4;
  cr -= 4;
  while (cr) {
    if (cr < 4)
      return;
    cl = (c[2] << 8) + c[3] + 4;
    if (cr < cl)
      return;
    switch (c[1]) {
    case 1: /* client id */
      if (fcid) {
        return;
      } else {
        if (cl != cduidlen || memcmp(c, cduid, cduidlen))
          return;
        fcid = 1;
      }
      break;
    case 2: /* server id */
      if (fsid) {
        return;
      } else {
        if (solicited) {
          if (cl != sduidlen || memcmp(c, sduid, sduidlen))
            return;
          fsid = 1;
        } else {
          if (cl > DUID_MAX_LEN)
            return;
          memcpy(sduid, c, cl);
          sduidlen = cl;
        }
        fsid = 1;
      }
      break;
    case 3: /* iana */
      if (fiana) {
        return;
      } else {
        if (cl < 44 || c[17] != 5 || c[19] != 24) /* check if with iaaddr */
          return;
        if (solicited) {
          if (be64toh(*(uint64_t *)(c + 20)) != dhcpprefix)
            return;
          dhcpaid = be64toh(*(uint64_t *)(c + 28));
          if (dhcp_cache_cur < DHCP_CACHE_SIZE)
            dhcp_cache[dhcp_cache_cur++] = dhcpaid;
        } else {
          dhcpt1 = be32toh(*(uint32_t *)(c + 8));
          dhcpt2 = be32toh(*(uint32_t *)(c + 12));
          memcpy(dhcpaip.s6_addr, c + 20, 16);
          dhcppreferedtime = be32toh(*(uint32_t *)(c + 36));
          dhcpvalidtime = be32toh(*(uint32_t *)(c + 40));
          dhcpprefix = be64toh(*(uint64_t *)(c + 20));
          dhcpaid = be64toh(*(uint64_t *)(c + 28));
          if (dhcp_cache_cur < DHCP_CACHE_SIZE)
            dhcp_cache[dhcp_cache_cur++] = dhcpaid;
        }
        fiana = 1;
      }
      break;
    }
    c += cl;
    cr -= cl;
  }

  if (fcid && fsid && fiana)
    ddselect_flag = 1;
}

/* find dhcp server and initialize dhcp delimit parameters */
int ddsolicit(int required) {
  uint64_t mac = 0x333300010002;
  uint64_t prefix = 0xff02000000000000;
  uint64_t id = 0x10002;
  struct udphdr *udphdr = (struct udphdr *)buf;

  memset(cduid, 0, DUID_MAX_LEN);
  memset(sduid, 0, DUID_MAX_LEN);
  cduid[1] = 1; /* client id */
  cduid[3] = 10;
  cduid[5] = 3;
  cduid[7] = 1;
  memcpy(cduid + 8, ethhdr->h_source, 6);
  cduidlen = 14;

  memset(buf, 0, cap);
  udphdr->source = htons(546);
  udphdr->dest = htons(547);
  cur = sizeof(struct udphdr);

  trid = random();
  iaid = random();
  buf[cur] = 1;
  memcpy(buf + cur + 1, &trid, 3);
  cur += 4;
  memcpy(buf + cur, cduid, cduidlen);
  cur += cduidlen;
  buf[cur + 1] = 8; /* elapsed time */
  buf[cur + 3] = 2;
  cur += 6;
  buf[cur + 1] = 3; /* ia-na */
  buf[cur + 3] = 12;
  memcpy(buf + cur + 4, &iaid, 4);
  cur += 16;
  buf[cur + 1] = 6; /* optreq */
  buf[cur + 3] = 4;
  buf[cur + 5] = 23; /* optreq: dns */
  buf[cur + 7] = 24; /* optreq: localdomain */
  cur += 8;

  udphdr->len = htons(cur);
  ddselect_set_filter(&dhcpfilter);
  ddsend(mac, prefix, id, NXT_UDP);
  ddselect(ddsolicit_callback);
  if (required && !ddselect_flag) {
    fprintf(stderr, "can't find dhcp server\n");
    exit(-1);
  }
  return ddselect_flag;
}

/* ddrebind send dhcp rebind, and set ddrebind_flag to zero,
 * ddrebind_callback check the dhcp reply iana option,
 * if with one address, just set ddselect_flag and return,
 * if with two addresses, set allocated address to ddrebind_flag and return.
 * ddrebind check both ddselect_flag and ddrebind_flag to draw a result.
 * the allocated address should append to dhcp_cache.
 */

int ddrebind_flag;

void ddrebind_callback(u_char *user, const struct pcap_pkthdr *h,
                       const u_char *bytes) {
  struct ip6_hdr *ip6hdr =
      (struct ip6_hdr *)((uint8_t *)bytes + sizeof(struct ethhdr));
  struct udphdr *udphdr = (struct udphdr *)((uint8_t *)bytes + HDRSIZE);
  uint8_t *c = (uint8_t *)bytes + HDRSIZE + sizeof(struct udphdr);
  int cr = h->caplen - HDRSIZE - sizeof(struct udphdr), cl;

  if (cr < 4 || ip6hdr->ip6_nxt != NXT_UDP || c[0] != 7 ||
      memcmp(c + 1, &trid, 3))
    return;
  c += 4;
  cr -= 4;
  while (cr) {
    if (cr < 4)
      return;
    cl = (c[2] << 8) + c[3] + 4;
    if (cr < cl)
      return;
    if (c[1] == 3) {
      if (cl < 44 | c[17] != 5 || c[19] != 24)
        return;
      ddselect_flag = 1;
      if (*(uint32_t *)(c + 40)) /* check the first iaaddr's validtime */
        ddrebind_flag = 1;
      if (cl >= 72 && c[45] == 5 && c[47] == 24 &&
          dhcp_cache_cur <
              DHCP_CACHE_SIZE) /* check if another iaaddr was allocated */
        dhcp_cache[dhcp_cache_cur++] = (*(uint64_t *)(c + 56));
      return;
    }
    c += cl;
    cr -= cl;
  }
}

/* allocatable check via dhcp rebind, rebind address: dhcpprefix+rid */
int ddrebind(uint64_t rid) {
  uint64_t mac = 0x333300010002;
  uint64_t prefix = 0xff02000000000000;
  uint64_t id = 0x10002;
  struct udphdr *udphdr = (struct udphdr *)buf;

  memset(buf, 0, cap);
  udphdr->source = htons(546);
  udphdr->dest = htons(547);
  cur = sizeof(struct udphdr);

  trid = random();
  iaid = random();
  buf[cur] = 6;
  memcpy(buf + cur + 1, &trid, 3);
  cur += 4;
  memcpy(buf + cur, cduid, cduidlen);
  cur += cduidlen;
  buf[cur + 1] = 8; /* elapsed time */
  buf[cur + 3] = 2;
  cur += 6;
  buf[cur + 1] = 3; /* ia-na */
  buf[cur + 3] = 40;
  memcpy(buf + cur + 4, &iaid, 4);
  cur += 16;
  buf[cur + 1] = 5; /* iaaddr */
  buf[cur + 3] = 24;
  ((uint64_t *)(buf + cur + 4))[0] = htobe64(dhcpprefix);
  ((uint64_t *)(buf + cur + 4))[1] = htobe64(rid);
  cur += 28;

  udphdr->uh_ulen = htons(cur);
  ddrebind_flag = 0;
  ddselect_set_filter(&dhcpfilter);
  ddsend(mac, prefix, id, NXT_UDP);
  ddselect(ddrebind_callback);
  if (!ddselect_flag)
    return 0;
  return ddrebind_flag;
}

uint64_t llid, luid, ulid, uuid;

/* check dhcpprefix+cid is allocatable, via both ddrebind and ddnd */
int rebind_check(uint64_t cid) {
  if (verbose)
    printf("check %lx: ", cid);
  for (int i = 0; i < dhcp_cache_cur; i++)
    if (cid == dhcp_cache[i]) {
      if (verbose)
        puts("hit in cache");
      return 1;
    }
  if (ddrebind(cid)) {
    if (verbose)
      puts("hit in dhcp reply");
    return 1;
  }
  if (ddnd(dhcpprefix, cid)) {
    if (verbose)
      puts("hit in neighbor advertise");
    return 1;
  }
  if (verbose)
    puts("miss");
  return 0;
}

/* binary search lower/upper limit of dhcp server address pool */

uint64_t rebind_find_lower_limit() {
  uint64_t h = (llid >> 1) + (luid >> 1);
  if ((llid & 1) && (luid & 1))
    h++;
  if (llid + 1 >= luid)
    return h;
  if (rebind_check(h))
    luid = h;
  else
    llid = h;
  return rebind_find_lower_limit();
}

uint64_t rebind_find_upper_limit() {
  uint64_t h = (ulid >> 1) + (uuid >> 1);
  if ((ulid & 1) && (uuid & 1))
    h++;
  if (ulid + 1 >= uuid)
    return h;
  if (rebind_check(h))
    ulid = h;
  else
    uuid = h;
  return rebind_find_upper_limit();
}

/* repeat solicit address, find the min and the max */
void solicit_find_limit(int n) {
  uint64_t delta;

  if (!n)
    return;
  for (int i = 0; i < n; i++) {
    if (!ddsolicit(0)) {
      if (verbose)
        printf("lid: %lx, uid: %lx, solicit failed\n", luid, ulid);
      continue;
    }
    if (dhcpaid < luid)
      luid = dhcpaid;
    if (dhcpaid > ulid)
      ulid = dhcpaid;
    if (verbose)
      printf("lid: %lx, uid: %lx, solicited: %lx\n", luid, ulid, dhcpaid);
  }
  delta = 2 * (ulid - luid) / n;
  if (delta > luid)
    llid = 0;
  else
    llid -= delta;
  if (delta > 0xffffffffffffffff - ulid)
    uuid = 0xffffffffffffffff;
  else
    uuid += delta;
}

void ddprint_dhcp6() {
  solicited = 0;
  ddsolicit(1);
  solicited = 1;

  if (!inet_ntop(AF_INET6, dhcpip.s6_addr, ntopbuf, INET6_ADDRSTRLEN)) {
    perror("inet_ntop failed");
    exit(-1);
  }
  printf("DHCP IP: %s\n", ntopbuf);
  printf("DHCP DUID: ");
  for (int i = 4; i < sduidlen; i++)
    printf("%02x", sduid[i]);
  printf("\n");
  printf("DHCP T1: %d\n", dhcpt1);
  printf("DHCP T2: %d\n", dhcpt2);
  if (!inet_ntop(AF_INET6, dhcpaip.s6_addr, ntopbuf, INET6_ADDRSTRLEN)) {
    perror("inet_ntop failed");
    exit(-1);
  }
  printf("DHCP allocated: %s\n", ntopbuf);
  printf("DHCP prefered lifetime: %d\n", dhcppreferedtime);
  printf("DHCP valid lifetime: %d\n", dhcpvalidtime);

  switch (mode) {
  case solicit_once:
    break;
  case solicit:
    luid = ulid = dhcpaid;
    solicit_find_limit(solicit_count);
    printf("DHCP fake lower limit: %lx\n", luid);
    printf("DHCP fake upper limit: %lx\n", ulid);
    printf("DHCP fake limit probe: %lf\n",
           (double)(solicit_count - 1) / (solicit_count + 1));
    printf("DHCP lower limit: %lx\n", llid);
    printf("DHCP upper limit: %lx\n", uuid);
    break;
  case rebind:
    llid = 0;
    luid = ulid = dhcpaid;
    uuid = 0xffffffffffffffff;
    printf("DHCP lower limit: %lx\n", rebind_find_lower_limit());
    printf("DHCP upper limit: %lx\n", rebind_find_upper_limit());
    break;
  }
}

int main(int argc, char **argv) {
  parseargs(argc, argv);
  ddsend_init();
  ddselect_init();
  srandom(time(NULL));

  if (count == 1) {
    ddprint_dhcp6();
  } else {
    while (count-- > 0) {
      puts("--- BEG ---");
      ddprint_dhcp6();
      puts("--- END ---");
    }
  }

  return 0;
}
