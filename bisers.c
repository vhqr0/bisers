#include <endian.h>
#include <errno.h>
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
  puts("Usage: bisers [-i INTERFACE] [-T TAG] [-v]");
  puts("              [-t TIMEOUT] [-w WINDOW] [-c COUNT]");
  puts("              {-h | -d | -r | -s | -n}");
  puts("-h, --help          show this message");
  puts("-i, --interface     interface, default via pcap");
  puts("-T, --tag           tag output minor mode");
  puts("-v, --verbose       verbose output minor mode");
  puts("-C, --cache         cache file minor mode");
  puts("-t, --timeout       specified sr timeout, default to 100 (ms)");
  puts("-w, --window        specified dehcp window, defualt to 3");
  puts("-c, --count         specified solicit count, default to 128");
  puts("-d, --dehcp         delimit by dehcp mode");
  puts("-r, --rebind        delimit by rebind mode");
  puts("-s, --solicit       delimit by solicit mode");
  puts("-a, --auto          auto select delimit method (default)");
  puts("-n, --no-delimit    no delimit, just solicit once");
}

const char *iface = NULL, *tag = NULL, *cache = NULL;
int verbose = 0, timeout = 100, window = 3, count = 128;
enum { d_mode, r_mode, s_mode, a_mode, n_mode } mode = a_mode;
char errbuf[PCAP_ERRBUF_SIZE] = {0}, ntopbuf[INET6_ADDRSTRLEN];

void parseargs(int argc, char **argv) {
  pcap_if_t *alldevs, dev;
  int opt, optind;
  struct option options[] = {{"help", no_argument, NULL, 'h'},
                             {"interface", required_argument, NULL, 'i'},
                             {"tag", required_argument, NULL, 'T'},
                             {"verbose", no_argument, NULL, 'v'},
                             {"cache", required_argument, NULL, 'C'},
                             {"timeout", required_argument, NULL, 't'},
                             {"window", required_argument, NULL, 'w'},
                             {"count", required_argument, NULL, 'c'},
                             {"dehcp", no_argument, NULL, 'd'},
                             {"rebind", no_argument, NULL, 'r'},
                             {"solicit", no_argument, NULL, 's'},
                             {"no-delimit", no_argument, NULL, 'n'}};

  while ((opt = getopt_long(argc, argv, "hi:T:vC:t:w:c:drsan", options,
                            &optind)) > 0) {
    switch (opt) {
    case 'h':
      help();
      exit(0);
    case 'i':
      iface = optarg;
      break;
    case 'T':
      tag = optarg;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'C':
      cache = optarg;
      break;
    case 't':
      timeout = atoi(optarg);
      break;
    case 'w':
      window = atoi(optarg);
      break;
    case 'c':
      count = atoi(optarg);
      break;
    case 'd':
      mode = d_mode;
      break;
    case 'r':
      mode = r_mode;
      break;
    case 's':
      mode = s_mode;
      break;
    case 'a':
      mode = a_mode;
      break;
    case 'n':
      mode = n_mode;
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
  if (tag)
    verbose = 0;
}

#define DHCP_CACHE_SIZE 1024
uint64_t dhcp_cache[DHCP_CACHE_SIZE];
int dhcp_cache_cur = 0;

void cache_in() {
  FILE *fp;
  uint64_t id;

  if (!(fp = fopen(cache, "r"))) {
    if (errno != EEXIST)
      perror("fopen failed");
    return;
  }
  dhcp_cache_cur = 0;
  for (;;) {
    switch (fscanf(fp, "%lx\n", &id)) {
    case EOF:
      if (ferror(fp)) {
        perror("fscanf failed");
        exit(-1);
      }
      goto close;
      break;
    case 0:
      fprintf(stderr, "fscanf invalid data\n");
      exit(-1);
      break;
    case 1:
      if (dhcp_cache_cur >= DHCP_CACHE_SIZE)
        goto close;
      dhcp_cache[dhcp_cache_cur++] = id;
      break;
    default:
      fprintf(stderr, "fscanf unknown return value\n");
    }
  }
close:
  fclose(fp);
}

void cache_out() {
  FILE *fp;

  if (!(fp = fopen(cache, "w"))) {
    perror("fopen failed");
    exit(-1);
  }

  for (int i = 0; i < dhcp_cache_cur; i++)
    fprintf(fp, "%lx\n", dhcp_cache[i]);

  fclose(fp);
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

#define NXT_UDP 0x11
#define NXT_ICMP6 0x3a

void icmp6cksum();
void udpcksum();

/* pcap:         pcap capture handler
 * pfd:          pcap handler selectable fd
 * nafilter:     pcap filter for neighbor advertise
 * dhcpfilter:   pcap filter for dhcp reply
 * sr_flag:      flag should be set by cb to break select loop
 */

#define NAFILTER "icmp6[icmp6type]==icmp6-neighboradvert"
#define DHCPFILTER "ip6 and udp src port 547 and udp dst port 546"

pcap_t *pcap = NULL;
int pfd;
struct bpf_program nafilter, dhcpfilter;

int sr_flag = 0;

void sr_init() {
  struct ifreq ifr;

  /* init ifr */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);
  /* init sockfd */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket failed");
    exit(-1);
  }
  if (ioctl(sockfd, SIOCGIFINDEX, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFINDEX failed");
    exit(-1);
  }
  /* init sall */
  memset(&sall, 0, sizeof(sall));
  sall.sll_ifindex = ifr.ifr_ifindex;
  if (ioctl(sockfd, SIOCGIFMTU, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFMTU failed");
    exit(-1);
  }
  /* init pkt */
  mtu = ifr.ifr_mtu;
  if (mtu < 1280) {
    fprintf(stderr, "interface mtu too small: %d\n", mtu);
    exit(-1);
  }
  pkt = (uint8_t *)malloc(mtu);
  memset(pkt, 0, mtu);
  /* init pkt pointers */
  ethhdr = (struct ethhdr *)pkt;
  ip6hdr = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
  buf = pkt + HDRSIZE;
  cap = mtu - HDRSIZE;
  cur = 0;
  /* init pkt eth fields */
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr, sizeof(ifr)) < 0) {
    perror("ioctl SIOCGIFHWADDR failed");
    exit(-1);
  }
  memcpy(ethhdr->h_source, ifr.ifr_hwaddr.sa_data, 6);
  ethhdr->h_proto = htons(ETH_P_IPV6);
  /* init pkt ip6 fields */
  ip6hdr->ip6_src.s6_addr[0] = 0xfe;
  ip6hdr->ip6_src.s6_addr[1] = 0x80;
  memcpy(ip6hdr->ip6_src.s6_addr + 8, ethhdr->h_source, 3);
  ip6hdr->ip6_src.s6_addr[8] ^= 2;
  ip6hdr->ip6_src.s6_addr[11] = 0xff;
  ip6hdr->ip6_src.s6_addr[12] = 0xfe;
  memcpy(ip6hdr->ip6_src.s6_addr + 13, ethhdr->h_source + 3, 3);
  ip6hdr->ip6_vfc = 0x60;
  ip6hdr->ip6_hlim = 0xff;
  /* init pcap */
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
  /* init pfd */
  if ((pfd = pcap_get_selectable_fd(pcap)) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_get_selectable_fd failed");
    exit(-1);
  }
  /* init filters */
  if (pcap_compile(pcap, &nafilter, NAFILTER, 1, 0) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_compile failed");
    exit(-1);
  }
  if (pcap_compile(pcap, &dhcpfilter, DHCPFILTER, 1, 0) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_compile failed");
    exit(-1);
  }
}

/* set filter, send pkt, capture and cb until sr_flag is
 * set or timeout
 *
 * target mac:      mac
 * target ip:       prefix+id
 * next header:     nxt
 * payload length:  cur
 * payload:         buf
 */
void sr(uint64_t mac, uint64_t prefix, uint64_t id, uint8_t nxt,
        struct bpf_program *filter, pcap_handler cb) {
  fd_set rfds;
  struct timeval tv;

  /* set pcap filter */
  if (pcap_setfilter(pcap, filter) == PCAP_ERROR) {
    pcap_perror(pcap, "pcap_setfilter failed");
    exit(-1);
  }
  /* set pkt fields */
  mac = htobe64(mac);
  memcpy(ethhdr->h_dest, ((uint8_t *)&mac) + 2, 6);
  ((uint64_t *)&ip6hdr->ip6_dst.s6_addr)[0] = htobe64(prefix);
  ((uint64_t *)&ip6hdr->ip6_dst.s6_addr)[1] = htobe64(id);
  ip6hdr->ip6_plen = htons(cur);
  ip6hdr->ip6_nxt = nxt;
  /* set cksum maybe */
  switch (nxt) {
  case NXT_ICMP6:
    icmp6cksum();
    break;
  case NXT_UDP:
    udpcksum();
    break;
  }
  /* send pkt */
  if (sendto(sockfd, pkt, cur + HDRSIZE, 0, (struct sockaddr *)&sall,
             sizeof(sall)) < 0) {
    perror("send failed");
    exit(-1);
  }
  /* init select */
  sr_flag = 0;
  tv.tv_sec = 0;
  tv.tv_usec = timeout << 10;
  /* select */
  while (!sr_flag && (tv.tv_usec || tv.tv_sec)) {
    FD_ZERO(&rfds);
    FD_SET(pfd, &rfds);
    switch (select(pfd + 1, &rfds, NULL, NULL, &tv)) {
    case 1:
      pcap_dispatch(pcap, 1, cb, NULL);
      break;
    case -1:
      perror("select failed");
      exit(-1);
      break;
    }
  }
}

/* udp checksum
 * ip6 src || ip6 udp || nxt(2) || plen(2) || buf
 */
void udpcksum() {
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
void icmp6cksum() {
  uint32_t sum = 0;
  uint16_t *p = (uint16_t *)buf;
  int c = cur + 40;

  memcpy(buf + cur, ip6hdr->ip6_src.s6_addr, 16);
  memcpy(buf + cur + 16, ip6hdr->ip6_dst.s6_addr, 16);
  buf[cur + 34] = cur >> 8;
  buf[cur + 35] = cur;
  buf[cur + 39] = NXT_ICMP6;

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

/* nd send neighbor solicit, and set nd_id to discovery id, nd_cb
 * check the neighbor advertise and set sr_flag to 1.
 */

uint64_t nd_id;

void nd_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(bytes + sizeof(struct ethhdr));
  struct nd_neighbor_advert *nahdr =
      (struct nd_neighbor_advert *)(bytes + HDRSIZE);

  if (h->caplen < HDRSIZE + sizeof(struct nd_neighbor_advert) ||
      be64toh(*((uint64_t *)(nahdr->nd_na_target.s6_addr + 8))) != nd_id)
    return;

  sr_flag = 1;
}

/* alive check via neighbor discovery, discovery address: dprefix+did */
int nd(uint64_t dprefix, uint64_t did) {
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
  nd_id = did;
  sr(mac, prefix, id, NXT_ICMP6, &nafilter, nd_cb);
  return sr_flag;
}

/* cduid:            client id option
 * sduid:            server id option
 * trid, iaid:       dhcp solicit/rebind id
 * dhcpip:           dhcp server address
 * dhcpaip:          dhcp allocated address, dhcpprefix+dhcpaid
 * solicited_flag:   if have solicited, we want track the same server
 */

#define DUID_MAX_LEN 128
uint8_t cduid[DUID_MAX_LEN], sduid[DUID_MAX_LEN];
int cduidlen, sduidlen;

uint32_t trid, iaid;
struct in6_addr dhcpip, dhcpaip;
uint64_t dhcpprefix, dhcpaid;
uint32_t dhcpt1, dhcpt2, dhcppreferedtime, dhcpvalidtime;

int solicited_flag = 0;

/* check dhcp advertise and set dhcp delimit parameters.  cduid is
 * initialized by solicit, trid/iaid is randomized generated every
 * time call solicit and rebind.  solicit_cb check serverid option and
 * set sduid, and, check iana option and set dhcpprefix, t1, t2,
 * validtime and preferedtime.  the solicited address shoud append to
 * dhcp_cache.
 */
void solicit_cb(u_char *user, const struct pcap_pkthdr *h,
                const u_char *bytes) {
  struct ip6_hdr *ip6hdr =
      (struct ip6_hdr *)((uint8_t *)bytes + sizeof(struct ethhdr));
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
        if (solicited_flag) {
          if (cl != sduidlen || memcmp(c, sduid, sduidlen))
            return;
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
        if (solicited_flag) {
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
    sr_flag = 1;
}

/* find dhcp server and initialize dhcp delimit parameters */
int solicit(int required, int solicited) {
  uint64_t mac = 0x333300010002;
  uint64_t prefix = 0xff02000000000000;
  uint64_t id = 0x10002;
  struct udphdr *udphdr = (struct udphdr *)buf;

  solicited_flag = solicited;
  if (!solicited_flag) {
    memset(sduid, 0, DUID_MAX_LEN);
    memset(cduid, 0, DUID_MAX_LEN);
    cduid[1] = 1; /* client id */
    cduid[3] = 10;
    cduid[5] = 3;
    cduid[7] = 1;
    memcpy(cduid + 8, ethhdr->h_source, 6);
    cduidlen = 14;
  }

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
  sr(mac, prefix, id, NXT_UDP, &dhcpfilter, solicit_cb);
  if (required && !sr_flag) {
    fprintf(stderr, "can't find dhcp server\n");
    exit(-1);
  }
  return sr_flag;
}

/* rebind send dhcp rebind, and set rebind_flag to zero,
 * rebind_cb check the dhcp reply iana option,
 * if with one address, just set sr_flag and return,
 * if with two addresses, set allocated address to rebind_flag and return.
 * rebind check both sr_flag and rebind_flag to draw a result.
 * the allocated address should append to dhcp_cache.
 */

int rebind_flag;

void rebind_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  struct ip6_hdr *ip6hdr =
      (struct ip6_hdr *)((uint8_t *)bytes + sizeof(struct ethhdr));
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
      sr_flag = 1;
      if (*(uint32_t *)(c + 40)) /* check the first iaaddr's validtime */
        rebind_flag = 1;
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
int rebind(uint64_t rid) {
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
  rebind_flag = 0;
  sr(mac, prefix, id, NXT_UDP, &dhcpfilter, rebind_cb);
  if (!sr_flag)
    return 0;
  return rebind_flag;
}

uint64_t llim = 0, ulim = 0;

uint64_t dflimit(uint64_t l, uint64_t u, int fl) {
  uint64_t h = (l >> 1) + (u >> 1), b, e;
  if ((l & 1) && (u & 1))
    h++;
  if (l >= u)
    return h;
  printf("check %lx: ", h);
  if (nd(dhcpprefix, h)) {
    if (verbose)
      puts("hit");
    return fl ? dflimit(l, h - 1, fl) : dflimit(h + 1, u, fl);
  }
  if (verbose)
    puts("miss");
  if (window > h - l)
    b = l;
  else
    b = h - window;
  if (window > u - h)
    e = u;
  else
    e = h + window;
  for (uint64_t i = b; i <= e; i++) {
    if (verbose)
      printf("check in window [%lx, %lx] %lx: ", b, e, i);
    if (nd(dhcpprefix, i)) {
      if (verbose)
        puts("hit");
      return fl ? dflimit(l, i - 1, fl) : dflimit(i + 1, u, fl);
    }
    if (verbose)
      puts("miss");
  }
  return fl ? dflimit(h + 1, u, fl) : dflimit(l, h - 1, fl);
}

void ddelimit(uint64_t h) {
  llim = dflimit(0, h, 1);
  ulim = dflimit(h, 0xffffffffffffffff, 0);
}

int rflimit_ck(uint64_t h) {
  if (verbose)
    printf("check %lx: ", h);
  for (int i = 0; i < dhcp_cache_cur; i++)
    if (h == dhcp_cache[i]) {
      if (verbose)
        puts("hit in cache");
      return 1;
    }
  if (rebind(h)) {
    if (verbose)
      puts("hit in dhcp reply");
    return 1;
  }
  if (nd(dhcpprefix, h)) {
    if (verbose)
      puts("hit in neighbor advertise");
    return 1;
  }
  if (verbose)
    puts("miss");
  return 0;
}

uint64_t rflimit(uint64_t l, uint64_t u, int fl) {
  uint64_t h = (l >> 1) + (u >> 1);
  if ((l & 1) && (u & 1))
    h++;
  if (l >= u)
    return h;
  if (rflimit_ck(h))
    return fl ? rflimit(l, h - 1, fl) : rflimit(h + 1, u, fl);
  return fl ? rflimit(h + 1, u, fl) : rflimit(l, h - 1, fl);
}

void rdelimit(uint64_t h) {
  llim = rflimit(0, h, 1);
  ulim = rflimit(h, 0xffffffffffffffff, 0);
}

void sdelimit(uint64_t h) {
  uint64_t delta;

  llim = ulim = h;
  if (!count)
    return;
  for (int i = 0; i < count; i++) {
    if (!solicit(0, 1)) {
      if (verbose)
        printf("llim: %lx, ulim: %lx, solicit failed\n", llim, ulim);
      continue;
    }
    if (dhcpaid < llim)
      llim = dhcpaid;
    if (dhcpaid > ulim)
      ulim = dhcpaid;
    if (verbose)
      printf("llim: %lx, ulim: %lx, solicit: %lx\n", llim, ulim, dhcpaid);
  }
  delta = (ulim - llim) / count;
  if (delta > llim)
    llim = 0;
  else
    llim -= delta;
  if (delta > 0xffffffffffffffff - ulim)
    ulim = 0xffffffffffffffff;
  else
    ulim += delta;
}

void print_dhcp6() {
  uint64_t dhcpaid1;

  if (cache) {
    cache_in();
    if (!tag)
      printf("DHCP load %d cache\n", dhcp_cache_cur);
  }

  solicit(1, 0);

  if (!tag) {
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
    printf("DHCP preferedtime: %d\n", dhcppreferedtime);
    printf("DHCP validtime: %d\n", dhcpvalidtime);
  }

mode:
  switch (mode) {
  case n_mode:
    return;
    break;
  case a_mode:
    if (!tag)
      puts("DHCP delimit method: Auto");
    dhcpaid1 = dhcpaid;
    solicit(1, 1);
    if (dhcpaid == dhcpaid + 1)
      mode = d_mode;
    if (rebind(dhcpaid - 1) || rebind(dhcpaid + 1))
      mode = r_mode;
    mode = s_mode;
    goto mode;
    break;
  case d_mode:
    if (!tag)
      puts("DHCP delimit method: DeHCP");
    ddelimit(dhcpaid);
    break;
  case r_mode:
    if (!tag)
      puts("DHCP delimit method: Rebind");
    rdelimit(dhcpaid);
    break;
  case s_mode:
    if (!tag)
      puts("DHCP delimit method: Solicit");
    sdelimit(dhcpaid);
    break;
  }

  if (tag) {
    printf("%s\t%lx\t%lx\n", tag, llim, ulim);
  } else {
    printf("DHCP llimit: %lx\n", llim);
    printf("DHCP ulimit: %lx\n", ulim);
  }

  if (cache) {
    cache_out();
    if (!tag)
      printf("DHCP save %d cache\n", dhcp_cache_cur);
  }
}

int main(int argc, char **argv) {
  parseargs(argc, argv);
  sr_init();
  srandom(time(NULL));
  if (cache)
    cache_in();
  print_dhcp6();
  if (cache)
    cache_out();
  return 0;
}
