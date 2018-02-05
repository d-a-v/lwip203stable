
#include "lwip/ip4_napt.h"

#if IP4_NAPT

#if IP_NAPT_MAX<255
#define NO_IDX ((u8_t)-1)
#else
#define NO_IDX ((u16_t)-1)
#endif
#define NT(x) ((x) == NO_IDX ? NULL : &ip_napt_table[x])

struct napt_table ip_napt_table[IP_NAPT_MAX] = {};
struct portmap_table ip_portmap_table[IP_PORTMAP_MAX] = {};
u16_t napt_list = NO_IDX, napt_list_last = NO_IDX, napt_free = 0;
int nr_active_napt_tcp = 0, nr_active_napt_udp = 0, nr_active_napt_icmp = 0;

/**
 * Enable/Disable NAPT for a specified interface.
 *
 * @param addr ip address of the interface
 * @param enable non-zero to enable NAPT, or 0 to disable.
 */
void
ip_napt_enable(u32_t addr, int enable)
{
  struct netif *netif;
  for (netif = netif_list; netif; netif = netif->next) {
    if (netif_is_up(netif) && !ip_addr_isany(&netif->ip_addr) && netif->ip_addr.addr == addr) {
      netif->napt = !!enable;
      break;
    }
  }
}

void
ip_napt_init()
{
  u16_t i;
  for (i = 0; i < IP_NAPT_MAX - 1; i++)
    ip_napt_table[i].next = i + 1;
  ip_napt_table[i].next = NO_IDX;
}

/* t must be indexed by napt_free */
static void
ip_napt_insert(struct napt_table *t)
{
  u16_t ti = t - ip_napt_table;
  if (ti != napt_free) *((int*)1)=1; //DEBUG
  napt_free = t->next;
  t->prev = NO_IDX;
  t->next = napt_list;
  if (napt_list != NO_IDX)
    NT(napt_list)->prev = ti;
  napt_list = ti;
  if (napt_list_last == NO_IDX)
    napt_list_last = ti;

#if LWIP_TCP
  if (t->proto == IP_PROTO_TCP)
    nr_active_napt_tcp++;
#endif
#if LWIP_UDP
  if (t->proto == IP_PROTO_UDP)
    nr_active_napt_udp++;
#endif
#if LWIP_ICMP
  if (t->proto == IP_PROTO_ICMP)
    nr_active_napt_icmp++;
#endif
}

static void
ip_napt_free(struct napt_table *t)
{
  u16_t ti = t - ip_napt_table;
  if (ti == napt_list)
    napt_list = t->next;
  if (ti == napt_list_last)
    napt_list_last = t->prev;
  if (t->next != NO_IDX)
    NT(t->next)->prev = t->prev;
  if (t->prev != NO_IDX)
    NT(t->prev)->next = t->next;
  t->prev = NO_IDX;
  t->next = napt_free;
  napt_free = ti;

#if LWIP_TCP
  if (t->proto == IP_PROTO_TCP)
    nr_active_napt_tcp--;
#endif
#if LWIP_UDP
  if (t->proto == IP_PROTO_UDP)
    nr_active_napt_udp--;
#endif
#if LWIP_ICMP
  if (t->proto == IP_PROTO_ICMP)
    nr_active_napt_icmp--;
#endif
}

#if LWIP_TCP
static u8_t
ip_napt_find_port(u8_t proto, u16_t port)
{
  int i, next;
  for (i = napt_list; i != NO_IDX; i = next) {
    struct napt_table *t = &ip_napt_table[i];
    next = t->next;
    if (t->proto == proto && t->mport == port)
      return 1;
  }
  return 0;
}

static struct portmap_table *
ip_portmap_find(u8_t proto, u16_t mport);

static u8_t
tcp_listening(u16_t port)
{
  struct tcp_pcb_listen *t;
  for (t = tcp_listen_pcbs.listen_pcbs; t; t = t->next)
    if (t->local_port == port)
      return 1;
  if (ip_portmap_find(IP_PROTO_TCP, port))
    return 1;
  return 0;
}
#endif // LWIP_TCP

#if LWIP_UDP
static u8_t
udp_listening(u16_t port)
{
  struct udp_pcb *pcb;
  for (pcb = udp_pcbs; pcb; pcb = pcb->next)
    if (pcb->local_port == port)
      return 1;
  if (ip_portmap_find(IP_PROTO_UDP, port))
    return 1;
  return 0;
}
#endif // LWIP_UDP

static u16_t
ip_napt_new_port(u8_t proto, u16_t port)
{
  if (PP_NTOHS(port) >= IP_NAPT_PORT_RANGE_START && PP_NTOHS(port) <= IP_NAPT_PORT_RANGE_END)
    if (!ip_napt_find_port(proto, port) && !tcp_listening(port))
      return port;
  for (;;) {
    port = PP_HTONS(IP_NAPT_PORT_RANGE_START +
                    os_random() % (IP_NAPT_PORT_RANGE_END - IP_NAPT_PORT_RANGE_START + 1));
    if (ip_napt_find_port(proto, port))
      continue;
#if LWIP_TCP
    if (proto == IP_PROTO_TCP && tcp_listening(port))
      continue;
#endif // LWIP_TCP
#if LWIP_UDP
    if (proto == IP_PROTO_UDP && udp_listening(port))
      continue;
#endif // LWIP_UDP

    return port;
  }
}

static struct napt_table*
ip_napt_find(u8_t proto, u32_t addr, u16_t port, u16_t mport, u8_t dest)
{
  u16_t i, next;
  struct napt_table *t;
  u32_t now = sys_now();
  for (i = napt_list; i != NO_IDX; i = next) {
    t = NT(i);
    next = t->next;
#if LWIP_TCP
    if (t->proto == IP_PROTO_TCP &&
        (((t->finack1 && t->finack2 || !t->synack) &&
          now - t->last > IP_NAPT_TIMEOUT_MS_TCP_DISCON) ||
         now - t->last > IP_NAPT_TIMEOUT_MS_TCP)) {
      ip_napt_free(t);
      continue;
    }
#endif
#if LWIP_UDP
    if (t->proto == IP_PROTO_UDP && now - t->last > IP_NAPT_TIMEOUT_MS_UDP) {
      ip_napt_free(t);
      continue;
    }
#endif
#if LWIP_ICMP
    if (t->proto == IP_PROTO_ICMP && now - t->last > IP_NAPT_TIMEOUT_MS_ICMP) {
      ip_napt_free(t);
      continue;
    }
#endif
    if (dest == 0 && t->proto == proto && t->src == addr && t->sport == port)
      return t;
    if (dest == 1 && t->proto == proto && t->dest == addr && t->dport == port
        && t->mport == mport)
      return t;
  }
  return NULL;
}

static void
ip_napt_update(struct napt_table *t)
{
  t->last = sys_now();
  /* move this entry to the top of napt_list */
  ip_napt_free(t);
  ip_napt_insert(t);
}

static u16_t
ip_napt_add(u8_t proto, u32_t src, u16_t sport, u32_t dest, u16_t dport)
{
  struct napt_table *t = ip_napt_find(proto, src, sport, 0, 0);
  if (t) {
    t->dest = dest;
    t->dport = dport;
    ip_napt_update(t);
    return t->mport;
  }
  t = NT(napt_free);
  if (t) {
    u16_t mport = sport;
#if LWIP_TCP
    if (proto == IP_PROTO_TCP)
      mport = ip_napt_new_port(IP_PROTO_TCP, sport);
#endif
#if LWIP_TCP
    if (proto == IP_PROTO_UDP)
      mport = ip_napt_new_port(IP_PROTO_UDP, sport);
#endif
    t->last = sys_now();
    t->src = src;
    t->dest = dest;
    t->sport = sport;
    t->dport = dport;
    t->mport = mport;
    t->proto = proto;
    t->fin1 = t->fin2 = t->finack1 = t->finack2 = t->synack = t->rst = 0;
    ip_napt_insert(t);
    return mport;
  }
  return 0;
}

/**
 * Register port mapping on the external interface to internal interface.
 * When the same port mapping is registered again, the old mapping is overwritten.
 * In this implementation, only 1 unique port mapping can be defined for each target address/port.
 *
 * @param proto target protocol
 * @param maddr ip address of the external interface
 * @param mport mapped port on the external interface, in host byte order.
 * @param daddr destination ip address
 * @param dport destination port, in host byte order.
 */
u8_t
ip_portmap_add(u8_t proto, u32_t maddr, u16_t mport, u32_t daddr, u16_t dport)
{
  mport = PP_HTONS(mport);
  dport = PP_HTONS(dport);
  int i;
  for (i = 0; i < IP_PORTMAP_MAX; i++) {
    struct portmap_table *p = &ip_portmap_table[i];
    if (p->valid && p->proto == proto && p->mport == mport) {
      p->dport = dport;
      p->daddr = daddr;
    } else if (!p->valid) {
      p->maddr = maddr;
      p->daddr = daddr;
      p->mport = mport;
      p->dport = dport;
      p->proto = proto;
      p->valid = 1;
      return 1;
    }
  }
  return 0;
}

static struct portmap_table *
ip_portmap_find(u8_t proto, u16_t mport)
{
  int i;
  for (i = 0; i < IP_PORTMAP_MAX; i++) {
    struct portmap_table *p = &ip_portmap_table[i];
    if (!p->valid)
      return 0;
    if (p->proto == proto && p->mport == mport)
      return p;
  }
  return NULL;
}

static struct portmap_table *
ip_portmap_find_dest(u8_t proto, u16_t dport, u32_t daddr)
{
  int i;
  for (i = 0; i < IP_PORTMAP_MAX; i++) {
    struct portmap_table *p = &ip_portmap_table[i];
    if (!p->valid)
      return 0;
    if (p->proto == proto && p->dport == dport && p->daddr == daddr)
      return p;
  }
  return NULL;
}

/**
 * Unregister port mapping on the external interface to internal interface.
 *
 * @param proto target protocol
 * @param maddr ip address of the external interface
 */
u8_t
ip_portmap_remove(u8_t proto, u16_t mport)
{
  mport = PP_HTONS(mport);
  struct portmap_table *last = &ip_portmap_table[IP_PORTMAP_MAX - 1];
  struct portmap_table *m = ip_portmap_find(proto, mport);
  if (!m)
    return 0;
  for (; m != last; m++)
    memcpy(m, m + 1, sizeof(*m));
  last->valid = 0;
  return 1;
}

#if LWIP_TCP
void
ip_napt_modify_port_tcp(struct tcp_hdr *tcphdr, u8_t dest, u16_t newval)
{
  u16_t s1 = PP_NTOHS(dest ? tcphdr->dest : tcphdr->src), s2 = PP_NTOHS(newval);
  u32_t chksum = PP_NTOHS(tcphdr->chksum), chksum2 = chksum;
  chksum += s1 - s2;
  chksum = (chksum >> 16) + (chksum & 0xffff);
  tcphdr->chksum = PP_HTONS(chksum);
  if (dest)
    tcphdr->dest = newval;
  else
    tcphdr->src = newval;
}

void
ip_napt_modify_addr_tcp(struct tcp_hdr *tcphdr, ip_addr_p_t *oldval, u32_t newval)
{
  u32_t s1 = PP_NTOHL(oldval->addr), s2 = PP_NTOHL(newval);
  u32_t chksum = PP_NTOHS(tcphdr->chksum);
  chksum += (s1 >> 16) + (s1 & 0xfff) - (s2 >> 16) - (s2 & 0xffff);
  chksum = (chksum >> 16) + (chksum & 0xffff);
  tcphdr->chksum = PP_HTONS(chksum);
}
#endif // LWIP_TCP

#if LWIP_UDP
void
ip_napt_modify_port_udp(struct udp_hdr *udphdr, u8_t dest, u16_t newval)
{
  u16_t s1 = PP_NTOHS(dest ? udphdr->dest : udphdr->src), s2 = PP_NTOHS(newval);
  u32_t chksum = PP_NTOHS(udphdr->chksum), chksum2 = chksum;
  chksum += s1 - s2;
  chksum = (chksum >> 16) + (chksum & 0xffff);
  udphdr->chksum = PP_HTONS(chksum);
  if (dest)
    udphdr->dest = newval;
  else
    udphdr->src = newval;
}

void
ip_napt_modify_addr_udp(struct udp_hdr *udphdr, ip_addr_p_t *oldval, u32_t newval)
{
  u32_t s1 = PP_NTOHL(oldval->addr), s2 = PP_NTOHL(newval);
  u32_t chksum = PP_NTOHS(udphdr->chksum);
  chksum += (s1 >> 16) + (s1 & 0xfff) - (s2 >> 16) - (s2 & 0xffff);
  chksum = (chksum >> 16) + (chksum & 0xffff);
  udphdr->chksum = PP_HTONS(chksum);
}
#endif // LWIP_UDP

void
ip_napt_modify_addr(struct ip_hdr *iphdr, ip_addr_p_t *field, u32_t newval)
{
  u32_t s1 = PP_NTOHL(field->addr), s2 = PP_NTOHL(newval);
  u32_t chksum = PP_NTOHS(IPH_CHKSUM(iphdr));
  chksum += (s1 >> 16) + (s1 & 0xfff) - (s2 >> 16) - (s2 & 0xffff);
  chksum = (chksum >> 16) + (chksum & 0xffff);
  IPH_CHKSUM_SET(iphdr, PP_HTONS(chksum));
  field->addr = newval;
}

/**
 * NAPT for an input packet. It checks weather the destination is on NAPT
 * table and modifythe packet destination address and port if needed.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
void
ip_napt_recv(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct portmap_table *m;
  struct napt_table *t;

#if LWIP_ICMP
  /* NAPT for ICMP Echo Request using identifier */
  if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
    struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    if (iecho->type == ICMP_ER) {
      t = ip_napt_find(IP_PROTO_ICMP, iphdr->src.addr, iecho->id, iecho->id, 1);
      if (!t)
        return;
      ip_napt_modify_addr(iphdr, &iphdr->dest, t->src);
      return;
    }

    return;
  }
#endif // LWIP_ICMP

#if LWIP_TCP
  if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    m = ip_portmap_find(IP_PROTO_TCP, tcphdr->dest);
    if (m) {
      /* packet to mapped port: rewrite destination */
      if (m->dport != tcphdr->dest)
        ip_napt_modify_port_tcp(tcphdr, 1, m->dport);
      ip_napt_modify_addr_tcp(tcphdr, &iphdr->dest, m->daddr);
      ip_napt_modify_addr(iphdr, &iphdr->dest, m->daddr);
      return;
    }
    t = ip_napt_find(IP_PROTO_TCP, iphdr->src.addr, tcphdr->src, tcphdr->dest, 1);
      if (!t)
        return; /* Unknown TCP session; do nothing */
      ip_napt_update(t);

      if (t->sport != tcphdr->dest)
        ip_napt_modify_port_tcp(tcphdr, 1, t->sport);
      ip_napt_modify_addr_tcp(tcphdr, &iphdr->dest, t->src);
      ip_napt_modify_addr(iphdr, &iphdr->dest, t->src);

      if ((TCPH_FLAGS(tcphdr) & (TCP_SYN|TCP_ACK)) == (TCP_SYN|TCP_ACK))
        t->synack = 1;
      if ((TCPH_FLAGS(tcphdr) & TCP_FIN))
        t->fin1 = 1;
      if (t->fin2 && (TCPH_FLAGS(tcphdr) & TCP_ACK))
        t->finack2 = 1; /* FIXME: Currently ignoring ACK seq... */
      if (TCPH_FLAGS(tcphdr) & TCP_RST)
        t->rst = 1;
      return;
  }
#endif // LWIP_TCP

#if LWIP_UDP
  if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
    struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    m = ip_portmap_find(IP_PROTO_UDP, udphdr->dest);
    if (m) {
      /* packet to mapped port: rewrite destination */
      if (m->dport != udphdr->dest)
        ip_napt_modify_port_udp(udphdr, 1, m->dport);
      ip_napt_modify_addr_udp(udphdr, &iphdr->dest, m->daddr);
      ip_napt_modify_addr(iphdr, &iphdr->dest, m->daddr);
      return;
    }
    t = ip_napt_find(IP_PROTO_UDP, iphdr->src.addr, udphdr->src, udphdr->dest, 1);
    if (!t)
      return; /* Unknown session; do nothing */
    ip_napt_update(t);

    if (t->sport != udphdr->dest)
      ip_napt_modify_port_udp(udphdr, 1, t->sport);
    ip_napt_modify_addr_udp(udphdr, &iphdr->dest, t->src);
    ip_napt_modify_addr(iphdr, &iphdr->dest, t->src);
    return;
  }
#endif // LWIP_UDP
}

/**
 * NAPT for a forwarded packet. It checks weather we need NAPT and modify
 * the packet source address and port if needed.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 * @param outp the netif on which this packet will be sent
 * @return ERR_OK if packet should be sent, or ERR_RTE if it should be dropped
 */
err_t
ip_napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp)
{
  if (!inp->napt)
    return ERR_OK;

#if LWIP_ICMP
  /* NAPT for ICMP Echo Request using identifier */
  if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
    struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    if (iecho->type == ICMP_ECHO) {
      /* register src addr and iecho->id and dest info */
      ip_napt_add(IP_PROTO_ICMP, iphdr->src.addr, iecho->id, iphdr->dest.addr, iecho->id);

      ip_napt_modify_addr(iphdr, &iphdr->src, outp->ip_addr.addr);
    }
    return ERR_OK;
  }
#endif

#if LWIP_TCP
  if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    u16_t mport;

    struct portmap_table *m = ip_portmap_find_dest(IP_PROTO_TCP, tcphdr->src, iphdr->src.addr);
    if (m) {
      /* packet from port-mapped dest addr/port: rewrite source to this node */
      if (m->mport != tcphdr->src)
        ip_napt_modify_port_tcp(tcphdr, 0, m->mport);
      ip_napt_modify_addr_tcp(tcphdr, &iphdr->src, m->maddr);
      ip_napt_modify_addr(iphdr, &iphdr->src, m->maddr);
      return ERR_OK;
    }
    if ((TCPH_FLAGS(tcphdr) & (TCP_SYN|TCP_ACK)) == TCP_SYN &&
        PP_NTOHS(tcphdr->src) >= 1024) {
      /* Register new TCP session to NAPT */
      mport = ip_napt_add(IP_PROTO_TCP, iphdr->src.addr, tcphdr->src,
                          iphdr->dest.addr, tcphdr->dest);
    } else {
      struct napt_table *t = ip_napt_find(IP_PROTO_TCP, iphdr->src.addr, tcphdr->src, 0, 0);
      if (!t || t->dest != iphdr->dest.addr || t->dport != tcphdr->dest) {
#if LWIP_ICMP
        icmp_dest_unreach(p, ICMP_DUR_PORT);
#endif
        return ERR_RTE; /* Drop unknown TCP session */
      }
      ip_napt_update(t);
      mport = t->mport;
      if ((TCPH_FLAGS(tcphdr) & TCP_FIN))
        t->fin2 = 1;
      if (t->fin1 && (TCPH_FLAGS(tcphdr) & TCP_ACK))
        t->finack1 = 1; /* FIXME: Currently ignoring ACK seq... */
      if (TCPH_FLAGS(tcphdr) & TCP_RST)
        t->rst = 1;
    }

    if (mport != tcphdr->src)
      ip_napt_modify_port_tcp(tcphdr, 0, mport);
    ip_napt_modify_addr_tcp(tcphdr, &iphdr->src, outp->ip_addr.addr);
    ip_napt_modify_addr(iphdr, &iphdr->src, outp->ip_addr.addr);
    return ERR_OK;
  }
#endif

#if LWIP_UDP
  if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
    struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);
    u16_t mport;

    struct portmap_table *m = ip_portmap_find_dest(IP_PROTO_UDP, udphdr->src, iphdr->src.addr);
    if (m) {
      /* packet from port-mapped dest addr/port: rewrite source to this node */
      if (m->mport != udphdr->src)
        ip_napt_modify_port_udp(udphdr, 0, m->mport);
      ip_napt_modify_addr_udp(udphdr, &iphdr->src, m->maddr);
      ip_napt_modify_addr(iphdr, &iphdr->src, m->maddr);
      return ERR_OK;
    }
    if (PP_NTOHS(udphdr->src) >= 1024) {
      /* Register new UDP session */
      mport = ip_napt_add(IP_PROTO_UDP, iphdr->src.addr, udphdr->src,
                          iphdr->dest.addr, udphdr->dest);
    } else {
      struct napt_table *t = ip_napt_find(IP_PROTO_UDP, iphdr->src.addr, udphdr->src, 0, 0);
      if (!t || t->dest != iphdr->dest.addr || t->dport != udphdr->dest) {
#if LWIP_ICMP
        icmp_dest_unreach(p, ICMP_DUR_PORT);
#endif
        return ERR_RTE; /* Drop unknown UDP session */
      }
      mport = t->mport;
    }

    if (mport != udphdr->src)
      ip_napt_modify_port_udp(udphdr, 0, mport);
    ip_napt_modify_addr_udp(udphdr, &iphdr->src, outp->ip_addr.addr);
    ip_napt_modify_addr(iphdr, &iphdr->src, outp->ip_addr.addr);
    return ERR_OK;
  }
#endif

  return ERR_OK;
}

#endif /* IP4_NAPT */
