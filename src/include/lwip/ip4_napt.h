
#ifndef LWIP_HDR_IP4_NAPT_H
#define LWIP_HDR_IP4_NAPT_H

#include "lwip/opt.h"

#if IP4_NAPT

#ifdef __cplusplus
extern "C" {
#endif

struct napt_table {
  u32_t last;
  u32_t src;
  u32_t dest;
  u16_t sport;
  u16_t dport;
  u16_t mport;
  u8_t proto;
  u8_t fin1 : 1;
  u8_t fin2 : 1;
  u8_t finack1 : 1;
  u8_t finack2 : 1;
  u8_t synack : 1;
  u8_t rst : 1;
#if IP_NAPT_MAX<255
  u8_t next, prev;
#else
  u16_t next, prev;
#endif
};

struct portmap_table {
  u32_t maddr;
  u32_t daddr;
  u16_t mport;
  u16_t dport;
  u8_t proto;
  u8 valid;
};

void  ip_napt_init();
err_t ip_napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp);
void  ip_napt_recv(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp);

#ifdef __cplusplus
}
#endif

#endif /* IP4_NAPT */

#endif /* LWIP_HDR_IP4_NAPT_H */
