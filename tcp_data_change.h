#ifndef TCP_DATA_CHANGE_H
#define TCP_DATA_CHANGE_H
#include "stdafx.h"

struct ST_JE_TCP_Packet{
    struct libnet_ipv4_hdr ip_header;
    struct libnet_tcp_hdr tcp_header;
};
struct ST_JE_NETFILTER_CHECK{
    u_int32_t id;
    bool check;
};
struct ST_JE_PSEUDO_HEADER{
    u_int32_t ip_src;
    u_int32_t ip_dst;
    u_int8_t reserv;
    u_int8_t protocol;
    u_int16_t total_len;
};

#endif // TCP_DATA_CHANGE_H

void usage();
void dump(unsigned char* buf, int size);
u_int32_t print_pkt (struct nfq_data *tb);
void ipCheckSum(unsigned char *packet, int16_t len);
void tcpCheckSum(unsigned char *packet);
