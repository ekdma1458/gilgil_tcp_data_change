#include "stdafx.h"
FlowC::FlowC(ST_JE_TCP_Packet *packet, bool check){
    if(check){
        src_ip = packet->ip_header.ip_src.s_addr;
        dst_ip = packet->ip_header.ip_dst.s_addr;
        src_port = packet->tcp_header.th_sport;
        dst_port = packet->tcp_header.th_dport;
    }else{
        src_ip = packet->ip_header.ip_dst.s_addr;
        dst_ip = packet->ip_header.ip_src.s_addr;
        src_port = packet->tcp_header.th_dport;
        dst_port = packet->tcp_header.th_sport;
    }
}
bool FlowC::operator<(const FlowC& other) const{
    return memcmp(this, &other, sizeof (FlowC)) < 0;
}
void FlowC::toString(){
    printf("src_ip : %d.%d.%d.%d\r\n", (ntohl(src_ip) & 0xff000000) >> 24  , (ntohl(src_ip) & 0x00ff0000) >> 16 , (ntohl(src_ip) & 0x0000ff00) >> 8 , ntohl(src_ip) & 0x000000ff);
    printf("dst_ip : %d.%d.%d.%d\r\n", (ntohl(dst_ip) & 0xff000000) >> 24  , (ntohl(dst_ip) & 0x00ff0000) >> 16 , (ntohl(dst_ip) & 0x0000ff00) >> 8 , ntohl(dst_ip) & 0x000000ff);
    printf("src_port : %d\r\n", ntohs(src_port));
    printf("dst_port : %d\r\n", ntohs(dst_port));
}
