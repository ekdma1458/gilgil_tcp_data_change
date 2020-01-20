#include "stdafx.h"

void usage(){
    printf("syntax: tcp_data_change <from string> <to string>\n");
    printf("sample: tcp_data_change hacking HOOKING");
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0){
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

void ipCheckSum(unsigned char *packet, int16_t len){
    ST_JE_TCP_Packet* temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(packet);
    temp_packet->ip_header.ip_len = htons(ntohs(temp_packet->ip_header.ip_len) + len);
    temp_packet->ip_header.ip_sum = 0;
    uint16_t *checksum_p = reinterpret_cast<uint16_t*>(packet);
    uint16_t checksum = 0;
    uint32_t temp_checksum = 0;
    for (int i = 0; i < (temp_packet->ip_header.ip_hl * 4) ; i = i + 2){
        temp_checksum = (checksum + ntohs(*(checksum_p + (i/2))));
        if (temp_checksum > 0xffff){
            checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
        }else{
            checksum = temp_checksum;
        }
        temp_checksum = 0;
    }
    temp_packet->ip_header.ip_sum = htons(~checksum);
}
void tcpCheckSum(unsigned char *packet){
    try {
        uint16_t pseudo_checksum = 0;
        uint16_t tcp_checksum = 0;
        uint16_t checksum = 0;
        uint32_t temp_checksum = 0;
        ST_JE_PSEUDO_HEADER pseudo = {0,};
        ST_JE_TCP_Packet* temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(packet);
        uint16_t *checksum_p;
        checksum_p = reinterpret_cast<uint16_t*>(&pseudo.ip_src);
        pseudo.ip_src = temp_packet->ip_header.ip_src.s_addr;
        pseudo.ip_dst = temp_packet->ip_header.ip_dst.s_addr;
        pseudo.reserv = 0;
        pseudo.protocol = temp_packet->ip_header.ip_p;
        pseudo.total_len =  htons(ntohs(temp_packet->ip_header.ip_len) - (temp_packet->ip_header.ip_hl * 4));
        temp_packet->tcp_header.th_sum = 0;
        for(u_int8_t i = 0; i < 6; i++){
            temp_checksum = (pseudo_checksum + ntohs(*(checksum_p + i)));
            if (temp_checksum > 0xffff){
                pseudo_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                pseudo_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        checksum_p = reinterpret_cast<uint16_t*>(&temp_packet->tcp_header.th_sport);

        for(u_int16_t i = 0; i < (ntohs(pseudo.total_len) / 2); i++){
            temp_checksum = (tcp_checksum + ntohs(*(checksum_p + i)));
            if (temp_checksum > 0xffff){
                tcp_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                tcp_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        if ((ntohs(pseudo.total_len) % 2) == 1){
            temp_checksum = (tcp_checksum + (*(packet + ntohs(pseudo.total_len) + (temp_packet->ip_header.ip_hl * 4) - 1) << 8));
            if (temp_checksum > 0xffff){
                tcp_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                tcp_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        if ((tcp_checksum + pseudo_checksum) > 0xffff){
            checksum = ((tcp_checksum + pseudo_checksum) & 0xffff) + ((tcp_checksum + pseudo_checksum) >> 16);
        } else{
            checksum = (tcp_checksum + pseudo_checksum);
        }
        checksum = ~checksum;
        temp_packet->tcp_header.th_sum = htons(checksum);

    } catch (exception e) {
        cout << "why " << endl;
        e.what();
    }
}

u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;

    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}

