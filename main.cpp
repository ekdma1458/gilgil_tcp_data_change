#include "stdafx.h"

char *from_str;
char *to_str;
map<pair<FlowC,FlowC>, pair<int16_t, uint32_t>> flow_map;
int size = 0;
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
       struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *test;

    u_int32_t id = 0;
    int count = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    int ret = nfq_get_payload(nfa, &test);
    if (ret >= 0){
        ST_JE_TCP_Packet* temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(test);
        if (temp_packet->ip_header.ip_p == 6) {
            FlowC snd_flow(temp_packet, true);
            FlowC dst_flow(temp_packet, false);
            string check = "";
            check.assign(reinterpret_cast<char*>(test), ret);
            int pos = check.find(from_str, 0);
            if (pos > 0) {
                while (pos > 0) {
                    check.replace(pos, strlen(from_str), to_str);
                    pos++;
                    pos = check.find(from_str, pos);
                    count++;
                }
                unsigned char *temp = reinterpret_cast<unsigned char*>(const_cast<char*>(check.c_str()));
                temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(temp);
                if (size != 0) {
                    if (flow_map.find(make_pair(snd_flow, dst_flow)) == flow_map.end()){
                        flow_map.insert(make_pair(make_pair(snd_flow, dst_flow), make_pair((size * count),temp_packet->tcp_header.th_seq)));
                        ipCheckSum(temp, (size * count));
                    }
                }
                tcpCheckSum(temp);
                return nfq_set_verdict(qh, id, NF_ACCEPT, check.size(), temp);
            } else {
                if (flow_map.find(make_pair(snd_flow, dst_flow)) != flow_map.end()){
                    if (temp_packet->tcp_header.th_flags & 0x11){
                        flow_map.at(make_pair(snd_flow, dst_flow)).first += 3000;
                    }
                    if (temp_packet->tcp_header.th_seq > flow_map.at(make_pair(snd_flow, dst_flow)).second){
                        temp_packet->tcp_header.th_seq = htonl(ntohl(temp_packet->tcp_header.th_seq) + flow_map.at(make_pair(snd_flow, dst_flow)).first);
                    }
                } else if(flow_map.find(make_pair(dst_flow, snd_flow)) != flow_map.end()){
                    if (flow_map.at(make_pair(dst_flow, snd_flow)).first  > 1500){
                        temp_packet->tcp_header.th_ack = htonl(ntohl(temp_packet->tcp_header.th_ack) - flow_map.at(make_pair(dst_flow, snd_flow)).first) - 3000;
                        flow_map.erase(make_pair(dst_flow, snd_flow));
                    } else {
                        temp_packet->tcp_header.th_ack = htonl(ntohl(temp_packet->tcp_header.th_ack) - flow_map.at(make_pair(dst_flow, snd_flow)).first);
                    }
                }
                tcpCheckSum(test);
                return nfq_set_verdict(qh, id, NF_ACCEPT, check.size(), test);
            }
        }
        printf("entering callback\n");
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if(argc < 3){
        usage();
        return 0;
    }
    from_str = argv[1];
    to_str = argv[2];
    size = strlen(to_str) - strlen(from_str);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

