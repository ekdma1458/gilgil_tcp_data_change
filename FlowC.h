#ifndef FLOWC_H
#define FLOWC_H
#include "stdafx.h"
class FlowC{
private:
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
public:
    FlowC(ST_JE_TCP_Packet *packet, bool check);
    bool operator<(const FlowC& other) const;
    void toString();
};

#endif // FLOWC_H
