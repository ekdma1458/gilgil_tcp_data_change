#ifndef STDAFX_H
#define STDAFX_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>	/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <string>
#include <iostream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <map>
#include "tcp_data_change.h"
#include "FlowC.h"
using namespace std;
#endif // STDAFX_H
