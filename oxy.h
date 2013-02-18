//
//  oxy.h
//  Oxy
//
//  Created by Ryan Berdeen on 2/17/13.
//  Copyright (c) 2013 Ryan Berdeen. All rights reserved.
//

#ifndef Oxy_oxy_h
#define Oxy_oxy_h

#include <netinet/in.h>

#define OXY_VERSION 1

#define OXY_BUNDLEID		"com.rberdeen.oxy.kext"
#define OXY_SF_HANDLE 0x4F585859 // OXXY
#define SOL_OXY 0x4F585859


struct outbound_connection {
    void *cookie;
    int flags;
    int pid;
    in_addr_t host;
    in_port_t port;
};

#define OXY_CONNECTION_IGNORE 0
#define OXY_CONNECTION_REJECT 1
#define OXY_CONNECTION_MODIFY 2

#define OXY_OPT_VERSION 0

#endif
