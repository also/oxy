//
//  main.c
//  oxy_client
//
//  Created by Ryan Berdeen on 2/17/13.
//  Copyright (c) 2013 Ryan Berdeen. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../oxy.h"

int main(int argc, const char * argv[]) {
    int ctl_socket = 0;
    struct ctl_info ctl_info;
    struct sockaddr_ctl sc;
    
    ctl_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (ctl_socket < 0) {
		perror("socket SYSPROTO_CONTROL");
		exit(0);
	}
	bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, OXY_BUNDLEID);
	if (ioctl(ctl_socket, CTLIOCGINFO, &ctl_info) == -1) {
		perror("ioctl CTLIOCGINFO");
        printf("Is the Oxy KEXT loaded?\n");
		exit(0);
	}
    
    bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
    
    if (connect(ctl_socket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
		perror("connect");
        if (errno == EBUSY) {
            printf("Only one connection allowed at a time.\n");
        }
        else if (errno == EPERM) {
            printf("Needs to be run as root.\n");
        }
		exit(0);
	}

    uint16_t version;
    socklen_t size = sizeof(version);
    if (getsockopt(ctl_socket, SYSPROTO_CONTROL, OXY_OPT_VERSION, &version, &size)) {
        perror("getsockopt OXY_OPT_VERSION");
        exit(0);
    }

    if (version != OXY_VERSION) {
        printf("Oxy client version %d doesn't match server version %d\n", OXY_VERSION, version);
        exit(1);
    }

    struct outbound_connection msg;

    while (recv(ctl_socket, &msg, sizeof(msg), 0) == sizeof(msg)) {
        unsigned char addstr[256];
        struct in_addr addr = {htonl(msg.host)};
        inet_ntop(AF_INET, &addr, (char*)addstr, sizeof(addstr));
        printf("pid %d connecting to %s:%d\n", msg.pid, addstr, msg.port);
        
        if (msg.host == 2905464893 && msg.port == 80) {
            printf("blocking connection to www.ryanberdeen.com:80\n");
            msg.flags = OXY_CONNECTION_REJECT;
        }
        if (msg.host == 134744072 && msg.port == 22) {
            printf("for some reason you are trying to ssh into google's dns server. how about www.ryanberdeen.com instead?\n");
            msg.flags = OXY_CONNECTION_MODIFY;
            msg.host = 2905464893;
        }

        if (send(ctl_socket, &msg, sizeof(msg), 0) == -1) {
            perror("send");
            exit(0);
        }
    }

    close(ctl_socket);
    
    return 0;
}

