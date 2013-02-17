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

#include "../oxy.h"

int main(int argc, const char * argv[])
{
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
    printf("ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
    
    bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
    
    if (connect(ctl_socket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
		perror("connect");
		exit(0);
	}
    
    char message[] = "Hello, Oxy!\n";
    if (send(ctl_socket, message, sizeof(message), 0) == -1) {
        perror("send");
		exit(0);
    }
    
    close(ctl_socket);
    
    return 0;
}
