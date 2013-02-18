//
//  main.c
//  oxy_test
//
//  Created by Ryan Berdeen on 2/18/13.
//  Copyright (c) 2013 Ryan Berdeen. All rights reserved.
//


#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>


int main(int argc, const char * argv[]) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    uint16_t version;
    socklen_t size = sizeof(version);

    if (getsockopt(sock, 0x4F585859, 0, &version, &size) == 0) {
        printf("Oxy version %d is looking at your sockets!\n", version);
    }
    else if (errno == EINVAL) {
        printf("Oxy not running.\n");
    }
    else {
        perror("getsockopt OXY_OPT_VERSION");
    }

    return 0;
}

