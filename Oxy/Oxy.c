//
//  Oxy.c
//  Oxy
//
//  Created by Ryan Berdeen on 2/1/13.
//  Copyright (c) 2013 Ryan Berdeen. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t Oxy_start(kmod_info_t * ki, void *d);
kern_return_t Oxy_stop(kmod_info_t *ki, void *d);

kern_return_t Oxy_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t Oxy_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
