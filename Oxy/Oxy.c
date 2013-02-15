//
//  Oxy.c
//  Oxy
//
//  Created by Ryan Berdeen on 2/1/13.
//  Copyright (c) 2013 Ryan Berdeen. All rights reserved.
//

#include <sys/systm.h>
#include <mach/mach_types.h>

#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <netinet/in.h>

#include <libkern/OSMalloc.h>

#define OXY_BUNDLEID		"com.rberdeen.oxy.kext"
#define OXY_HANDLE 0x4F585859 // OXXY


kern_return_t Oxy_start(kmod_info_t * ki, void *d);
kern_return_t Oxy_stop(kmod_info_t *ki, void *d);

static OSMallocTag global_malloc_tag;
static boolean_t global_filter_registered = FALSE;


static void oxy_unregistered_func(sflt_handle handle) {
    
}

static errno_t oxy_attach_func(void **cookie, socket_t so) {
    return 0;
}

static void oxy_detach_func(void *cookie, socket_t so) {
    int pid = proc_selfpid();
}

static void oxy_notify_func(void *cookie, socket_t so, sflt_event_t event, void *param) {
    
}

static errno_t oxy_connect_in_func(void *cookie,
                                   socket_t so,
                                   const struct sockaddr *from) {
    return 0;
}

static struct sflt_filter TLsflt_filter_ip4 = {
	OXY_HANDLE,	/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	OXY_BUNDLEID,				/* sf_name - cannot be nil else param err results */
	oxy_unregistered_func,	/* sf_unregistered_func */
	oxy_attach_func,		/* sf_attach_func - cannot be nil else param err results */
	oxy_detach_func,			/* sf_detach_func - cannot be nil else param err results */
	oxy_notify_func,			/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	NULL,			/* sf_data_in_func */
	NULL,			/* sf_data_out_func */
	oxy_connect_in_func,		/* sf_connect_in_func */
	NULL,		/* sf_connect_out_func */
	NULL,				/* sf_bind_func */
	NULL,		/* sf_setoption_func */
	NULL,		/* sf_getoption_func */
	NULL,			/* sf_listen_func */
	NULL					/* sf_ioctl_func */
};

kern_return_t Oxy_start(kmod_info_t * ki, void *d)
{
    int retval;
    
    printf("Oxy_start\n");
    global_malloc_tag = OSMalloc_Tagalloc(OXY_BUNDLEID, OSMT_DEFAULT);
    if (global_malloc_tag == NULL) {
        goto bail;
    }
    
    retval = sflt_register(&TLsflt_filter_ip4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (retval == 0) {
        global_filter_registered = TRUE;
    }
    else {
        goto bail;
    }
    
    return KERN_SUCCESS;
    
    bail:
    return KERN_FAILURE;
}

kern_return_t Oxy_stop(kmod_info_t *ki, void *d)
{
    if (!global_filter_registered) {
        // nothing is registered, so nothing to clean up
        return KERN_SUCCESS;
    }
    printf("Oxy_stop\n");
    if (global_malloc_tag) {
        OSMalloc_Tagfree(global_malloc_tag);
        global_malloc_tag = NULL;
    }
    return KERN_SUCCESS;
}
