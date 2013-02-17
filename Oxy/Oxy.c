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
#define OXY_SF_HANDLE 0x4F585859 // OXXY


kern_return_t Oxy_start(kmod_info_t * ki, void *d);
kern_return_t Oxy_stop(kmod_info_t *ki, void *d);

static OSMallocTag global_malloc_tag;

enum filter_state {
    UNREGISTERED,
    REGISTERED,
    UNREGISTERING
};

static enum filter_state global_filter_state = UNREGISTERED;


static void oxy_unregistered_func(sflt_handle handle) {
    global_filter_state = UNREGISTERED;
    printf("Oxy success sflt_unregister\n");
}

static errno_t oxy_attach_func(void **cookie, socket_t so) {
    return 0;
}

static void oxy_detach_func(void *cookie, socket_t so) {
}

static void oxy_notify_func(void *cookie, socket_t so, sflt_event_t event, void *param) {
    
}

static errno_t oxy_connect_out_func(void *cookie,
                                    socket_t so,
                                    const struct sockaddr *to) {
    printf("Oxy oxy_connect_out_func!\n");
    unsigned char name[256];
    unsigned char addstr[256];
    struct sockaddr_in* addr = (struct sockaddr_in*) to;
    inet_ntop(AF_INET, &addr->sin_addr, (char*)addstr, sizeof(addstr));
    proc_selfname((char*)name, sizeof(name));
    printf("Oxy connection: %s to %s:%d\n", name, addstr, ntohs(addr->sin_port));

    return 0;
}

static struct sflt_filter TLsflt_filter_ip4 = {
	OXY_SF_HANDLE,	/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
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
	NULL,		/* sf_connect_in_func */
	oxy_connect_out_func,		/* sf_connect_out_func */
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
        printf("Oxy failure OSMalloc_Tagalloc\n");
        goto bail;
    }
    
    retval = sflt_register(&TLsflt_filter_ip4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (retval == 0) {
        printf("Oxy success sflt_register\n");
        global_filter_state = REGISTERED;
    }
    else {
        printf("Oxy failure sflt_register\n");
        goto bail;
    }
    
    return KERN_SUCCESS;
    
    bail:
    if (global_filter_state == REGISTERED) {
        global_filter_state = UNREGISTERING;
        sflt_unregister(OXY_SF_HANDLE);
    }
    if (global_malloc_tag) {
        OSMalloc_Tagfree(global_malloc_tag);
        global_malloc_tag = NULL;
    }
    return KERN_FAILURE;
}

kern_return_t Oxy_stop(kmod_info_t *ki, void *d)
{
    errno_t retval;
    printf("Oxy_stop\n");
    if (global_filter_state == REGISTERED) {
        global_filter_state = UNREGISTERING;
        printf("Oxy unregistering\n");
        retval = sflt_unregister(OXY_SF_HANDLE);
        if (retval != 0) {
            printf("WTF? sflt_unregister returned %d\n", retval);
            // FIXME is this right?
            global_filter_state = REGISTERED;
        }
        // note that we might be unregistered by now.
    }
    if (global_filter_state != UNREGISTERED) {
        printf("Oxy not unregistered yet\n");
        return KERN_FAILURE;
    }
    if (global_malloc_tag) {
        OSMalloc_Tagfree(global_malloc_tag);
        printf("Oxy freed OSMalloc tag. All done.\n");
        global_malloc_tag = NULL;
    }
    return KERN_SUCCESS;
}
