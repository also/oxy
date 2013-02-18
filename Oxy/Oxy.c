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
#include <sys/kern_control.h>
#include <netinet/in.h>

#include <libkern/OSMalloc.h>

#include "oxy.h"

kern_return_t Oxy_start(kmod_info_t * ki, void *d);
kern_return_t Oxy_stop(kmod_info_t *ki, void *d);

static OSMallocTag global_malloc_tag;

static kern_ctl_ref gctl_ref;
static boolean_t g_kern_ctl_registered = FALSE;

enum filter_state {
    UNREGISTERED,
    REGISTERED,
    UNREGISTERING
};

static enum filter_state g_filter_state = UNREGISTERED;

static lck_mtx_t *g_mutex = NULL;
static lck_mtx_t *g_pending_connection_list_mutex = NULL;
static lck_grp_t *g_mutex_grp = NULL;

struct ctl_connection {
    kern_ctl_ref ref;
    u_int32_t unit;
    struct outbound_connection in_msg;
};

struct connection {
    TAILQ_ENTRY(connection) link;
    lck_mtx_t *mutex;
    boolean_t ready;
    struct outbound_connection opts;
};

TAILQ_HEAD(connection_list, connection);

static struct connection_list g_pending_connection_list; // protected by g_pending_connection_list_mutex

static struct ctl_connection g_ctl_connection = {
    NULL,
    NULL
};


static void sf_unregistered(sflt_handle handle) {
    g_filter_state = UNREGISTERED;
    printf("Oxy success sflt_unregister\n");
}

static errno_t sf_attach(void **cookie, socket_t so) {
    struct connection *conn = (struct connection *)OSMalloc(sizeof (struct connection), global_malloc_tag);
    if (conn == NULL) {
        return ENOBUFS;
    }
    conn->mutex = lck_mtx_alloc_init(g_mutex_grp, LCK_ATTR_NULL);
    if (conn->mutex == NULL) {
        OSFree(conn, sizeof(struct connection), global_malloc_tag);
        return ENOMEM;
    }
    *cookie = conn;
    return 0;
}

static void sf_detach(void *cookie, socket_t so) {
    struct connection *conn = cookie;

    if (!conn) {
        // is this possible?
        return;
    }

    lck_mtx_free(conn->mutex, g_mutex_grp);
    OSFree(conn, sizeof(struct connection), global_malloc_tag);
}

static void sf_notify(void *cookie, socket_t so, sflt_event_t event, void *param) {

}

static errno_t sf_connect_out(void *cookie,
                                    socket_t so,
                                    const struct sockaddr *to) {
    unsigned char name[256];
    unsigned char addstr[256];

    int result = 0;

    struct connection *conn = cookie;

    struct sockaddr_in* addr = (struct sockaddr_in*) to;
    inet_ntop(AF_INET, &addr->sin_addr, (char*)addstr, sizeof(addstr));
    proc_selfname((char*)name, sizeof(name));

    lck_mtx_lock(g_mutex);
    if (g_ctl_connection.ref) {
        conn->opts.cookie = cookie;
        conn->opts.flags = OXY_CONNECTION_IGNORE;
        conn->opts.pid = proc_selfpid();
        conn->opts.host = ntohl(addr->sin_addr.s_addr);
        conn->opts.port = ntohs(addr->sin_port);

        struct timespec t = { 5, 0 };

        lck_mtx_lock(g_pending_connection_list_mutex);
        TAILQ_INSERT_TAIL(&g_pending_connection_list, conn, link);
        /*
        int len = 0;
        struct connection *c;
        TAILQ_FOREACH(c, &g_pending_connection_list, link) {
            len++;
        }
        printf("Oxy there are %d pending connections\n", len);
         */
        lck_mtx_unlock(g_pending_connection_list_mutex);

        lck_mtx_lock(conn->mutex);

        /*
         the flags for this one are a little confusing...
         not sure if i'm getting this right
         http://lists.apple.com/archives/darwin-kernel/2008/Aug/msg00012.html
         http://lists.apple.com/archives/darwin-kernel/2007/Oct/msg00018.html
         http://lists.apple.com/archives/darwin-kernel/2012/Aug/msg00041.html
         specifically,
         @param flags Send flags. CTL_DATA_NOWAKEUP is currently the only supported flag.
         is totally wrong.
         */
        errno_t retval = ctl_enqueuedata(g_ctl_connection.ref, g_ctl_connection.unit, &conn->opts, sizeof(conn->opts), CTL_DATA_EOR);
        lck_mtx_unlock(g_mutex);

        if (retval != 0) {
            // TODO ummmm?
            printf("Oxy failure ctl_enqueuedata\n");
        }

        conn->ready = FALSE;

        retval = msleep(conn, conn->mutex, 0, "connect", &t);
        if (retval == 0) {
            if (conn->ready != TRUE) {
                // TODO maybe we need to loop...don't think so
                printf("WTF? how did we wake up?\n");
            }
            else {
                printf("Oxy works! %p\n", conn);
                if (conn->opts.flags != OXY_CONNECTION_IGNORE) {
                    if (conn->opts.flags == OXY_CONNECTION_REJECT) {
                        result = ECONNREFUSED;
                    }
                    else if (conn->opts.flags == OXY_CONNECTION_MODIFY) {
                        addr->sin_port = htons(conn->opts.port);
                        addr->sin_addr.s_addr = htonl(conn->opts.host);
                    }
                }
            }
        }
        else if (retval == EWOULDBLOCK) {
            printf("Oxy timed out waiting for response from client %p\n", conn);
        }
        else {
            printf("Oxy unexpected return from msleep %p\n", conn);
        }


        // TODO ... maybe we should do this when the client sends?
        lck_mtx_lock(g_pending_connection_list_mutex);
        TAILQ_REMOVE(&g_pending_connection_list, conn, link);
        lck_mtx_unlock(g_pending_connection_list_mutex);

        lck_mtx_unlock(conn->mutex);
    }
    else {
        lck_mtx_unlock(g_mutex);
    }

    return result;
}

static errno_t ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo) {
    errno_t retval = 0;
    printf("Oxy control process with pid=%d connected\n", proc_selfpid());

    // TODO reject connections if we're shutting down
    lck_mtx_lock(g_mutex);
    if (g_ctl_connection.ref) {
        // only one connection at a time, sorry
        retval = EBUSY;
    }
    else {
        g_ctl_connection.ref = ctl_ref;
        g_ctl_connection.unit = sac->sc_unit;
    }
    lck_mtx_unlock(g_mutex);
    return retval;
}

static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo) {
    printf("Oxy control process with pid=%d disconnected\n", proc_selfpid());
    lck_mtx_lock(g_mutex);
    if (ctl_ref == g_ctl_connection.ref && unit == g_ctl_connection.unit) {
        g_ctl_connection.ref = NULL;
        g_ctl_connection.unit = NULL;
    }
    lck_mtx_unlock(g_mutex);
    return 0;
}

static struct connection *find_connection(struct connection *cookie) {
    struct connection *conn;
    struct connection *conn_next;

    for (conn = TAILQ_FIRST(&g_pending_connection_list); conn != NULL; conn = conn_next) {
        if (conn == cookie) {
            return conn;
        }
        conn_next = TAILQ_NEXT(conn, link);
    }
    return NULL;
}

static errno_t ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags) {
    size_t len = mbuf_len(m);
    // TODO i'm pretty sure this doesn't need to lock because we only allow a single connection at a time...
    // but maybe a connection can send even if connect failed?
    if (len == sizeof(g_ctl_connection.in_msg)) {
        mbuf_copydata(m, 0, len, &g_ctl_connection.in_msg);

        lck_mtx_lock(g_pending_connection_list_mutex);
        struct connection *conn = find_connection(g_ctl_connection.in_msg.cookie);
        lck_mtx_unlock(g_pending_connection_list_mutex);
        if (conn == NULL) {
            printf("Oxy recieved invalid connection cookie\n");
        }
        else {
            lck_mtx_lock(conn->mutex);
            memcpy(&conn->opts, &g_ctl_connection.in_msg, sizeof(g_ctl_connection.in_msg));
            conn->ready = TRUE;
            wakeup(conn);
            // fuck yeah
            lck_mtx_unlock(conn->mutex);
        }
    }
    else {
        printf("Oxy recieved invalid control message\n");
    }
    return 0;
}

static struct sflt_filter TLsflt_filter_ip4 = {
    OXY_SF_HANDLE,   /* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
    SFLT_GLOBAL,     /* sf_flags */
    OXY_BUNDLEID,    /* sf_name - cannot be nil else param err results */
    sf_unregistered, /* sf_unregistered_func */
    sf_attach,       /* sf_attach_func - cannot be nil else param err results */
    sf_detach,       /* sf_detach_func - cannot be nil else param err results */
    sf_notify,       /* sf_notify_func */
    NULL,            /* sf_getpeername_func */
    NULL,            /* sf_getsockname_func */
    NULL,            /* sf_data_in_func */
    NULL,            /* sf_data_out_func */
    NULL,            /* sf_connect_in_func */
    sf_connect_out,  /* sf_connect_out_func */
    NULL,            /* sf_bind_func */
    NULL,            /* sf_setoption_func */
    NULL,            /* sf_getoption_func */
    NULL,            /* sf_listen_func */
    NULL             /* sf_ioctl_func */
};

static struct kern_ctl_reg gctl_reg = {
    OXY_BUNDLEID,       /* use a reverse dns name which includes a name unique to your comany */
    0,                  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,                  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    CTL_FLAG_PRIVILEGED,/* privileged access required to access this filter */
    0,                  /* use default send size buffer */
    (8 * 1024),         /* Override receive buffer size */
    ctl_connect,        /* Called when a connection request is accepted */
    ctl_disconnect,     /* called when a connection becomes disconnected */
    ctl_send,           /* ctl_ctl_send - handles data sent from the client to kernel control */
    NULL,               /* called when the user process makes the setsockopt call */
    NULL                /* called when the user process makes the getsockopt call */
};

static errno_t alloc_locks(void) {
    g_mutex_grp = lck_grp_alloc_init(OXY_BUNDLEID, LCK_GRP_ATTR_NULL);
    if (g_mutex_grp == NULL) {
        printf("error calling lck_grp_alloc_init\n");
        return ENOMEM;
    }

    g_pending_connection_list_mutex = lck_mtx_alloc_init(g_mutex_grp, LCK_ATTR_NULL);
    if (g_pending_connection_list_mutex == NULL) {
        printf("error calling lck_grp_alloc_init\n");
        return ENOMEM;
    }

    g_mutex = lck_mtx_alloc_init(g_mutex_grp, LCK_ATTR_NULL);
    if (g_mutex == NULL) {
        printf("error calling lck_mtx_alloc_init\n");
        return ENOMEM;
    }
    return 0;
}

static void free_locks(void) {
    if (g_mutex) {
        lck_mtx_free(g_mutex, g_mutex_grp);
        g_mutex = NULL;
    }
    if (g_pending_connection_list_mutex) {
        lck_mtx_free(g_pending_connection_list_mutex, g_mutex_grp);
        g_pending_connection_list_mutex = NULL;
    }
    if (g_mutex_grp) {
        lck_grp_free(g_mutex_grp);
        g_mutex_grp = NULL;
    }
}

kern_return_t Oxy_start(kmod_info_t * ki, void *d)
{
    int retval;

    printf("Oxy_start\n");
    retval = alloc_locks();
    if (retval) {
        goto bail;
    }

    TAILQ_INIT(&g_pending_connection_list);

    global_malloc_tag = OSMalloc_Tagalloc(OXY_BUNDLEID, OSMT_DEFAULT);
    if (global_malloc_tag == NULL) {
        printf("Oxy failure OSMalloc_Tagalloc\n");
        goto bail;
    }

    retval = sflt_register(&TLsflt_filter_ip4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (retval == 0) {
        g_filter_state = REGISTERED;
    }
    else {
        printf("Oxy failure sflt_register\n");
        goto bail;
    }

    retval = ctl_register(&gctl_reg, &gctl_ref);
    if (retval == 0) {
        g_kern_ctl_registered = TRUE;
    }
    else {
        printf("Oxy failure ctl_register\n");
        goto bail;
    }

    return KERN_SUCCESS;

    bail:
    // TODO what happens if any of these fail?
    if (g_filter_state == REGISTERED) {
        g_filter_state = UNREGISTERING;
        sflt_unregister(OXY_SF_HANDLE);
    }
    if (g_kern_ctl_registered) {
        ctl_deregister(gctl_ref);
        g_kern_ctl_registered = FALSE;
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
    if (g_filter_state == REGISTERED) {
        g_filter_state = UNREGISTERING;
        printf("Oxy unregistering\n");
        retval = sflt_unregister(OXY_SF_HANDLE);
        if (retval != 0) {
            printf("WTF? sflt_unregister returned %d\n", retval);
            // FIXME is this right?
            g_filter_state = REGISTERED;
        }
        // note that we might be unregistered by now.
    }
    if (g_filter_state != UNREGISTERED) {
        printf("Oxy not unregistered yet\n");
        return KERN_FAILURE;
    }
    if (g_kern_ctl_registered) {
        retval = ctl_deregister(gctl_ref);
        if (retval != 0) {
            printf("Oxy failure ctl_deregister\n");
            return retval;
        }
    }

    free_locks();

    if (global_malloc_tag) {
        OSMalloc_Tagfree(global_malloc_tag);
        printf("Oxy freed OSMalloc tag. All done.\n");
        global_malloc_tag = NULL;
    }
    return KERN_SUCCESS;
}
