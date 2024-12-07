#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>  
#include <signal.h>
#include <net/if.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "xdp-struct-definition.h"


static int ifindex;
struct xdp_program *prog = NULL;



static void poll_stats(int map_fd, int map_fd_time, int interval) {
    int key = 0;
    struct datarec value;

    while (1) {

        if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
            fprintf(stderr, "Error in bpf_map_lookup_elem\n");
            break;
        }
        printf("Total packets: %lld\n", value.counter);
        sleep(interval);
    }

}

int main(int argc, char *argv[])
{
    int prog_fd, map_fd, map_fd_time, ret;
    struct bpf_object *bpf_obj;

    if (argc != 2) {
        printf("Usage: %s IFNAME\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return 1;
    }
    char *filename = "xdp-counter.bpf.o";
    char *progname = "count";

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
    xdp_opts.open_filename = filename;
    xdp_opts.prog_name = progname;
    xdp_opts.opts = &opts;
        
    struct xdp_program *prog = xdp_program__create(&xdp_opts);
    int  err = libxdp_get_error(prog);
        if (err) {
                char errmsg[1024];
                libxdp_strerror(err, errmsg, sizeof(errmsg));
                fprintf(stderr, "ERR: loading program: %s\n", errmsg);
            return 1    ;
        }

    ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret) {
        printf("Error, Set xdp fd on %d failed\n", ifindex);
        return ret;
    }

    prog_fd = xdp_program__fd(prog);
        if (prog_fd < 0) {
                fprintf(stderr, "ERR: xdp_program__fd failed: %d\n", prog_fd);
        return 1;
        }
    printf("XDP-PROGRAM LOADED\n");

    bpf_obj = xdp_program__bpf_obj(prog);
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xdp_counter");
    if (map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
        return map_fd;
    }
    
    /*
    __u32 key = 0;
    __u64 value = 0;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Error, failed to set map counter value to 0\n");
        return 1;
    }
    */

    poll_stats(map_fd,map_fd_time, 2);

    return 0;
}
