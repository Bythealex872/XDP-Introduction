/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "./xdp-struct-definition.h"
#include <linux/types.h>




struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct datarec);
        __uint(max_entries, 1000);
}xdp_counter SEC(".maps");


SEC("xdp")
int count(struct xdp_md *ctx){
 
   struct datarec *rec;
    __u32 key = 0;
    rec = bpf_map_lookup_elem(&xdp_counter, &key);
    if (!rec)
    {
        return XDP_ABORTED;
    }
    bpf_spin_lock(&rec->lock);
    rec->counter++;
    bpf_spin_unlock(&rec->lock);


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";