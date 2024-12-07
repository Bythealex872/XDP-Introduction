/* This fileis used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#include <linux/types.h>
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data to be stored on the map */
        struct datarec {
                __u64 counter;
                struct bpf_spin_lock lock;
        };

#endif 

#ifndef  MAP_SIZE
#define MAP_SIZE 100
#endif