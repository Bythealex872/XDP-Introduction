# XDP-Introduction
XDP Hands On - Sistemas Empotrados II

## Dependencies

Before starting please install the following dependencies that are needed for compiling XDP programs:

```
sudo apt install clang llvm libelf-dev libbpf-dev libpcap-dev build-essential
sudo apt install linux-headers-$(uname -r)

```
On Debian 
```
sudo apt install linux-perf
```
On Ubuntu
```
sudo apt install linux-tools-$(uname -r)
```

Install libxdp and libbpf
```
git clone https://github.com/xdp-project/xdp-tools
sudo apt install m4
cd /xdp-tools/lib
make
sudo make install
```

## Your first XDP program 

We will write our first XDP program.This is a really basic XDP program that will drop any incoming packet.



``` C
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
```
If this is your first time working with XDP, you may have questions such as what SEC("xdp") means and what the struct xdp_md *ctx parameter represents.

The SEC("xdp") macro informs the compiler that the function immediately following it is an XDP program. As a result, the compiler generates an ELF file containing an XDP section, which can later be loaded into the kernel. Note that a single ELF file can contain multiple XDP sections.

The xdp_md structure provides metadata about the incoming network packet. In this example, we will not make use of it, but it will be utilized in later examples.

```
clang -O2 -target bpf -c xdp-drop.bpf.c -o xdp-drop.bpf.o
```
Some options like the -O2 should sound familiar. Using the -target bpf we are indicating that we are compiling a bpf program(XDP is build on top of ebpf). 

The result is an object file that contains the different sections defined in the source code (for example, those marked with SEC("xdp")). This object file can then be loaded into the kernel.

Now we are going to load the program on a network interface. There are multiple ways to to load a XDP program into the kernel. In our case we are going to use the iproute2 utility.

```
sudo ip link set dev lo xdpgeneric obj xdp-drop.bpf.o sec xdp
```

Our XDP program is now laoded into the kernel. We can check that is loaded by sending data to that interface. We can use the ping utility for that.

```
alex@alex:~/XDP-Introduction$ ping localhost
PING localhost(localhost (::1)) 56 data bytes
^C
--- localhost ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4076ms

```

As you can see we are not getting response form the ping that means the frames are been dropped by our XDP program. 

We can now unload the program from the interface using the iproute2 tool:

```
sudo ip link set dev lo xdpgeneric off
```

We have now loaded our first XDP program into the kernel but we can do a lot of more things with this technology.

## Parsing packets on XDP 

Before diving deeper into XDP, it is important to understand some basic concepts about how computer networks work.

A network frame is composed of protocol headers and data. At the beginning of the packet, you’ll find the Layer 2 (Data Link) protocol header, followed by the Layer 3 (Network) protocol header, and so on through the higher layers.

These headers contain essential information about the incoming frame, such as the source IP address, destination IP address, and other protocol-specific fields.

One of the most common use cases for an XDP program is to parse the headers of incoming packets and make decisions based on the information they contain.

### UDP Firewall

The XDP program on xdp-parse.bpf.c will parse the headers of the incoming frames and will drop any UDP frame. Some key aspects of the program are the following ones:

```c
void *data_end = (void *)(long)ctx->data_end;
void *data     = (void *)(long)ctx->data;

```

Are arrays that contain the starting adress of the frame and the endign adress of the frame , trying to to a memory access outside of that memory range will cause the program to not be able to load into the kernel. Accesing to local variables is fine.

Functions such as **parse_ethhdr** or **parse_iphdr**, will motify the pointer to the next header , and will also return a struct with the header. You can acces that struct to get extra information.

### Hands On
Take a look at the source code after that load into the kernel the xdp-parse.bpf.c for that compile it using clang and load it with the iproute2 utility. For any compilation problem regarding linux headers check the **Problems** section.
```
clang -O2 -target bpf -c xdp-parse.bpf.c -o xdp-parse.bpf.o
sudo ip link set dev lo xdpgeneric obj xdp-parse.bpf.o sec xdp
```
The provided **udp_client.c** and **udp_server.c** can be used to generate and receive udp frames using the localhost interface and the port 1000. As you can see  when the xdp program is loaded the client is sending UDP frames, but the server is not able to receive them.

Please modify the **xdp-parse.bpf.c** so UDP frames going to the port 1000 are not dropped , the rest of UDP frames should still be dropped. 



## ebpf Maps

You may have already noticed that we cannot store any information between different executions of an XDP program. For example, what if we want to count how many packets have been received? Or how can we communicate with a user-space process?

The answer lies in eBPF maps.
Maps are shared memory areas between kernel space and user space that allow eBPF programs to store persistent data.

Maps are defined as a section of the object generated by the compiler with the macro SEC.

We can define wich tipe of map on the field type ,on this example we will use an array. Maps are use a key value storage and we have to indicate wich data structure will the key be. In our case a unsigned int. We also can indicate wich data structure will we be storing on the map in our case is a custom struct called datarec. Both the XDP program and the userspace program have to be aware of this. And we can finally define how many entries we want the map to have. In our case is 1000 but we will only use one.

```c
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct datarec);
        __uint(max_entries, 1000);
}xdp_counter SEC(".maps");

```

Accesing the values of the map can be done both from a userspace application using libbpf or by a ebpf aplication. Examples can be found on **xdp-counter-example.c** and  **xdp-counter-example-bpf.c** . For this assigment we will be using our own custom loader instead of the iproute2 utility. This way we have more controll of what we load into the kernel and we have an easy acces to the maps. 


First lets take a look at the **xdp-counter-example-bpf.c**. As you can see is a really simple porgram it just updates the counter when a frame is received. The map is shared by multiple process so we have to acces it under mutual exclusion , that is why we are using a spinlock. 

Now lets take a look at the loader **xdp-counter-example.c** , this program will first load the XDP program and after that will pull the map and print the number of incoming packets:

We first need to get the id of the network interface where we want to load the XDP program:

```c
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return 1;
    }
```
After that we need to obtain the xdp program form the object file and load it into the interface:

```c
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
```

Once the program has been loaded we can get the file descriptor of the map we have defined:
```c
    bpf_obj = xdp_program__bpf_obj(prog);
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xdp_counter");
    if (map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
        return map_fd;
    }
```

We can later use that file descriptor for accesing to the map using libbpf:

```c
        if (bpf_map_lookup_elem(map_fd, &key, &value) != 0) {
            fprintf(stderr, "Error in bpf_map_lookup_elem\n");
            break;
        }
        printf("Total packets: %lld\n", value.counter);
```
In this example we are getting the value sotored on the key entry of the map.

The **xdp-counter-example.c** will load an xdp program into the kernel that will update the map with the number of incoming packets , meanwhile the userspace program will print them.

You can compile them and run them using the run.sh script:

```
clang -O2 -o xdp-counter xdp-counter-example.c -lxdp -lbpf
clang -O2 -g -target bpf -c xdp-counter-example.bpf.c -o xdp-counter.bpf.o
sudo ./run.sh
```

### Hands On

Please try to make a program that will print how many udp and tcp frames are been received. You can use the xdp-parse.bpf.c as starting point for the XDP program and the xdp-counter-example.c as a starting point for loading the XDP program and for polling the stats. 

You can try the counter program. First compile both the userspace and the XDP program.

clang -O2 -o xdp-counter xdp-counter-example.c -lxdp -lbpf
clang -O2 -g -target bpf -c xdp-counter-example.bpf.c -o xdp-counter.bpf.o

You can launch the program using the run.sh script

## Problems  

 /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found **

Find where the .h file is , might not be on /usr/include 
```
find /usr/include/ -name types.h | grep asm
```
Make a softlink between the headers and where the library expects them : 
```
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

This problem might happen with other required headers depending on the linux distro. The solutions provided above work with any other header.

