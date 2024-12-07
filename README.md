# XDP-Introduction
XDP Hands On - Sistemas Empotrados II

## Dependencies

Before starting doing this hands on please install the following dependencies that are needed for compiling XDP programs:

```
sudo apt install clang llvm libelf-dev libpcap-dev build-essential
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
## Your first XDP program 

We will write our first XDP program, this is a really basic XDP program that will drop any incoming packet.

The code is really simple:

``` C
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
```
If is your first time working with XDP you might have some questions for example what is the SEC("xdp") and what is the struct xdp_md *ctx. 

The Macro SEC("xdp") indicates to the compiler that the function bellow it is an xdp program, that way the compiler will generate the elf with a section XDP that will be loaded into the kernel. One ELF can have multiple XDP sections.

The struct xdp_md has the metadata of the incoming packet on this example we will not use it but we will use it on the next examples.

Now we have to compile our xdp program. We will use clang.

```
clang -O2 -target bpf -c xdp-drop.bpf.c -o xdp-drop.bpf.o
```
Some options like the -O2 should sound familiar. Using the -target bpf we are indicating that we are compiling a bpf program(XDP is build on top of bpf). 

The compiler will create and object file. This file has the different sections we have indicated in the source code.

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
We can now unload the program from the interface using the iproute2 tool:

```
sudo ip link set dev lo xdpgeneric off
```

We have now loaded our first XDP program into the kernel but we can do a lot of more things with this technology.

## Parsing packets on XDP 

### Network packet structure
Before going more in depth into XDP we need to understand some basics about how computer networks work. A network frame is made of protocol headers and data. The start of the packet has the layer2 protocol after that there usually is th elayer 3 protocol etc etc. For example an UDP frame send throught internet will have this structure

|------------------|-----------|-------------|
| ETHERNET HEADER  | IP HEADER | UDP HEADER  |
|------------------|-----------|-------------|

This headers contain important information about the incoming frame such us source ip , destination ip. One of the common use cases of XDP program is parsing the headers of the incoming frames and make decision based on their headers.

### UDP Firewall

The XDP program on xdp-parse.bpf.c will parse the headers of the incoming frames and will drop any UDP frame. Some key aspects of the program are the following ones:

```c
void *data_end = (void *)(long)ctx->data_end;
void *data     = (void *)(long)ctx->data;

```

Are arrays that contain the starting adress of the frame and the endign adress of the frame , trying to to a memory access outside of that memory range will cause the program to not be able to load into the kernel. Accesing to local variables is fine.

Functions such as **parse_ethhdr** or **parse_iphdr**, will motify the pointer to the next header , and will also return a struct with the header. You can acces that struct to get extra information.

### Hands On

Load into the kernel the xdp-parse.bpf.c for that compile it using clang and load it with the iproute2 utility. For any compilation problem regarding linux headers check the **Problems** section.
```
clang -O2 -target bpf -c xdp-parse.bpf.c -o xdp-parse.bpf.o
sudo ip link set dev lo xdpgeneric obj xdp-parse.bpf.o sec xdp
```
The provided **udp_client.c** and **udp_server.c** can be used to generate and receive udp frames using the localhost interface and the port 1000. As you can see the client is sending UDP frames but the server is not able to receive them.

Please modify the **xdp-parse.bpf.c** so UDP frames going to the port 1000 are not dropped , the rest of UDP frames should still be dropped. 


## ebpf Maps

Some of you might have already realised that we can not store any iformation between the execution of different programs. For example What happens if I want to count how many frames I have received.

The answer to this question are ebpf maps. They are a shared memory areas between the kernel space and the user space that allow ebpf programs to store persistent information. 

### Install lib-xdp

git clone https://github.com/xdp-project/xdp-tools
sudo apt install m4
cd lib
make
sudo make install


Compile user_space:
clang -O2 -o xdp-counter xdp-counter-example.c -lxdp -lbpf
clang -O2 -target bpf -c xdp-counter-example.bpf.c -o xdp-counter.bpf.o


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

