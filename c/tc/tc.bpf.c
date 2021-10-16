#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc.h"

//#include <linux/if_ether.h>
#define ETH_ALEN 6
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

#define htons bpf_htons
#define ntohl bpf_ntohl
#define ntohs bpf_ntohs

pid_t my_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(value, u16);
    __type(key, u32);
} ports SEC(".maps");

struct iphdr* is_ipv4(struct ethhdr *eth, void *data_end) 
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == htons(ETH_P_IP)) {
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

struct ipv6hdr* is_ipv6(struct ethhdr *eth, void *data_end) 
{
    struct ipv6hdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == htons(ETH_P_IPV6)) {
        iph = (struct ipv6hdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

struct arphdr* is_arp(struct ethhdr *eth, void *data_end)
{
    struct arphdr *arp = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*arp) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == htons(ETH_P_ARP)) {
        arp = (struct arphdr*)((void*)eth + sizeof(*eth));
    }
    return arp;
}

struct udphdr* is_udp(void *iph, u8 hdr_sz, void *data_end)
{
    struct udphdr *udph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*udph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_UDP) {
        udph = (struct udphdr*)((void*)iph + hdr_sz);
    }
    return udph; 
}

struct tcphdr* is_tcp(void *iph, u8 hdr_sz, void *data_end)
{
    struct tcphdr *tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*tcph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_TCP) {
        tcph = (struct tcphdr*)((void*)iph + hdr_sz);
    }
    return tcph;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    int rc = TC_ACT_SHOT;
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    pid_t tgid = BPF_CORE_READ(t, tgid);
    pid_t pid = BPF_CORE_READ(t, pid);
    if (tgid == my_pid) {
        rc = TC_ACT_OK; // dont report the kernel dont report myself
        bpf_printk("dont report me!");
        return rc;
    }
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    struct iphdr *iph = is_ipv4(eth, data_end);
    struct ipv6hdr *iph6 = is_ipv6(eth, data_end);
    struct arphdr *arp = is_arp(eth, data_end);

    struct tc_evt *evt = NULL;
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        bpf_printk("no ringbuff");
        goto rb_err;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->eth_type = htons(BPF_CORE_READ(eth, h_proto));
    bpf_probe_read_kernel_str(evt->comm, TASK_LEN, BPF_CORE_READ(t, group_leader, comm));
    evt->tgid = tgid;
    evt->pid = pid;
    bpf_printk("comm is: %s eth_type is 0x%04x", evt->comm, evt->eth_type);

    if (iph) {
        u8 hdr_sz = sizeof(*iph);
        struct udphdr *udph = is_udp(iph, hdr_sz, data_end);
        struct tcphdr *tcph = is_tcp(iph, hdr_sz, data_end);

        u32 daddr = iph->daddr;

        if (tcph || udph) {
            bpf_printk("dest ip is %08x", ntohl(daddr));
        } else {
            goto err; 
        }

        bpf_probe_read_kernel(&evt->ip.addr.ipv4_daddr, sizeof(evt->ip.addr.ipv4_daddr), &daddr);
    
        if (tcph) {
            bpf_printk("is tcp %d", ntohs(tcph->source));
            bpf_printk("  %d\n", ntohs(tcph->dest));

            evt->ip.ipp = TCP_V4;
            evt->ip.port = ntohs(tcph->dest);
        } else if(udph) {
            bpf_printk("is udp %d", htons(udph->source));
            bpf_printk("  %d\n", htons(udph->dest));
        
            evt->ip.port = ntohs(udph->dest);
        }
    } else if (iph6) {
        u8 hdr_sz = sizeof(*iph6);
        struct udphdr *udph = is_udp(iph6, hdr_sz, data_end);
        struct tcphdr *tcph = is_tcp(iph6, hdr_sz, data_end);

        if (tcph || udph) {
            /*for (int i = 0; i < sizeof(iph6->daddr.in6_u.u6_addr8); i++) {*/
                /*bpf_printk("%02x",iph6->daddr.in6_u.u6_addr8[i]);*/
            /*}*/
        } else {
            goto err; 
        }

        bpf_probe_read_kernel(&evt->ip.addr.ipv6_daddr, sizeof(evt->ip.addr.ipv6_daddr), &iph6->daddr.in6_u.u6_addr8);

        if (tcph) {
            bpf_printk("is tcpv6 %d", ntohs(tcph->source));
            bpf_printk("  %d\n", ntohs(tcph->dest));
            evt->ip.ipp = TCP_V6;
            evt->ip.port = ntohs(tcph->dest);
        } else if(udph) {
            bpf_printk("is udpv6 %d", htons(udph->source));
            bpf_printk("  %d\n", htons(udph->dest));
            evt->ip.ipp = UDP_V6;
            evt->ip.port = ntohs(udph->dest);
        }
    } else if (arp) {
        bpf_probe_read_kernel(&evt->arp, sizeof(evt->arp), arp);
        bpf_printk("arp");
    }

    rc = TC_ACT_SHOT;
    if (evt->eth_type == ETH_P_ARP) rc = TC_ACT_OK;
    /*if (evt->ip.port == 53) rc = TC_ACT_OK;*/
    /*if (evt->ip.port == 5355) rc = TC_ACT_OK;*/
    /*if (evt->ip.port == 22) rc = TC_ACT_OK;*/
    /*if (evt->ip.port == 443) rc = TC_ACT_OK;*/
    //if (evt->ip.port == 80) rc = TC_ACT_OK;
    bpf_printk("%d\n", evt->ip.port);

    u32 i = 0;
    for (i = 0; i < 10; i++) {
        u16 *port;
        u32 key = i;
        port = bpf_map_lookup_elem(&ports, &key);
        if (port && evt->ip.port == *port) {
            rc = TC_ACT_OK;
        }
    }

    if (rc == TC_ACT_SHOT) {
        evt->pkt_state = BLOCKED;
    } else {
        evt->pkt_state = ALLOWED;
    }
    bpf_ringbuf_submit(evt, 0);
    evt = NULL;
err:
    if (evt) bpf_ringbuf_discard(evt, 0);
rb_err:
    return rc;
}

char LICENSE[] SEC("license") = "GPL";
