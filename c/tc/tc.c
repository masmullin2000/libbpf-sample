#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>

#include "tc.h"
#include "tc.skel.h"

static volatile bool exiting = false;

char* print_proto(enum ip_proto ipp)
{
    switch(ipp) {
        case TCP_V4:
            return "TCP ipv4";
        case UDP_V4:
            return "UDP ipv4";
        case TCP_V6:
            return "TCP ipv6";
        case UDP_V6:
            return "UDP ipv6";
        default:
            return "OTHER";
    }
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_evt(void *ctx, void *data, size_t sz)
{
    struct tc_evt *evt = data;

    //if (evt->pkt_state == ALLOWED) return 0;

    if (evt->pkt_state == ALLOWED) printf("ALLOWED ");
    else printf("BLOCKED ");


    if (evt->eth_type == ETH_P_IP || evt->eth_type == ETH_P_IPV6) {
        fflush(stdout);
        //return 0;
        printf("comm: %s\n", evt->comm);
        printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);
        if (evt->ip.ipp == TCP_V4 || evt->ip.ipp == UDP_V4) {
            char addr[15];
            memset(addr, 0, sizeof(addr));
            snprintf(addr, sizeof(addr), "%d.%d.%d.%d",
                evt->ip.addr.ipv4_daddr[0],
                evt->ip.addr.ipv4_daddr[1],
                evt->ip.addr.ipv4_daddr[2],
                evt->ip.addr.ipv4_daddr[3]);
            printf("dest: %s\n", addr);
#if 0
            // causes problems with systemd-resolved
            struct sockaddr_in sa;
            char site[NI_MAXHOST];
            sa.sin_family = AF_INET;
       
            int res = inet_pton(AF_INET, addr, &sa.sin_addr);
            if (res != 1){
                printf("inet issue %d\n", res);
            }
            res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), site, sizeof(site), NULL, 0, NI_NAMEREQD);
            if (!res) {
                printf("site: %s\n", site);
            } else {
                printf("site: unknown\n");
            }
#endif
        } else {
            printf("dest: ");
            char addr[30];
            char a[6];
            memset(addr, 0, sizeof(addr));
            for (int i = 0; i < 14; i+=2) {
                snprintf(a, 6, "%02x%02x:",
                    evt->ip.addr.ipv6_daddr[i],
                    evt->ip.addr.ipv6_daddr[i+1]);
                strncat(addr, a, 6);
            }
            snprintf(a, 6, "%02x%02x",
                evt->ip.addr.ipv6_daddr[14],
                evt->ip.addr.ipv6_daddr[15]);
            strncat(addr, a, 6);
            printf("%s\n", addr);
#if 0
            // causes problems with systemd-resolved
            struct sockaddr_in6 sa;
            char site[NI_MAXHOST];
            sa.sin6_family = AF_INET6;
       
            int res = inet_pton(AF_INET6, addr, &sa.sin6_addr);
            if (res != 1){
                printf("inet issue %d\n", res);
            }
            res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), site, sizeof(site), NULL, 0, NI_NAMEREQD);
            if (!res) {
                printf("site: %s\n", site);
            } else {
                printf("site: unknown %d\n", res);
            }
#endif
        }
        printf("port: %d\n", evt->ip.port);
        printf("protocol: %s\n", print_proto(evt->ip.ipp));
    } else {//if (evt->eth_type == ETH_P_ARP) {
        printf("eth type 0x%04x\n", evt->eth_type);
        printf("comm: %s\n", evt->comm);
        printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);
 
        printf("hardware: %d\n", evt->arp.ar_hrd);
        printf("proto: %d\n", evt->arp.ar_pro);
        printf("len hard: %d\n", evt->arp.ar_hln);
        printf("len proto: %d\n", evt->arp.ar_pln);
        printf("op: %d\n", evt->arp.ar_op);
    }
    
    printf("\n");
    fflush(stdout);
    return 0;
}

void allow_port(int map_fd, uint16_t port)
{
    static uint32_t key = 0;
    bpf_map_update_elem(map_fd, &key, &port, 0);
    key++;
}

int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 2, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tc *skel = tc__open_and_load();
    skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;
    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    bpf_tc_attach(&hook, &opts);
    
    int map_fd = bpf_map__fd(skel->maps.ports);
    for (int i = 0; i < argc; i++) {
        int port = atoi(argv[i]);
        allow_port(map_fd, port);
        /*allow_port(map_fd, 443);*/
        /*allow_port(map_fd, 22);*/
        /*allow_port(map_fd, 53);*/
        /*allow_port(map_fd, 5355);*/
    }
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);

    while(!exiting) {
        ring_buffer__poll(rb, 1000);
    }

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}
