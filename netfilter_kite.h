#ifndef NETFILTER_KITE
    #define NETFILTER_KITE

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/init.h>


#include "linked_list.h"
#include "kite_hook.h"


static int packet_dropper = 0;
static struct nf_hook_ops *nfho;

static unsigned int hack_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	char port[6];


	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		snprintf(port, 6, "%hu", ntohs(udph->dest));
		if (find_node(&ports_to_drop, port) == 0){
			return NF_DROP;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		snprintf(port, 6, "%hu", ntohs(tcph->dest));
		if (find_node(&ports_to_drop, port) == 0){
			return NF_DROP;
		}
	}
	
	return NF_ACCEPT;
}

static int switch_net_hook(void){
    if(packet_dropper == 1){
		nf_unregister_net_hook(&init_net, nfho);
		packet_dropper = 0;
		return 0;
	}

    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hack_packet;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;						/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;			/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);
	
	packet_dropper = 1;
	return 0;
}
#endif
