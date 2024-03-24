#ifndef NETFILTER_KITE
    #define NETFILTER_KITE

	#include <linux/netfilter.h>
	#include <linux/netfilter_ipv4.h>
	#include <linux/ip.h>
	#include <linux/tcp.h>
	#include <linux/udp.h>
	#include <linux/socket.h>
	#include <linux/init.h>
	#include <linux/icmp.h>

	#include "linked_list.h"
	#include "kite_hook.h"


static int packet_blocker = 0; // signal if to activate the netfilter
static struct nf_hook_ops *nfho;


/* The netfilter in Linux is a framework that allows packet filtering in the kernel. It's a feature
   built into the kernel, and provides the additional infrastructure for firewalls and packet filtering tools
   others.
   Netfilter can filter packets at different levels in the OSI model. It provides a set of hooks
   At various points in the protocol stack, where filtering rules can be applied to incoming packets or
   going out These hooks form the basis of liptables, to implement firewall rules and functionality
   another way of filtering packets
   sk_buff is the main networking structure representing a packet.
   This hook acts as a firewall to block traffic to a specific port
   ntohs is a function that converts the endianess of the variable to from big(network) to little(linux).
*/
static unsigned int hack_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	long payload_length;
	char port[6];

	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_ICMP){ // discard any ICMP packets
		return NF_DROP;
	}

	// block UDP connections to selected ports
	if (iph->protocol == IPPROTO_UDP) { 
		udph = udp_hdr(skb);
		snprintf(port, 6, "%hu", ntohs(udph->dest));
		if (find_node(&ports_to_drop, port) == 0){
			payload_length = ntohs(udph->len) - sizeof(udph) <= 0; /*filter udp scans that sends an empty packet by checking if the payload is empty*/
			if(payload_length <= 0){
				return NF_DROP; // Drop the packet
			}
		}
	}

	// block TCP connections to selected ports
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		snprintf(port, 6, "%hu", ntohs(tcph->dest));
		if (find_node(&ports_to_drop, port) == 0){
			if(skb->data_len <= 0){ /*filter tcp scans that sends an empty packet by checking if the payload is empty*/
				return NF_DROP; // Drop the packet
			}
		}
	}
	
	return NF_ACCEPT;
}

/*netfilter hook switch, can use another function to split ping block functionality*/
static int switch_net_hook(void){
    if(packet_blocker == 1){
		nf_unregister_net_hook(&init_net, nfho);
		kfree(nfho);
		packet_blocker = 0;
		return 0;
	}

    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL); // allocate memory for a netfilter hook
	
	// Initialize netfilter hook
	nfho->hook = (nf_hookfn*)hack_packet;		// hook function
	nfho->hooknum = NF_INET_PRE_ROUTING;		// received packets(before processing)
	nfho->pf = PF_INET;							// IPv4
	nfho->priority = NF_IP_PRI_FIRST;			// max hook priority
	
	nf_register_net_hook(&init_net, nfho); //register the hook
	
	packet_blocker = 1;
	return 0;
}



/* sniffers use libpcap that uses BPF to filter packets without user-space
BPF is a kernel feature. The filter should be triggered immediately when a packet is received at the network interface.
As the original BPF paper said To minimize memory traffic, the major bottleneck in most modern system,
the packet should be filtered ‘in place’ (e.g., where the network interface DMA engine put it)
rather than copied to some other kernel buffer before filtering.
libpcap opens a socket which uses packet_create function that hooks packet_rcv to handle packet sockets(skb)
(AF_PACKET, which allows getting raw packets on the the ethernet level)
Uses packet_rcv_spkt, if the recieved packet is not empty, uses tpacket_rcv)*/


static int hack_packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	char dest_port[6];
	char source_port[6];


	iph = ip_hdr(skb); // wrap and struct the packet socket buffer
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(udph->dest));
		snprintf(source_port, 6, "%hu", ntohs(udph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(tcph->dest));
		snprintf(source_port, 6, "%hu", ntohs(tcph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG			
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP;
		}
	}
	return orig_packet_rcv(skb, dev, pt, orig_dev);
}

static int hack_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	char dest_port[6];
	char source_port[6];


	if (!skb)
		return orig_packet_rcv_spkt(skb, dev, pt, orig_dev);
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(udph->dest));
		snprintf(source_port, 6, "%hu", ntohs(udph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP; 
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(tcph->dest));
		snprintf(source_port, 6, "%hu", ntohs(tcph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP;
		}
	}
	return orig_packet_rcv_spkt(skb, dev, pt, orig_dev);
}

static int hack_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	char dest_port[6];
	char source_port[6];

	if (!skb)
		return orig_tpacket_rcv(skb, dev, pt, orig_dev);
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(udph->dest));
		snprintf(source_port, 6, "%hu", ntohs(udph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		snprintf(dest_port, 6, "%hu", ntohs(tcph->dest));
		snprintf(source_port, 6, "%hu", ntohs(tcph->source));
#ifdef KITE_DEBUG
		pr_info("a %s\n", dest_port);
#endif
		if (find_node(&ports_to_hide, source_port) == 0 || find_node(&ports_to_hide, dest_port) == 0){
#ifdef KITE_DEBUG
			find_node(&ports_to_hide, source_port) == 0 ? pr_info("packet from %s was blocked\n", source_port) : pr_info("packet to %s was blocked\n", dest_port);
#endif
			return NF_DROP;
		}
	}
	return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}
#endif
