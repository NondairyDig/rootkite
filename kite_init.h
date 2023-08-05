#ifndef KITE_INIT
    #define KITE_INIT
    
    #include <linux/version.h> // get kernel versions

#ifdef CONFIG_X86_64 /* check if system is 64bit*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) /*check if kernel version uses ptregs_t type for system calls*/
#define PTREGS_SYSCALL_STUB 1 /*signal 64bit*/
#endif
#endif
#endif
