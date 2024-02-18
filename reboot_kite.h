#include <linux/linkage.h>


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_reboot(const struct pt_regs *regs){
    return -1; //return error when trying to reboot
}
#else
static asmlinkage int hack_reboot(int magic1, int magic2, unsigned int cmd, void* arg){
    return -1;
}
#endif