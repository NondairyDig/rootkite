#ifndef MEMORY_HANDLER_KITE
    #define MEMORY_HANDLER_KITE


static inline void flip_cr0_force(unsigned long val){ //method to change cr0 register to un/protect the kernel memory
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}


static void unprotect_memory(void){
    flip_cr0_force(read_cr0() & (~ 0x10000)); // &'ing to set the 6th bit in the register and reversing it to 0 to unprotect the memory
    printk(KERN_INFO "unprotected memory\n");
}


static void protect_memory(void){
    flip_cr0_force(read_cr0() | (0x10000)); // |'ing to set the 6th bit in the register to 1 unprotect the memory
    printk(KERN_INFO "protected memory\n");
}
#endif