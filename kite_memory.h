#ifndef MEMORY_KITE
    #define MEMORY_KITE


void disable_write_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
        value &= ~0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

void enable_write_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
        value |= 0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}
#endif