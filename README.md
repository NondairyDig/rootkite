# Rootkite - Linux Kernel Rootkit

![LINUX](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![License](https://img.shields.io/badge/License-GPL-blue.svg)
![Version](https://img.shields.io/badge/Version-1.0-brightgreen.svg)
![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)

## Description

Rootkite is a rootkit written for the Linux kernel as a kernel module. It is designed to alter functions and user functionality to hide files, processes, itself, grant root access to any process, and block system rebooting. The rootkit is controlled through the controller.c file by interacting with the device file exported on the path /dev/controller. The hooking machanism is done with ftrace, altering the address found in kallsyms to point symbols to our "hacked" functions.

**Warning**: Rootkits are powerful tools with potentially harmful consequences. They can be used for malicious purposes, and their use is generally considered unethical and against system security principles. This rootkit is provided for educational purposes only. Do not use it on any system without proper authorization, and always respect the laws and policies governing software use in your region.

## Features

- Hides specified files based on user input.
- Hides specified processes based on user input.
- Hides specified ports based on user input.
- Hides specified users based on user input.
- Can render the machine unusable.
- Blocks packet sniffing specified ports based on user input.
- Hides itself.
- Grants root access to any process.
- Blocks system rebooting and shutdown.
- Creates a backdoor using a reverse shell.
- Keylogger

## How to Use

**Warning**: Do not use this rootkit on any system without proper authorization.

1. **Compilation**:
   - Compile the rootkite.c rootkit file as a kernel module and load it using `insmod`.
   - Compile the controller.c for interaction with the rootkit to change files/processes hiding.
   <br />
   <br />
2. **Interaction**: Use the controller.c program to interact with the rootkit. Execute the following commands to control the rootkit functionality:
   - To hide the rootkit itself, execute: `kill -64 1`.
   - To grant root access to the current process, execute: `kill -64 2`.
   - To activate reverse shell, execute: `kill -64 3`.
   - To activate keylogging, execute: `kill -64 4`.
   - To activate file/process/port/user hiding and port scan block, execute: `kill -63 1`.
   - To start blocking system reboot, execute: `kill -63 2`.
   - To activate packet sniffing block on speciefic ports, execute: `kill -63 3`.
   - To forkbomb the system, execute: `kill -63 4`.
   - To control what files or processes to hide, execute the controller program with either arguments:
      - ./controller "hide \<file prefix to hide>"
      - ./controller "hidep \<pid to hide>"
      - ./controller "hidepo \<port to hide>"
      - ./controller "hidepd \<port to block scan to>"
      - ./controller "hideu \<user to hide>"
      - ./controller "hidee \<executable to block>"
      - ./controller "show\<suffix> \<object to unhide>"

## Files

- **rootkite.c:**  <br />
This is the main file of the Rootkite kernel module. It includes various headers required for kernel module development. The module initializes, installs hooks, and registers a misc device called "controller" to communicate with user-space and control the rootkit's functionality. The Activation of the functionallities is done by hooking the "kill" system call and calling specific signals with pid s(as specfiied above).

- **kite_init.h:** <br />
This header file is used to determine whether the system is 64-bit and the kernel version. It defines PTREGS_SYSCALL_STUB when the system is 64-bit and the kernel uses ptregs_t type for system calls.

- **kite_hook.h:** <br />
This header file is responsible for hooking the original kernel functions using ftrace. It provides functions to install and remove hooks, resolve hook addresses, and ftrace thunks for hooking the functions. The hooks are kept in an array in the main file, and declared there. Because of unavaillability of kallsysm_lookup_name functtion, it is probed using kprobe, and then used to get a symbol's(syscall or other function) address.

- **getdents_hacks.h:** <br />
This header file contains the functions required for hiding files and directories. It contains the function to hook to the getdents and getdents64 system calls, which are used to list directory entries. The functions in this file manipulate the directory entries to hide files and processes whose names match specific criteria.

- **device_handler.h:** <br />
This header file defines the read and write functions for the "controller" misc device. The "controller" device is used to communicate with the rootkit from user-space and control its behavior. The write function is used to send commands to hide files, processes, etc., and the read function retrieves the last command written to the device.

- **root_setter.h:** <br />
This header file contains a function (set_root) responsible for escalating the calling process's privileges to root (superuser). It uses prepare_creds to copy the current credentials of the calling process and commit_creds functions to set the user and group IDs(real, effective, file system) to 0, effectively elevating the process to root.

- **mod_hide.h:** <br />
This header file contains the functions to hide/show the lkm, using the linux modules linked list, removing it from there and return it to the same place by request.

- **files_hacks.h:** <br />
This header file contains hooks for statx to hide files that are requested by the user when refrenced directly with ls. pread64 and openat, those are to hide logged in users using the utmp file. the hook was created to check if the utmp file(users logged in) is opened, if it was, we save the file descriptor to later check in pread64 hook to filter the users. can block file access by filtering in openat; for more complex file filtering/hiding can be used to filter by file descriptors in statx.

- **forkbomb.h:** <br />
This header file containes functions that create user processes, runs as a child of system workqueues(kworkers, executors of kthreads) that are children of kthreadd. (ie. it runs with full root capabilities and optimized affinity). the kthreadd enumerates other kernel threads; it provides interface routines through which other kernel threads can be dynamically spawned at runtime by kernel services.
Those functions are to create a backdoor using a bash reverse shell and a forkbomb to render the machine unuseable.

- **hide_ports.h:** <br />
This header file contains functions to hide ports that are listed with tools like netstat using tcp4_seq_show that is called to read from a sequence file, /proc/net/tcp and /proc/net/udp, sequence files are files containing a large dataset, those specificaly are what ports are being used in the system, displayed by netstat. seq_file is a structure, like file_operations, enabling us to access the fields we want in the dataset.

- **hide_processes.h:** <br />
This header file contains functions to hide processes, it uses the file ops of /proc to change its iterate_shared to call a filldir function that filters by filenames or pid's in this case, if found the function skips the file. filldir is used to specify the requested layout for directory listing.

- **keylogger.h:** <br />
This header file contains functions to realize keylogging abilities, by hooking read() can keylog bash shells because they are interactive, using read to always read input from stdin, we can hook read to keylog bash shells, also used as a command logger for non-interactive shells, and mess with user input

- **execve_blocker.h:** <br />
This header file contains functions to block execution of binaries by user request. The functionality works by hooking execve, then going through the requested binary and blocking if its in the user's requests. Can also change to another executable to mess with the victim*

- **linked_list.h:** <br />
This header file contains functions to deal with linked lists, this tool is using the linked list structure to keep track of what objects to hide, each type has a list, better to define ourselves for a simpler implementation then the existing one, the structure provides iterating the nodes at O(n) at most. also providing the ability to insert objects on the fly.

- **netfilter_kite.h:** <br />
This header file contains functions to deal with network traffic, sniffers use libpcap that uses BPF to filter packets without user-space
So BPF is a kernel feature. The filter should be triggered immediately when a packet is received at the network interface.
As the original BPF paper said To minimize memory traffic, the major bottleneck in most modern system,
the packet should be filtered ‘in place’ (e.g., where the network interface DMA engine put it)
rather than copied to some other kernel buffer before filtering.
libpcap opens a socket which uses packet_create function that hooks packet_rcv to handle packet sockets.(skb)
(AF_PACKET, which allows getting raw packets on the the ethernet level)(if old architecture(SOCK_PACKET),
the packet then is passed to the hooked function.
uses packet_rcv_spkt, if the recieve packet is not empty, uses tpacket_rcv) then theres a netfilter hook which acts like a firewall where we filter udp/tcp scans that sends an empty packet by checking if the payload is empty, and also filter ping, can add more functionality like address filter. hooks using the built in netfilter nf_register_net_hook function.

- **utmp.h:** <br />
This header file is to use utmp.h that is not defined in the kernel so we define it on our own, contains the utmp struct to handle logged in users. is used in files_hacks.h.

- **controller.c**: <br />
This is a user-space program that interacts with the "controller" device created by the rootkit. It is used to send commands to the rootkit to hide files and processes. It takes a single argument (hide\<suffix> \<object name> or show\<suffix> \<object name>) to specify the action it wants to take.
Overall, the Rootkite kernel module is designed to be a rootkit, providing hidden functionality and capabilities to elevate privileges and manipulate system processes and files.

## License

This project is licensed under the GNU General Public License (GPL). See the [LICENSE](LICENSE) file for details.

## Acknowledgments

The authors acknowledge the Linux kernel development community for their work on the kernel. The rootkit code borrows concepts from various sources and should be credited to their respective authors.

## Warning

This rootkit can cause harm to computer systems if used without proper authorization. It is intended for educational purposes only, and any malicious use is strictly prohibited. The authors are not responsible for any misuse or damage caused by this software.

Use it responsibly and ethically, with respect for others' systems and privacy.

## Disclaimer

This rootkit is provided for educational and research purposes only. It is not intended for malicious use. The authors are not responsible for any damage or misuse caused by this software. Use it responsibly and legally, with proper authorization.
