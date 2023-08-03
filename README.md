# Rootkite - Linux Kernel Rootkit


![LINUX](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![License](https://img.shields.io/badge/License-GPL-blue.svg)
![Version](https://img.shields.io/badge/Version-0.5-brightgreen.svg)
![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)
## Description

Rootkite is a rootkit written for the Linux kernel as a kernel module. It is designed to alter functions and user functionality to hide files, processes, itself, grant root access to any process, and block system rebooting. The rootkit is controlled through the controller.c file by interacting with the device file exported on the path /dev/controller. The hooking machanism is done with ftrace, altering the address found in kallsyms to point symbols to our "hacked" functions.

**Warning**: Rootkits are powerful tools with potentially harmful consequences. They can be used for malicious purposes, and their use is generally considered unethical and against system security principles. This rootkit is provided for educational purposes only. Do not use it on any system without proper authorization, and always respect the laws and policies governing software use in your region.

## Features

- Hides specified files and processes based on user input.
- Hides itself
- Grants root access to any process.
- Blocks system rebooting.

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
   - To activate file/process hiding, execute: `kill -63 1`.
   - To start blocking system reboot, execute: `kill -63 2`.
   - To control what files or processes to hide, execute the controller program with either arguments:
      - ./controller "hide \<file prefix to hide>"
      - ./controller "hidep \<pid to hide>"
## Files

1. rootkite.c:
This is the main file of the Rootkite kernel module. It includes various headers required for kernel module development. The module initializes, installs hooks, and registers a misc device called "controller" to communicate with user-space and control the rootkit's functionality. The Activation of the functionallities is done by hooking the "kill" system call and calling specific signals with pid s(as specfiied above).

2. kite_init.h:
This header file is used to determine whether the system is 64-bit and the kernel version. It defines PTREGS_SYSCALL_STUB when the system is 64-bit and the kernel uses ptregs_t type for system calls.

3. kite_hook.h:
This header file is responsible for hooking the original kernel functions using ftrace. It provides functions to install and remove hooks, resolve hook addresses, and ftrace thunks for hooking the functions. The hooks are kept in an array in the main file, and declared there. Because of unavaillability of kallsysm_lookup_name functtion, it is probed using kprobe, and then used to get a symbol's(syscall or other function) address.

4. getdents_hacks.h:
This header file contains the functions required for hiding files and directories. It contains the function to hook to the getdents and getdents64 system calls, which are used to list directory entries. The functions in this file manipulate the directory entries to hide files and processes whose names match specific criteria.

5. device_handler.h:
This header file defines the read and write functions for the "controller" misc device. The "controller" device is used to communicate with the rootkit from user-space and control its behavior. The write function is used to send commands to hide files, processes, etc., and the read function retrieves the last command written to the device.

6. root_setter.h:
This header file contains a function (set_root) responsible for escalating the calling process's privileges to root (superuser). It uses prepare_creds to copy the current credentials of the calling process and commit_creds functions to set the user and group IDs(real, effective, file system) to 0, effectively elevating the process to root.

7. mod_hide.h
This header file is contains the functions to hide/show the lkm, using the linux modules linked list, removing it from there and return it to the same place by request.

8. controller.c:
This is a user-space program that interacts with the "controller" device created by the rootkit. It is used to send commands to the rootkit to hide files and processes. It takes a single argument (hide <filename prefix> or hidep <process name>) to specify the action it wants to take.
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
