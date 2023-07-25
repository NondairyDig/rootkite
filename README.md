# Rootkite - Linux Kernel Rootkit


![LINUX](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![License](https://img.shields.io/badge/License-GPL-blue.svg)
![Version](https://img.shields.io/badge/Version-0.3-brightgreen.svg)
![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)
## Description

Rootkite is a rootkit written for the Linux kernel as a kernel module. It is designed with the purpose of altering functions and user functionality to hide files, processes, grant root access to any process, and block system rebooting. The rootkit is controlled through the controller.c file by interacting with the device file exported on the path /dev/controller.

**Warning**: Rootkits are powerful tools with potentially harmful consequences. They can be used for malicious purposes, and their use is generally considered unethical and against system security principles. This rootkit is provided for educational purposes only. Do not use it on any system without proper authorization, and always respect the laws and policies governing software use in your region.

## Features

- Hides specified files and processes based on user input.
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

## Disclaimer

This rootkit is provided for educational and research purposes only. It is not intended for malicious use. The authors are not responsible for any damage or misuse caused by this software. Use it responsibly and legally, with proper authorization.

## License

This project is licensed under the GNU General Public License (GPL). See the [LICENSE](LICENSE) file for details.

## Acknowledgments

The authors acknowledge the Linux kernel development community for their work on the kernel. The rootkit code borrows concepts from various sources and should be credited to their respective authors.

## Warning

This rootkit can cause harm to computer systems if used without proper authorization. It is intended for educational purposes only, and any malicious use is strictly prohibited. The authors are not responsible for any misuse or damage caused by this software.

Use it responsibly and ethically, with respect for others' systems and privacy.

## Support and Contact

For any questions or concerns related to this project, you can contact the author at [email@example.com](mailto:email@example.com).
