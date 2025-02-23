# detpl - LD_PRELOAD Malware Detection Tool
detpl is a security tool specifically designed to detect malware related to LD_PRELOAD. It helps identify and prevent system security threats by monitoring the behavior of system libraries and checking for potential hidden files.

## Tool Information
- **Version**: 1.0
- **Author**: sinister

## Usage Instructions
To run the detpl tool, use the following format:
```
./detpl [options]...
```

## Supported Functions
detpl provides a series of functions for detection and analysis:
- `--dlhook-check`: Detect internal hook structures
- `--dlsym-check`: Detect dynamic loader functions
- `--syslib-check`: Check if commonly used system library functions have been modified
- `--procenv-check`: Check LD_PRELOAD in /proc/PID/environ
- `--so-search [LIBRARY]`: Search for specific shared library files
- `--preload-file-check`: View the content of the /etc/ld.so.preload file
- `--preload-file-erase`: Erase the content of the /etc/ld.so.preload file
- `--search-hidden-file [PATH]`: Search for hidden files in the specified path
- `--displib`: Display the loaded library names
- `--all-check`: Comprehensive check
- `--checklist`: List the symbol table

### Special Parameter
- `-nouselib`: Use syscall to bypass system library functions

## Practical Use Cases and Detailed Steps
### Scenario 1: Detect if System Library Functions are Hooked
To determine whether system library functions have been hooked by malware, execute the check with the following command:
```
./detpl --syslib-check -nouselib
```
#### Example Output

[![785E4.jpeg](https://i.imgs.ovh/2025/02/23/785E4.jpeg)](https://imgloc.com/image/785E4)

```
[+] opendir checking...!!!Found hooked address 0x7ffe3ae985d2 (/usr/lib/libseconf/libdl.so) <-> real address 0x7ffe3a983f60!!!
[+] readdir checking...!!!Found hooked address 0x7ffe3ae981a1 (/usr/lib/libseconf/libdl.so) <-> real address 0x7ffe3a983fa0!!!
```
#### Analysis Results
The above output indicates that functions such as opendir and readdir have been hooked and redirected to /usr/lib/libseconf/libdl.so

### Scenario 2: Search for Hidden Files
After discovering that functions have been hooked, you can further search for potentially existing hidden files:
```
./detpl --search-hidden-file /usr
```
#### Example Output
```
[HIDDEN FILE] /usr/lib/libseconf/libdl.so
[HIDDEN FILE] /usr/lib/libseconf/.backup_ld.so
```
#### Analysis Results
Multiple hidden.so files were found in the /usr/lib/libseconf/ directory, which may be related to malware

### Scenario 3: Confirm Processes Injected with a Specific so Library
After confirming the hidden files, use the following command to view which processes have been injected with libdl.so:
```
./detpl --so-search libdl.so
```
#### Example Output
```
Found /usr/sbin/sshd(45893) /usr/lib/libseconf/libdl.so
Found /usr/bin/bash(45901) /usr/lib/libseconf/libdl.so
```
#### Analysis Results
Multiple important processes (such as sshd and bash) have been injected with libdl.so, indicating a potential security risk

## Implementation Principles
### 1. Principle of Detecting Function Hooks
The tool fills its own GOT table through the first call, and then uses the ELF symbol resolution method to check for address changes to determine whether a function has been hooked

### 2. Principle of Detecting Internal Hook Structures
#### Dynamic Redirection Method in Early glibc Versions
In early glibc versions, there were two internal structures, `_dl_open_hook` and `_dlfcn_hook`, which could be used for function redirection

#### dlsym Code Associated with the _dl_open_hook Structure
```
(gdb) disas __libc_dlsym
Dump of assembler code for function __libc_dlsym
0x0000003b8d502970 <__libc_dlsym+0>: sub $0x48,%rsp
0x0000003b8d502974 <__libc_dlsym+4>: mov 2408661(%rip),%rax # 0x3b8d74ea50 <_dl_open_hook>
0x0000003b8d50297b <__libc_dlsym+11>: mov %rdi,(%rsp)
0x0000003b8d50297f <__libc_dlsym+15>: mov %rsi,0x8(%rsp)
0x0000003b8d502984 <__libc_dlsym+20>: test %rax,%rax
0x0000003b8d502987 <__libc_dlsym+23>: jne 0x3b8d5029f4 <__libc_dlsym+132>
```

#### Association between dlsym and _dlfcn_hook
```
(gdb) disas dlsym
Dump of assembler code for function dlsym
0x0000003b8dc01070 <dlsym+0>: push %rbp
0x0000003b8dc01071 <dlsym+1>: push %rbx
0x0000003b8dc01072 <dlsym+2>: sub $0x28,%rsp
0x0000003b8dc01076 <dlsym+6>: mov 2105379(%rip),%rax # 0x3b8de030a0 <_dlfcn_hook>
0x0000003b8dc0107d <dlsym+13>: test %rax,%rax
0x0000003b8dc01080 <dlsym+16>: jne 0x3b8dc010dc <dlsym+108>
```
#### Principle Summary
If `_dl_open_hook` or `_dlfcn_hook` is not empty, the related functions (`__libc_dlsym` and `dlsym`) will call the malicious hook function. detpl detects whether there are abnormal changes by analyzing these hook structures

## Tool Security Features
- **Non - intrusive Design**: Does not use the LKM (Linux Kernel Module) method, nor inject any processes at the application layer
- **syscall - level Detection**: The `-nouselib` parameter can be selected to directly use syscall to bypass system library functions, improving detection reliability

## Summary
detpl is an LD_PRELOAD - related malware detection tool that can help system administrators promptly discover library tampering in critical processes and identify potential security threats. Through functions such as `syslib-check`, `so-search`, and `search-hidden-file`, users can quickly check for maliciously injected so shared libraries and take appropriate security measures
