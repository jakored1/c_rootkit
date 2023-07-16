# C Rootkit
This is a projecct I made to learn a bit more about linux internals and the C language.   
It is not widely tested and it is not stealthy (yet ;)), so I do not recommend using at all.  
For now, all it does is hide all files that start with the string 'rootkit'  
  
It was created on:
```bash
uname -a
Linux UBUNTU 5.19.0-45-generic #46~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 7 15:06:04 UTC 20 x86_64 x86_64 x86_64 GNU/Linux

lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.2 LTS
Release:	22.04
Codename:	jammy

cat /proc/version
Linux version 5.19.0-46-generic (buildd@lcy02-amd64-025) (x86_64-linux-gnu-gcc (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #47~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 21 15:35:31 UTC 2
```

### Setup
To use it download the rootkit.c file and the Makefile,  
put them in the same directory, and in the directory enter the 'make' command
```bash
mkdir ~/rootkit
mv rootkit.c Makefile ~/rootkit/
cd ~/rootkit/
sudo make
```
You should now have a bunch of files in that directory.  
If you feel like deleting them later, just run 'make clean' in the same directory

### Running the rootkit
To run it:
```bash
sudo su            # switch to root user
cd ~/rootkit/      # switch to the rootkit directory
lsmod              # show all loaded kernel modules, you will not see the 'rootkit' module cause we haven't loaded it yet
dmesg --clear      # clears all kernel logs so it will be easy to see ours
insmod rootkit.ko  # load rootkit and run it!
lsmod              # now you should see the rootkit here 
dmesg              # show kernel logs, we will see our rootkit messages here
ls                 # you will notice that all the files that start with 'rootkit' don't appear anymore
rmmod rootkit.ko   # remove rootkit
lsmod              # rootkit is not loaded anymore
```
