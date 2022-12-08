---
title: xv6-四
date: 2022-06-07 15:59:34
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客探索一下xv6从**U-mode**地址空间**trap**(陷入)到**S-mode**地址空间的机制(前面{% post_link xv6-二 %}已经介绍的非常详细了)

# Lab traps

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/traps.html)帮助熟悉**xv6**的**trap**(陷入)机制

## Backtrace

### 要求

> Implement a backtrace() function in kernel/printf.c. Insert a call to this function in sys_sleep, and then run bttest, which calls sys_sleep. Your output should be as follows:
>
> ```bash
> backtrace:
> 0x0000000080002cda
> 0x0000000080002bb6
> 0x0000000080002898
>```
>
>After bttest exit qemu. In your terminal: the addresses may be slightly different but if you run addr2line -e kernel/kernel (or riscv64-unknown-elf-addr2line -e kernel/kernel) and cut-and-paste the above addresses as follows:
>
> ```bash
> $ addr2line -e kernel/kernel
> 0x0000000080002de2
> 0x0000000080002f4a
> 0x0000000080002bfc
> Ctrl-D
>```
> 
>You should see something like this:
> ```bash
> kernel/sysproc.c:74
> kernel/syscall.c:224
> kernel/trap.c:85
>```
  
### 分析

根据riscv的调用约定，riscv的**stack frame**(栈帧)有固定格式
![riscv帧示意图](frame.png)

可以看到，每一个**frame**的前16个字节，保存着**返回地址**和**上一个frame的栈顶地址**

通过当前**frame**的地址(s0寄存器值)，即可以此遍历当前所有的**frame**

### 实现

首先，在**kernel/vm.c**中添加**kwalkaddr**函数，从而判断对应的**s0**指向的地址是否为有效地址，用以终止**frame**的遍历
```c
// kernel/vm.c
// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// It is lookup in kernel pagetable
uint64
kwalkaddr(uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(kernel_pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}
```

其次，在**kernel/printf.c**中，通过内敛汇编获取当前**frame**的**s0**寄存器值，从而按照前面所分析的，完成所有**frame**的遍历
```c
// kernel/printf.c
// print the call stack to console
// according to the call convention
// -8(s0) is the return address
// -16(s0) is the prev frame's s0
void
backtrace(void)
{
  uint64 s0;

  // get the current frame s0
  asm volatile(
    "mv %0, s0"
    : "=r"(s0));
  
  printf("backtrace:\n");

  //walk through the frame
  while(kwalkaddr(s0)) {
    printf("%p\n", *(uint64*)(s0 - 8));
    s0 = *(uint64*)(s0 - 16);
  }

}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="backtrace" grade
```
![backtrace实验结果](backtrace实验结果.png)

## Alarm

### 要求

> In this exercise you'll add a feature to xv6 that periodically alerts a process as it uses CPU time. This might be useful for compute-bound processes that want to limit how much CPU time they chew up, or for processes that want to compute but also want to take some periodic action. More generally, you'll be implementing a primitive form of user-level interrupt/fault handlers; you could use something similar to handle page faults in the application, for example. Your solution is correct if it passes alarmtest and usertests. 

### 分析

刚看到这个lab时，就立马联想到前面{% post_link linux内核学习-八 %}中Linux内核处理信号的过程

要实现**alarm**功能，主要有以下几个难点
1. 如何记录并触发**alarm**
2. 如何执行**U-mode**中进程定义的**handler**
3. 如何从**handler**中返回触发**alarm**前的上下文

#### 记录和触发alarm

只需要在**struct proc**中添加相关的数据结构，即可记录**alarm**的时间间隔、当前状态和**handler**信息

而触发**alarm**也很简单，只需要在每次**timer interrupt**(时钟中断)时刷新**alarm**数据结构信息，并判断即可

#### 执行handler

根据之前博客分析的**trap**流程，其会在**usertrapret**(kernel/trap.c)中，设置**sepc**(Supervisor Exception Program Counter)，从而指定**trap**返回后，**U-mode**对应的第一条指令地址

在前面触发**alarm**时，将**struct proc**的**trapframe**字段的**epc**值设置为对应的**handler**，其会在**usertrapret**(kernel/trap.c)中赋值给**sepc**，从而完成**trap**返回后执行**handler**

需要注意的是，为了确保之后可以恢复到触发**alarm**前的**U-mode**的上下文，自然需要保存该**sepc**原始值以及其他信息，在下面部分进行介绍

#### 返回触发alarm上下文

根据前面的分析，为了在触发**alarm**并执行完**handler**后，仍然能恢复触发前的执行状态，内核需要保存相关的数据——即**struct proc**的**trapframe**数据

在执行完**handler**后，**sigreturn**系统调用保存的**trapframe**和触发**alarm**时的**trapframe**很可能完全不一致。因此需要在前面执行**handler**前，备份**struct proc**的**trapframe**数据。

而由于xv6的精巧设计，**trapframe**中包含触发**alarm**前的程序上下文，和触发**alarm**对应的**epc**。从而在**sigreturn**系统调用中恢复之前保存的**trapframe**，即可在从**trap**退出后，恢复到触发**alarm**前的状态

### 实现

首先，在**kernel/proc.h**中更改**struct proc**的结构体，添加记录**alarm**信息和保存**trapframe**数据的字段
```c
// kernel/proc.h
// Per-process state
struct proc {
  struct spinlock lock;

  // p->lock must be held when using these:
  enum procstate state;        // Process state
  struct proc *parent;         // Parent process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // these are private to the process, so p->lock need not be held.
  uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  struct trapframe *trapframe; // data page for trampoline.S
  struct trapframe tf_bak;     // store the frame when invoke the alarm handler
                               // restore the frame when invoke sigreturn

  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  alarm alarm;                 // Process's alarm
};

// kernel/syssig.h
typedef struct {
    uint64 fn;                  // user-defined callback function
    int time;                   // tick remained for alarms
    int interval;               // alarm interval tick.
    int status;                 // the alarm struct's status
} alarm;
```

接着，实现**sysalarm**系统调用，从而添加**alarm**
```c
// kernel/syssig.c
// add an alarm
uint64
sys_sigalarm(void)
{
  struct proc *p = myproc();

  if(p == 0 || p->alarm.status != ALARM_UNUSE)
    return -1;

  int interval;
  uint64 fn;

  if(argint(0, &interval) < 0 || argaddr(1, &fn) < 0)
    return -1;
  
  // handle corner case
  if(interval < 0)
    return -1;
  if(interval == 0 && fn == 0)
    return 0;

  p->alarm.status = ALARM_WAIT;
  p->alarm.fn = fn;
  p->alarm.interval = interval;
  p->alarm.time = interval;

  return 0;
}
```


下面完成**alarm**的更新和触发，即在**timer interrupt**时更新并判断**alarm**。当**alarm**需要被触发时，则保存当前的**trapframe**，并更改**epc**字段即可
```c
// kernel/syssig.c
void
handle_alarm(void)
{
  struct proc *p = myproc();

  if(p == 0)
    return;

  if(p->alarm.status != ALARM_WAIT)
    return;
  
  if(p->alarm.time > 0)
    --p->alarm.time;

  if(p->alarm.time == 0) {

    // it is time to invoke the alarm handler
    p->alarm.status = ALARM_HANDLE;

    // store the U-mode trapframe
    memmove(&p->tf_bak, p->trapframe, sizeof(struct trapframe));

    // it should execute the fn callback, when from the trap 
    p->trapframe->epc = p->alarm.fn;

  }

}

// kernel/trap.c
// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
    ...
  } else if(scause == 0x8000000000000001L){
    // software interrupt from a machine-mode timer interrupt,
    // forwarded by timervec in kernelvec.S.

    if(cpuid() == 0){
      clockintr();
    }
    
    // acknowledge the software interrupt by clearing
    // the SSIP bit in sip.
    w_sip(r_sip() & ~2);

    // handle the alarm
    handle_alarm();

    return 2;
  } else {
    return 0;
  }
}
```

最后，则是实现**sigreturn**系统调用，恢复保存的**trapframe**，从**handler**中返回到触发**alarm**前的状态
```c
// kernel/syssig.c
// it was in the signal handler
// yet its origin context is saved
// so just restore to origin context
uint64
sys_sigreturn(void)
{

  struct proc *p = myproc();

  if(p == 0 || p->alarm.status != ALARM_HANDLE)
    return -1;
  
  p->alarm.status = ALARM_WAIT;
  p->alarm.time = p->alarm.interval;

  // store the U-mode trapframe
  memmove(p->trapframe, &p->tf_bak, sizeof(struct trapframe));

  return 0;
}
```


### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="alarmtest" grade
```
![alarmtest实验结果](alarmtest实验结果.png)