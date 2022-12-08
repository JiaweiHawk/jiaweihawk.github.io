---
title: xv6-二
date: 2022-05-21 22:24:40
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客探索一下xv6内核的系统调用过程


# xv6启动流程

参考[xv6-book](https://pdos.csail.mit.edu/6.828/2020/xv6/book-riscv-rev1.pdf)，可以对xv6的启动过程有非常清晰的认识，这对于理解linux内核的启动大有裨益

首先，写在**ROM**中的**boot loader**，将内核装载入内存中，并将执行流跳转到固定的入口点(代码写死在ROM中，自然跳转的入口点也是固定的)

因此，编译内核时，需要将内核的入口函数**_entry**(kernel/entry.S:6)编译到**boot loader**指定的地址处(xv6是0x80000000)

而为了*让生活更美好*，**_entry**函数使用汇编指令初始化栈后，跳转到使用C语言编写的**start**(kernel/start.c:20)。
**start**函数的主要工作就是设置**CSRs**(control and state registers)，从而切换到**S-mode**(supervisor mode)，并将执行流设置成**main**(kernel/main.c:10)。**start**函数实现的非常巧妙，其通过设置**CSRs**，伪造一个异常处理保存的上下文，其上下文的特权级是**S-mode**，PC是**main**。执行**mret**指令后，通过恢复上下文，完成特权级和执行流的转换

在**main**函数中，即初始化内核的子系统，并执行**userinit**(kernel/proc.c:211)，创建第一个进程。
**userinit**函数申请进程描述符和虚拟地址空间等资源，将**initcode.S**(user/initcode.S:1)的汇编代码映射入进程中并设置为进程入口函数。而**initcode.S**中的汇编代码很简单，伪代码如下所示
```c
exec("/init", {"/init", 0});
exit()
```

而**/init**是user/init.c编译的可执行程序，其初始化中断设备，初始化文件描述符，并启动**sh**


# xv6的trap过程

实际上，合理推测任何架构下的**trap**(陷入)过程都是类似的
1. 硬件执行必要的寄存器更改，并跳转到相关向量处
2. 汇编形式的向量代码会执行C形式的服务例程
3. 从服务例程返回到剩余的向量代码
4. 硬件执行必要的寄存器更改，返回到**trap**前上下文执行

之所以需要硬件参入，是避免用户态程序参入**陷入**执行过程，从而避免某些软件通过**陷入**执行恶意代码
之所以需要有汇编形式的参入，是为了方便符合CPU架构的对于**trap**的某些硬件接口约束


## 硬件处理

当用户态执行**ecall**指令调用系统调用，或设备产生**interrupt**(中断)，或指令引发**exception**(异常)，此时会**trap**，即陷入内核。RISC-V架构的硬件会立马执行如下步骤
1. 如果是设备中断，并且**sstatus**(Supervisor Status Register)的**SIE**(Supervisor Interrupt Enable)比特是被清空的，则不执行下属操作(相当于被无视)
2. 清除**sstatus**(Supervisor Status Register)的**SIE**(Supervisor Interrupt Enable)比特，关闭中断
3. 将**pc**寄存器复制到**sepc**(Supervisor Exception Program Counter)
4. 将当前特权级保存在**sstatus**(Supervisor Status Register)的**SPP**(Supervisor Previous Privilege)比特
5. 设置**scause**(Supervisor Cause)，用来表示**trap**的原因
6. 将当前特权级更改为**S-mode**
7. 将**stvec**(Supervisor Trap Vector Base Address)复制到**pc**寄存器
8. 开始执行新的**pc**寄存器的执行流

可以看到，riscv硬件处理的步骤并不是很多，主要就是保存了当前的特权级和pc寄存器，并切换了新的特权级和pc寄存器

而诸如页表切换、栈切换等**x86**架构中硬件处理的部分，则都交给内核完成

需要特别注意的是，每一个CPU都有一组上述的寄存器，也就是同一时间可以有多个CPU在处理中断

## 汇编形式的向量代码

之所以称为向量代码，是因为在**x86**架构下，其新**pc**寄存器值是一个函数指针数组中的元素。这里虽然并不是相似的机制(直接将固定的地址赋给**pc**，而非从数组中索引元素)，但是仍然继承了类似的名称

### stvec

**stvec**(Supervisor Trap Vector Base Address)寄存器在**S-mode**和**U-mode**的虚拟地址并不一样，且其实际指向的物理地址也不一样

#### S-mode

在**S-mode**下，**stvec**(Supervisor Trap Vector Base Address)寄存器在**main**(kernel/main.c:11)中初始化，调用**trapinithart**(kernel/trap.c:25)，将**stvec**寄存器的值初始化为**kernelvec**(kernel/kernelvec.S:10)

在直白一些，在**S-mode**下**trap**，硬件处理后会跳转至**kernelvec**处执行

#### U-mode

**U-mode**下找**stvec**(Supervisor Trap Vector Base Address)寄存器初始化的位置略难，因为还没开始认真分析创建进程的流程(会在后面进行分析)

当创建用户进程时，在**allocproc**(kernel/proc.c:127)函数中，其会指定用户进程执行的第一条指令为**forkret**(kernel/proc.c:534)。在该执行流中，其调用的**usertrapret**(kernel/trap.c:100~~，剧透一下，每次**U-mode**进程从**trap**返回时，也会调用**usertrapret**~~)会初始化**stvec**(Supervisor Trap Vector Base Address)寄存器，将**stvec**寄存器的值初始化为**TRAMPOLINE + (uservec - trampoline)**

其相关的符号如下所示
```c
//kernel/memlayout.h
#define TRAMPOLINE (MAXVA - PGSIZE)

//kernel/trampoline.S
.globl trampoline
trampoline:
.align 4
.globl uservec
uservec:    

//kernel/proc.c
if(mappages(pagetable, TRAMPOLINE, PGSIZE,
            (uint64)trampoline, PTE_R | PTE_X) < 0)
```

因此，实际上**stvec**值初始化为**uservec**(kernel/trampoline.S:16)

在直白一些，在**U-mode**下**trap**，硬件处理后会跳转至**uservec**处执行


### 汇编代码

对于**S-mode**和**U-mode**，有不同的入口地址，自然其功能有少许不同

#### S-mode

**S-mode**的这部分代码相对比较简单，在内核栈中保存所有的寄存器，然后调用**kerneltrap**(kernel/trap.c:133)的服务例程
其不涉及到页表变换或栈切换

#### U-mode

**U-mode**这部分的代码相对来说更复杂一些，因为其需要实现的功能更多——切换页表、切换栈并保存寄存器

其比较麻烦的点在于涉及到的细节较多

为了良好的隔离性，进程在**U-mode**和在**S-mode**使用不同的栈和页表
而进程在陷入内核时，需要可以快速找到其对应的**内核栈**和**内核页表**，并完成切换。切换会导致一些小问题——相同的虚拟地址在不同的页表中可能会映射向不同的物理地址(例如切换的一瞬间，**pc**寄存器指向的指令是否发生变化等)；如何在**S-mode**地址空间中找到保存的**U-mode**的上下文等

解决该问题的一个关键就是riscv提供的**sscratch**(Supervisior Scratch)寄存器——其保存**U-mode**地址空间下存储的**U-mode**上下文(因为riscv只支持寄存器间接访存，没有额外的寄存器，如何将所有寄存器保存到指定内存中)

其整个机制如下所示
1. 在内核初始化时，将物理地址**uservec**(前面**U-mode**汇编代码的入口处)映射到**S-mode**地址空间的**TRAMPOLINE**。根据前面的分析，即此时**TRAMPOLINE**虚拟地址在不同的页表中指向相同的物理地址，从而即使切换也不改变内容(解决切换瞬间可能执行指令不一致问题)(kernel/vm.c:47)
2. 在创建用户进程中，在设置页表时，将物理地址**uservec**映射到**U-mode**地址空间中的**TRAMPOLINE**地址(即此时**TRAMPOLINE**虚拟地址在不同的页表中指向相同的物理地址)(kernel/proc.c:171)。将申请的**trapframe**物理地址映射到**S-mode**地址空间中的对应地址(kernel/proc.c:111)和**U-mode**地址空间中的对应地址(kernel/proc.c:178)，不需要像**TRAMPOLINE**一样将虚拟地址映射到相同的物理地址，只需要**S-mode**和**U-mode**，各有一个虚拟地址映射到相同的物理地址即可
3. 在用户进程刚刚创建完，从**S-mode**返回之前，将**内核页表**物理地址、**内核栈**在**S-mode**地址空间的虚拟地址，在**S-mode**地址空间中存储到**trapframe**物理页上(由于前面的映射关系，**U-mode**地址空间的**trapframe**对应的虚拟地址处的值也变更了)(kernel/trap.c:104). 并将**U-mode**地址空间的**trapframe**地址放置在**sscratch**(Supervisior Scratch)中(kernel/trampoline.S:137)
4. 当用户进程**trap**时，通过**sscratch**，即可将当前上下文保存到**trapframe**中，并从**trapframe**中加载**内核页表**和**内核栈**(kernel/trampoline.S:29)，并调用**usertrap**(kernel/trap.c:36)

在直白一些，通过页表映射，可以在**U-mode**和**S-mode**地址空间中，映射**trapframe**页用来保存上下文、内核栈**S-mode**地址和内核页表，从而在**U-mode**地址空间中通过**sscratch**寄存器访问**trapframe**；在**S-mode**地址空间通过**struct proc**全局变量访问**trapframe**。通过将**U-mode**和**S-mode**地址空间的**TRAMPOLINE**虚拟地址都映射到**uservec**处，从而确保在切换地址空间时，执行的相关汇编指令不会更改


## 服务例程

当通过汇编代码，完成了硬件接口的约束后，**life is better**

此刻即可以通过**C**，实现所需的功能

此时已经处于内核栈，并且切换到内核页表。**S-mode**和**U-mode**执行不同的服务例程


### 从S-mode进行trap

如果从**S-mode**进行**trap**，其必然不会主动**trap**，则只需要考虑设备中断即可。

因为可能会被调度(如果是时间中断)，则前面**硬件处理**部分保存的**sepc**(Supervisor Exception Program Counter)和**sstatus**(Supervisor Status Register)可能会被覆盖，则将其保存在内核栈中(kernel/trap.c:137)，然后执行相关的程序即可

当执行完服务例程后，其恢复前面保存的相关寄存器质(kernel/trap.c:158)，继续执行**kernelvec.S**后面的部分即可(kernel/kernelvec.S:51)


### 从U-mode进行trap

类似于从**S-mode**进行**trap**，由于可能会被调度(时间中断),则前面**硬件处理**部分保存的**sepc**(Supervisor Exception Program Counter)和**sstatus**(Supervisor Status Register)可能会被覆盖，但这里并没有保存在内核栈中(虽然也可以，但是因为实现原因没有)，而是保存在**trapframe**中(kernel/trap.c:51)

除此之外，由于可能发生**S-mode**的**trap**，因此需要更改**stvec**(Supervisor Trap Vector Base Address)为**kernelvec**(kernel/trap.c:46)，确保再次陷入时仍然是正确的

当完成服务例程后，其执行**usertrapret**(kernel/trap.c:89)，恢复前面保存的值，同时重置一些关键信息(一方面可能由于进程调度更改的CPU敏感信息，另一方面需要清空内核栈，还有刚刚创建完的用户进程的初始化)，并最后执行**userret**(kernel/trampoline.S:88)


由于**U-mode**的特殊性，其**trap**需要解决**U-mode**切换到**S-mode**再切换为**U-mode**的过程，并且创建用户进程也涉及**S-mode**切换为**U-mode**，所以会略显复杂


## 汇编形式的向量代码2

对称的，从**trap**退出到时，同样需要满足相关的硬件接口约束

### 返回到S-mode

也就是前面**汇编形式的向量代码**的反向操作即可，从内核栈中恢复上下文即可(kernel/kernelvec.S:51)

### 返回到U-mode

同样是前面**汇编形式的向量代码**的反向操作，包括切换为**用户页表**和切换到**用户栈**

其中从前面的**usertrapret**返回时，其将**trapframe**在**U-mode**地址空间的虚拟地址和**U-mode**的页表作为参数传入，则恢复起来要相当容易，即首先切换到**U-mode**页表，然后依次从**trapframe**中恢复上下文和**sscratch**(Supervisior Scratch)(kernel/trampoline.S:88)

## 硬件处理2

终于到最后一步，执行**sret**指令

其同样是前面硬件处理的逆操作

RISC-V架构的硬件会执行如下步骤
1. 将**sepc**(Supervisor Exception Program Counter)复制到**pc**寄存器
2. 将特权级从**sstatus**(Supervisor Status Register)的**SPP**(Supervisor Previous Privilege)比特恢复
3. 开始执行新的**pc**寄存器的执行流


# xv6的系统调用

前面也分析过了，系统调用是**trap**的一种，其在**usertrap**(kernel/trap.c:67)调用**syscall**处理(kernel/syscall.c:132)

riscv和其他架构的**syscall**处理方法相似，将系统调用整理成函数指针数组(kernel/syscall.c:108)，将**系统调用号**作为下标即可

其系统调用号通过**a7**寄存器传递(kernel/syscall.c:138)，返回值通过**a0**寄存器传递(kernel/syscall.c:140)，也就是通过访问**trapframe**上相关数据即可实现

这里需要特别说明的是系统调用的参数，尤其是指针类型的参数——因为**S-mode**和**U-mode**使用的页表不一样，其**trapframe**传递的引用类型的参数需要特别处理，也就是将**U-mode**地址空间中虚拟地址对应的物理地址映射入**S-mode**中，再进行访问(kernel/vm.c:379)

# Lab system calls

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/syscall.html)帮助熟悉**xv6**的系统调用的实现

## system call tracing

### 要求

> In this assignment you will add a system call tracing feature that may help you when debugging later labs. You'll create a new **trace** system call that will control tracing. It should take one argument, an integer "mask", whose bits specify which system calls to trace. For example, to trace the fork system call, a program calls **trace(1 << SYS_fork)**, where SYS_fork is a syscall number from **kernel/syscall.h**. You have to modify the xv6 kernel to print out a line when each system call is about to return, if the system call's number is set in the mask. The line should contain the process id, the name of the system call and the return value; you don't need to print the system call arguments. The **trace** system call should enable tracing for the process that calls it and any children that it subsequently forks, but should not affect other processes. 

### 分析

根据前面的分析，内核函数的服务例程调用位于**syscall**(kernel/syscall.c:172)
因此只需要在调用结束后，输出相关的调用信息即可

而判断当前进程是否被**trace**，以及**trace**了那些系统调用，可以通过在**struct proc**添加标志位集合字段即可。即在输出调用信息前，判断该系统调用对应的标志位是否被设置，从而决定是否输出调用信息

而实现**trace**系统调用则简单的多，即将传入的参数赋给当前进程的对应字段即可

需要特别说明的是，该字段的值应该可以进程，即**fork**的时候，子进程**struct proc**结构体的相关字段应该和父进程的对应字段一样，从而**trace**系统调用可以继续追踪进程的子进程


### 实现


首先，在Makefile中添加测试目标，如下所示
```Makefile
UPROGS=\
	$U/_cat\
	$U/_echo\
	$U/_forktest\
	$U/_grep\
	$U/_init\
	$U/_kill\
	$U/_ln\
	$U/_ls\
	$U/_mkdir\
	$U/_rm\
	$U/_sh\
	$U/_stressfs\
	$U/_trace\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\

```

其次，添加**trace**系统调用的声明，如下所示
```c
// kernel/syscall.h
// System call numbers
#define SYS_fork    1
#define SYS_exit    2
#define SYS_wait    3
#define SYS_pipe    4
#define SYS_read    5
#define SYS_kill    6
#define SYS_exec    7
#define SYS_fstat   8
#define SYS_chdir   9
#define SYS_dup    10
#define SYS_getpid 11
#define SYS_sbrk   12
#define SYS_sleep  13
#define SYS_uptime 14
#define SYS_open   15
#define SYS_write  16
#define SYS_mknod  17
#define SYS_unlink 18
#define SYS_link   19
#define SYS_mkdir  20
#define SYS_close  21
#define SYS_trace  22


// kernel/syscall.c
extern uint64 sys_chdir(void);
extern uint64 sys_close(void);
extern uint64 sys_dup(void);
extern uint64 sys_exec(void);
extern uint64 sys_exit(void);
extern uint64 sys_fork(void);
extern uint64 sys_fstat(void);
extern uint64 sys_getpid(void);
extern uint64 sys_kill(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_mknod(void);
extern uint64 sys_open(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_unlink(void);
extern uint64 sys_wait(void);
extern uint64 sys_write(void);
extern uint64 sys_uptime(void);
extern uint64 sys_trace(void);

static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_trace]   sys_trace,
};


static char *syscall_names[] = {
[SYS_fork]    "fork",
[SYS_exit]    "exit",
[SYS_wait]    "wait",
[SYS_pipe]    "pipe",
[SYS_read]    "read",
[SYS_kill]    "kill",
[SYS_exec]    "exec",
[SYS_fstat]   "fstat",
[SYS_chdir]   "chdir",
[SYS_dup]     "dup",
[SYS_getpid]  "getpid",
[SYS_sbrk]    "sbrk",
[SYS_sleep]   "sleep",
[SYS_uptime]  "uptime",
[SYS_open]    "open",
[SYS_write]   "write",
[SYS_mknod]   "mknod",
[SYS_unlink]  "unlink",
[SYS_link]    "link",
[SYS_mkdir]   "mkdir",
[SYS_close]   "close",
[SYS_trace]   "trace",
};


// user/user.h
// system calls
int fork(void);
int exit(int) __attribute__((noreturn));
int wait(int*);
int pipe(int*);
int write(int, const void*, int);
int read(int, void*, int);
int close(int);
int kill(int);
int exec(char*, char**);
int open(const char*, int);
int mknod(const char*, short, short);
int unlink(const char*);
int fstat(int fd, struct stat*);
int link(const char*, const char*);
int mkdir(const char*);
int chdir(const char*);
int dup(int);
int getpid(void);
char* sbrk(int);
int sleep(int);
int uptime(void);
int trace(int mask);

// user/usys.pl
entry("fork");
entry("exit");
entry("wait");
entry("pipe");
entry("read");
entry("write");
entry("close");
entry("kill");
entry("exec");
entry("open");
entry("mknod");
entry("unlink");
entry("fstat");
entry("link");
entry("mkdir");
entry("chdir");
entry("dup");
entry("getpid");
entry("sbrk");
entry("sleep");
entry("uptime");
entry("trace");
```


最后，实现**trace**系统调用相关功能
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
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  int trace_mask;              // Process trace mask
};



// kernel/sysproc.c
// mark current process as traced process
uint64
sys_trace(void)
{
  struct proc *p = myproc();
  int mask;

  if(argint(0, &mask) < 0)
    return -1;

  p->trace_mask |= mask;

  return 0;
}


// kernel/proc.c
// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  np->parent = p;

  // inherit parent trace_mask
  np->trace_mask = p->trace_mask;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  np->state = RUNNABLE;

  release(&np->lock);

  return pid;
}



// kernel/syscall.c
void
syscall(void)
{
  int num;
  struct proc *p = myproc();
  int res;

  num = p->trapframe->a7;
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    res = syscalls[num]();

    // output the information if current process is traced
    if(((p->trace_mask) >> num) & 1)
      printf("%d: syscall %s -> %d\n", p->pid, 
              syscall_names[num], res);

  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    res = -1;
  }

  p->trapframe->a0 = res;
}
```


### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=trace grade
```
![trace实验结果](trace实验结果.png)


## sysinfo

### 要求

> In this assignment you will add a system call, **sysinfo**, that collects information about the running system. The system call takes one argument: a pointer to a **struct sysinfo** (see **kernel/sysinfo.h**). The kernel should fill out the fields of this struct: the **freemem** field should be set to the number of bytes of free memory, and the **nproc** field should be set to the number of processes whose **state** is not **UNUSED**. We provide a test program sysinfotest; you pass this assignment if it prints "sysinfotest: OK". 

### 分析

和上一个实验基本一致，但需要注意系统调用的参数使用

由于**S-mode**和**U-mode**的页表不一样，则对于**U-mode**地址空间的虚拟地址，需要将其对应的物理地址映射入**S-mode**地址空间后在进行访问

### 实现

首先，在Makefile中添加测试目标，如下所示
```Makefile
OBJS = \
  $K/entry.o \
  $K/start.o \
  $K/console.o \
  $K/printf.o \
  $K/uart.o \
  $K/kalloc.o \
  $K/spinlock.o \
  $K/string.o \
  $K/main.o \
  $K/vm.o \
  $K/proc.o \
  $K/swtch.o \
  $K/trampoline.o \
  $K/trap.o \
  $K/syscall.o \
  $K/sysproc.o \
  $K/bio.o \
  $K/fs.o \
  $K/log.o \
  $K/sleeplock.o \
  $K/file.o \
  $K/pipe.o \
  $K/exec.o \
  $K/sysfile.o \
  $K/sysinfo.o \
  $K/kernelvec.o \
  $K/plic.o \
  $K/virtio_disk.o \


UPROGS=\
	$U/_cat\
	$U/_echo\
	$U/_forktest\
	$U/_grep\
	$U/_init\
	$U/_kill\
	$U/_ln\
	$U/_ls\
	$U/_mkdir\
	$U/_rm\
	$U/_sh\
	$U/_stressfs\
	$U/_sysinfotest\
	$U/_trace\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\

```

其次，添加**sysinfo**系统调用的声明，如下所示
```c
// kernel/syscall.h
// System call numbers
#define SYS_fork     1
#define SYS_exit     2
#define SYS_wait     3
#define SYS_pipe     4
#define SYS_read     5
#define SYS_kill     6
#define SYS_exec     7
#define SYS_fstat    8
#define SYS_chdir    9
#define SYS_dup     10
#define SYS_getpid  11
#define SYS_sbrk    12
#define SYS_sleep   13
#define SYS_uptime  14
#define SYS_open    15
#define SYS_write   16
#define SYS_mknod   17
#define SYS_unlink  18
#define SYS_link    19
#define SYS_mkdir   20
#define SYS_close   21
#define SYS_trace   22
#define SYS_sysinfo 23


// kernel/syscall.c
extern uint64 sys_chdir(void);
extern uint64 sys_close(void);
extern uint64 sys_dup(void);
extern uint64 sys_exec(void);
extern uint64 sys_exit(void);
extern uint64 sys_fork(void);
extern uint64 sys_fstat(void);
extern uint64 sys_getpid(void);
extern uint64 sys_kill(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_mknod(void);
extern uint64 sys_open(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_unlink(void);
extern uint64 sys_wait(void);
extern uint64 sys_write(void);
extern uint64 sys_uptime(void);
extern uint64 sys_trace(void);
extern uint64 sys_sysinfo(void);

static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_trace]   sys_trace,
[SYS_sysinfo] sys_sysinfo,
};



// user/user.h
struct stat;
struct rtcdate;
struct sysinfo;

// system calls
int fork(void);
int exit(int) __attribute__((noreturn));
int wait(int*);
int pipe(int*);
int write(int, const void*, int);
int read(int, void*, int);
int close(int);
int kill(int);
int exec(char*, char**);
int open(const char*, int);
int mknod(const char*, short, short);
int unlink(const char*);
int fstat(int fd, struct stat*);
int link(const char*, const char*);
int mkdir(const char*);
int chdir(const char*);
int dup(int);
int getpid(void);
char* sbrk(int);
int sleep(int);
int uptime(void);
int trace(int mask);
int sysinfo(struct sysinfo*);



// user/usys.pl
entry("fork");
entry("exit");
entry("wait");
entry("pipe");
entry("read");
entry("write");
entry("close");
entry("kill");
entry("exec");
entry("open");
entry("mknod");
entry("unlink");
entry("fstat");
entry("link");
entry("mkdir");
entry("chdir");
entry("dup");
entry("getpid");
entry("sbrk");
entry("sleep");
entry("uptime");
entry("trace");
entry("sysinfo");
```


最后，实现**sysinfo**系统调用相关功能
```c
// kernel/defs.h
// kalloc.c
void*           kalloc(void);
void            kfree(void *);
void            kinit(void);
uint64          kfreemem(void);

// proc.c
int             cpuid(void);
void            exit(int);
int             fork(void);
int             growproc(int);
pagetable_t     proc_pagetable(struct proc *);
void            proc_freepagetable(pagetable_t, uint64);
int             kill(int);
struct cpu*     mycpu(void);
struct cpu*     getmycpu(void);
struct proc*    myproc();
void            procinit(void);
void            scheduler(void) __attribute__((noreturn));
void            sched(void);
void            setproc(struct proc*);
void            sleep(void*, struct spinlock*);
void            userinit(void);
int             wait(uint64);
void            wakeup(void*);
void            yield(void);
int             either_copyout(int user_dst, uint64 dst, void *src, uint64 len);
int             either_copyin(void *dst, int user_src, uint64 src, uint64 len);
void            procdump(void);
uint64          nproc(void);


// kernel/kalloc.c
// collect the info of free memory
// returns the amount of free memory in bytes
uint64
kfreemem(void)
{
  uint64 free_page_number = 0;
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;

  while(r) {
    ++free_page_number;
    r = r->next;
  }
  release(&kmem.lock);

  return free_page_number * PGSIZE;
}


// kernel/proc.c
// collect the information about the processes.
// return the number of the processes, whose status is
//not UNUSED
uint64
nproc(void)
{

  struct proc *p;
  uint64 number = 0;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state != UNUSED)
      ++number;
    release(&p->lock);
  }

  return number;
}


// kernel/sysinfo.c
#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "sysinfo.h"


uint64
sys_sysinfo(void)
{

    struct sysinfo sysinfo;
    uint64 dst;                 // user pointer to struct sysinfo
    struct proc *p = myproc();

    
    if(argaddr(0, &dst) < 0)
        return -1;

    sysinfo.freemem = kfreemem();
    sysinfo.nproc = nproc();


    if(copyout(p->pagetable, dst, (char*)&sysinfo, sizeof(sysinfo)) < 0)
        return -1;

    return 0;
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=sysinfo grade
```
![sysinfo实验结果](sysinfo实验结果.png)