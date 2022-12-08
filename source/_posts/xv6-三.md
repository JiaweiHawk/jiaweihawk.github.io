---
title: xv6-三
date: 2022-05-26 09:46:10
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客探索一下xv6内核的虚拟内存机制


# xv6的页表机制

**page table**(页表)是典型的软、硬件结合的机制，即硬件提供相关的电路实现和接口，操作系统根据硬件的接口，实现相关的服务


## 页表硬件

对于**riscv**指令来说(无论在**S-mode**还是**U-mode**)，其操作的是**virtual address**(虚拟地址)。但是对于机器的**RAM**来说，其操作的是**physical address**(物理地址)

而**page table**的硬件部分，则是连接两个地址的组件——其将**virtual address**(虚拟地址)映射为**physical address**(物理地址)

**page table**工作的基本逻辑如下图所示
![page table工作示意图](page-table工作示意图.png)

直白的说，其将**虚拟地址空间**和**物理地址空间**以**页**(4096字节)为单位切分，并以**页**为单位进行映射(即通过**page table**记录页号之间的映射关系)


当然，**riscv**支持多种**page table**机制，但是这些机制的大体思路和上面的图所展示的是一致的

xv6采用了**Sv39**方案的**page table**，即support a 39-bit virtual address space。该方案中，64bit的**virtual address**仅仅使用低39bit，如下所示
![Sv39 virtual address示意图](sv39-virtual-address.png)


**Sv39**方案中的**虚拟地址**和**物理地址**的映射略微复杂一些，但基本原理和前面是一致的，即以**页**为单位进行映射，如下所示
![Sv39地址映射示意图](sv39地址映射示意图.png)

**Sv39**方案中的**page table**可以抽象成三层树。每一层树都是**页**(4096字节)大小的，包含**512**个**PTE**(page table entries)的**pd**(page directory)。**pte**(page table entries)是一个**8字节**大小的，包含其指向的**物理页**的序号和属性的元素。

未开启**page table**之前，所有指令访问的内存数据都是**physical address**
而如果准备使用**page table**机制，只需要首先在物理内存中初始化好页表(即填充每级**pd**的**pte**元素)，并将**page table**的根**pd**的物理地址装载入**satp**(Supervisor Address Translation and Protection)寄存器即可。之后任何指令访问的内存数据，都是需要经过**page table**映射处理的**virtual address**



## 内核抽象

**page table**在内核中抽象出的对象即为**address space**
正如前面分析过的，**内核地址空间**(即**S-mode**)和**用户地址空间**(即**U-mode**)中，相同的**virtual address**，往往映射到不同的**physical address**，也就是访问内存往往不一致


### 内核地址空间

xv6包含单个**内核页表**，即仅仅含有一个**内核地址空间**

为了在**内核地址空间**中，可以高效、方便的管理硬件、物理内存等资源，xv6精心构建如下所示的**内核地址空间**映射关系
![内核地址空间示意图](内核地址空间示意图.png)

可以看到，**内核地址空间**大致分为如下几个区域
1. $[0, KERNBASE(0x80000000))$
  **QEMU**会将I/O设备接口映射到低0x80000000内存处
  内核为了方便进行管理，自然采用最简单直接的映射方式——直接映射，也就是将这部分的**virtual address**映射到相同值的**physical address**，从而降低管理的心智负担(kernel/vm.c:28)

2. $[KERNBASE(0x80000000), PHYSTOP(0x86400000))$
  这部分是实际上剩余可用的物理内存，则为了方便内核管理内存资源，自然类似于上面，采用最简单直接的映射方式——直接映射，也就是将这部分的**virtual address**映射到相同值的**physical address**，从而降低管理的心智负担。(kernel/vm.c:40)

  这里额外说明一下，xv6的内核镜像也被加载到这部分**physical address**，也就是**virtual address**处。由于是直接映射，则内核代码中的访存指令可以正常运行

3. $[MAXVA(0x4000000000) - 0x1000, MAXVA(0x4000000000))$
  正如前面博客介绍过的，这部分静态的映射**trap**过程的汇编处理部分(kernel/vm.c:47)，并且后面要介绍的用户态空间，这部分**virtual address**同样映射到相同的**physical address**处

4. $[PHYSTOP(0x86400000), MAXVA(0x4000000000) - 0x1000)$
  这部分是每个进程的内核栈页。每个CPU的第一个进程的内核栈是静态映射到内核镜像相关数据加载的**physical address**(kernel/entry.S:11)；对于其余进程的内核栈，则动态申请内核管理的物理内存资源并进行映射(kernel/proc.c:37)

再直白一些，对于**内核地址空间**的**virtual address**，基本上**直接映射**到**physical address**，从而方便内核进行资源管理——通过访问与**physical address**相同值的**virtual address**，就可以直接访问到相应的**physical address**，真正的**make life easier**


### 用户地址空间

xv6中每个进程拥有一个单独的**page table**，从而完成进程间以及进程和内核间的隔离

xv6构建的**用户地址空间**布局如下所示
![用户地址空间示意图](用户地址空间示意图.png)

除了**trampoline**部分，其余的**virtual address**都是动态映射到**physical address**中——即申请对应的物理页，并在页表中添加映射
而对于**trampoline**，这部分前面也介绍了，将其静态映射到内核镜像对应代码的装载的物理地址即可

这里还想额外说一下。由于**内核地址空间**是**直接映射**，则在内核地址空间中，通过**virtual address**，可以轻易访问到物理页，也就是可以轻松访问到用户进程的**页表**，从而更改进程的**用户地址空间**信息，而这也是很多系统调用的实现原理(例如exec，直接重新初始化用户页表，从而初始化用户地址空间)


# Lab page tables

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/pgtbl.html)帮助熟悉**xv6**的页表

## print a page table

### 要求

> Define a function called **vmprint()**. It should take a **pagetable_t** argument, and print that pagetable in the format described below. Insert **if(p->pid==1) vmprint(p->pagetable)** in exec.c just before the **return argc**, to print the first process's page table. You receive full credit for this assignment if you pass the **pte printout** test of **make grade**.

### 分析

根据前面分析，**page table**可以抽象为一个**树**，则可以尝试使用递归方法，递归的解析**page table**

实际上，除了根页表外，每一个**pd**都是由**512**个**pte**组成的，其输出格式仅仅和**pte**的值和其**pd**层级有关，方便递归遍历的实现

这里需要提醒的是，则解析**pte**时，需要通过其**PTE_V**标志位，判断该**pte**是否有效

### 实现

在**kernel/exec.c**文件中，实习递归解析的方法即可
```c
//kernel/exec.c

static void vmprint(pagetable_t pagetable);

int
exec(char *path, char **argv)
{
  ...
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);

  // print the first process's page table
  if(p->pid == 1)
    vmprint(p->pagetable);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

  ...
}


// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
// recursively walk the page-table by _vmprint
static void
_vmprint(pagetable_t pagetable, int level)
{

  for(int pte_no = 0; pte_no < 512; ++pte_no) {

    pte_t *pte = &pagetable[pte_no];

    // if pte is invalid, just ignore the following parse
    if((*pte & PTE_V) == 0)
      continue;

    // parse the pte

    // print the indent
    for(int i = 2 - level; i >= 0; --i) {
      printf("..");
      if(i)
        printf(" ");
    }

    // print the index, content and physical address
    printf("%d: pte %p pa %p\n", pte_no, *pte, PTE2PA(*pte));
    
    // recursively walk the next level, if next level is valid
    if(level)
      _vmprint((pagetable_t)PTE2PA(*pte), level - 1);
  }

}


// print the page table content for given page table
static void
vmprint(pagetable_t pagetable)
{
  printf("page table %p\n", pagetable);
  _vmprint(pagetable, 2);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="pte printout" grade
```
![pte printout实验结果](pte_printout实验结果.png)

## a kernel page table per process

### 要求

> Your first job is to modify the kernel so that every process uses its own copy of the kernel page table when executing in the kernel. Modify **struct proc** to maintain a kernel page table for each process, and modify the scheduler to switch kernel page tables when switching processes. For this step, each per-process kernel page table should be identical to the existing global kernel page table. You pass this part of the lab if **usertests** runs correctly.

### 分析

这部分内容着实需要对于xv6整体有非常好的理解

这里分析一下用户进程的生命周期

- 进程的创建
  如果是第一个用户进程，其在**userinit**(kernel/proc.c:223)中创建用户态地址空间，其关键的调用栈如下所示
  ![初始用户进程调用栈](初始用户进程调用栈.png)
  而对于其余的用户进程，其通过**fork**(kernel/proc.c:269)来继承用户态地址空间，其关键的调用栈如下所示
  ![非初始用户进程调用栈](非初始用户进程调用栈.png)

  再直白些，进程的创建主要设置进程**S-mode**的**context**(**struct proc**的**context**字段，主要用于scheduler)和进程**U-mode**的**context**(**struct proc**的**trapframe**字段，用于恢复用户态执行)

- 进程的初始化
  在**进程的创建**中，所有的进程的**struct proc**的**context**字段的**ra**值，在**allocproc**(kernel/proc.c:92)中被设置为**forkret**(kernel/proc.c:562)

  在**scheduler**(kernel/proc.c:467)中，调用**swtch**(kernel/swtch.S:9)，从而切换到进程的**struct proc**的**context**上下文，其关键的调用栈如下所示
  ![进程的初始化调用栈](进程的初始化调用栈.png)

  再直白些，**scheduler**(kernel/proc.c:467)从**context**字段恢复上下文后，在**forkret**(kernel/proc:562)完成相关资源初始化后，通过**usertrapret**(kernel/trap.c:89)，类似与**trap**返回，从**trapframe**字段恢复**U-mode**的上下文

  一般来说，其会在**U-mode**接着调用**exec**系统调用，相关调用栈如下所示
  ![exec调用栈](exec调用栈.png)

  **exec**(kernel/exec.c:13)就是通过**proc_pagetable**(kernel/proc.c:168)新创建用户态地址空间，并通过**uvmalloc**(kernel/proc.c:168)和**copyout**(kernel/vm.c:424)将执行文件映射入用户态地址空间，同时释放掉原始的用户态地址空间

- 进程的终结
  当进程结束时，其会调用**exit**系统调用，最后执行**exit**(kernel/proc.c:343)，来释放并更改进程的状态。其关键的调用栈如下所示
  ![exit调用栈](exit调用栈.png)

  实际上，**exit**(kernel/proc.c:343)仅仅将进程状态标记为**ZOMBIE**，然后更改与其余进程的关系，但并此时仍然没有释放进程的资源(类似于Linux的**defunct**状态)

  其进程资源的彻底释放，是等待该进程的父进程调用**wait**系统调用，从而回收进程的资源。其关键的调用栈如下所示
  ![wait调用栈](wait调用栈.png)


了解了进程的声明周期后，给其添加**process identical**的内核页表就相对很简单了
很自然的，在进程的创建时构建内核页表；在进程释放其资源时释放内核页表(这里要特别小心，注意**freeproc**(kernel/proc.c:145)在生命周期中调用一次，而**proc_freepagetable**(kernel/proc.c:201)会在**exec**时同样调用)即可

而另一个问题时何时切换页表。根据前面的分析，**swtch**(kernel/swtch.S:9)时才切入或切出进程的内核上下文。因此在**swtch**(kernel/swtch.S:9)调用前和后切换就行。
而考虑到如下因素
- **swtch**(kernel/swtch.S:9)是汇编代码不方便插入
- **swtch**(kernel/swtch.S:9)切入和切出后立马进入**scheduler**(kernel/proc.c:494)
- **scheduler**(kernel/proc.c:494)使用自己独立，位于内核镜像的全局变量声明的栈

因此，在**scheduler**调用**swtch**和从**swtch**返回时完成页表的切换即可。
这里则特别提醒一下，从**swtch**跳出后，需要将内核页表切换为原始的全局页表——因为从**swtch**返回时，使用的仍然是之前进程的**process identical**内核页表，而从**swtch**返回，可能是因为进程结束，则进程的资源(**process identical**内核页表)可能会被其他CPU释放掉，导致该**process identical**内核页表无效，则继续使用必然会导致相关的错误

### 实现

首先，在**struct proc**结构体中，添加**process identical**的内核页表字段
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
  pagetable_t kernel_pagetable;// process's identical kernel page-table
  struct trapframe *trapframe; // data page for trampoline.S
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
};
```

其次，添加**process identical**内核页表的分配和释放即可
```c
// kernel/vm.c
/*
 * create a process's identical kernel page table
 */
pagetable_t
ukvminit(uint64 kstack)
{
  pagetable_t pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);

  // uart registers
  mappages(pagetable, UART0, PGSIZE, 
            UART0, PTE_R | PTE_W);

  // virtio mmio disk interface
  mappages(pagetable, VIRTIO0, PGSIZE, 
            VIRTIO0, PTE_R | PTE_W);

  // CLINT
  mappages(pagetable, CLINT, 0x10000, 
            CLINT, PTE_R | PTE_W);

  // PLIC
  mappages(pagetable, PLIC, 0x400000, 
            PLIC, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  mappages(pagetable, KERNBASE, (uint64)etext-KERNBASE,
            KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  mappages(pagetable, (uint64)etext, PHYSTOP-(uint64)etext,
            (uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  mappages(pagetable, TRAMPOLINE, PGSIZE,
          (uint64)trampoline, PTE_R | PTE_X);

  // Map the process's kernel stack in kernel_pagetable
  // to the process's identical kernel page-table 
  uint64 pa = kvmpa(kstack);
  mappages(pagetable, kstack, PGSIZE, 
            pa, PTE_R | PTE_W);

   return pagetable;
}

// Recursively free page-table pages.
// All leaf mappings is ignored,
// For it must be kernel mappings, or
// it will be free in nvmunmap
void
ukvmfree(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      ukvmfree((pagetable_t)child);
      pagetable[i] = 0;
    }
  }
  kfree((void*)pagetable);
}
```

接着，在进程分配和释放时，同时分配和释放对应的内核页表
```c
// kernel/proc.c
// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();

  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // A process's identical kernel page-table
  p->kernel_pagetable = ukvminit(p->kstack);
  if(p->kernel_pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->kernel_pagetable)
    ukvmfree(p->kernel_pagetable);
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->kernel_pagetable = 0;
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}
```

最后，则是在**scheduler**函数中，完成内核页表的切换即可
```c
// kernel/proc.c
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  
  c->proc = 0;
  for(;;){
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();
    
    int found = 0;
    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;

        // When switch to other process
        // Just change to process's identical kernel page-table
        // as requested
        w_satp(MAKE_SATP(p->kernel_pagetable));
        sfence_vma();

        swtch(&c->context, &p->context);

        // Return from swtch, satp point to the process identical kernel page-table
        // What's worse, the process resource may be cleaned, which result the satp
        // a invalid page-table
        // so, we need switch to the common kernel page-table, which is always a
        // invalid page-table contains all page-table
        kvminithart();

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;

        found = 1;
      }
      release(&p->lock);
    }
#if !defined (LAB_FS)
    if(found == 0) {
      intr_on();
      asm volatile("wfi");
    }
#else
    ;
#endif
  }
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="usertests" grade
```
![a kernel page table per process实验结果](usertests实验结果.png)

## simplify copyin/copyinstr

### 要求

> Replace the body of **copyin** in **kernel/vm.c** with a call to **copyin_new** (defined in **kernel/vmcopyin.c**); do the same for **copyinstr** and **copyinstr_new**. Add mappings for user addresses to each process's kernel page table so that **copyin_new** and **copyinstr_new** work. You pass this assignment if **usertests** runs correctly and all the **make grade** tests pass.

### 分析

根据实验指南，只需要在每次更改**U-mode**页表映射时，以相同的方式更改**S-mode**的**process identical**的内核页表映射即可

实际上，改变**U-mode**页表映射只会出现在**sys_exec**(kernel/sysfile.c:415)、**sys_fork**(kernel/sysproc.c:26)、**sys_sbrk**(kernel/sysproc.c:41)、**freeproc**(kernel/proc.c:144)和**userinit**(kernel/proc.c:223)中

而添加和删除相关的**process identical**的内核页表和上一个**lab**并没有什么区别——仅仅是删除时删除指定的页表项

### 实现

首先，实现在**process identical**的内核页表中，添加**U-mode**的页表映射关系
```c
// kernel/vm.c

// Map the user virtual memory to the physical memory
// in the same way in user pagetable
// it should map in S-mode perm; and it should has limit the maximum size 
uint64
ukvmmap(pagetable_t kp, pagetable_t up, uint64 oldsz, uint64 newsz)
{
  uint64 a;
  pte_t *pte;

  if(newsz < oldsz)
    return 0;

  if(newsz > PLIC)
    panic("ukvmmap: newsze >= PLIC\n");
  
  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    pte = walk(up, a, 0);
    if(pte == 0) {
      ukvmunmap(kp, a, oldsz);
      return -1;
    }

    if(mappages(kp, a, PGSIZE, PTE2PA(*pte), PTE_FLAGS(*pte) ^ PTE_U) != 0){
      ukvmunmap(kp, a, oldsz);
      return -1;
    }
  }
  return 0;
}


// Unmap user pages in kernel pagetable to bring the process size 
// from oldsz to newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
ukvmunmap(pagetable_t kp, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;

    // the physical memory will be freed in uvmdealloc
    uvmunmap(kp, PGROUNDUP(newsz), npages, 0);
  }

  return newsz;
}
```

这里额外说明一下几个注意点
1. 映射的虚拟地址有上限——根据博客开始时**S-mode**内存布局，其**boot ROM**部分和**CLINT**部分在启动后可以覆盖掉；而用户程序基址为**0**，则为了与原本的**S-mode**内核内存布局冲突，其添加的虚拟地址上限为**PLIC**
2. 添加相关的的映射关系，其属性应该为**PTE_S**，即仅**S-mode**可接触——因为该页表是切换到**S-mode**才会使用的，避免越权访问
3. 删除**S-mode**内核页表相关的映射关系时，无需释放掉物理内存——对应的物理内存会在**U-mode**释放页表资源时进行释放


其次，则是在用户空间页表被更改时，同样更改**S-mode**的**process identical**的内核页表的相关表项
```c
// kernel/proc.c
// Set up first user process.
void
userinit(void)
{
  ...
  // allocate one user page and copy init's instructions
  // and data into it.
  uvminit(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;
  ukvmmap(p->kernel_pagetable, p->pagetable, 0, p->sz);

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer
  ...
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  ...
  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }

  np->sz = p->sz;
  // Map user memory from parent to child in kernel pagetable
  if(ukvmmap(np->kernel_pagetable, np->pagetable, 0, np->sz) < 0) {
    freeproc(np);
    release(&np->lock);
    return -1;
  }

  np->parent = p;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);
  ...
}

// kernel/exec.c
int
exec(char *path, char **argv)
{
  ...
  // Load program into memory.
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    uint64 sz1;
    if((sz1 = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    sz = sz1;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    if(loadseg(pagetable, ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }

  uint64 oldsz = p->sz;

  ...
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);
  ukvmunmap(p->kernel_pagetable, oldsz, 0);

  // Map the user memory into kernel pagetable
  if(ukvmmap(p->kernel_pagetable, p->pagetable, 0, p->sz) < 0)
    goto bad;

  // print the first process's page table
  if(p->pid == 1)
    vmprint(p->pagetable);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}


// kernel/proc.c
// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz, newsz;
  struct proc *p = myproc();

  newsz = sz = p->sz;
  if(n > 0){
    if((newsz = uvmalloc(p->pagetable, sz, sz + n)) == 0 ||
      ukvmmap(p->kernel_pagetable, p->pagetable, sz, sz + n) < 0) {
      return -1;
    }
  } else if(n < 0){
    newsz = uvmdealloc(p->pagetable, sz, sz + n);
    ukvmunmap(p->kernel_pagetable, sz, sz + n);
  }
  p->sz = newsz;
  return 0;
}
```

而对于**proc_freepagetable**，其无需进行更改，保持前一个**lab**的实现即可——因为前一个**lab**已经实现了释放整个**process identical**的内核页表页表项，并且不释放最终的物理内存。而这正符合前面的分析

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="usertests" grade
```
![Simplify copyin/copyinstr实验结果](usertest_copyin实验结果.png)