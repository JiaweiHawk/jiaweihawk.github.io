---
title: xv6-十
date: 2022-10-08 22:30:30
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客研究**xv6**的**虚拟内存**的管理机制

# Lab mmap

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/mmap.html)用来实现**xv6**的**虚拟内存**的管理机制

## 要求

> **mmap** can be called in many ways, yet this lab requires only a subset of its features relevant to memory-mapping a file. You can assume that **addr** will always be zero, meaning that the kernel should decide the virtual address at which to map the file. **mmap** returns that address, or 0xffffffffffffffff if it fails. **length** is the number of bytes to map; it might not be the same as the file's length. **prot** indicates whether the memory should be mapped readable, writeable, and/or executable; you can assume that **prot** is **PROT_READ** or **PROT_WRITE** or both. **flags** will be either **MAP_SHARED**, meaning that modifications to the mapped memory should be written back to the file, or **MAP_PRIVATE**, meaning that they should not. You don't have to implement any other bits in **flags**. **fd** is the open file descriptor of the file to map. You can assume **offset** is zero (it's the starting point in the file at which to map).
>
> **munmap** should remove mmap mappings in the indicated address range. If the process has modified the memory and has it mapped **MAP_SHARED**, the modifications should first be written to the file. An **munmap** call might cover only a portion of an mmap-ed region, but you can assume that it will either unmap at the start, or at the end, or the whole region (but not punch a hole in the middle of a region). 
>
> You should implement enough **mmap** and **munmap** functionality to make the **mmaptest** test program work. If **mmaptest** doesn't use a **mmap** feature, you don't need to implement that feature. 
>
> When you're done, you should see this output:
> ```bash
$ mmaptest
mmap_test starting
test mmap f
test mmap f: OK
test mmap private
test mmap private: OK
test mmap read-only
test mmap read-only: OK
test mmap read/write
test mmap read/write: OK
test mmap dirty
test mmap dirty: OK
test not-mapped unmap
test not-mapped unmap: OK
test mmap two files
test mmap two files: OK
mmap_test: ALL OK
fork_test starting
fork_test OK
mmaptest: all tests succeeded
$ usertests
usertests starting
...
ALL TESTS PASSED
$ 
```

## 分析

实际上，**mmap()**和**munmap()**是***nix**系统中，管理进程**virtual address space**的重要途径之一。

在**xv6**中，进程的**虚拟地址空间**布局大致如下所示
![进程虚拟地址空间布局](vasl.png)

1. ELF程序、进程stack
  **xv6**会在**exec()**(kernel/exec.c:42)中，将**可执行文件*载入到进程的虚拟地址空间的**起始地址**(0)处；在**exec()**(kernel/exec:67)中，初始化用户态的栈空间信息
2. 进程heap
  **xv6**通过管理**sz**指针(类似于Linux的brk指针)，从而在进程运行时，动态的分配或释放堆空间。进程可以通过**sbrk()**系统调用，向**xv6**申请分配或释放相关的**heap**。这部分空间向高地址方向生长
3. trampoline、trapframe
  **xv6**会将**uservec**(kernel/trampoline.S:16)和**userret**(kernel/trampoline.S:88)物理页，在**内核地址空间**和进程的**虚拟地址空间**，都映射到**trampoline**处。这样确保进程在陷入内核或从内核返回时，即使页表进行了切换，仍能执行同一份代码。除此以外，为了在陷入内核前，保存当前进程的上下文，内核会为每个进程分配相关的物理页保存其上下文，并将其上下文所在的物理页映射到对应进程的**TRAPFRAME**处
4. 进程map
  由于进程heap向高地址方向动态生长，则在运行过程中，高地址空间还剩余了未使用空间，则可以将其当做进程的map区域。即进程可以从**trampoline、trapframe**区域的下边界开始，向低地址方向动态生长

当选定进程map的地址空间位置后，下一步需要考虑的则是如何管理每一个map区域。这里为了实现简单，就通过在进程的**struct proc**(kernel/proc.h:86)中添加有序数组进行管理，每一个数组元素都是一个连续的map区域

## 实现

首先，添加管理**map**区域的数据结构，如下所示
```c
// kernel/proc.h

/*
 * @struct uvmarea is used to manage each process mmap mappings.
 * Each @struct uvmarea represents a continuous, non-overlapped
 * mmap mappings in process. And each process has their own
 * @struct uvmareas array, stored in @struct proc. This array
 * is sorted descend by @st field.
 * 
 * When process requests for a map mapping, kernel does not
 * alloc the physical memory, or map the user virtual memory to
 * the physical memory in pagetable. Instead, kernel will only allocates the
 * @struct uvmarea. Only when process triggers the page-fault does kernel
 * alloc the physical memory and map the relative user virtual memory to this
 * physical memory.
 */
struct uvmarea {

  uint64 st;                  // Begin address of the map mapping area
  uint64 ed;                  // End border of the map mapping area
                              // uvmarea range should be [st, ed)

  struct file *f;             // Open file descriptor of the file to map
  uint offset;                // Starting point in the file at which to map
  int prot;                   // The desired memory protection
  int flags;                  // Whether updates are carried through to
                              // the underlying file
};

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

  struct uvmarea vm[NUVMAREA]; // User virtual memory areas
  uint64 nvm;                  // Number of vm area
};
```
这里使用**struct uvmarea**管理进程的每一个map区域，其包含传入**mmap()**系统调用的用来描述**map区域**的所有参数信息

其次，为了实现方便，每一次进程调用**mmap()**时，内核从**vm**有序数组中选取起始地址最小的，作为该次**map区域**地址上界。之后初始化**struct uvmarea**元素，并将其插入到**vm**有序数组中，如下所示
```c
// kernel/mmap.c

/*
 * map files or devices into memory
 * void *mmap(void *addr, uint length, int prot, int flags,
 *            int fd, uint offset)
 * 
 * @addr: You can assume that @addr will always be zero, meaning
 * that the kernel should decide the virtual address at which to
 * map the file.
 * 
 * @length: @length is the number of bytes to map; it might not
 * be the same as the file's length.
 * 
 * @prot: @prot indicates whether the memory should be mapped
 * readable, writeable, and/or executable; you can assume that
 * @prot is PROT_READ or PROT_WRITE or both.
 * 
 * @flags: @flags will be either MAP_SHARED, meaning that modifications
 * to the mapped memory should be written back to the file,
 * or MAP_PRIVATE, meaning that they should not.
 * 
 * @fd: @fd is the open file descriptor of the file to map.
 * 
 * @offset: You can assume @offset is zero (it's the starting
 * point in the file at which to map).
 * 
 * @return: mmap returns the virtual address that kernel decides to map,
 * or 0xffffffffffffffff if it fails.
 */
static uint64 mmap(void *addr, uint length, int prot,
                   int flags, int fd, uint offset)
{
    struct file *f;
    struct proc *p = myproc();
    uint64 address = (uint64)addr;

    /* Kernel only supports NUVMAREA elements in struct proc vm arrays */
    if(p->nvm >= NUVMAREA)
        return -1;

    /* do some sanity check to ensure that @addr is 0 */
    assert(address == 0);
    
    /* do some sanity check to ensure that
     * @prot is PROT_READ or PROT_WRITE or both.
     */
    assert(((prot & (PROT_READ | PROT_WRITE)) != 0) &&
           ((prot & ~(PROT_READ | PROT_WRITE)) == 0));
    
    /* do some sanity check to ensure that
     * @flags is MAP_SHARED or MAP_PRIVATE
     */
    assert((flags == MAP_SHARED) || (flags == MAP_PRIVATE));

    /* do some sanity check to ensure that
     * @fd is a valid file descriptor
     */
    assert((fd >= 0) && (fd < NOFILE) &&
           ((f = p->ofile[fd]) != 0));
    
    /* do some sanity check to ensure that
     * f's mode, prot and flags is valid combinartion
     */
    /* PROT_READ only when f's mode is readable */
    if((prot & PROT_READ) != 0 && f->readable == 0)
        return -1;
    /* MAP_SHARED, PROT_WRITE only when f's mode is writable */
    if(flags == MAP_SHARED && (prot & PROT_WRITE) != 0 &&
       f->writable == 0)
        return -1;

    /* increase the struct file to avoid use-after-free */
    filedup(f);

    /* For the struct proc vm arrays is sorted descend by st field.
     * So we can choose the first element's st field, as this mapping
     * end border. If array is empty, just select the mmap
     * border(MMAPBASE) as this mapping end border.
     */
    if(p->nvm == 0)
        address = MMAPBASE;
    else
        address = PGROUNDDOWN(p->vm[p->nvm - 1].st);
    
    /* do some sanity check for end border
     * - address should be aligned to PGSIZE
     * - remain space should be bigger enough for this
     * mapping.
     */
    if((length > address) || ((address - PGROUNDUP(length)) < p->sz)) {
        fileclose(f);
        return -1;
    }

    /* calculate the start address */
    address -= PGROUNDUP(length);

    /* Create PTEs for virtual addresses.
     *
     * Kernel will only use mappages to create PTEs, so
     * its @pa argument should be 0. Its physical memory
     * allocating and mapping should be delayed in
     * page fault handle, so its @perm should not set
     * PTE_U flag, which can triggers the page fault.
     */
    for(int i = 0; i < PGROUNDUP(length); i += PGSIZE) {
        if(mappages(p->pagetable, address + i, PGSIZE,
                    0, prot2perm(prot)) == -1) {
            mmap_uvmunmap(p->pagetable, address, i / PGSIZE);
            fileclose(f);
            return -1;
        }
    }

    /* Insert the uvm area in struct proc's struct uvmarea arrays,
     * to trace this mmap mapping. Because arrays is sorted descend,
     * kernel just need to insert the element in the tail.
     *
     * This uvmarea is used to alloc the physical memory and map to
     * the virtuam memory traced by struct uvmarea, when triggering
     * page-fault.
     */
    p->vm[p->nvm++] = (struct uvmarea){
        .st = address,
        .ed = address + length,
        .f = f,
        .offset = offset,
        .prot = prot,
        .flags = flags,
    };

    return address;
}
```

需要注意的是，为了提高效率，这里在进行**mmap()**时，仅仅分配了虚拟地址空间(即创建了PTE)，并没有分配实际的物理页，并且该虚拟页的权限也没有**PTE_U**。这样，当进程访问**mmap()**的地址空间时，会触发**page fault**，内核可以在处理该**page fault**时，在实际进行物理地址页的分配和映射即可，如下所示
```c
// kernel/trap.c

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();
  } else if((which_dev = devintr()) != 0){
    // ok
  } else {

    /* handle possible mmap page fault */
    if(mmap_handle_page_fault(r_stval(), r_scause()) != 0) {
    /* mmap fails to handle page fault */

      printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
      printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
      p->killed = 1;

    }
  }

  if(p->killed)
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
    yield();

  usertrapret();
}

// kernel/mmap.c

/* Handle possible mmap page fault.
 * If exception address belongs to the process map mappings, and
 * cause fits the relative mapping protection, then kernel will
 * allocates the physical memory and map it with relative virtual
 * memory page.
 *
 * @va: virtual address triggers this page fault
 *
 * @scause: the page fault type
 *
 * @return: return 0 if it successes to handle, or -1 if it fails
 */
int mmap_handle_page_fault(uint64 va, uint64 scause) {

    struct uvmarea vm;
    struct proc *p = myproc();
    int idx = uvmarea_find(p->vm, p->nvm, va);
    void *pa;
    uint offset, size;
    pte_t *pte;

    /* check whether this va is in map mappings */
    if(idx == -1)
        return -1;
    
    vm = p->vm[idx];

    /* kernel will treats page fault in page */
    va = PGROUNDDOWN(va);

    /* handle the page fault according to the scause type */
    switch(scause) {

        case 13:
        /* Load Page Fault */

            /* check whether situation is matched */
            if((vm.prot & PROT_READ) == 0)
                return -1;
            
            /* alloc the physical memory */
            if((pa = kalloc()) == 0)
                return -1;
            
            /* get the PTE created by mmap */
            if((pte = walk(p->pagetable, va, 0)) == 0) {
                kfree(pa);
                return -1;
            }

            mmap_assert_pte(pte);

            /* map the physical memory */
            *pte |= PA2PTE(pa) | PTE_U;

            /* initial the page data */
            memset(pa, 0, PGSIZE);

            /* read the page data
             * kernel should store the initial offset
             * then set to the des offset
             * finally restore the initial offset
             */
            offset = vm.f->off;
            size = vm.ed - va;

            vm.f->off = vm.offset + (va - vm.st);
            fileread(vm.f, va, size <= PGSIZE ? size : PGSIZE);
            vm.f->off = offset;

            break;

        /* none situation is matched*/
        default:
            return -1;
    }

    return 0;
}
```

当调用**munmap()**系统调用时，则查找该区间对应的元素，并根据相关情况释放资源，如下所示
```c
// kernel/mmap.c

/* Remove npages of mappings starting from va, mapped from
 * mmap().
 * va must be page-aligned, the mappings may exist, and
 * perm may be 0
 */
void mmap_uvmunmap(pagetable_t pagetable, uint64 va,
                          uint64 npages) {

    uint64 a;
    pte_t *pte;

    assert((va % PGSIZE) == 0);

    for(a = va; a < va + npages*PGSIZE; a += PGSIZE) {

        pte = walk(pagetable, a, 0);
        mmap_assert_pte(pte);


        /* PTEs in mmap mapping regions have only two situation
        * - *pte == (PTE_V | perm)
        * - *pte == (PTE_V | PTE_U | perm | pa)
        * So add sanity check to ensure ptes is valid
        */
        if((*pte & PTE_U) != 0) {
        /* Only in second situation does pte allocates physical page */

            kfree((void*)PTE2PA(*pte));

        }

        *pte = 0;
    }
}

/*
 * unmap files or devices into memory
 * uint64 munmap(void *addr, uint length)
 * 
 * @addr: the begin address of the mmap mappings that kernel
 * wants to remove
 * 
 * @length: the mmap mappings range that kernel wants to remove
 * 
 * @return: munmap returns 0 if it successes,
 * or 0xffffffffffffffff if it fails.
 * 
 * you can assume that *munmap will either unmap at the start,
 * or at the end, or the whole region (but not punch a hole
 * in the middle of a region).
 */
uint64 munmap(void *addr, uint length)
{
    struct uvmarea vm;
    struct proc *p = myproc();
    uint64 address = (uint64)addr,
           idx = uvmarea_find(p->vm, p->nvm, address);
    uint offset;
    
    /* Failed to find the area contains address */
    if(idx == -1)
        return 0;
    
    /* do some sanity check for this area */
    assert(idx >= 0 && idx < p->nvm);
    assert(address >= (vm = p->vm[idx]).st &&
           length <= (vm.ed - address));
    

    /* Write back the modifications for MAP_SHARED */
    if((vm.prot & PROT_WRITE) != 0 && vm.flags == MAP_SHARED) {

        /* write the page data
         * kernel should store the initial offset
         * then set to the des offset
         * finally restore the initial offset
         */
        offset = vm.f->off;
        vm.f->off = offset + (address - p->vm[idx].st);
        filewrite(vm.f, address, length);
        vm.f->off = offset;

    }

    /* munmap the relative virtual memory, yet the problem
     * is that user may only munmap a portion of an
     * mmap-ed region, but user will either unmap at the start,
     * or at the end, or the whole region. kernel can deal with
     * these situations one by one
     */

    if(vm.st == address && (vm.ed - address) == length) {
    /* unmap the whole region */

        mmap_uvmunmap(p->pagetable, PGROUNDDOWN(vm.st),
                 ((PGROUNDUP(vm.ed) - PGROUNDDOWN(vm.st))) / PGSIZE);

        /* free the resource
         * - close the open file
         * - free the struct proc array's element
         * - decrease the struct proc's nvm field
         */
        fileclose(vm.f);
        memmove(p->vm + idx, p->vm + idx + 1,
                (p->nvm - idx - 1) * sizeof(struct uvmarea));
        --p->nvm;

    }else if(vm.st == address) {
    /* unmap at the start */

        mmap_uvmunmap(p->pagetable, PGROUNDDOWN(address),
                 ((PGROUNDDOWN(address + length) - PGROUNDDOWN(vm.st))) / PGSIZE);

        /* change the struct uvmarea's st and offset field
         */
        p->vm[idx].st += length;
        p->vm[idx].offset += length;

    }else {
    /* unmap at the end */

        /* add sanity check to ensure it free the end region */
        assert((vm.ed - address) == length);

        mmap_uvmunmap(p->pagetable, PGROUNDUP(address),
                 ((PGROUNDUP(vm.ed) - PGROUNDUP(address))) / PGSIZE);

        /* change the struct uvmarea's end field */
        p->vm[idx].ed = address;

    }
    
    return 0;
}
```
这里特别需要注意的是，对于进程map的区域，其可能已经通过**page fault**分配了物理页，并添加了**PTE_U**权限；可能还没有分配物理页，并且未修改权限。因此在释放相关资源时，需要特别注意一下。

最后需要解决的，则是进程**fork()**或**exit()**后，进程map区域的变化。对于**fork()**，子进程应该拥有和父进程完全一致的map区域，这里将父进程相关的页表完全复制给子进程，并且将对应的虚拟页设置为只读，从而避免父、子进程的条件竞争(由于测试数据没有**fork()**后在写，所以并没有完全实现类似于**COW**机制)；对于**exit()**，则类似于处理**page fault**，需要注意有些虚拟页分配了物理页，并添加了**PTE_U**权限；可能还没有分配物理页，并且未修改权限
```c
// kernel/mmap.c

/* Deal with the mmap mapping regions
 * First, kernel needs to copy these mapping regions
 * and alter mapping meta data, such as increasing
 * physical memory reference.
 *
 * Second, kernel needs to remap these mapping, to
 * remove PTE_W perm, like Copy-On-Write
 *
 */
int mmap_fork(struct proc *parent, struct proc *child) {

    /* copy mapping regions */

    /* copy the struct uvmarea arrays */
    memcpy(child->vm, parent->vm, sizeof(parent->vm));
    /* copy the nvm field number */
    child->nvm = parent->nvm;
    /* copy the PTE and alter meta data */
    for(int i = 0; i < parent->nvm; ++i) {

        /* copy the PTE */
        if(mmap_uvmcopy(parent->pagetable, child->pagetable, 
                        parent->vm[i].st,
                        parent->vm[i].ed - parent->vm[i].st) != 0) {
            while(--i >= 0) {
                mmap_uvmunmap(child->pagetable, PGROUNDDOWN(parent->vm[i].st),
                              (PGROUNDUP(parent->vm[i].ed) -
                               PGROUNDDOWN(parent->vm[i].st)) / PGSIZE);
                fileclose(parent->vm[i].f);
            }
            return -1;
        }

        /* increase the file reference*/
        filedup(parent->vm[i].f);
    }


    /* remove all mmap mapping region PTE_W perm to avoid race-condition */
    for(int i = 0; i < parent->nvm; ++i) {

        mmap_uvmrdonly(parent->pagetable, child->pagetable,
                       parent->vm[i].st,
                       parent->vm[i].ed - parent->vm[i].st);

    }

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

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  /* handle mmap mappings */
  if(mmap_fork(p, np) != 0) {

    iput(np->cwd); 
    for(i = 0; i < NOFILE; i++)
      if(np->ofile[i])
        fileclose(np->ofile[i]);

    freeproc(np);
    release(&np->lock);
    return -1;
  }

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  np->state = RUNNABLE;

  release(&np->lock);

  return pid;
}

// kernel/mmap.c

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;

  /* free the mmap mapping region */
  for(int i = 0; i < p->nvm; ++i)
    mmap_uvmunmap(p->pagetable, p->vm[i].st,
                  (p->vm[i].ed - p->vm[i].st) / PGSIZE);
  memset(p->vm, 0, sizeof(struct uvmarea) * p->nvm);
  p->nvm = 0;

  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
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

## 结果

执行如下命令，完成实验测试
```bash
make grade
```
![mmap实验结果](mmap实验结果.png)