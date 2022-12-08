---
title: xv6-六
date: 2022-06-14 16:39:45
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客研究**xv6**的**Copy-on-Write**机制的实现

# Lab Copy-on-Write Fork for xv6

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/cow.html)用来实现**xv6**的**Copy-on-Write**机制


## Copy-on-Write

### 要求

>  Your task is to implement **copy-on-write** **fork** in the xv6 kernel. You are done if your modified kernel executes both the cowtest and usertests programs successfully. 

### 分析

**Copy-on-Write**和**lazy allocation**非常类似，都是为了节省直接分配导致的性能损失，从而推迟实际的**physical page**的分配和映射，仅仅完成**virtual page**的分配。

其中，**Copy-on-Write**是在进程**fork**时，仅仅复制父进程的**pd**(页表)，而共享实际的**physical page**，从而节省了**physical page**的分配和内容的复制。而实际的**页框**(physical page)分配，延迟到父进程或子进程执行写操作——因为其余指令不更改内存空间数据，则共享一个**physical page**完全没问题

自然的，其实现思路也和**lazy allocation**基本一致，推迟**fork**系统调用中**physical page**的分配和映射，找到触发进程写访问的位置，并在该位置完成最终的**physical page**的分配和映射

### 实现

本次实验将进程**fork**时的申请的内存更改为**Copy-on-Write**方式，则更改**fork**系统调用的**uvmcopy**函数，该函数负责子进程内存空间的分配
```c
// kernel/vm.c
// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i, 
        mask = ~PTE_W;
  uint flags;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0)
      panic("uvmcopy: page not present");
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);

    // Copy-on-Write fork
    // So just copy the pte and mark pages
    // as no writable
    phy_page_acquire(pa);
    *pte = *pte & mask;
    if(mappages(new, i, PGSIZE, pa, flags & mask) != 0){
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}
```

可以看到，子进程仅仅复制了父进程的页表项，即共用相同的**physical page**，并更改其权限为不可读(从而可以捕获所有的写指令)
这样做有一个问题，在释放的时候可能会**double free**，从而造成极其严重的后果。因此，对于**physical page**添加引用计数机制，其机制如下所示
1. 当有虚拟地址和**physical page**映射时，该**physical page**的引用加一
2. 当释放**physical page**时，只有引用计数为1时，才将该**physical page**插入到空闲链上并将引用计数置零；否则仅仅将其引用计数减一

这样子在复用原来的代码基础上，完美的解决了**double free**问题。
```c
// kernel/kalloc.c
// physical page reference nubmer
static int refs[PGROUNDUP(PHYSTOP) / PGSIZE + 1];
#define PHYIDX(addr)  ( \
        (((uint64)addr) - (uint64)end) / PGSIZE\
        )

// try to acquire this page, so increase the physical acquire page
// reference in refs array.
uint64 phy_page_acquire(uint64 addr)
{
  uint64 val = -1;
  if(addr >= PHYSTOP)
    panic("phy_page_acquire: addr is too big\n");
  
  uint64 idx = PHYIDX(addr);
  
  acquire(&kmem.lock);
  if((val = ++refs[idx]) <= 0)
    panic("phy_page_acquire: \n");
  release(&kmem.lock);

  return val;
}

uint64 phy_page_ref(uint64 addr)
{
  uint64 val = -1;
  if(addr >= PHYSTOP)
    panic("phy_page_ref: addr is too big\n");
  
  uint64 idx = PHYIDX(addr);
  
  acquire(&kmem.lock);
  if((val = refs[idx]) < 0)
    panic("phy_page_ref: invalid val\n");
  release(&kmem.lock);

  return val;
}



// try to release this page, so decrease the physical acquire page
// reference in refs array.
static uint64
phy_page_release(uint64 addr)
{
  uint64 val = -1;
  if(addr >= PHYSTOP)
    panic("phy_page_release: addr is too big\n");
  
  uint64 idx = PHYIDX(addr);
  
  acquire(&kmem.lock);
  if((val = --refs[idx]) < 0)
    panic("phy_page_release: invalid val\n");
  release(&kmem.lock);

  return val;
}

// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // release the page only when
  // page's reference is 0
  if(phy_page_release((uint64)pa) == 0) {

    // Fill with junk to catch dangling refs.
    memset(pa, 1, PGSIZE);

    r = (struct run*)pa;

    acquire(&kmem.lock);
    r->next = kmem.freelist;
    kmem.freelist = r;
    release(&kmem.lock);

  }
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r) {
    memset((char*)r, 5, PGSIZE); // fill with junk
    phy_page_acquire((uint64)r); // add page reference
  }
  return (void*)r;
}
```

其次则是在实际触发写访存时，完成最终的**Copy-on-Write**。主要有两个位置，一个是**U-mode**下用户程序的写指令，可以通过**trap**完成捕获并处理；另一个则是**S-mode**下，内核可能向用户地址空间写入数据(如系统调用写出数据)，则可以提前处理**Copy-on-Write**
```c
// kernel/trap.c
// if it is triggered by Copy-on-Write
// just call the copy_on_write function
// to deal with it, or kernel should
// panic
static void
handle_page_fault(uint64 va)
{
  if(copy_on_write(va) != 0)
    trap_panic();
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
    ...
    switch(scause) {
      case 0xf:
        //Store page fault
        handle_page_fault(r_stval());
        break;

      default:
        trap_panic();
        break;
    }

   ...
}

// kernel/vm.c
// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);

    // walk will panic if va0 >= MAXVA,
    // unlike the walkaddr
    if(va0 >= MAXVA)
      return -1;
    pte = walk(pagetable, va0, 0);

    if(pte == 0)
      return -1;
    
    // handle copy-on-write in kernel
    if(((uint64)(*pte & PTE_W) == 0) && copy_on_write(va0) != 0)
      return -1;

    pa0 = PTE2PA(*pte);
    if(pa0 == 0)
      return -1;
    
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}
```

最后，则是实现实际的**Copy-on-Write**，其逻辑也比较简单
1. 如果当前访问的**virtual address**所在的**physical page**引用计数为1，则表示只有当前进程在使用该**physical page**，则直接添加修改为可写即可
2. 如果引用计数不为1，则完成实际的**physical page**的分配和映射即可

```c
// kernel/vm.c
// execute the Copy-on-Write
// when trigger a store page fault for
// its flags without PTE_W, then
// use Copy-on-Write
uint64 copy_on_write(uint64 va)
{
  struct proc *p = myproc();
  pte_t *pte;
  uint64 pa, new_pa, flag;
  va = PGROUNDDOWN(va);

  // access the virtual address out of
  // alloced virtual memory
  if(va >= p->sz)
    return -1;

  // if access the guard page under the stack
  // it should kill the process
  pte = walk(p->pagetable, va, 0);
  if(pte && (*pte & PTE_V) != 0 && ((*pte & PTE_U) == 0 || (*pte & PTE_W) != 0))
    return -1;
  
  pa = PTE2PA(*pte);

  if(phy_page_ref(pa) == 1) {

    // don not need alloc a new physical page
    // just change the map flag
    *pte |= PTE_W;

  }else {

    flag = PTE_FLAGS(*pte);

    // alloc a new physical page
    if((new_pa = (uint64)kalloc()) == 0)
      return -1;

    // copy the content
    // from origin memory
    // to new physical memory
    memmove((void*)new_pa, (const void*)pa, PGSIZE);

    // unmap the va
    uvmunmap(p->pagetable, va, 1, 1);

     // and remap it to relative
     // virtual address
    if(mappages(p->pagetable, va, PGSIZE, new_pa, flag | PTE_W) != 0) {
      kfree((void*)new_pa);
      return -1;
    }
  }

  return 0;
}
```

本次试验中，感悟颇多。
在写代码的过程中，除了写之前良好的构思外，**debug**能力是重中之重。一方面要学会**防御式编程**，从而在异常时方便调试；另一方面要学会定位错误实际发生的位置——根据崩溃信息，在适当的地址处下断点，并结合动态调试器中上下文信息完成调试。
比如在实现**Copy-on-Write**函数时，没有将原始**physical page**内容复制到新分配的**physical page**中，导致触发**非法指令**异常。则首先应该在**usertrap**处下断点，查看具体的异常信息，发现其调用栈中充满无效数据。由于当前仅仅实现了处理**page fault**的功能，则在**usertrap**断点处，单步跟随处理写异常的执行流，很容易发现异常处理结束后，其栈上大量的**0x05**(内存分配时填充的垃圾数据)，从而解决该bug

### 结果

执行如下命令，完成实验测试
```bash
make grade
```
![Copy-on-Write实验结果](copy_on_write实验结果.png)