---
title: xv6-九
date: 2022-09-02 09:59:45
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客研究**xv6**的**文件系统**机制

# 文件系统总览

文件系统是用来管理**持久型**数据的子系统。
由于其需要解决很多问题，所以其抽象层次非常复杂，如下所示
![文件系统抽象层次](fs.png)

另一方面，文件系统也被称为**on-disk data structure**，其需要在磁盘中以一定的数据结构进行组织，从而可以让操作系统高效的将文件系统**导出到**磁盘或从**磁盘**导入到内存中，如下所示
![磁盘数据布局](disk.png)

## Disk Layer

### 设计

**Disk Layer**用于抽象对磁盘的读写
一般情况下，操作系统通过对磁盘的端口寄存器进行读写，从而完成对磁盘状态的控制和数据的读写。这也就是驱动

由于现实中有各种各样的磁盘，从而需要各种各样的驱动程序。为了隐藏这些实现细节，则通过**Disk Layer**将其抽象成统一的接口，即名称相同的函数指针
在驱动初始化时，将这些指针覆盖为驱动自己的函数。之后调用这些统一的接口，则相当于直接调用这些驱动的函数，从而将不同的驱动实现统一为了相同的接口

### 实现

由于目前**xv6**仅仅涉及到**QEMU**的**virtio disk**设备，因此其仅仅实现了位于**kernel/virtio_disk.c**的该设备的驱动函数**virtio_disk_rw()**，并将其当做**Disk Layer**的接口

即当**xv6**需要读、写磁盘时，其会调用**virtio_disk_rw()**函数完成

## Buffer Cache Layer

### 设计

由于磁盘读、写速度相比较内存访问慢很多，因此操作系统会缓存频繁访问的磁盘的**block**，从而避免每次重新从磁盘中缓慢的读取数据

而为了保证正确性，操作系统需要确保任何时候，操作系统中任何磁盘的**block**有至多一个**cache**；任何一个**block**的**cache**同时被至多一个进程访问。这些可以通过{% post_link xv6-八 %}介绍的**锁机制**实现

一般情况下，操作系统中使用**固定数量**的**buffer**来缓存磁盘的**block**。当操作系统访问不在**cache**中的**block**时，其可能需要覆盖掉其他的**buffer**。为了尽可能减少读取磁盘的次数，每次选择覆盖掉**Least Recently Used**的**buffer**进行覆盖，因为一般**Least Recently Used**的**buffer**，也是最不可能再被重复使用的**buffer**

### 实现

#### 结构体

**xv6**使用位于**kernel/buf.h**的**struct buf**结构体表示每一个**buffer**，如下所示
```c
// kernel/fs.h
#define BSIZE 1024  // block size

// kernel/buf.h
struct buf {
  int valid;   // has data been read from disk?
  int disk;    // does disk "own" buf?
  uint dev;
  uint blockno;
  struct sleeplock lock;
  uint refcnt;
  struct buf *prev; // LRU cache list
  struct buf *next;
  uchar data[BSIZE];
};
```

**xv6**使用位于**kernel/bio.c**的**bcache**结构，抽象整个**Buffer Cache Layer**, 如下所示。
```c
// kernel/bio.c
struct {
  struct spinlock lock;
  struct buf buf[NBUF];

  // Linked list of all buffers, through prev/next.
  // Sorted by how recently the buffer was used.
  // head.next is most recent, head.prev is least.
  struct buf head;
} bcache;
```

其中，**xv6**将**Buffer Cache Layer**中所有**buffer**通过静态数组的形式定义，并通过**buffer**的**prev**字段和**next**字段组织成双向链表。其中**bcache.head**的**next**方向是**Less Recently Used**的**buffer**(即**bcache.head.next**是**Most Recently Used**)；而**prev**恰恰相反，是**More Recently Used**(即**bcache.head.prev**是**Least Recently Used**)

#### bget()

**Buffer Cache Layer**中最重要的两个函数就是位于**kernel/bio.c**的**bget()**和**brelse()**

其中，**bget()**，顾名思义，会从**Buffer Cache Layer**中申请一个指定设备的指定**block**的**buffer**。这里有几点需要特别注意
1. 当前待缓存的**block**，可能已经在**Buffer Cache Layer**中被缓存；或者在被释放的某个**buffer**，其仍然保留该**block**的缓存数据，未被清除。为了尽可能减少磁盘读取次数，则优先返回这些**buffer**，并使用其上的数据即可。由于当前访问的**block**，往往之前也会被访问，则基于**Least Recently Used**算法，从**bcache.head.next**(即**Most Recently Used**)，沿着**next**方向(即**Less Recently Used**)遍历即可
2. 当申请到**buffer**后，再返回前需要获取锁，从而确保任何时候任何**buffer**，仅会被至多一个进程操作。如果有多个进程操作，可能会出现一个进程写；另一个进程读的情况，从而导致数据不一致

#### brelse()

**brelse()**，当**xv6**使用完**buffer**后，则**xv6**需要调用此函数释放**buffer**

为了实现减少磁盘的读、写，这里释放**buffer**时，需要注意如下几点：
1. 释放**buffer**时，仅仅释放获取的**lock**和**计数引用**，其余诸如设备号、块号和块内容等不能清除，因为后续可能会快被重新使用
2. 考虑到当前访问的块，很可能马上被继续访问，则将当前**buffer**移动到**bcache.head.next**位置(即**Most Recently Used**)，从而方便**bget()**复用这些数据

#### bread()/bwrite()

这里的逻辑很简单，通过**Device Layer**的**virtio_disk_rw()**，即可将磁盘的数据读入**buffer**；或将**buffer**中的数据写到磁盘中即可

需要注意的是，为了确保任何时候任何**buffer**被至多一个进程访问，其需要在上锁的情况下调用**virtio_disk_rw()**

## Logging Layer

### 设计

**Logging Layer**用于文件系统的**Crash Recovery**

在文件系统进行一系列的磁盘写入工作时，崩溃(如突然断电等)的发生会导致磁盘数据的不一致。操作系统往往会通过**Logging Layer**来解决这类问题

在正式进行磁盘的写入工作前，操作系统现将计划要写入的数据以**log**的形式写入磁盘中。当所有的**log**都成功写入后，再向磁盘中写入一个特殊的**commit**记录，表示当前**log**成功写入。之后开始正式的磁盘写入工作，当操作系统完成所有的磁盘写入工作后，操作系统会清除掉瓷盘中的**log**，表示本次写入的完成

通过**Logging Layer**，即使发生**Crash**，在每次操作系统重启时，也能恢复文件系统的一致性。更具体地说，如果重启后，磁盘中存在特殊的**commit**，则根据保存的**log**，重新执行磁盘的**写入**工作。对于其余的情况，则操作系统认为要么写入工作还没开始，要么已经成功完成，并不会导致磁盘的非一致性错误，则无需处理

### 实现

#### 结构体

**xv6**使用位于**kernel/buf.c**的**struct log**来描述**Logging Layer**，如下所示
```c
// The log is a physical re-do log containing disk blocks.
// The on-disk log format:
//   header block, containing block #s for block A, B, C, ...
//   block A
//   block B
//   block C
//   ...
// Log appends are synchronous.

// Contents of the header block, used for both the on-disk header block
// and to keep track in memory of logged block# before commit.
struct logheader {
  int n;
  int block[LOGSIZE];
};

struct log {
  struct spinlock lock;
  int start;
  int size;
  int outstanding; // how many FS sys calls are executing.
  int committing;  // in commit(), please wait.
  int dev;
  struct logheader lh;
};
struct log log;
```

这里需要特别注意的是，由于文件系统需要在内存或磁盘上导出或加载。因此文件系统的**on-disk**结构和**in-memory**结构有极大的关联性，但是往往也有较大的不一致。因为**in-memory**结构除了需要包含**on-disk**的数据，还需要包含一些运算所需要的数据结构，诸如**spinlock**等的结构会出现在**in-memory**结构，而不会出现在**on-disk**结构中

#### begin_op()

在**xv6**的**Logging Layer**中，**log**的典型用法如下所示
```c
begin_op();
...
bp = bread(...);
bp->data[...] = ...;
log_write(bp);
...
end_op();
```

顾名思义，位于**kernel/log.c**的**begin_op()**函数表示写磁盘的**准备操作**

**begin_op()**需要在**Logging Layer**中申请**log**空间。为此，其需要获取相关的自旋锁，从而互斥的判断相关字段即可

这里需要特别说明的是，**begin_op()**和**end_op()**之间因当包含完整的**写操作**，即仅仅执行这些操作，仍然能保持磁盘数据的一致性。如果一次要写入的数据特别多，则应该拆分成诸如**kernel/file.c**的**filewrite()**的多个**“原子”写操作**

#### log_write()

位于**kenel/log.c**的**log_write()**函数，将在正式执行**写磁盘**操作前，将要更新的**block**序号，写入到相关的**in-memory**的**log**数据中

这里需要特别注意的是，**log_write()**需要调用**bpin()**，增加相关**block**序号的**buffer**的引用计数，从而避免其被后续**brelse()**释放**buffer()**，导致更新内容丢失

#### end_op()

顾名思义，位于**kernel/log.c**的**end_op()**函数表示完成**log**的写入，将正式开始**写磁盘**操作

而**写磁盘**操作也分为以下几部分
1. 将此次**写磁盘**涉及的**block**数据(**buffer**中的更新数据)写入到磁盘的**log**部分
2. 将当前的**in-memory**的**log**对象(主要是**log header**数据)写入到**on-disk**的**log**对象中。这也是前面提到的特殊的**commit**内容
3. 将此次**写磁盘**涉及的**block**数据(**buffer**中的更新数据)写入到磁盘的**data**部分
4. 清空**in-memory**的**log header**，并将其写入到**on-disk**的**log**对象，彻底完成一次**写磁盘**操作

## Inode Layer

### 设计

**Inode Layer**用来抽象文件系统中的**文件项**

正如前面所说的，文件系统的部分抽象层，往往包括**in-memory**表示和**on-disk**表示，而且**in-memory**表示往往比**on-disk**表示多了一些操作所需要的必须的数据结构,**Inode Layer**也不例外。对于**on-disk**的**inode**，其是描述一个文件或目录的大小和**data block**信息的数据结构；对于**in-memory**的**inode**，其就是**on-disk**的**inode**的拷贝，并且附带前面所说的内核所需要的必要结构信息

这里需要特别说明，为了减少磁盘读、写从而提高性能，操作系统会缓存**inode**，类似于**Buffer Cache Layer**——即释放**inode**时，仅仅减少该结构的引用计数，直到引用计数为0才最终释放**inode**

### 实现

#### 结构体

**xv6**使用位于**kernel/fs.h**的**struct dinode**描述**on-disk**的**inode**；使用位于**kernel/file.h**的**struct inode**描述**in-memory**的**inode**，如下所示
```c
// kernel/fs.h
// On-disk inode structure
struct dinode {
  short type;           // File type
  short major;          // Major device number (T_DEVICE only)
  short minor;          // Minor device number (T_DEVICE only)
  short nlink;          // Number of links to inode in file system
  uint size;            // Size of file (bytes)
  uint addrs[NDIRECT+1];   // Data block addresses
};

// kernel/file.h
// in-memory copy of an inode
struct inode {
  uint dev;           // Device number
  uint inum;          // Inode number
  int ref;            // Reference count
  struct sleeplock lock; // protects everything below here
  int valid;          // inode has been read from disk?

  short type;         // copy of disk inode
  short major;
  short minor;
  short nlink;
  uint size;
  uint addrs[NDIRECT+1];
};
```

这里在特别分析一下**inode**如何表示**文件/目录项**，如下图所示
![inode示意图](inode.png)。其数据在**addrss1-address12**和**indirect**所指向的**data block**中，但是存储的都是**block**块号，需要在具体的转换为**block**中数据才行

而**xv6**使用位于**kernel/fs.c**的**icache**结构描述**inode**缓冲，如下所示
```c
struct {
  struct spinlock lock;
  struct inode inode[NINODE];
} icache;
```

#### iget()

在**xv6**中，**Inode Layer**的经典用法如下所示
```c
ip = iget(dev, inum)
ilock(ip)
... example and modify ip->XXX ...
iunlock(ip)
iput(ip)
```

**xv6**使用位于**kernel/fs.c**的**iget()**函数，在**inode**缓冲中分配对应的**inode**

根据前面的分析，如果该**inode**已经被缓存，则添加**引用计数ref**即可；否则找到可以覆盖的**inode**缓冲，并初始化即可

需要特别注意的是，在**iget()**函数中并不会实际载入磁盘中的数据，仅仅初始化**in-memory**的**inode**中必要的数据结构而已

#### ilock()

**xv6**使用位于**kernel/fs.c**的**ilock()**函数，从而方便进程互斥的访问**inode**。一般当进程需要上锁时，则表明需要读、写资源，也就是进程会访问或更改**inode**数据，因此这里会将**inode**的**on-disk**数据加载到内存中，方便后续的操作

需要说明的是，这里仅仅加载**inode**的**控制信息**和部分**数据信息**，**inode**的所有数据信息都会通过**bmap()**函数，获取数据对应的**block**号，在使用**bget()**进行访问即可

#### iput()

**xv6**使用位于**kernel/fs.c**的**iput()**函数，释放**inode**，即减少**inode**的引用计数即可

需要特别注意的是，当**inode**的引用计数为0时，则表明此时对于**inode**表示的文件或目录操作结束，此时应当判断一下该文件是否应该被删除，即判断**nlink**字段是否为0，从而完成相关的删除操作即可

## Directory Layer

### 设计

**Directory Layer**是用来抽象文件系统中的目录

实际上，目录就是一种特殊的文件——其内容就是一系列的**目录项**序列

一般来说，每一个**目录项**包含目录项的名称和目录项指向的文件**inode**的**block**块号，从而可以很好的抽象目录

### 实现

#### 结构

正如前面分析的，**目录**是一种**特殊**的**文件**，所以**xv6**也使用位于**kernel/fs.h**的**struct dinode**和位于**kernel/file.h**的**struct inode**进行描述

但由于**目录**中的数据内容都是**目录项**，**xv6**使用位于**kernel/fs.h**的**struct dirent**描述**目录项**

#### dirlookup()

**Directory Layer**中最重要的，即在**目录**中找到对应的**目录项**。**xv6**使用位于**kernel/fs.c**的**dirlookup()**来实现该功能

其逻辑也很简单，也就是以**目录项**的格式，依次遍历当前**目录**数据即可

## Pathname Layer

### 设计

**Pathname Layer**用来将**human-friendly**的路径，转换为**Machine-friendly**的**Inode Layer**的**Inode**

在直白一些，就是将**树状**文件系统，转换为**on-disk**文件系统。操作系统通过迭代查找**目录**，从而将**路径信息**转换为对应的**inode**，方便后续操作

### 实现

#### namex()

正如前面分析的，**Pathname Layer**主要就是通过迭代目录，从而转化为对应文件的**inode**

**xv6**通过**namex()**，非常精巧的实现了该要求。其**namex()**函数的定义就非常巧妙，如下所示
```c
// Look up and return the inode for a path name.
// If parent != 0, return the inode for the parent and copy the final
// path element into name, which must have room for DIRSIZ bytes.
// Must be called inside a transaction since it calls iput().
static struct inode*
namex(char *path, int nameiparent, char *name)
```

即如果要查找父目录，则**namex()**返回父目录的**inode**，而**name**则被设置为剩余的路径元素信息，方便后续的文件查找；如果要查找的是该文件，则**namex()**直接返回该文件的**inode**，而**name**则被设置为**NULL**

这个**API**极大的拓展了**Pathname Layer**的灵活性，其实现也非常巧妙，特别是**skipelem()**的实现，如下所示
```c
// kernel/fs.c

// Copy the next path element from path into name.
// Return a pointer to the element following the copied one.
// The returned path has no leading slashes,
// so the caller can check *path=='\0' to see if the name is the last one.
// If no name to remove, return 0.
//
// Examples:
//   skipelem("a/bb/c", name) = "bb/c", setting name = "a"
//   skipelem("///a//bb", name) = "bb", setting name = "a"
//   skipelem("a", name) = "", setting name = "a"
//   skipelem("", name) = skipelem("////", name) = 0
//
static char*
skipelem(char *path, char *name)
{
  char *s;
  int len;

  while(*path == '/')
    path++;
  if(*path == 0)
    return 0;
  s = path;
  while(*path != '/' && *path != 0)
    path++;
  len = path - s;
  if(len >= DIRSIZ)
    memmove(name, s, DIRSIZ);
  else {
    memmove(name, s, len);
    name[len] = 0;
  }
  while(*path == '/')
    path++;
  return path;
}

// Look up and return the inode for a path name.
// If parent != 0, return the inode for the parent and copy the final
// path element into name, which must have room for DIRSIZ bytes.
// Must be called inside a transaction since it calls iput().
static struct inode*
namex(char *path, int nameiparent, char *name)
{
  struct inode *ip, *next;

  if(*path == '/')
    ip = iget(ROOTDEV, ROOTINO);
  else
    ip = idup(myproc()->cwd);

  while((path = skipelem(path, name)) != 0){
    ilock(ip);
    if(ip->type != T_DIR){
      iunlockput(ip);
      return 0;
    }
    if(nameiparent && *path == '\0'){
      // Stop one level early.
      iunlock(ip);
      return ip;
    }
    if((next = dirlookup(ip, name, 0)) == 0){
      iunlockput(ip);
      return 0;
    }
    iunlockput(ip);
    ip = next;
  }
  if(nameiparent){
    iput(ip);
    return 0;
  }
  return ip;
}
```

即**skipelem()**在迭代路径时，提供了一次迭代所需要的充足信息，所以实现的逻辑非常清晰和优雅，值得好好学习!

## File Descriptor Layer

### 设计

**File Descriptor Layer**用来将操作系统的各种资源(例如**pipes**、**devies**等)抽象为统一的系统接口——**File Descriptor**

操作系统一般会给每个进程一个独立的打开文件表，其中每一个都是资源(例如**inode**、**device**等)的包装。而这些打开文件表的表项，都被操作系统全局的文件表维护

### 实现

#### 结构

**xv6**使用位于**kernel/file.h**的**struct file**描述**File Descriptor**接口，使用位于**kernel/proc.h**的**proc->ofile**描述进程的打开文件，使用位于**kernel/file.c**的**ftable**描述操作系统中所有的打开文件，如下所示
```c
// kernel/file.h

struct file {
  enum { FD_NONE, FD_PIPE, FD_INODE, FD_DEVICE } type;
  int ref; // reference count
  char readable;
  char writable;
  struct pipe *pipe; // FD_PIPE
  struct inode *ip;  // FD_INODE and FD_DEVICE
  uint off;          // FD_INODE
  short major;       // FD_DEVICE
};

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
};

// kernel/file.c

struct {
  struct spinlock lock;
  struct file file[NFILE];
} ftable;
```

# Lab file system

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/fs.html)用来加深对于**xv6**的**文件系统**机制的理解

## Large files

### 要求

> Modify **bmap()** so that it implements a doubly-indirect block, in addition to direct blocks and a singly-indirect block. You'll have to have only 11 direct blocks, rather than 12, to make room for your new doubly-indirect block; you're not allowed to change the size of an on-disk inode. The first 11 elements of **ip->addrs[]** should be direct blocks; the 12th should be a singly-indirect block (just like the current one); the 13th should be your new doubly-indirect block. You are done with this exercise when **bigfile** writes 65803 blocks and **usertests** runs successfully: 

### 分析

如果要添加**inode**的**doubly-indirect block**的支持，则参考下图，更改所有涉及**inode**的**data block**的数据结构和操作即可
![inode示意图](inode.png)

总的来说，涉及到**inode**的**data block**细节的，只有**on-disk**的**struct dinode**结构和**in-memory**的**struct inode**，相关的宏以及获取**data block**块号的**bmap()**和清空**data block**的**itrunc()**

### 实现

首先，我们将**inode**的**data block**布局，更改为**11**个**direct block**、**1**个**indirect block**和**1**个**doubly indirect block**，即更改**struct dinode**和**struct inode**的**arrays**字段，如下所示
```c
// kernel/fs.h

#define NDIRECT     11                                //Number of direct data block
#define NINDE       1                                 //Number of indirect data entries
#define NBPIND      (BSIZE / sizeof(uint))            //Number of data block per indirect entry
#define NINDIRECT   (NINDE * NBPIND)
#define NDINDE      1                                 //Number of doubly indirect data enties
#define NINDEPDIND  (BSIZE / sizeof(uint))            //Number of indirect data entries per doubly indirect entry
#define NBPDIND     (NINDEPDIND * NBPIND)             //Number of data block per doubly indirect entry
#define NDINDIRECT  (NDINDE * NBPDIND)
#define MAXFILE     (NDIRECT + NINDIRECT + NDINDIRECT)

// On-disk inode structure
struct dinode {
  short type;           // File type
  short major;          // Major device number (T_DEVICE only)
  short minor;          // Minor device number (T_DEVICE only)
  short nlink;          // Number of links to inode in file system
  uint size;            // Size of file (bytes)
  uint addrs[NDIRECT+NINDE+NDINDE];   // Data block addresses
};


// kernel/file.h
// in-memory copy of an inode
struct inode {
  uint dev;           // Device number
  uint inum;          // Inode number
  int ref;            // Reference count
  struct sleeplock lock; // protects everything below here
  int valid;          // inode has been read from disk?

  short type;         // copy of disk inode
  short major;
  short minor;
  short nlink;
  uint size;
  uint addrs[NDIRECT+NINDE+NDINDE];
};
```

其次来重构**bmap()**函数，其思路非常简单——由于**inode**的**data block**按照**direct block**、**indirect block**和**doubly indirect block**顺序排列，可以简单理解为将一维数组的下标解析为三维数组的坐标

对于**direct block**，其**arrays**数组中存储的就是**data block**的块号，则直接返回即可；对于**indirect block**，其**arrays**数组中存储的是**direct block**的块号，还需要再载入**direct block**块这一个步骤；类似的，对于**doubly indirect block**，其**arrays**数组中存储的时**indirect block**块号，还需要再载入**indirect block**、接着载入**direct block**块两个步骤，如下所示
```c
// kernel/fs.c

// Return the disk block address of the nth block in inode ip.
// If there is no such block, bmap allocates one.
static uint
bmap(struct inode *ip, uint bn)
{
  uint addr, *a;
  struct buf *bp;

  if(bn < NDIRECT){
    if((addr = ip->addrs[bn]) == 0)
      ip->addrs[bn] = addr = balloc(ip->dev);
    return addr;
  }
  bn -= NDIRECT;

  if(bn < NINDIRECT){
    // Load indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT+bn/NBPIND]) == 0)
      ip->addrs[NDIRECT+bn/NBPIND] = addr = balloc(ip->dev);

    bn %= NBPIND;
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn]) == 0){
      a[bn] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    return addr;
  }
  bn -= NINDIRECT;

  if(bn < NDINDIRECT){
    // Load doubly indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT+NINDE+bn/NBPDIND]) == 0)
      ip->addrs[NDIRECT+NINDE+bn/NBPDIND] = addr = balloc(ip->dev);

    // Load indirect block, allocating if necessary.
    bn %= NBPDIND;
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn/NBPIND]) == 0){
      a[bn/NBPIND] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);

    bn %= NBPIND;
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn]) == 0){
      a[bn] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    return addr;
  }

  panic("bmap: out of range");
}
```

最后则是重构**itrunc()**，其依次遍历**inode**的**direct block**、**indirect block**和**doubly indirect block**，将这些**block**和这些block包含的**data block**通过**bfree()**释放掉即可，如下所示
```c
// kernel/fs.c

// Truncate inode (discard contents).
// Caller must hold ip->lock.
void
itrunc(struct inode *ip)
{
  int i, j, k;
  struct buf *bp1, *bp2;
  uint *a1, *a2;

  // free direct data blocks
  for(i = 0; i < NDIRECT; i++){
    if(ip->addrs[i]){
      bfree(ip->dev, ip->addrs[i]);
      ip->addrs[i] = 0;
    }
  }

  // free indirect data blocks
  for(i = 0; i < NINDE; i++) {
    if(ip->addrs[NDIRECT+i]) {
      bp1 = bread(ip->dev, ip->addrs[NDIRECT+i]);
      a1 = (uint*)bp1->data;
      for(j = 0; j < NBPIND; j++) {
        if(a1[j])
          bfree(ip->dev, a1[j]);
      }
      brelse(bp1);
      bfree(ip->dev, ip->addrs[NDIRECT+i]);
      ip->addrs[NDIRECT+i] = 0;
    }
  }

  // free doubly indirect data blocks
  for(i = 0; i < NDINDE; i++) {
    if(ip->addrs[NDIRECT+NINDE+i]) {
      bp1 = bread(ip->dev, ip->addrs[NDIRECT+NINDE+i]);
      a1 = (uint*)bp1->data;
      for(j = 0; j < NINDEPDIND; j++) {
        if(a1[j]) {
          bp2 = bread(ip->dev, a1[j]);
          a2 = (uint*)bp2->data;
          for(k = 0; k < NBPIND; k++) {
            if(a2[k])
              bfree(ip->dev, a2[k]);
          }
          brelse(bp2);
          bfree(ip->dev, a1[j]);
        }
      }
      brelse(bp1);
      bfree(ip->dev, ip->addrs[NDIRECT+NINDE+i]);
      ip->addrs[NDIRECT+NINDE+i] = 0;
    }
  }

  ip->size = 0;
  iupdate(ip);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="bigfile" grade
```
![bigfile实验结果](bigfile实验结果.png)

## Symbolic links

### 要求

> You will implement the **symlink(char *target, char *path)** system call, which creates a new symbolic link at path that refers to file named by target. For further information, see the man page symlink. To test, add symlinktest to the Makefile and run it. Your solution is complete when the tests produce the following output (including usertests succeeding). 
> ```bash
$ symlinktest
Start: test symlinks
test symlinks: ok
Start: test concurrent symlinks
test concurrent symlinks: ok
$ usertests
...
ALL TESTS PASSED
$ 
```

### 分析

由于文件系统在解析**符号链接**文件时，会采用和其他文件类型完全不同的方式，因此可以添加新的文件类型即可

而为了完成**符号链接**功能，则重构系统调用中涉及文件系统的部分，添加**符号链接**类型的功能支持即可

### 实现

首先，在**xv6**中添加**symlink**系统调用，即添加相关的系统调用号和系统调用声明，如下所示
```c
// kernel/syscall.h

// System call numbers
#define SYS_symlink 22

// kernel/syscall.c
extern uint64 sys_symlink(void);

static uint64 (*syscalls[])(void) = {
  ...
[SYS_symlink] sys_symlink,
};

// user/user.h
int symlink(const char *target, const char *linkpath);

// user/usys.pl
entry("symlink");
```

其次则是实现系统调用**symlink()**，即完成必要的检查后，创建相关的**符号链接**类型的文件即可。其中根据要求，**符号链接**类型的文件内容是传入的路径字符串即可，如下所示
```c
// kernel/sysfile.c

// Create a symbol file pointing to the given path
uint64
sys_symlink(void)
{
  char target[MAXPATH], linkpath[MAXPATH];
  struct inode *ip;

  if(argstr(0, target, MAXPATH) < 0 || argstr(1, linkpath, MAXPATH) < 0)
    return -1;

  begin_op();
  if((ip = create(linkpath, T_SYMLINK, 0, 0)) == 0){
    end_op();
    return -1;
  }

  // write the target to the inode
  if(writei(ip, 0, (uint64)target, 0, MAXPATH) != MAXPATH)
    panic("symlink: writei");

  iunlockput(ip);
  end_op();

  return 0;
}
```

下面则是添加**符号链接**的操作。实际上，**符号链接**的作用，就是路径替换，即解析该**符号链接**时，相当于解析其替换的文件。在具体一些，在**xv6**中，即解析其替换的文件的**inode**。因此，可以通过更改**open**系统调用，返回其实际指向的文件的**inode**即可，如下所示
```c
// kernel/sysfile.c

uint64
sys_open(void)
{
  char path[MAXPATH];
  int fd, omode, iterate;
  struct file *f;
  struct inode *ip;
  int n;

  if((n = argstr(0, path, MAXPATH)) < 0 || argint(1, &omode) < 0)
    return -1;

  begin_op();

  if(omode & O_CREATE){
    ip = create(path, T_FILE, 0, 0);
    if(ip == 0){
      end_op();
      return -1;
    }
  } else {

    if((ip = namei(path)) == 0){
      end_op();
      return -1;
    }

    ilock(ip);

    // deal with symlink file
    if((omode & O_NOFOLLOW) == 0) {
      iterate = 0;
      while(ip->type == T_SYMLINK) {
        if((readi(ip, 0, (uint64)path, 0, MAXPATH)) != MAXPATH || iterate++ >= MAXITER) {
          iunlockput(ip);
          end_op();
          return -1;
        }

        iunlockput(ip);
        if((ip = namei(path)) == 0) {
          end_op();
          return -1;
        }
        ilock(ip);
      }
    }

    if(ip->type == T_DIR && omode != O_RDONLY){
      iunlockput(ip);
      end_op();
      return -1;
    }
  }

  ...

  iunlock(ip);
  end_op();

  return fd;
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS="symlink" grade
```
![symlink实验结果](symlink实验结果.png)