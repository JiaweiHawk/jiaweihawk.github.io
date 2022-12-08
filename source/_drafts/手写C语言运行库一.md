---
title: 手写C语言运行库一
date: 2021-07-03 11:30:36
categories: "手写"
tags: ["手写","C语言运行库"]
---


# 前言

  为了加深对于**链接、装载与库**的理解，这里特别根据**《程序员的自我修养——链接、装载与库》**书中的资料，手写一个支持**C**/**C++**的运行库——**hawkCRT**/**hawkCRT++**

  总体上，我们希望**hawkCRT**具有如下的性质：
- 以**ANIS C**的标准库为目标，尽可能接口相一致
- 具有入口函数`hawk_entry`
- 具有基本的进程相关操作
- 简单支持堆操作`malloc`、`free`
- 简单支持文件操作`fopen`、`fread`、`fwrite`、`fclose`、`fflush`
- 简单支持字符串操作`strcpy`、`strlen`、`strcmp`
- 简单支持输出操作`printf`、`sprintf`
- 简单支持登记函数`atexit`
- 支持跨平台

  而对于**hawkCRT++**，我们希望具有如下性质：
- 简单支持`string`类的相关操作
- 简单支持`cout`对象的构造和析构
- 简单支持堆操作`new`、`delete`


# 跨平台

  使用宏实现源代码的跨平台——即同一个源代码可以在不同的平台上编译运行
  对于在Windows和Linux平台上代码不同的部分，通过如下结构
```c
#ifdef WIN32
  //Windows实现代码
#else
  //Linux实现代码
#endif
```

  在Linux平台下，我们使用如下编译命令生成静态运行库，避免使用标准库和内置库相关符号
```bash
$gcc -c -m32 -fno-builtin -nostdlib -fno-stack-protector hawkCRT.c malloc.c stdio.c string.c format.c

$ar -rs libhawkCRT.a hawkCRT.o malloc.o stdio.o string.o format.o
```
  使用该标准库，使用如下命令进行链接和编译，从而生成使用该运行库的可执行文件
```bash
$gcc -c -m32 -ggdb -fno-builtin -nostdlib -fno-stack-protector test.c
l
$d -m elf_i386 -static -e hawk_crt_entry test.o libhawkCRT.a -o test
```

  而对于Windows平台，我们需要传递`WIN32`的宏，因此执行如下命令，完成Windows实现代码部分的编译和运行
```bash
$cl /c /DWIN32 /GS- /utf-8 hawkCRT.c malloc.c stdio.c format.c string.c

$lib hawkCRT.obj malloc.obj stdio.obj format.obj string.obj /OUT:libhawkCRT.lib
```

  而由于Windows平台下使用了相关的系统调用，因此还生成测试文件时，需要引入一些其他库，其过程如下所示
```bash
$cl /c /DWIN32 /utf-8 test.c

$link test.obj libhawkCRT.lib kernel32.lib Advapi32.lib /NODEFAULTLIB /entry:hawk_crt_entry /OUT:test.exe
```


# 整体流程

  根据《程序员的自我修养——链接、装载与库》的分析，C程序从`_start`/`mainCRTStartup`函数开始，经历堆栈初始化、IO初始化等相关初始化过程，最终跳转到指定的入口函数

  这里我们的`hawkCRT`同样具有类似的流程，其初始函数为`hawk_crt_entry`，默认的入口函数为`hawk_main`，整体流程如下图所示
  ![C运行库整体流程](C运行库整体流程.PNG)


## 入口函数实现

  入口函数的大体框架如下所示
```c
void hawk_crt_entry(void) {
  /*
  	相关初始化代码
  */
  
  int ret = main(argc, argv);
  exit(ret);
}
```

  这里初始化代码需要完成参数初始化、堆初始化、IO初始化和参数初始化等工作



### 参数初始化

  实际上，**main**函数往往也有参数，其为`int main(int argc, char *argv[]);`。其中，其参数在命令行调用时跟在程序名称后面。当我们进入程序入口时，即`hawk_crt_entry`时，其栈布局如下所示

  ![程序初始栈结构](程序初始栈结构.PNG)

  我们将函数参数在入口处保存，之后传递给**main**即可
  对于**Windows**，调用**系统API**，即**GetCommandLineA**，依次进行解析即可
  对于**Linux**，通过获取**esp**，进行设置即可。这里需要注意的是，由于这里设置入口函数就是**hawk_ctr_entry**，因此栈中无须返回地址；但是其仍然是一个函数，因此栈中仍然包含有旧**ebp**，则**argc**位于**ebp + 4**处，**argv**位于**ebp + 8**处

### 堆初始化

  实际上对于堆初始化，即完成管理堆空间的相关数据结构的初始化。

  这里为了实现的方便，将堆大小固定为**32MB**，并使用**位图**管理堆空间，其中**1bit**对应**1024Bytes**，也就是需要**4096**个char进行管理。而每一个分配的是chunk对象，其结构如下所示
  ![chunk结构](chunk结构.PNG)

  其中，整个chunk可以由**chunk头**和**chunk体**构成。
  chunk头用于保存该chunk的大小信息，其添加了**magic**字段，由**chunkAddr**、**size**字段和系统生成的随机数异或的值构成，从而避免缓冲区溢出；而**size**字段存储的是整个chunk的字节大小。
  chunk体则是最后分配到的可使用的内存空间

  则对于堆的初始化，其步骤如下：
1. 调用系统的API，申请**32MB**的固定空间作为运行库的堆空间
2. 调用系统的API，生成**magic**字段所需要的随机数
3. 创建并初始化**位图**数据结构。需要注意的是，**位图**本身也属于堆空间，初始化的时候，**位图**所在的空间应该在**位图**中表明已被使用


  在申请堆空间时，其步骤如下：
1. 根据位图寻找足够大小的连续空闲内存
2. 设置该片内存的**magic**字段和**size**字段
3. 设置该片内存的**位图**状态
4. 返回该片内存的**returnAddr**地址，作为申请的可使用内存空间的起始值


  在释放堆空间时，其步骤如下：
1. 判断释放地址是否在有效堆空间内。即是否在申请的**32MB**内存空间中
2. 判断释放地址对应的chunk是否为有效chunk。即chunk对应的**位图**状态是否为已使用、**magic**字段是否正确
3. 重置该内存对应的**位图**状态


  堆相关的关键代码如下所示
```c
//
// Created by hawk on 7/4/21.
//

#include "hawkCRT.h"


/*
 * 用来管理堆空间的相关信息
 * 包含 起始地址、结束地址、运行生成随机值、位图  等参数
 */
#define HEAPSIZE ((unsigned int)32 * 1024 * 1024)     //堆空间 32MB
#define PERSIZE ((unsigned int)1024)                  //即分配的最小单位为1024B，也是位图中1bit管理的空间大小
#define BYTEPERBIT ((unsigned int)8)                 //1byte对应的bit个数，一般都是8
#define BITMAPSIZE ((HEAPSIZE) / BYTEPERBIT / PERSIZE)
#define SIZE_SZ ((unsigned int)(sizeof(unsigned int) / sizeof(char)))

/*
 * chunk的相关操作，方便对chunk进行各种操作
 */

// base + offset的地址值
#define MEMOFFSET(base, offset) ((void*)((unsigned char*)(base) + (unsigned int)(offset)))


/*
 * bitmap中byte从0计数，bit从0计数
 * 这里直接通过指针操作，从而可以通过宏进行设置
 */
#define BYTEGETBIT(byte, idx) ((unsigned char)(*((unsigned char*)(byte)) >> (7 - (unsigned int)(idx))) & 1)
#define BYTESETBIT(byte, idx) (*(unsigned char*)(byte) |= (1 << (7 - (idx))))
#define BYTECLEARBIT(byte, idx) (*(unsigned char*)(byte) &= ~(1 << (7 - (idx))))
#define BITMAPGETBIT(bitmap, idx) (BYTEGETBIT( ((unsigned char*)bitmap) + ((idx) / 8) , (idx) % 8))
#define BITMAPSETBIT(bitmap, idx) (BYTESETBIT( ((unsigned char*)bitmap) + ((idx) / 8) , (idx) % 8))
#define BITMAPCLEARBIT(bitmap, idx) (BYTECLEARBIT( ((unsigned char*)bitmap) + ((idx) / 8) , (idx) % 8))
#define CHUNKALLIGN (~(PERSIZE - 1))
#define ADJUSTSIZE(mem) (((unsigned int)(mem) + PERSIZE - 1 + SIZE_SZ * 2) & (CHUNKALLIGN))
#define CHUNKTOIDX(base, chunk) ((unsigned int)((unsigned int)((unsigned char*)(chunk) - (unsigned char*)(base)) / PERSIZE))
#define IDXTOCHUNK(base, idx) ((void*)((unsigned char*)(base) + ((unsigned int)(idx)) * PERSIZE))
#define MEMTOCHUNK(mem) ((void*)((unsigned char*)(mem) - (unsigned int)(SIZE_SZ * 2)))
#define CHUNKTOMEM(chunk) ((void*)((unsigned char*)(chunk) + (unsigned int)(SIZE_SZ * 2)))
#define SETCHUNKMAGIC(chunk, magic) (*(unsigned int*)(chunk) = (unsigned int)(magic))
#define SETCHUNKSIZE(chunk, size) (*(unsigned int*)((unsigned char*)(chunk) + SIZE_SZ) = (unsigned int)(size))
#define GETCHUNKMAGIC(chunk) (*(unsigned int*)(chunk))
#define GETCHUNKSIZE(chunk) (*((unsigned int*)((unsigned char*)chunk + SIZE_SZ)))



typedef struct MSTATE {
    unsigned int random;
    unsigned char bitmap[BITMAPSIZE];
} Mstate;
static Mstate *mstate = NULL;




//  申请32MB地址空间作为内存空间
static void *request_heap(void);
//  生成随机数
static unsigned int generate_random(void);
//  设置bitmap的位，用来申请堆空间
static void setbit(void *base, unsigned int size);





#ifdef WIN32
#include <Windows.h>
#endif

//  申请32MB地址空间作为内存空间
static void *request_heap(void) {

    void *heapAddr = NULL;  // 堆空间的起始地址

#ifdef WIN32
    heapAddr = VirtualAlloc(0, HEAPSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(heapAddr == NULL) { return NULL; }
#else


    /*
     * brk(0)
     * 通过调用32位的syscall，获取当前的break位置。当asm修改寄存器值时，一定添加clobber，否则可能原本寄存器包含重要的值会被覆盖
     */
    __asm__ __volatile__("movl $0x2d, %%eax\n\t"
                         "movl $0, %%ebx\n\t"
                         "int $0x80\n\t"
                         "movl %%eax, %0\n\t"
                         : "=r"(heapAddr) :: "%eax", "%ebx");



    void *heapEndAddr = MEMOFFSET(heapAddr, HEAPSIZE), *addr = heapAddr;



    /*
     * brk(heapEndArrd)
     * 继续调用32位的syscall，重新设置break的位置，从而这段空间作为堆空间
     */
    __asm__ __volatile__("movl $0x2d, %%eax\n\t"
                         "movl %1, %%ebx\n\t"
                         "int $0x80\n\t"
                         "movl %%eax, %0\n\t"
                         : "=r"(addr) : "r"(heapEndAddr) : "%eax", "%ebx");

    if(addr != heapEndAddr) { return NULL; }
#endif

    return heapAddr;
}


//  生成随机数
static unsigned int generate_random(void) {
    unsigned int random = 0;
#ifdef WIN32
    HCRYPTPROV hCryptProv;
    CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
    CryptGenRandom(hCryptProv, 4, (BYTE*)(&random));
#else

    /*
     * fd = open("/dev/random", "r")
     * 调用32位的syscall，打开文件，"r"用0表示
     */
    unsigned char *file = "/dev/random";
    unsigned int fd = -1, flag = O_RDONLY;
    __asm__ __volatile__("movl $0x5, %%eax\n\t"
                         "movl %1, %%ebx\n\t"
                         "movl %2, %%ecx\n\t"
                         "int $0x80\n\t"
                         "movl %%eax, %0\n\t"
    : "=r"(fd) : "r"(file), "r"(flag) : "%eax", "%ebx", "%ecx");

    /*
     * read(fd, &random, 4)
     * 调用32位的syscall，读取数据到random值中
     */
    __asm__ __volatile__("movl $0x3, %%eax\n\t"
                         "movl %0, %%ebx\n\t"
                         "movl %1, %%ecx\n\t"
                         "movl $4, %%edx\n\t"
                         "int $0x80\n\t"
    :: "r"(fd), "r"(&random) : "%eax", "%ebx", "%ecx", "%edx");


    /*
     * close(fd)
     * 调用32位的syscall，关闭文件
     */
    __asm__ __volatile__("movl $0x6, %%eax\n\t"
                         "movl %0, %%ebx\n\t"
                         "int $0x80\n\t"
    :: "r"(fd): "%eax", "%ebx");
#endif

    return random;
}


//  设置bitmap的位，用来申请堆空间
static void setbit(void *base, unsigned int size) {
    unsigned int idx = CHUNKTOIDX(mstate, base);


    if(size + idx >= HEAPSIZE) { return; }
    for(unsigned int i = 0; i < size; ++i) { BITMAPSETBIT(mstate->bitmap, idx + i); }
}



//  申请堆空间
void *malloc(unsigned int size) {
    size = ADJUSTSIZE(size) / PERSIZE;
    for(int i = size; i <= HEAPSIZE; ++i) {
        int j = i - size;
        for(; j < i; ++j) {
            if(BITMAPGETBIT(mstate->bitmap, j) != 0) { break; }
        }

        if(j < i) { continue; }

        void *chunk = IDXTOCHUNK(mstate, i - size);
        SETCHUNKMAGIC(chunk, mstate->random);
        SETCHUNKSIZE(chunk, size * PERSIZE);
        setbit(chunk, size);

        return CHUNKTOMEM(chunk);
    }

    return NULL;
}



//释放堆空间
void free(void *mem) {
    void *chunk = MEMTOCHUNK(mem);

    int idx = CHUNKTOIDX(mstate, chunk), size = GETCHUNKSIZE(chunk) / PERSIZE;
    for(int i = 0; i < size; ++i) { BITMAPCLEARBIT(mstate->bitmap, idx + i); }
}


//  初始化堆空间，包括申请堆地址空间，完成相关的数据结构初始化
void hawk_crt_heap_init(void) {

    void *heapBase = request_heap();


    // 起始位置为 Mstate 结构，用来保存相关的信息
    mstate = (Mstate *)heapBase;
    mstate->random = generate_random();
    setbit(mstate, ADJUSTSIZE(sizeof(Mstate) / sizeof(unsigned char)) / PERSIZE);
}
```


### IO初始化

  这里为了实现方便，仅仅包含基本的文件操作功能，实现简单的缓冲功能，因此整个IO部分实现起来的思路就很简单——简单包装相关的**文件句柄/文件描述符**，并根据这些信息，调用系统提供的API，实现相关的IO操作。其中包装的**文件句柄/文件描述符**基本结构如下

  ![FILE结构](FILE结构.PNG) 

在打开文件时，其步骤如下：
1. 调用**系统API**，即**CreateFileA**/**open**，返回相关的**HANDLE**/**File Descriptro**
2. 根据传递的参数和系统API返回值，生成上面的**FILE**结构



在文件写入数据时，其步骤如下：
1. 如果相关的**FILE**结构中缓冲已满，则调用**系统API**，即**WriteFile**/**write**，清空缓冲至文件并重新设置缓冲
2. 将数据保存至**FILE**结构的缓冲中，数据大小为待写入数据大小和缓冲区大小的最小值。如果这一步未将待写入数据处理完，则截取未完成的待写入数据，并重新从1. 开始


这里由于文件写入数据时会先写入缓冲区中，再等缓冲区满才写入文件中，因此需要刷新缓冲区数据至文件，其步骤如下：
1. 检查**FILE**结构中**flag**字段，确保是写入类型的
2. 直接调用**系统API**，即**WriteFile**/**write**，将相关**FILE**结构中的缓冲区数据全部写入文件


从文件读入数据时，其步骤如下：
1. 如果相关的**FILE**结构中缓冲已空，则调用**系统API**，即**ReadFile**/**read**，读取数据到缓冲区。这里将数据从缓冲区中间开始放置，方便后面格式化字符串回退字符时重新放置入缓冲区中。
2. 将**FILE**结构的缓冲区数据保存至待读入空间中，其保存的数据量为待读入数据和缓冲区数据的最小值。如果这一步保存的数据量小于待读入的数据量，则重新从1. 开始


最后，关闭已打开的文件，其步骤如下：
1. 如果相关的**FILE**结构是写入类型的，调用前面的刷新缓冲区功能，确保所有数据已经写入文件
2. 根据相关的**FILE**结构，调用**系统API**，即**CloseHandle**/**close**，完成文件的关闭


而对于IO的初始化，其主要是将系统默认打开的**标准输入**、**标准输出**和**标准错误输出**文件包装为相关的**FILE**结构即可
```c
//
// Created by hawk on 7/4/21.
//

#include "hawkCRT.h"

#define BUFSIZE (0x300)





#ifdef WIN32
#include <Windows.h>
//  生成包装的文件描述副
static FILE *generate_file_descriptor(HANDLE fd, unsigned  int flag) {
#else
//  生成包装的文件描述副
static FILE *generate_file_descriptor(unsigned int fd, unsigned int flag) {
#endif


    FILE *file = (FILE*)malloc(sizeof(FILE) + BUFSIZE);
    file->fd = (unsigned int)fd;
    file->buf = (unsigned char*)file + BUFSIZE;
    file->bufAvailable = file->bufUnavailable = 0;
    file->bufSize = BUFSIZE;
    file->flag = flag;

    return file;
}


//  指定权限打开文件
FILE *fopen(const char *filename, const char *mode) {
    unsigned int flag = 0;

#ifdef WIN32
    HANDLE fd = 0;

    if(compare(mode, "r") == 0) {
        flag |= O_RDONLY;
        fd = CreateFileA(filename, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    }else if(compare(mode, "w") == 0) {
        flag |= O_WRONLY;
        fd = CreateFileA(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    }

    if(fd == INVALID_HANDLE_VALUE) { return NULL; }
#else
    int fd = 0;

    if(compare(mode, "r") == 0) {
        flag |= O_RDONLY;
        __asm__ __volatile__("movl $0x5, %%eax\n\t"
                             "movl %1, %%ebx\n\t"
                             "movl %2, %%ecx\n\t"
                             "int $0x80\n\t"
                             "movl %%eax, %0\n\t"
        : "=r"(fd) : "r"(filename), "r"(O_RDONLY) : "%eax", "%ebx", "%ecx", "%edx");
    }else if(compare(mode, "w") == 0) {
        flag |= O_WRONLY ;
        int access = 00700;
        __asm__ __volatile__("movl $0x5, %%eax\n\t"
                             "movl %1, %%ebx\n\t"
                             "movl %2, %%ecx\n\t"
                             "movl %3, %%edx\n\t"
                             "int $0x80\n\t"
                             "movl %%eax, %0\n\t"
        : "=r"(fd) : "r"(filename), "r"(O_WRONLY | O_CREAT | O_TRUNC), "g"(access) : "%eax", "%ebx", "%ecx", "%edx");
    }

    if(fd < 0) { return NULL; }
#endif


    return generate_file_descriptor(fd, flag);
}



//  关闭打开的文件，并释放相关资源
int fclose(FILE *file) {
    if(file == NULL) { return 1; }

    if(file->flag == O_WRONLY) { fflush(file); }

#ifdef WIN32
    int res = CloseHandle((HANDLE)file->fd);
    if(res == 0) { return FCLOSE_ERROR; }
#else
    int res = 0;
    __asm__ __volatile__("movl $0x6, %%eax\n\t"
                         "movl %1, %%ebx\n\t"
                         "int $0x80\n\t"
                         "movl %%eax, %0\n\t"
    : "=r"(res): "r"(file->fd): "%eax", "%ebx");
    if(res != 0) { return FCLOSE_ERROR; }
#endif


    free(file);
    return 0;
}


/*
 * 如果当前缓冲区为空，则读取半满，为了后面格式化字符串读取回退方便
 *
 * 如果当前缓冲区非空，则读取MIN(size， 缓冲区可用大小)的内容
 *
 * 如果返回值为-1，表示无输入；否则可以继续调用fread_from_buf
 */
static int fread_from_buf(void *dst, int size, FILE *stream) {
    if(stream->bufAvailable == stream->bufUnavailable) {
        stream->bufAvailable = stream->bufUnavailable = stream->bufSize / 2;

        int read_size = 0;
#ifdef WIN32
        ReadFile((HANDLE)stream->fd, stream->buf + stream->bufAvailable, stream->bufSize - stream->bufUnavailable, &read_size, 0);
        if(!read_size) { return -1;}
#else
        __asm__ __volatile__("movl $0x3, %%eax\n\t"
                             "movl %1, %%ebx\n\t"
                             "movl %2, %%ecx\n\t"
                             "movl %3, %%edx\n\t"
                             "int $0x80\n\t"
                             "movl %%eax, %0\n\t"
        : "=r"(read_size): "r"(stream->fd), "r"(stream->buf + stream->bufAvailable), "g"(stream->bufSize - stream->bufUnavailable) : "%eax", "%ebx", "%ecx", "%edx");

        if(!read_size) { return -1; }
#endif

        stream->bufUnavailable += read_size;
    }

    int buf_size = stream->bufUnavailable - stream->bufAvailable;
    int read_size = buf_size < size ? buf_size : size;

    for(int i = 0; i < read_size; ++i) { ((unsigned char*)dst)[i] = stream->buf[stream->bufAvailable++]; }
    return read_size;
}


//  从文件中读取数据， 返回读取到的字节个数
int fread(void *dst, int size, int count, FILE *stream) {
    if(size <= 0 || count <= 0 || stream == NULL || stream->flag != O_RDONLY) { return 0; }

    int read_size = 0, need_size = size * count;
    while(need_size) {
        int read_from_buf_size = fread_from_buf((unsigned char*)dst + read_size, need_size, stream);
        if(read_from_buf_size < 0) { break; }

        read_size += read_from_buf_size;
        need_size -= read_from_buf_size;
    }

    return read_size;
}





/*
 * [0, stream->bufAvailable)表示已经写入文件中的数据，[stream->bufAvailable, stream->bufUnavailable)表示还未写入文件中的数据
 *
 * 返回值为-1表示未正常写入数据，否则返回写入的数据个数
 */
static int fwrite_to_buf(const void *dst, int size, FILE *stream) {
    int write_size = 0;
    if(stream->bufUnavailable == stream->bufSize) {

#ifdef WIN32
        WriteFile((HANDLE)stream->fd, stream->buf + stream->bufAvailable, stream->bufUnavailable - stream->bufAvailable, &write_size, 0);

#else
        __asm__ __volatile__("movl $0x4, %%eax\n\t"
                             "movl %1, %%ebx\n\t"
                             "movl %2, %%ecx\n\t"
                             "movl %3, %%edx\n\t"
                             "int $0x80\n\t"
                             "movl %%eax, %0\n\t"
        : "=r"(write_size): "r"(stream->fd), "r"(stream->buf + stream->bufAvailable), "g"(stream->bufUnavailable - stream->bufAvailable) : "%eax", "%ebx", "%ecx", "%edx");

#endif

        if(write_size == stream->bufUnavailable - stream->bufAvailable) {
            stream->bufAvailable = stream->bufUnavailable = 0;
            return 0;
        }else {
            stream->bufAvailable += write_size;
            return -1;
        }
    }

    int buf_size = stream->bufSize - stream->bufUnavailable;
    write_size = buf_size < size ? buf_size : size;

    for(int i = 0; i < write_size; ++i) { stream->buf[stream->bufUnavailable++] = ((unsigned char*)dst)[i]; }
    return write_size;
}

//  将数据写入到文件中，返回成功写入的字节个数
int fwrite(const void *dst, int size, int count, FILE *stream) {
    if(stream == NULL || size <= 0 || count <= 0 || stream->flag != O_WRONLY) { return 0; }

    int need_size = size * count, write_size = 0;
    while(need_size) {
        int write_to_buf_size = fwrite_to_buf((const unsigned char*)dst + write_size, need_size, stream);
        if(write_to_buf_size < 0) { break; }

        write_size += write_to_buf_size;
        need_size -= write_to_buf_size;
    }

    return write_size;
}


//  刷新输出IO的缓冲区
void fflush(FILE *stream) {
    if(stream == NULL || stream->flag != O_WRONLY || stream->bufAvailable == stream->bufUnavailable) { return; }

    int write_size = 0;
#ifdef WIN32
    WriteFile((HANDLE)stream->fd, stream->buf + stream->bufAvailable, stream->bufUnavailable - stream->bufAvailable, &write_size, 0);

#else
    __asm__ __volatile__("movl $0x4, %%eax\n\t"
                         "movl %1, %%ebx\n\t"
                         "movl %2, %%ecx\n\t"
                         "movl %3, %%edx\n\t"
                         "int $0x80\n\t"
                         "movl %%eax, %0\n\t"
    : "=r"(write_size): "r"(stream->fd), "r"(stream->buf + stream->bufAvailable), "g"(stream->bufUnavailable - stream->bufAvailable) : "%eax", "%ebx", "%ecx", "%edx");
#endif


    if(write_size == stream->bufUnavailable - stream->bufAvailable) {
        stream->bufAvailable = stream->bufUnavailable = 0;
    }else {
        stream->bufAvailable += write_size;
    }
}


FILE *stdin, *stdout, *stderr;          //  标准输入、标准输出、标准错误输出


//  初始化stdin、stdout、stderr
void hawk_crt_io_init(void) {
#ifdef WIN32
    stdin = generate_file_descriptor(GetStdHandle(STD_INPUT_HANDLE), O_RDONLY);
    stdout = generate_file_descriptor(GetStdHandle(STD_OUTPUT_HANDLE), O_WRONLY);
    stderr = generate_file_descriptor(GetStdHandle(STD_ERROR_HANDLE), O_WRONLY);
#else
    stdin = generate_file_descriptor(0, O_RDONLY);
    stdout = generate_file_descriptor(1, O_WRONLY);
    stderr = generate_file_descriptor(2, O_WRONLY);
#endif
}
```


## 格式化字符串

  为了最基本的输入、输出功能，我们实现一个简易版的**printf**/**fprintf**输出函数，以及**scanf**/**fscanf**输入函数，用来交互。这些都是最简易版的，基本只包括**%s**和**%d**参数，以方便实现。


  首先，由于上面这些函数都是**变长参数**函数，因此我们需要完善**变长参数**功能。C语言支持定义具有**变长参数**的函数，对于不确定的参数，使用`[returnType] [functionName]([type1] arg1, ...)`进行声明，即使用省略号完成变参的声明。
  由于Windows环境的msvc编译器已经内置了相关的**变长参数**访问的操作，这里为了兼容，声明如下的Linux宏进行统一操作
```c
#define va_list (void*)
#define va_start(ap, arg) ((ap) = (va_list)&(arg) + sizeof((arg)))
#define va_arg(ap, t)     (*((t)*)(((ap) += sizeof(t)) - sizeof(t)))
#define va_end(ap)        ((ap) = NULL)

void test(void *format, ...) {
	va_list args;
	va_start(args, format);
	int arg1 = va_arg(args, int);
}
```

  可以看到，其仅仅是根据C语言传参的约定，即栈从高地址向低地址生长，而函数参数从右向左入栈。则从低地址到高地址遍历遍历栈相当于从左到右遍历参数。

  对于**printf**和**fprintf**，这里仅仅实现了**%s**和**%d**控制符，因此实现起来很方便——遍历**format**值，遇到控制符，则输出相关的变参；否则直接输出即可。


  对于**scanf**和**fscanf**，其稍微有一些麻烦——我们不知道一次需要读取多少字节，只能读取一个字节，经过判断后完成放回还是继续读取。由于前面实现读取时特意将数据从缓冲区中间开始放置，则回退字符串还是比较简单的，其过程如下所示：
1. 确认相关**FILE**结构的**bufAvailable**字段是否为0；否则返回0，表示无法进行回退
2. 将传入字符回退至缓冲区的**bufAvailable**处

  这里还需要特别说明一下，由于**Windows**下的换行符是`\r\n`，因此在**scanf**或**fscanf**时需要注意分割不同输入的处理
```c
//
// Created by hawk on 7/9/21.
//

#include "hawkCRT.h"



#ifdef WIN32
#include <Windows.h>
#else

//  定义变长参数相关的操作
#define va_list void *
#define va_start(ap, arg) ((ap) = (va_list)&(arg) + sizeof((arg)))
#define va_arg(ap, t)     (*(t*)(((ap) += sizeof(t)) - sizeof(t)))
#define va_end(ap)        ((ap) = NULL)

#endif



static int vprintf(FILE *stream, const char *format, va_list args) {
    int write_size = 0;
    void *chr;
    for(int i = 0; format[i]; ++i) {
        if(format[i] == '%') {
            switch (format[++i]) {
                case '%':
                    write_size += fwrite(format + i, sizeof(char), 1, stream);
                    break;
                case 's':
                    chr = va_arg(args, char*);
                    write_size += fwrite(chr, sizeof(char), strlen(chr) - 1, stream);
                    break;
                case 'd':
                    chr = itoa(va_arg(args, int), malloc(32), 10);
                    write_size += fwrite(chr, sizeof(char), strlen(chr) - 1, stream);
                    free(chr);
                    break;
                default:
                    write_size += fwrite(format + (--i), sizeof(char), 1, stream);
            }
        }else {
            write_size += fwrite(format + i, sizeof(char), 1, stream);
        }
    }
    va_end(args);

    fflush(stream);
    return write_size;
}



//  向标准输出格式化输出数据
int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    return vprintf(stdout, format, args);
}


//  向打开的文件流中格式化输出数据
int fprintf(FILE *stream, const char *format, ...) {
    va_list args;
    va_start(args, format);
    return vprintf(stream, format, args);
}




//  将字符进行回退
static int ungetc(int chr, FILE *stream) {
    if(stream == NULL || !stream->bufAvailable) { return 0; }

    stream->buf[--stream->bufAvailable] = (unsigned char)chr;
    return 0;
}



static int vscanf(FILE *stream, const char *format, va_list args) {
    int read_size = 0;
    int chr = 0;

    char *str;
    int val, idx, flag;

    for(int i = 0; format[i]; ++i) {
        if(format[i] == '%') {
            switch (format[++i]) {
                case 's':
                    //  读取字符串
                    str = va_arg(args, char*);
                    idx = 0;

                    //清除所有空格字符
                    while(1) {
                        fread(&chr, sizeof(char), 1, stream);
                        if(chr == ' ' || chr == '\t' || chr == '\n' || chr == '\r') { continue; }

                        ungetc(chr, stream);
                        break;
                    }
                    while(1) {
                        fread(&chr, sizeof(char), 1, stream);
                        if(chr == ' ' || chr == '\t' || chr == '\n' || chr == '\r') {
                            ungetc(chr, stream);
                            break;
                        }
                        str[idx++] = chr;
                    }
                    str[idx] = 0;
                    ++read_size;
                    break;
                case 'd':
                    //  读取数字
                    flag = val = 0;
                    //清除所有空格字符
                    while(1) {
                        fread(&chr, sizeof(char), 1, stream);
                        if(chr == ' ' || chr == '\t' || chr == '\n' || chr == '\r') { continue; }

                        ungetc(chr, stream);
                        break;
                    }

                    //读取符号信息
                    fread(&chr, sizeof(char), 1, stream);
                    if(chr == '-') { flag = 1; }
                    else if(chr == '+') {;}
                    else { ungetc(chr, stream); }

                    while(1) {
                        fread(&chr, sizeof(char), 1, stream);
                        if(chr >= '0' && chr <= '9') {
                            val = (val * 10) + chr - '0';
                            continue;
                        }

                        ungetc(chr, stream);
                        break;
                    }

                    *(va_arg(args, int*)) = flag ? (-val) : val;
                    ++read_size;
                    break;
                default:
                    --i;
                    fread(&chr, sizeof(char), 1, stream);
                    if(chr != format[i]) {
                        ungetc(chr, stream);
                        return read_size;
                    }
            }
        }else {
            fread(&chr, sizeof(char), 1, stream);
            if(chr != format[i]) {
                ungetc(chr, stream);
                break;
            }
        }
    }
    va_end(args);


    return read_size;
}




//  从标准输入中格式化获取数据
int scanf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    return vscanf(stdin, format, args);
}



//  从打开的文件流中格式化获取数据
int fscanf(FILE *stream, const char *format, ...) {
    va_list args;
    va_start(args, format);
    return vscanf(stream, format, args);
}
```


  最后，这里给出[源代码、构建脚本和测试文件](hawkCRT.rar)，方便进行改进