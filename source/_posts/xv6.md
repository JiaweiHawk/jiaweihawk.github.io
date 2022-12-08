---
title: xv6
date: 2022-05-19 20:05:10
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

大名鼎鼎的MIT的**[6.828](https://pdos.csail.mit.edu/6.828/2020/)**课程
看了课程提供的[视频](https://www.youtube.com/watch?v=tc4ROCJYbm0)，瞬间心潮澎湃
希望可以通过这门课程，加深对于操作系统方面的理解


# Lab Utilities

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/util.html)帮助熟悉**xv6**操作系统


##  Boot xv6

在Linux的终端中，执行如下命令，安装相关依赖
```bash
sudo apt-get install git build-essential gdb-multiarch qemu-system-misc gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu 
```

执行如下命令，拉取**xv6**仓库
```bash
git clone git@gitee.com:jiaweihawk/mit-6.S081.git
```


执行如下命令，拉取**gdb**并编译
```bash
sudo apt-get install libgmp-dev libncurses5-dev \
  && wget http://mirrors.aliyun.com/gnu/gdb/gdb-12.1.tar.gz\
  && tar -zxvf gdb-12.1.tar.gz\
  && cd gdb-12.1\
  && ./configure --enable-tui=yes --target=riscv64\
  && make -j $(nproc)\
  && sudo make install
```


执行如下命令，切换到**util**分支
```bash
git checkout util
```


在终端中执行如下命令，启动**qemu**模拟器，并加载运行xv6
```bash
make qemu
```

## sleep

### 要求

> Implement the UNIX program **sleep** for xv6; your **sleep** should pause for a user-specified number of ticks. A tick is a notion of time defined by the xv6 kernel, namely the time between two interrupts from the timer chip. Your solution should be in the file **user/sleep.c**.

### 分析

实际上，根据实验指南的说明
通过调用相关的系统调用，即可完成**sleep**程序的要求
需要注意的是，当完成或发现异常时，通过**exit**系统调用，完成进程的最终退出即可

### 实现

在Makefile中添加该用户态程序目标，如下所示
```makefile
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
	$U/_sleep\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\
```

再在**user/**目录下，创建**sleep.c**文件，仿照**user/echo.c**文件，添加相关的头文件，完成对**sleep**系统调用的包装。代码如下所示
```c
#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  int time = 0;


  if(argc <= 1)
  {
    fprintf(2, "usage: sleep time...\n");
    exit(0);
  }

  time = atoi(argv[1]);
  sleep(time);

  exit(0);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=sleep grade
```
![sleep实验结果](sleep实验结果.png)


## pingpong

### 要求

> Write a program that uses UNIX system calls to ''ping-pong'' a byte between two processes over a pair of pipes, one for each direction. The parent should send a byte to the child; the child should print "<pid>: received ping", where <pid> is its process ID, write the byte on the pipe to the parent, and exit; the parent should read the byte from the child, print "<pid>: received pong", and exit. Your solution should be in the file **user/pingpong.c**.

### 分析

根据实验指南的说明
通过**fork**、**pipe**和**getpid**系统调用，即可完成**pingpong**程序的要求

这里根据实验手册，需要明确两点
1. **fork**在父进程中的返回值是pid，在子进程中的返回值是0
2. **pipe**初始化的管道，其数组的第一个元素是读端，第二个元素是写端

### 实现

在Makefile中添加该用户态程序目标，如下所示
```makefile
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
	$U/_pingpong\
	$U/_rm\
	$U/_sh\
	$U/_sleep\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\
```

再在**user/**目录下，创建**pingpong.c**文件，仿照**user/sleep.c**文件，添加相关的头文件，完成管道创建和读写。相关代码如下所示
```c
#include "kernel/types.h"
#include "user/user.h"

/*
 * 初始化子进程的文件描述符信息
 * 关闭父进程写管道的写端
 * 关闭父进程读管道的读端
 *
 * 从而子进程从父进程写管道中读取数据
 * 向父进程读管道中写入数据
 */
static void
prepare_child_fds(int *parent_write_p, int *parent_read_p)
{
    //关闭父进程写管道的写段
    close(parent_write_p[1]);

    //关闭父进程读管道的读端
    close(parent_read_p[0]);
}



/*
 * 初始化父进程的文件描述符信息
 * 关闭父进程写管道的读端
 * 关闭父进程读管道的写端
 *
 * 从而进程向父进程写管道中写入数据
 * 从父进程读管道中读出数据
 */
static void
prepare_parent_fds(int *parent_write_p, int *parent_read_p)
{
    //关闭父进程写管道的读段
    close(parent_write_p[0]);

    //关闭父进程读管道的写端
    close(parent_read_p[1]);
}


int main(void)
{
    int parent_write_p[2], parent_read_p[2];
    char byte = 0;
    

    // 初始化管道
    pipe(parent_write_p);
    pipe(parent_read_p);


    if(fork() == 0) {

        // 在子进程中
        prepare_child_fds(parent_write_p, parent_read_p);

        //从写管道中读出数据
        read(parent_write_p[0], &byte, 1);
        
        // 输出相应信息
        printf("%d: received ping\n", getpid());

        //向读管道中写入数据
        write(parent_read_p[1], &byte, 1);

    } else {

        // 在父进程中
        prepare_parent_fds(parent_write_p, parent_read_p);

        //向写管道中写入数据
        write(parent_write_p[1], &byte, 1);
        
        //从读管道中读入数据
        read(parent_read_p[0], &byte, 1);

        // 输出相应信息
        printf("%d: received pong\n", getpid());
        
        
        //等待子进程正常退出后，父进程退出
        wait(0);
    }

    //确保子进程和父进程正常退出
    exit(0);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=pingpong grade
```
![pingpong实验结果](pingpong实验结果.png)



## primes

### 要求

> Write a concurrent version of prime sieve using pipes. This idea is due to Doug McIlroy, inventor of Unix pipes. The picture halfway down [this page](https://swtch.com/~rsc/thread/) and the surrounding text explain how to do it. Your solution should be in the file **user/primes.c**.

### 分析

根据实验指南可知，**CSP**模型描述了一个如下图所示进程链
![进程链](进程链.png)

其每个进程从进程链中上一个元素接受输入，输出确定的质数，并将剩余的可能的质数输出到进程链的下一个元素。

由于**fork**系统调用的特性，可以抽象一个**worker**模型，来描述进程链的每一个元素。

**worker**模型有如下特点
- 其标准输入被覆盖为父进程(进程链的上一个元素)的管道写端
- 其会创建另一个**worker**，作为其子进程

而**worker**模型的实现也很容易，其第一个特点是由上一个**worker**实现的，而**worker**模型实际上要实现的就是——其可以创建一个子进程，该子进程的标准输入被覆盖为管道的写端，并且子进程会接着执行**worker**执行流

在直白一些，就是有一个**worker**函数，该函数会**fork**一个子进程，子进程初始化相关的文件描述符后，继续执行**worker**函数即可

唯一要考虑的就是，如何构造第一个**worker**和最后一个**worker**元素，这里特殊处理一下就行

### 实现

在Makefile中添加该用户态程序目标，如下所示
```makefile
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
	$U/_pingpong\
	$U/_primes\
	$U/_rm\
	$U/_sh\
	$U/_sleep\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\
```

再在**user/**目录下，创建**primes.c**文件，仿照**user/echo.c**文件，添加相关的头文件，完成**worker**模型的实现。代码如下所示
```c
#include "kernel/types.h"
#include "user/user.h"

typedef unsigned char bool;
#define true    1
#define false   0

/*
 * 初始化子进程的文件描述符
 * 关闭管道符的写端
 * 将管道符的读端覆盖进程的标准输入描述符
 */
static void
prepare_child_fds(int *pipefd)
{

    //关闭管道符的写端
    close(pipefd[1]);

    //覆盖标准输入
    close(0);
    dup(pipefd[0]);
    close(pipefd[0]);
}

/*
 * worker子线程
 * 其从被覆盖的标准输入中读取候选数据
 * 并将可能的素数传递给子进程
 *
 * 如果其从父进程中读入了n个数(n >= 1)
 * 第一个数是要输出的素数
 * 第2到n个数，如果是可能的质数(非第一个数的倍数)，则传递给子进程即可
 */
static void
worker()
{
    int prime = 0, number, pipefd[2];
    bool has_forked = false;


    //从父进程中读入第一个素数
    read(0, &prime, sizeof(prime));
    printf("prime %d\n", prime);


    //开始将后续的可能质数传递给子进程
    while(read(0, &number, sizeof(number)) != 0) {
        if(number % prime) {

            // number为可能的质数
            // 将该数字传递给子进程
            if(!has_forked) {

                pipe(pipefd);

                if(fork() == 0) {

                    //在子进程中
                    prepare_child_fds(pipefd);

                    //子进程继续执行worker工作即可
                    worker();
                }

                //关闭管道符的读端
                close(pipefd[0]);

                //初始化子进程
                has_forked = true;
            }

            write(pipefd[1], &number, sizeof(number));
        }
    }


    //此时worker的工作基本做完
    //关闭管道符的写端，从而通知子进程已经没有数据
    close(pipefd[1]);

    //如果有子进程，则等待子进程退出即可
    if(has_forked)
        wait(0);


    //结束进程即可
    exit(0);
}


int main(void)
{
    int pipefd[2];    

    pipe(pipefd);

    //创建worker链
    if(fork() == 0) {

        prepare_child_fds(pipefd);

        //子进程继续执行worker工作即可
        worker();
    }


    //这里是初始worker
    //即其自己指定输入，而非从父进程中读取输入
    printf("prime 2\n");


    //将所有可能的素数传递给子进程
    for(int i = 3; i < 35; i += 2)
        write(pipefd[1], &i, sizeof(i));

    //此时worker的工作基本做完
    //关闭管道符的写端，从而通知子进程已经没有数据
    close(pipefd[1]);

    //等待子进程退出即可
    wait(0);

    //结束进程即可
    exit(0);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=primes grade
```
![primes实验结果](primes实验结果.png)


## find

### 要求

> Write a simple version of the UNIX find program: find all the files in a directory tree with a specific name. Your solution should be in the file **user/find.c**.

### 分析

根据实验指南和xv6源代码
目录也是文件，并且目录内容是**struct dirent**数组

再直白一些，从目录文件描述符读取的字节，实际上就是**struct dirent**数组，其每一个元素就是一个目录项，包含有该目录项对应的名称

则基本逻辑就是递归的遍历目录项即可

### 实现

在Makefile中添加该用户态程序目标，如下所示
```makefile
UPROGS=\
	$U/_cat\
	$U/_echo\
	$U/_find\
	$U/_forktest\
	$U/_grep\
	$U/_init\
	$U/_kill\
	$U/_ln\
	$U/_ls\
	$U/_mkdir\
	$U/_pingpong\
	$U/_primes\
	$U/_rm\
	$U/_sh\
	$U/_sleep\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\
```

再在**user/**目录下，创建**find.c**文件，仿照**user/ls.c**文件，添加相关的头文件，完成目录项的遍历。相关代码如下所示
```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"


/*
 * 在path目录下，寻找名称为name的文件
 *
 * 即递归path的目录树，依次比较名称即可
 */
static void
find(char *path, const char *name)
{

  char buf[512], *p;
  int fd;
  struct dirent de;
  struct stat st;

  if((fd = open(path, O_RDONLY)) < 0){
    fprintf(2, "find: cannot open %s\n", path);
    return;
  }

  if(fstat(fd, &st) < 0){
    fprintf(2, "find: cannot stat %s\n", path);
    close(fd);
    return;
  }

  switch(st.type){

    case T_DIR:

      if(strlen(path) + 1 + DIRSIZ + 1 > sizeof(buf)){
        printf("find: path too long\n");
        break;
      }
      strcpy(buf, path);
      p = buf+strlen(buf);
      *p++ = '/';

      while(read(fd, &de, sizeof(de)) == sizeof(de)){

        if(de.inum == 0)
          continue;
        
        // 对于.和..文件，无需进行递归遍历
        if(!strcmp(de.name, ".") || !strcmp(de.name, ".."))
          continue;
        
        // 如果文件名称为目标字符串，则输出即可
        if(!strcmp(de.name, name))
          printf("%s/%s\n", path, de.name);
        
        strcpy(p, de.name);
        find(buf, name);
      }

      break;
  }
  close(fd);
}


int
main(int argc, char *argv[])
{
  if(argc <= 2)
  {
    fprintf(2, "usage: find path name\n");
    exit(0);
  }

  find(argv[1], argv[2]);
  exit(0);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=find grade
```
![find实验结果](find实验结果.png)



## xargs

### 要求

> Write a simple version of the UNIX xargs program: read lines from the standard input and run a command for each line, supplying the line as arguments to the command. Your solution should be in the file **user/xargs.c**.

### 分析

注意看清实验要求
xargs将管道输入的每一行当作要执行命令的额外参数
思路很简单，即在栈上申请一个**args**数组，并将**xargs**的参数复制到新数组中，并在最后添加从管道中解析出的参数即可

### 实现

在Makefile中添加该用户态程序目标，如下所示
```makefile
UPROGS=\
	$U/_cat\
	$U/_echo\
	$U/_find\
	$U/_forktest\
	$U/_grep\
	$U/_init\
	$U/_kill\
	$U/_ln\
	$U/_ls\
	$U/_mkdir\
	$U/_pingpong\
	$U/_primes\
	$U/_rm\
	$U/_sh\
	$U/_sleep\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_xargs\
	$U/_zombie\
```

再在**user/**目录下，创建**xargs.c**文件，仿照**user/ls.c**文件，添加相关的头文件，并完成参数数组的设置即可。相关的代码如下所示
```c
#include "kernel/types.h"
#include "user/user.h"

#define MAXLINE     256


/*
 * 默认每一行不超过256个字节
 */
int main(int argc, char *argv[])
{

  char buf[MAXLINE];
  char *args[argc + 1];


  //设置参数列表
  for(int i = 1; i < argc; ++i)
    args[i - 1] = argv[i];

  args[argc - 1] = buf;
  args[argc] = 0;


  //从标准输入中读取参数
  int ch = 0;
  int idx = 0;
  while(read(0, &ch, 1) != 0) {

    if(ch == '\n') {
      
      // 一行解析结束，fork-exec执行
      args[argc - 1][idx] = 0;

      if(fork() == 0) {

        //在子进程中
        exec(args[0], args);
        fprintf(2, "xargs: cannot exec %s\n", args[0]);
        exit(0);

      }

      //等待子进程结束
      wait(0);

      //重新解析行
      idx = 0;

    }else
      args[argc - 1][idx++] = ch;

  }


  //终止当前进程
  exit(0);
}
```

### 结果

执行如下命令，完成实验测试
```bash
make GRADEFLAGS=xargs grade
```
![xargs实验结果](xargs实验结果.png)