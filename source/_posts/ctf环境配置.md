---
title: ctf环境配置
date: 2021-07-21 21:21:25
tags: ['信息安全','设置']
categories: ['信息安全']
---

# 前言

  为了方便，将CTF的环境配置进行总结，方便日后快速恢复环境等


# 二进制

## PWN环境

  由于一般PWN题目涉及到各种**Glibc**版本，这里搭建多个虚拟机，下面给出主要版本下的虚拟机安装

### ubuntu16.04

  其安装脚本如下所示
  ```bash
#!/bin/sh


# necessary setting and software
sudo passwd root \
        && su -c 'echo -e "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse" > /etc/apt/sources.list' \
        && sudo apt-get clean \
        && sudo apt-get update \
        && sudo apt-get upgrade -y \
        && sudo apt-get install -y python python3 \
        gdb patchelf strace ltrace \
        gcc gcc-multilib g++-multilib nasm \
        git wget curl \
        open-vm-tools-desktop fuse \
        && wget https://hub.fastgit.org/neovim/neovim/releases/download/stable/nvim-linux64.tar.gz \
        && sudo tar -zxf nvim-linux64.tar.gz -C /usr/bin \
        && rm -rf nvim-linux64.tar.gz


# neovim
sudo ln -sf /usr/bin/nvim-linux64/bin/nvim /usr/bin/vi \
        && mkdir ~/.config/nvim \
        && /bin/bash -c 'echo -e "set clipboard+=unnamedplus\nlet g:python_recommended_style = 0" > ~/.config/nvim/init.vim'


# python2-pip
wget https://bootstrap.pypa.io/pip/$(python2 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py -O get-pip.py \
        && python2 get-pip.py \
        && rm -rf get-pip.py \
        && python2 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# python3-pip
wget https://bootstrap.pypa.io/pip/$(python3 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py -O get-pip3.py \
        && python3 get-pip3.py \
        && rm -rf get-pip3.py \
        && python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# pwntools
python2 -m pip install pathlib2 pwntools


# pwndbg
git clone https://hub.fastgit.org/pwndbg/pwndbg ~/pwndbg \
        && (cd ~/pwndbg && ./setup.sh)
```


### ubuntu 18.04

  ```bash
#!/bin/sh


# necessary setting and software
sudo passwd root \
        && su -c 'echo -e "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse" > /etc/apt/sources.list' \
        && sudo apt-get clean \
        && sudo apt-get update \
        && sudo apt-get upgrade -y \
        && sudo apt-get install -y python python-pip python3 python3-pip \
        gdb patchelf strace ltrace ruby \
        gcc gcc-multilib g++-multilib nasm \
        git wget curl \
        open-vm-tools-desktop fuse neovim


# neovim
sudo ln -sf /usr/bin/nvim /usr/bin/vi \
        && mkdir ~/.config/nvim \
        && /bin/bash -c 'echo -e "set clipboard+=unnamedplus\nlet g:python_recommended_style = 0" > ~/.config/nvim/init.vim'


# python2-pip
python2 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# python3-pip
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# ruby
sudo gem install one_gadget

# pwntools
python2 -m pip install pathlib2 pwntools


# pwndbg
git clone https://hub.fastgit.org/pwndbg/pwndbg ~/pwndbg \
        && (cd ~/pwndbg && ./setup.sh)
```


### ubuntu 20.04

   ```bash
#!/bin/sh


# necessary setting and software
sudo passwd root \
        && su -c 'echo -e "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse\n\ndeb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse" > /etc/apt/sources.list' \
        && sudo apt-get clean \
        && sudo apt-get update \
        && sudo apt-get upgrade -y \
        && sudo apt-get install -y python python3 python3-pip \
        gdb patchelf strace ltrace ruby \
        gcc gcc-multilib g++-multilib nasm \
        git wget curl \
        open-vm-tools-desktop fuse neovim


# neovim
sudo ln -sf /usr/bin/nvim /usr/bin/vi \
        && mkdir ~/.config/nvim \
        && /bin/bash -c 'echo -e "set clipboard+=unnamedplus\nlet g:python_recommended_style = 0" > ~/.config/nvim/init.vim'


# python2-pip
wget https://bootstrap.pypa.io/pip/$(python2 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py -O get-pip.py \
        && python2 get-pip.py \
        && rm -rf get-pip.py \
        && python2 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# python3-pip
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
        && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# ruby
sudo gem install one_gadget

# pwntools
python2 -m pip install pathlib2 pwntools \
        && sudo ln -sf ~/.local/bin/checksec /usr/bin/checksec


# pwndbg
git clone https://hub.fastgit.org/pwndbg/pwndbg ~/pwndbg \
        && (cd ~/pwndbg && ./setup.sh)
```
```dockerfile
# Example for dockerfile
FROM ubuntu:20.04



# 下载需要安装的依赖和软件
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list \
	&& sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list \
	&& apt-get clean \
	&& apt-get update \
	&& DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y python python-dev python3 python3-distutils \
	gdb patchelf strace ltrace\
	gcc gcc-multilib g++-multilib nasm \
	git neovim wget curl tmux




# 设置neovim
RUN ln -sf /usr/bin/nvim /usr/bin/vi


# 设置python2
RUN wget https://bootstrap.pypa.io/pip/$(python2 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py \
	&& python2 get-pip.py \
	&& rm -rf get-pip.py \
	&& python2 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U \
	&& python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple


# 设置python3
RUN wget https://bootstrap.pypa.io/pip/get-pip.py \
	&& python3 get-pip.py \
	&& rm -rf get-pip.py \
	&& python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U \
	&& python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# 安装pwntools
RUN python2 -m pip install pathlib2 pwntools



# 配置pwndbg
RUN git clone https://hub.fastgit.org/pwndbg/pwndbg /usr/bin/pwndbg \
	&& (cd /usr/bin/pwndbg && ./setup.sh)



# 配置tmux，方便进行分屏调试
RUN echo 'set-option -g mouse on' > /etc/tmux.conf



# 创建相关目录，之后会将主机上指定目录进行挂载，并设置为工作目录
RUN mkdir ctf



# 进入容器的bash目录位于/ctf中
WORKDIR /ctf



# 由于pwntools执行debug，必须先提前开启tmux，因此直接设置初始执行程序为tmux即可
CMD ["tmux"]
```


## patchelf

  **CTF**的**PWN**类型题目中，会有复杂的动态链接库和依赖关系，我们需要修改这些二进制的信息，使其可以在本地环境下正常运行，可以通过**patchelf**程序进行实现。

### dynamic loader

  如果没有正确的动态载入器，我们会导致程序执行错误或无法找到程序，因此可以通过如下命令修改指定的动态载入器地址
  ```bash
patchelf --set-interpreter [path] [execute]
  ```

### runtime path

  有时程序需要使用特殊的动态链接库，因此其指定了动态链接库的首要查找路径，即**runtime path(rpath)**。我们在本地可以通过修改**rpath**字段的值，从而让其在本地的对应路径下去寻找动态链接库，命令如下
  ```bash
patchelf --set-rpath [path] [execute]
  ```


## LD_*环境变量

  由于程序的动态链接和依赖关系十分的复杂，因此linux本身也提供了一些环境变量，方便进行程序动态链接和依赖的查找和调试

### LD_DEBUG

  实际上通过设置**LD_DEBUG**变量，可以方便的调试程序动态链接的各种过程，比如

 ```bash
LD_DEBUG=libs [execute]
 ```

  终端会输出程序寻找动态库的全过程，然后接着是正常的执行过程。

  **LD_DEBUG**中包含多个可选的值，如**libs**、**symbols**等，可以通过设置**help**值，然后屏幕会输出所有的可选项及其含义。


### LD_LIBRARY_PATH

  类似于前面的**runtime path**，但是优先级次一级。即程序运行前，在查找动态链接库时，会首先在指定的**rpath**路径下查找；然后在指定的**LD_LIBRARY_PATH**路径下查找；最后在系统的默认路径下进行查找

  其命令执行形式如下所示
  ```bash
LD_LIBRARY_PATH=[path] [execute]
  ```

## GDB调试器

  再做*PWN*题目的时候，需要进行相关的调试，这就需要Linux中的**GDB**进行辅助。

### 常用命令

  **GDB**及其插件中提供了大量的操作，方便进行调试程序，在[GDB教程资源](http://www.gnu.org/software/gdb/documentation/)和[pwndbg教程](https://browserpwndbg.readthedocs.io/en/docs/commands/misc/pwndbg/)中有详细的信息，这里简单介绍几个
  1. `starti`，该命令将程序执行到真正的入口处，并停止等待后续**DEBUG**命令
  2. `call [function]`，直接调用`function`函数执行
  3. `break [address] if [condition]`，即当条件`condition`满足时，程序会在执行到`address`时停止
  4. `break *$rebase(address)`，即在装载基地址偏移`address`设立断点
  5. `dprintf *$rebase(address) "%d\n", $rax`，即当执行到`*$rebase(address)`地址处，输出相关的格式信息
  6. `find [/SIZE-CHAR] START-ADDRESS, END-ADDRESS, EXPR1`，即在指定范围内寻找指定值和类型的数据，其中，**SIZE-CHAR**可选*b*、*h*、*w*、*g*，分别表示8bit、16bit、32bit和64bit
  7. `p *(struct s*)(address)`，即将*address*地址处的变量当作**struct s**结构体的指针，并打印出具体的结构体信息
  8. `![command]`，即在gdb中打开**shell**，执行*command*指令

### 命令执行

  除了手动一条一条命令的进行交互，也可以通过命令行，按照提前给定的指令依次执行，如下所示
  ```bash
gdb [file] -ex [command1] -ex [command2] ...
  ```
  之后，gdb加载给定的目标程序，并按照参数顺序，依次在**GDB**中执行参数中传递的命令



## pwntools库

  这是专门用于CTF和漏洞利用的Python库

### PWN模板

  为了方便*PWN*，这里专门给出一个标准脚本，可以稍加修改即可用于任何不同的*PWN*题目
  ```python
#!/usr/bin/python2
# -*- coding:utf-8 -*-
from pwn import *
import sys
import platform

'''
	待修改数据
'''
context.log_level = 'debug'
context.arch = 'amd64'				# 32位使用i386
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

execve_file = None
lib_file = None
gdbscript = '''starti;'''
argv = []




'''
	这里给出asm 汇编->机器代码的相关样例
'''
if context.arch == 'amd64':
	shellcode = asm('''
mov	rax, %d		/*rbx = "/bin/sh"*/
push	rax
mov	rdi, rsp	/*rdi -> "/bin/sh"*/
xor	esi, esi	/*esi -> NULL*/
xor	edx, edx	/*edx -> NULL*/
push	0x3b
pop	rax		/*rax = 0x3b*/
syscall			/*execve("/bin/sh")*/
'''%(u64('/bin/sh'.ljust(8, '\x00'))))
elif context.arch == 'i386':
	shellcode = asm('''
push	%d		/*"/bin"*/
push	%d		/*"/sh\x00"*/
mov	ebx, esp	/*ebx -> "/bin/sh"*/
xor	ecx, ecx	/*ecx -> NULL*/
xor	edx, edx	/*edx -> NULL*/
push	11
pop	eax		/*eax = 11*/
nt 0x80		/*execve("/bin/sh")*/
'''%(u32('/bin'), u32('/sh\x00')))




'''
	elf.plt[`symbol`] 获取elf文件中导入符号的plt地址
	elf.got[`symbol`] 获取elf文件中导入符号的got地址
	elf.sym['symbol'] 获取elf文件中本地符号的函数实际地址
'''
if execve_file != None:
	elf = ELF(execve_file)

'''
	lib.sym[`symbol`] 获取lib中符号地址
	lib.search['string'].next() 获取lib中字符串地址
'''
if lib_file != None:
	lib = ELF(lib_file)

log.info('-----------------------------------------------------------')


'''
	执行爆破攻击
	只有当成功获取shell或者键盘Ctrl+C退出时，程序中止循环
	否则程序一直进行循环
'''


def exp():
	if 'd' in sys.argv:
		r = gdb.debug([execve_file] + argv, gdbscript, env={'LD_LIBRARY_PATH':'./'})	# 首先加载当前目录下的动态库文件
	else:
		r = remote(sys.argv[1], sys.argv[2])

	r.interactive()

while True:
	try:
		exp()
		break
	except KeyboardInterrupt:
		break
	except:
		continue

	
log.info('-----------------------------------------------------------')
  ```


## IDA

  IDA是世界上顶级的交互式反汇编工具，往往使用**IDA**静态分析程序，从而理清程序中的代码组织结构，并统计相关资源信息

### IDAPython

  这是IDA的一个插件，允许IDA执行相关的*python*脚本信息。其中，该插件提供了大量的[IDA接口](https://hex-rays.com/products/ida/support/idapython_docs/frames.html)，从而可以方便的获取程序的相关信息，我们将其整理成如下模板
  ```python
import ida_bytes

'''
	获取虚拟地址处的1字节的值
	返回的是整形
'''
val = ida_bytes.get_byte(address)
  ```



# ~~Web~~
