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
sudo ln -sf /usr/bin/nvim /usr/bin/vi \
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
sudo ln -sf /usr/bin/nvim /usr/bin/vi \
    && mkdir ~/.config/nvim \
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
#include <linux/module.h>
#include <linux/stddef.h>

static int __init
hawk_init(void) {
	printk("----------------------------------begin---------------------------------------\n");
	return 0;
}

static void __exit
hawk_exit(void) {
	printk("----------------------------------end---------------------------------------\n");
}

module_init(hawk_init);
module_exit(hawk_exit);
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
  | -append | kernel的参数，[参考链接](https://docs.kernel.org/admin-guide/kernel-parameters.html)<br>**root**:根文件系统对应的设备，有默认值 <br>**init**:制定内核执行的第一条命令，有默认值 <br>**console**:console对应的设备，一般用**ttyS0**，从而重定向到串口 |
  | -enable-kvm | 开启KVM虚拟化 |
  | -nographic | 关闭Qemu GUI。可以使用-monitor重定向Qemu控制台;-serial重定向guest串口信息; -display重定向guest的GUI |
  | -smp | 设置虚拟机cpu属性 |
  | -cpu | 设置cpu模型信息 |
  | -no-reboot | 当内核崩溃后，静止重启 |
  | -no-shutdown | 当内核崩溃后，冻结在崩溃位置处 |


## 调试环境

  为了方便，根据上面的介绍，准备好了[调试环境](kernel.tar.gz)。
  解压后，在`Makefile`中更改**KERNEL**指定内核映像即可

## 模板

### qemu启动脚本

则本地调试脚本如下所示
  ```bash
#!/bin/sh
set -xe

# 根文件系统路径
ROOT=$(pwd)/rootfs

# 文件系统映像路径
ROOTFS=$(pwd)/rootfs.cpio

# 内核镜像路径
KERNEL=$(pwd)/bzImage

# exp源代码路径
EXP=$(pwd)/exp.c

# 静态编译exp
gcc -o $(pwd)/rootfs/exp -Wall -static ${EXP}

# 生成文件系统映像
(cd ${ROOT}; find . | cpio -o --format=newc > ${ROOTFS})

# 启动qemu
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -monitor /dev/null \
    -kernel ${KERNEL} \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    -initrd ${ROOTFS} \
    -smp cores=2,threads=2 \
    -cpu kvm64,smep,smap \
    -no-shutdown -no-reboot \
    -s
```

### gdb配置文件
```
# .gdbinit

# 设置kernel基址
set $base=0xffffffff81000000

target remote localhost:1234
```

### exp

```c
#include <stdio.h>
#include <stdlib.h>

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
        exit(1); \
    } \
}

/* Global variables
 * 定义使用到的全局变量
 */



/* modprobe_path提权
 * 条件:
 *      1. 覆写`modprobe_path`符号的内容从`/sbin/modprobe`
 * 更改为 `/tmp/a`, 即 *(modprobe_path) = 0x612f706d742f
 *
 * 参考: https://www.anquanke.com/post/id/232545#h3-6
 */
void modprobe_exp()
{
    printf("[*] set fake modprobe content\n");
    fflush(stdout);
    system("echo '#!/bin/sh' > /tmp/a");
    system("echo 'cp /root/flag /tmp/flag' >> /tmp/a");
    system("echo 'chmod 777 /tmp/flag' >> /tmp/a");


    printf("[*] set fake modprobe permission\n");
    fflush(stdout);
    system("chmod +x /tmp/a");


    printf("[*] set unknown file content\n");
    fflush(stdout);
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");


    printf("[*] set unknown file permission\n");
    fflush(stdout);
    system("chmod +x /tmp/dummy");


    printf("[*] run unknown file\n");
    fflush(stdout);
    system("/tmp/dummy");


    printf("[*] read the flag\n");
    fflush(stdout);
    system("cat /tmp/flag");
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