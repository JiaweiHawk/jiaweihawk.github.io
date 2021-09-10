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

  由于一般PWN题目涉及到各种**Glibc**版本，因此为了搭建环境方便起见，使用**Docker**来配置PWN题目所需要的各种镜像

### 安装docker

  在终端中执行如下命令，安装**docker**并启动**docker服务**，
  ```bash
sudo pacman -S docker
sudo systemctl start docker
sudo systemctl enable docker
  ```


### 更换docker镜像源

  由于docker拉取镜像时，默认从**docker hub**上拉取，速度较慢，因此更换为国内的镜像仓库，创建**/etc/docker/daemon.json**文件，
  ```json
{
 "registry-mirrors" : [
   "https://mirror.ccs.tencentyun.com",
   "http://registry.docker-cn.com",
   "http://docker.mirrors.ustc.edu.cn",
   "http://hub-mirror.c.163.com"
 ],
 "insecure-registries" : [
   "registry.docker-cn.com",
   "docker.mirrors.ustc.edu.cn"
 ],
 "debug" : true,
 "experimental" : true
}
  ```

  然后重启**docker**服务更新设置，即执行如下命令
  ```bash
sudo systemctl restart docker
  ```

### 设置用户组

  由于**docker**进程基本都以**root**账户的身份进行运行，因此将当前用户添加入**docker**用户组，避免之后每次执行命令都需要添加**sudo**
  ```bash
sudo usermod -aG docker ${USER}
  ```

### 获取docker镜像


 #### 直接拉取

  这里已经提前建好了相关的镜像，执行如下命令进行拉取
  ```bash
docker pull h4wk1ns/pwn:[glibc23]/[glibc27]/[glibc31] &&
docker tag h4wk1ns/pwn:[glibc23]/[glibc27]/[glibc31] [pwn23]/[pwn27]/[pwn31] &&
docker rmi h4wk1ns/pwn:[glibc23]/[glibc27]/[glibc31] 
  ```

 #### 重新构建

  这里采用主流的**Ubuntu**镜像，作为PWN环境的宿主系统，使用**Dockerfile**快速构建相关的镜像，可以点击查看[Dockerfile说明](https://docs.docker.com/engine/reference/builder/)

  基本的两个样例镜像如下所示
```dockerfile
# Example for dockerfile
FROM ubuntu:16.04



# 下载需要安装的依赖和软件
RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
	&& sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
	&& apt-get clean \
	&& apt-get update \
	&& DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y python python-dev python3 python3-dev \
	gdb patchelf strace ltrace \
	gcc gcc-multilib g++-multilib nasm \
	git wget curl tmux \
	&& wget https://hub.fastgit.org/neovim/neovim/releases/download/stable/nvim-linux64.tar.gz \
	&& tar -zxf nvim-linux64.tar.gz -C /usr/bin \
	&& rm -rf nvim-linux64.tar.gz




# 设置neovim
RUN ln -sf /usr/bin/nvim-linux64/bin/nvim /usr/bin/vi


# 设置python2
RUN wget https://bootstrap.pypa.io/pip/$(python2 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py \
	&& python2 get-pip.py \
	&& rm -rf get-pip.py \
	&& python2 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U \
	&& python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple



# 设置python3
RUN wget https://bootstrap.pypa.io/pip/$(python3 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py \
	&& python3 get-pip.py \
	&& rm -rf get-pip.py \
	&& python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U \
	&& python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple




# 安装pwntools
RUN python2 -m pip install pathlib2 pwntools



# 配置pwndbg
RUN git clone https://hub.fastgit.org/pwndbg/pwndbg /usr/bin/pwndbg \
	&& (cd /usr/bin/pwndbg && ./setup.sh) \
	&& sed -i "s/env_args.append('{}=\"{}\"'.format(key, env.pop(key)))/env_args.append('{}={}'.format(key, env.pop(key)))/g" /usr/local/lib/python2.7/dist-packages/pwnlib/gdb.py



# 配置tmux，方便进行分屏调试
RUN echo 'set-option -g mouse on' > /etc/tmux.conf



# 创建相关目录，之后会将主机上指定目录进行挂载，并设置为工作目录
RUN mkdir ctf



# 进入容器的bash目录位于/ctf中
WORKDIR /ctf



# 由于pwntools执行debug，必须先提前开启tmux，因此直接设置初始执行程序为tmux即可
CMD ["tmux"]
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


  接着，在终端执行如下命令，构建**docker**镜像
  ```bash
docker build -t ctf .
  ```


 为了以后方便拉取，我们将其推送到**docker hub**中的个人账户即可，
  在终端中登录**docker hub**的账户，如下
  ```bash
docker logout
docker login
  ```

  最后，使用`tag`命令，将镜像名称进行规范化，并最终完成**docker hub**的推送，其命令如下
  ```bash
docker tag [local-repo] h4wk1ns/[glibc31] 
docker push h4wk1ns/pwn:[glibc31] 
  ```

  实际上在生成镜像的过程中，产生了非常多的中间镜像，可以将所有的镜像进行全部删除，之后在拉取，执行如下命令即可
  ```bash
docker rmi $(docker images -a -q)
  ```

### 运行容器
  当我们需要在当前目录下进入该环境时，执行如下命令
  ```bash
docker run -it -v $(pwd):/ctf pwn
  ```


### 删除容器
  当我们使用完环境，要删除该容器时，执行如下命令
  ```bash
docker rm $(docker ps -a | grep "ctf" | awk '{print $1}')
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
