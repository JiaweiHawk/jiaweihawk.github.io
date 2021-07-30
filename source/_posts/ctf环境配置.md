---
title: ctf环境配置
date: 2021-07-21 21:21:25
tags: ['信息安全','设置']
categories: ['信息安全']
---

# 前言

  为了方便，将CTF的环境配置进行总结，方便日后快速回复环境等


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

### 拉取Ubuntu镜像

  这里采用主流的**Ubuntu**镜像，作为PWN环境的宿主系统，其**Dockerfile**如下所示
  ```dockerfile
FROM UBUNTU:20.04
```

## GDB调试器

  再做*PWN*题目的时候，需要进行相关的调试，这就需要Linux中的**GDB**进行辅助。
  在终端中执行如下命令，完成gdb和32位环境

  ```bash
sudo pacman -S gdb libc6-dev-i386
  ```

### 插件配置

  为了方便调试*PWN*题目，需要为**GDB**安装相关插件，有**[peda](https://github.com/longld/peda)**、**[gef](https://github.com/hugsy/gef)**和**[pwndbg](https://github.com/pwndbg/pwndbg)**可以进行选择
  可以点击上面的链接，根据官网的指导进行相关的安装。由于个人对于**pwndbg**比较熟悉，因此以**pwndbg**的安装过程为例
  在终端中执行如下命令

  ```bash
sudo pacman -S pwndbg
echo "source /usr/share/pwndbg/gdbinit.py" > ~/.gdbinit
  ```

  对于**Ubuntu**来说，执行如下命令
  ```bash
git config --global url."https://hub.fastgit.org/".insteadOf "https://github.com/"

git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

git config --global --unset url."https://hub.fastgit.org/".insteadOf
  ```


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

  这是专门用于CTF和漏洞利用的Python库，可以在终端中执行如下命令进行安装
  ```bash
python2 -m pip -i https://pypi.tuna.tsinghua.edu.cn/simple install pwntools
  ```

  对于**Ubuntu**系统，其一般没有*pip2*，需要首先单独进行安装，执行如下命令
  ```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
  ```


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

if 'MANJARO' in platform.platform():
	context.terminal = ['konsole', '-e']

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
int 0x80		/*execve("/bin/sh")*/
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
		r = gdb.debug([execve_file] + argv, gdbscript, env = {'LD_LIBRARY_PATH' : './'})	# 首先加载当前目录下的动态库文件
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
