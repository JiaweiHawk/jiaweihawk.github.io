---
title: ctf环境配置
date: 2021-07-21 21:21:25
tags: ['信息安全','设置']
categories: ['信息安全']
---

# 前言

  为了方便，将CTF的环境配置进行总结，方便日后快速回复环境等


# 二进制

## GDB调试器

  再做*PWN*题目的时候，需要进行相关的调试，这就需要Linux中的**GDB**进行辅助。
  在终端中执行如下命令，完成gdb的安装
  ```bash
sudo pacman -S gdb
```

### 插件配置

  为了方便调试*PWN*题目，需要为**GDB**安装相关插件，有**[peda](https://github.com/longld/peda)**、**[gef](https://github.com/hugsy/gef)**和**[pwndbg](https://github.com/pwndbg/pwndbg)**可以进行选择
  可以点击上面的链接，根据官网的指导进行相关的安装。由于个人对于**pwndbg**比较熟悉，因此以**pwndbg**的安装过程为例
  在终端中执行如下命令
  ```bash
sudo pacman -S pwndbg
echo "source /usr/share/pwndbg/gdbinit.py" > ~/.gdbinit
```


### 常用命令

  **GDB**及其插件中提供了大量的操作，方便进行调试程序，在[GDB教程资源](http://www.gnu.org/software/gdb/documentation/)和[pwndbg教程](https://browserpwndbg.readthedocs.io/en/docs/commands/misc/pwndbg/)中有详细的信息，这里简单介绍几个
  1. `starti`，该命令将程序执行到真正的入口处，并停止等待后续**DEBUG**命令
  2. `call [function]`，直接调用`function`函数执行
  3. `break [address] if [condition]`，即当条件`condition`满足时，程序会在执行到`address`时停止
  4. `break *$rebase(address)`，即在装载基地址偏移`address`设立断点
  5. `dprintf *$rebase(address) "%d\n", $rax`，即当执行到`*$rebase(address)`地址处，输出相关的格式信息

### 命令执行

  除了手动一条一条命令的进行交互，也可以通过命令行，按照提前给定的指令依次执行，如下所示
  ```bash
gdb [file] -ex [command1] -ex [command2] ...
```
  之后，gdb加载给定的目标程序，并按照参数顺序，依次在**GDB**中执行参数中传递的命令



## pwntools库

  这是专门用于CTF和漏洞利用的Python库，可以在终端中执行如下命令进行安装
  ```bash
pip2 install pwntools
```


### PWN模板

  为了方便*PWN*，这里专门给出一个标准脚本，可以稍加修改即可用于任何不同的*PWN*题目
  ```python
#!/usr/bin/python2
# -*- coding:utf-8 -*-
from pwn import *
import os
import sys

'''
	待修改数据
'''
context(log_level = 'debug', arch = 'amd64', os = 'linux')
execve_file = None
lib_file = None
gdbscript = '''starti
'''




'''
	这里给出asm 汇编->机器代码的相关样例
'''
shell = asm('''
mov	rbx, %d		#rbx = "/bin/sh"
push	rbx
push	rsp
pop	rdi		#rdi -> "/bin/sh"
xor	esi, esi	#esi -> NULL
xor	edx, edx	#edx -> NULL
push	0x3b
pop	rax		#rax = 0x3b
syscall			#execve("/bin/sh")
'''%(u64('/bin/sh'.ljust(8, '\x00'))))




'''
	elf.plt[`symbol`] 获取elf文件中符号的plt地址
	elf.got[`symbol`] 获取elf文件中符号的got地址
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
while True:
	try:
		if 'd' in sys.argv:
			r = gdb.debug(execve_file, gdbinit)
		else:
			r = remote(sys.argv[1], sys.argv[2])

		r.recv(timeout = 1)
		r.interactive()
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
