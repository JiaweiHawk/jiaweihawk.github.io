---
title: Linux终端
date: 2023-09-21 16:08:02
tags: ['linux', '内核']
categories: ['内核']
---

# 前言

之前就对TTY、PTY和PTS等概念比较迷惑，但因为知识储备问题并没有细究。最近刚好看到几篇相关的文章，觉得讲的非常不错，打算整理一下。

# 终端架构

目前Linux中终端的整体架构如下所示

![Linux终端架构](整体架构图.png)

其基本的工作流程如下所示：
1. 终端模拟器(Terminal Emulator)打开`/dev/ptmx`(pseudo terminal master multiplexer)设备，分配一个可用的ptm(pseudo terminal master)设备的文件描述符。如[ptmx_open()](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/drivers/tty/pty.c#L824-L849)所示，Linux内核在打开ptm设备时，也会自动的创建一个pts(pseudo terminal slave)设备，与该ptm一一对应。
2. 终端模拟器`fork()`子进程。子进程打开之前ptm设备对应的pts设备，并使用`dup()`将打开的pts设备的文件描述符设备为子进程的标准输入、标准输出和标准错误输出。
3. 子进程执行**bash**程序。此时，**bash**和终端模拟器通过伪终端(pty, pseudo terminal)进行通信，即终端模拟器通过ptm设备读取的数据是**bash**通过pts设备写入的数据，而**bash**通过pts设备读取的数据是终端模拟器通过ptm设备写入的数据。

# 发展历史

初看整个终端架构，大部分人都会觉得其过于复杂。为什么要引入pty概念呢，不能通过内核中的管道等机制实现终端模拟器和**bash**的通信吗？
实际上，这个架构的形成是因为Linux内核需要保持对早期终端设备的兼容性，整个终端设备的发展历史如下所示：

## 电传打字机

电传打字机(Teletype, tty)是早期的计算机输入输出设备，如![借用Waynerv大佬的图](电传打字机.jpg)所示。

那时候因为计算机很昂贵，所以不存在个人电脑一说，都是服务器-终端架构(类似于现在的云电脑，属于是殊途同归了)。即电传打字机通过两条线缆连接到计算机的UART(Universal Asynchronous Receiver and Transmitter)接口，一条线缆传输电传打字机键盘输入的信息到服务器，一条线缆传输服务器的输出信号到电传打字机，整个系统架构如![tty整体架构提](tty整体架构图.png)所示。

整个UART驱动、Line Discipline模块和TTY驱动共同组成了一个TTY，其整体工作流程如下所示
1. 在电传打字机上按下按钮并产生电信号，电信号会通过线缆传送到服务器
2. 服务器的UART驱动会将电缆传送的电信号转换为ASCII字符并交给Line Discipline模块处理
3. 如[__receive_buf()](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/drivers/tty/n_tty.c#L1592-L1631)所示，Line Discipline模块会缓存所有的ASCII字符并解析特殊字符，一直等到遇到指定字符(^M, ^Z, ^C...)才会将相关数据或信号传递给tty core驱动或者TTY进程组
4. tty core驱动将Line Discipine模块传递的数据通过标准输入传递给程序处理
5. 程序将要输出的数据写入到标准输出中，传递到tty core驱动
6. tty core驱动将程序输出的数据写入到Line Discipline模块的临时缓冲区，然后传递给UART驱动进行处理
7. UART驱动会将Line Discipline模块传递的数据，转换为电信号并通过线缆传送到电传打字机

可以看到，在这个时期，这个架构是比较合理的。而内核为了保持对这个时期终端设备的兼容性，这个架构的很多组件在现有的架构中仍然被保留了下来。

## 虚拟控制台

![Linux虚拟控制台](虚拟控制台.png)
随着时代的发展，个人电脑蓬勃发展，显示器和键盘成为计算机主流的输入输出设备，UART和电传打字机已经不复存在。为了在保持兼容性的基础上适应时代变化，Linu内核通过软件实现模拟出vt(虚拟控制台，没有什么问题是多加一个抽象层不能解决的)，并将计算机连接的键盘和显示器作为虚拟控制台实际的输入输出即可，其架构如![虚拟控制台架构](虚拟控制台架构.png)所示

可以看到，和电传打字机时期的终端架构没什么太大的变化，仅仅是将硬件的电传打字机终端通过内核模块进行软件抽象而已。

## 伪终端

虽然Linux通过内核的虚拟控制台实现了对终端硬件设备的模拟，但是虚拟控制台仍然无法适应如下的许多场景：
1. 用户希望使用由用户实现的终端模拟程序，以拓展终端的功能，比如界面美化等功能。
2. 用户希望实现通过网络访问远程主机上的面向终端的程序(如`vi`等)。这些程序需要执行一些面向终端的操作，如通过termios接口设置终端的`icanon`等设置，从而实现终端对前台job的控制等。因此无法简单通过管道等机制进行通信，需要某种机制能接入当前的tty系统。

因此，为了在保持兼容性的前提下，满足如上的需求，则产生了最开头介绍的架构，如![伪终端架构](整体架构图.png)所示。

# 参考

1. [Unix 终端系统（TTY）是如何工作的](https://waynerv.com/posts/how-tty-system-works/)
2. [到底什么是标准输入输出](https://ytcoode.io/article/到底什么是标准输入输出/index.html)
3. [Linux TTY framework(3)_从应用的角度看TTY设备](http://www.wowotech.net/tty_framework/application_view.html)
4. [Linux 的伪终端的基本原理 及其在远程登录（SSH，telnet等）中的应用](https://www.cnblogs.com/zzdyyy/p/7538077.html)
5. [TTY 到底是什么？](https://www.kawabangga.com/posts/4515)