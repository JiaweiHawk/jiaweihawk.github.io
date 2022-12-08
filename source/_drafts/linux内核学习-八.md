---
title: linux内核学习-八
date: 2022-04-28 13:25:07
tags: ['linux', '内核']
categories: ['内核']
---

# 前言

本篇博客将研究Linux内核的信号机制
信号机制一开始用于用户态进程间的通信，现在也被内核用于通知进程所发生的事件

# 信号简介

信号(signal)是很短的消息，可以被发送到一个进程或一个进程组。其发送的信息通常是一个数，以此标识信号。

## 信号的作用

使用信号的两个主要目的是
1. 让进程知道已经发生了一个特定的事件
2. 强迫进程执行自己代码中的信号处理程序

## 信号 

基于80x86架构的Linux内核所处理的信号定义与[arch/x86/include/uapi/asm/signal.h](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/include/uapi/asm/signal.h#L23)

| 编号 | 信号名称 | 缺省操作 | 解释 | POSIX |
| :-: | :-: | :-: | :-: | :-: |
| 1 | SIGHUP | Terminate | 挂起控制终端或进程 | 是 |
| 2 | SIGINT | Terminate | 来自键盘的中断 | 是 |
| 3 | SIGQUIT | Dump | 从键盘退出 | 是 |
| 4 | SIGILL | Dump | 非法指令 | 是 |
| 5 | SIGTRAP | Dump | 追踪的断点 | 否 |
| 6 | SIGABRT | Dump | 异常结束 | 是 |
| 6 | SIGIOT | Dump | 等价于SIGABRT | 否 |
| 7 | SIGBUS | Dump | 总线错误 | 否 |
| 8 | SIGFPE | Dump | 浮点异常 | 是 |
| 9 | SIGKILL | Terminate | 强迫进程终止 | 是 |
| 10 | SIGUSR1 | Terminate | 对进程可用 | 是 |
| 11 | SIGSEGV | Dump | 无效的内存引用 | 是 |
| 12 | SIGUSR2 | Terminate | 对进程可用 | 是 |
| 13 | SIGPIPE | Terminate | 向无读者的管道写 | 是 |
| 14 | SIGALRM | Terminate | 实时定时器时钟 | 是 |
| 15 | SIGTERM | Terminate | 进程终止 | 是 |
| 16 | SIGSTKFLT | Terminate | 协处理器栈错误 | 否 |
| 17 | SIGCHLD | Ignore | 子进程停止、结束或在被跟踪时，获得信号 | 是 |
| 18 | SIGCONT | Continue | 如果已停止，则恢复执行 | 是 |
| 19 | SIGSTOP | Stop | 停止进程执行 | 是 |
| 20 | SIGTSTP | Stop | 从tty发出停止进程 | 是 |
| 21 | SIGTTIN | Stop | 后台进程请求输入 | 是 |
| 22 | SIGTTOU | Stop | 后台进程请求输出 | 是 |
| 23 | SIGURG | Ignore | 套接字上的紧急条件 | 是 |
| 24 | SIGXCPU | Dump | 超过CPU时限 | 否 |
| 25 | SIGXFSZ | Dump | 超过文件大小的限制 | 否 | 
| 26 | SIGVTALRM | Terminate | 虚拟定时器时钟 | 否 |
| 27 | SIGPROF | Terminate | 概况定时器时钟 | 否 |
| 28 | SIGWINCH | Ignore | 窗口调整大小 | 否 |
| 29 | SIGIO | Terminate | I/O现在可能发生 | 否 |
| 30 | SIGPWR | Terminate | 电源供给失效 | 否 |
| 31 | SIGSYS | Dump | 坏的系统调用 | 否 |
| 31 | SIGUNUSED | Dump | 等价于SIGSYS | 否 |

## 信号处理

信号的一个重要特点就是可以随时被发送给状态进程不可预知的进程。如果信号发送给非运行进程，则该信号需要由内核保存，直到该进程恢复执行为止。

因此，内核将信号处理的流程划分为两个不同阶段
1. 信号产生
  内核更新目标进程的数据结构，标识该信号已被发送
2. 信号传递
  内核强迫目标进程通过以下方式，对信号做出反应：或改变目标进程的执行状态，或开始执行一个特定的信号处理程序，或两者都是

每个所产生的信号至多被传递一次，并且一旦被传递出去，目标进程描述符中有关该信号的所有信息都被取消。

对于已经产生，但并没有被传递的信号，被称为**挂起信号**(pending signal)。任何时候，一个进程仅存在给定类型的一个挂起信号，同一进程同种类型的其他信号不会排队，只是简单地被丢弃。

一般来说，信号处理会有如下性质
1. 信号通常只被当前正运行的进程传递(即由current进程传递)
2. 给定类型的信号，可以由进程选择性地阻塞。在这种情况下，在取消阻塞前，该进程将不接受这个信号
3. 当进程执行一个信号处理函数时，通常**屏蔽**相应的信号，直到处理程序结束。因此，信号处理程序不必是可重入的

而上述描述的信号处理特征，要求内核必须
1. 记住每个进程阻塞了那些信号
2. 当从内核态切换到用户态时，对任何一个进程都要检查是否有信号到达
3. 处理信号，即信号可能在进程运行期间的任意时刻，请求把进程切换到一个信号处理函数，并在该函数返回以后恢复原来执行的上下文


## 信号传递

如果进程对一个信号阻塞，则其不会被传递；只有在进程解除相应信号的阻塞后，进程才会传递对应的信号

进程以下列三种方式之一，对信号做出传递
1. 显示地忽略信号。
2. 执行与信号相关的缺省操作
  - Terminate
    进程被终止(杀死)
  - Dump
    进程被终止(杀死)，并且，如果可能，创建包含进程执行上下文的核心转储文件
  - Ignore
    信号被忽略
  - Stop
    进程被停止，即把进程置为**TASK_STOPPED**状态
  - Continue
    如果进程被停止，则将其状态设置为**TASK_RUNNING**状态
3. 调用相应的信号处理函数，捕获信号

需要注意的是，**SIGKILL**和**SIGSTOP**信号不可以被显示地忽略、捕获或阻塞，也就是其通常必须执行相应的缺省操作。

## 与信号相关的数据结构

Linux内核需要追踪当前什么信号正在挂起或被屏蔽，以及每个线程组是如何处理所有信号的。Linux内核中使用多个数据结构进行管理，其关系如下图所示
![信号相关的数据结构关系](信号数据结构关系.png)

### struct task_struct

Linux内核位于[include/linux/sched.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/sched.h#L728)的进程描述符中，包含诸多当前进程的相关信号信息。该结构体的重要的相关字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| struct signal_struct * | signal | 指向进程的信号描述符的指针 |
| struct sighand_struct __rcu * | sighand | 指向进程的信号处理程序描述符的指针 |
| sigset_t | blocked | 被阻塞信号的掩码 |
| sigset_t | real_blocked | 被阻塞信号的临时掩码 |
| struct sigpending | pending | 存放私有挂起信号的数据结构 |
| unsigned long | sas_ss_sp | 信号处理程序备用堆栈的地址 |
| size_t | sas_ss_size | 信号处理程序备用堆栈的大小 |


### struct signal_struct

Linux内核使用位于[include/linux/sched/signal.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/sched/signal.h#L93)的信号描述符，用来描述进程组共享的挂起信号和一些进程组的与信号处理关系不那么密切的资源。总而言之，信号描述符被属于同一线程组的所有进程共享，对属于同一线程组的每个进程而言，信号描述符中的字段必须都是相同的。该结构体的重要字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| refcount_t | sigcnt | 信号描述符的使用计数器 |
| atomic_t | live | 线程组中活动进程的数量 |
| wait_queue_head_t | wait_chldexit | 在系统调用**wait4()**中睡眠的进程的等待队列 |
| struct task_struct * | curr_target | 接受信号的线程组中最后一个进程的进程描述符 |
| struct sigpending | shared_pending | 存放共享挂起的信号的数据结构 |
| int | group_exit_code | 线程组的进程终止代码 |
| int | notify_count | 在杀死整个线程组时使用 |
| struct task_struct * | group_exec_task | 在杀死整个线程组时使用 |
| int | group_stop_count | 在停止整个线程组的时候使用 |


### struct sighand_struct

Linux内核使用位于[include/linux/sched/signal.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/sched/signal.h#L20)的信号处理程序描述符，从而描述线程组的每个信号必须怎样被处理。该结构体的重要字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| refcount_t | count | 信号处理程序描述符的使用计数器 |
| struct k_sigaction[64] | action | 线程组在传递信号时，所执行操作的结构数组 |


### struct k_sigaction

由于信号处理的相关特性与体系结构有关，因此Linux内核使用位于[include/linux/signal_types.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/signal_types.h#L51)的**struct k_sigaction**，从而即包含对用户态进程所隐藏的特性，亦包含用户态进程熟悉的**struct sigaction**结构。
在80x86体系下，信号处理的所有特性都对用户态进程可见，因此**struct k_sigaction**包装，实际使用位于[arch/x86/include/uapi/asm/signal.h](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/include/uapi/asm/signal.h#L94)的**struct sigaction**。该结构体的重要字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| __sighandler_t | sa_handler | 指定要执行操作的类型<br>可以是函数指针，也可以是SIG_DFL(缺省操作)或SIG_IGN(忽略信号) |
| sigset_t | sa_mask | 指定当前信号处理程序运行时，要屏蔽掉的信号 |
| unsigned long | sa_flags | 指定必须如何处理该信号 |

### struct sigpending

内核需要跟踪当前的线程组的挂起信号，线程组的挂起信号存储在如下两个队列中
1. 共享挂起信号队列。即信号描述符的**shared_pending**字段，存放整个线程组的挂起信号
2. 私有挂起信号队列。即进程描述符的**pending**字段，存放特定进程的挂起信号

而内核使用位于[include/linux/signal_types.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/signal_types.h#L32)的**struct sigpending**结构体来描述挂起信号队列。该结构体的重要字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| sigset_t | signal | 该挂起队列的信号位掩码 |
| struct list_head | list | 包含**struct sigqueue**的双向链表 |

而Linux内核使用位于[include/linux/signal_types.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/signal_types.h#L22)的**struct sigqueue**，作为挂起信号队列的元素类型。其重要的字段如下所示

| 类型 | 字段名称 | 描述 |
| :-: | :-: | :-: |
| struct list_head | list | 挂起队列双向链表的相关字段 |
| kernel_siginfo_t | info | 描述产生信号的事件<br>包括信号编号、发送信号者的标识等信息 |

# 产生信号

很多内核函数都可以产生信号，即根据需要，更新一个或多个进程的相关描述符。之后并不直接执行**信号传递**操作，而是可能根据信号的类型和相关目标进程的状态，唤醒一些进程，并促使这些进程接受信号

一般的，内核或另一个进程可以通过如下内核函数，为指定进程产生信号

| 函数名称 | 函数位置 | 说明 |
| :-: | :-: | :-: |
| send_sig | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1645) | 向单一进程发送信号 |
| send_sig_info | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1628) | 与**send_sig**类似，但还使用**siginfo_t**结构中的拓展信息 |
| force_sig | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1651) | 发送既不能被进程显式忽略，亦不能被进程阻塞的信号 |
| force_sig_info | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1356) | 与**force_sig**类似，只是还是用**siginfo_t**结构中的拓展信息 |
| SYSCALL_DEFINE2(tkill) | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L3970) | **tkill**的系统调用服务例程<br>向指定一个进程发送信号 |
| SYSCALL_DEFINE3(tgkill) | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L3954) | **tgkill**的系统调用服务例程<br>向指定线程发送信号 |

实际上，上述函数都是对于[kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1290)的**int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type)**函数的包装，将在后面进行具体分析

而内核或另一个进程，同样可以通过如下内核函数，为指定线程组产生信号

| 函数名称 | 函数位置 | 说明 |
| :-: | :-: | :-: |
| SYSCALL_DEFINE2(kill) | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L3773) | **kill**的系统调用服务例程<br>向指定进程(线程组)发送指定信号 |
| SYSCALL_DEFINE3(rt_sigqueueinfo) | [kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L3998) | **rt_sigqueueinfo**的系统调用服务例程<br>向指定线程组发送信号 |

实际上，上述函数都是对于[kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1435)的**int group_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type)**函数的包装，将在后面进行具体分析


## do_send_sig_info

Linux内核使用位于[kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1290)的**int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type)**函数，向单个指定进程发送信号。其化简后的逻辑如下所示

```c
int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p,
			enum pid_type type)
{
	unsigned long flags;
	int ret = -ESRCH;

	if (lock_task_sighand(p, &flags)) {
		ret = send_signal(sig, info, p, type);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}


static int send_signal(int sig, struct kernel_siginfo *info, struct task_struct *t,
			enum pid_type type)
{
	return __send_signal(sig, info, t, type, force);
}


static int __send_signal(int sig, struct kernel_siginfo *info, struct task_struct *t,
			enum pid_type type, bool force)
{
	if (!prepare_signal(sig, t, force))
		goto ret;

	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;

	/*
	 * Short-circuit ignored signals and support queuing
	 * exactly one non-rt signal, so that we can get more
	 * detailed information about the cause of the signal.
	 */
	if (legacy_queue(pending, sig))
		goto ret;

	/*
	 * Skip useless siginfo allocation for SIGKILL and kernel threads.
	 */
	if ((sig == SIGKILL) || (t->flags & PF_KTHREAD))
		goto out_set;

	/*
	 * Real-time signals must be queued if sent by sigqueue, or
	 * some other real-time mechanism.  It is implementation
	 * defined whether kill() does so.  We attempt to do so, on
	 * the principle of least surprise, but since kill is not
	 * allowed to fail with EAGAIN when low on memory we just
	 * make sure at least one signal gets delivered and don't
	 * pass on the info struct.
	 */
	if (sig < SIGRTMIN)
		override_rlimit = (is_si_special(info) || info->si_code >= 0);
	else
		override_rlimit = 0;

	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit, 0);

	if (q) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = task_tgid_nr_ns(current,
							task_active_pid_ns(t));
			rcu_read_lock();
			q->info.si_uid =
				from_kuid_munged(task_cred_xxx(t, user_ns),
						 current_uid());
			rcu_read_unlock();
			break;
		case (unsigned long) SEND_SIG_PRIV:
			clear_siginfo(&q->info);
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_KERNEL;
			q->info.si_pid = 0;
			q->info.si_uid = 0;
			break;
		default:
			copy_siginfo(&q->info, info);
			break;
		}
	}

out_set:
	signalfd_notify(t, sig);
	sigaddset(&pending->signal, sig);
	complete_signal(sig, t, type);
ret:
	trace_signal_generate(sig, info, t, type != PIDTYPE_PID, result);
	return ret;
}
```

其大体思路很简单，就是向指定的进程挂起信号队列中添加对应的信号元素即可(忽略诸多细节)。


## group_send_sig_info

Linux内核使用位于[kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L1435)的**int group_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type)**函数，向整个线程组发送信号。其化简后的逻辑如下所示

```c
int group_send_sig_info(int sig, struct kernel_siginfo *info,
			struct task_struct *p, enum pid_type type)
{
	ret = check_kill_permission(sig, info, p);

	if (!ret && sig)
		ret = do_send_sig_info(sig, info, p, type);

	return ret;
}
```

可以看到，其实际上就是前面**do_send_sig_info**的简单包装——原因也很简单，向指定进程发送信号和向整个线程组发送信号的大体逻辑基本一致，除了一个将信号添加至私有挂起信号队列中(进程描述符的**pending**字段)，另一个添加至共享挂起信号队列(信号描述符的**shared_pending**字段)中


# 传递信号

当内核根据前面的介绍，为相关的进程产生信号后。但是由于对应的进程不一定运行在CPU上，因此内核会延迟信号传递的任务。
而一般的，为了确保进程的挂起信号可以得到内核的处理，内核会在完成中断、异常或系统调用后，并在恢复用户态之前，检查是否存在挂起的信号，并调用位于[kernel/entry/common.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/entry/common.c#L143)的`static void handle_signal_work(struct pt_regs *regs, unsigned long ti_work)`函数~~(这个信号传递函数，甚至名称都和以前版本完全不一样，找了好久)~~


## 获取挂起信号

根据前面的介绍，内核会遍历处理所有的挂起信号。Linux内核使用位于[kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/kernel/signal.c#L2624)的**bool get_signal(struct ksignal *ksig)**函数，遍历所有的挂起信号。其函数调用栈如下所示
```
handle_signal_work(regs, ti_work)
			|
			+void arch_do_signal_or_restart(struct pt_regs *regs, bool has_signal)
											|
											+bool get_signal(struct ksignal *ksig)
```

~~不过居然在**get_signal**函数中执行信号的缺省handle，意料之外但是情理之中~~

其省略部分细节的代码如下所示
```c
bool get_signal(struct ksignal *ksig)
{

	for (;;) {
		/*
		 * Signals generated by the execution of an instruction
		 * need to be delivered before any other pending signals
		 * so that the instruction pointer in the signal stack
		 * frame points to the faulting instruction.
		 */
		type = PIDTYPE_PID;
		signr = dequeue_synchronous_signal(&ksig->info);
		if (!signr)
			signr = dequeue_signal(current, &current->blocked,
					       &ksig->info, &type);

		if (!signr)
			break; /* will return 0 */

		ka = &sighand->action[signr-1];

		if (ka->sa.sa_handler == SIG_IGN) /* Do nothing.  */
			continue;
		if (ka->sa.sa_handler != SIG_DFL) {
			/* Run the handler.  */
			ksig->ka = *ka;
			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;

			break; /* will return non-zero "signr" value */
		}

		/*
		 * Now we are doing the default action for this signal.
		 */
		if (sig_kernel_ignore(signr)) /* Default is nothing. */
			continue;

		/*
		 * Global init gets no signals it doesn't want.
		 * Container-init gets no signals it doesn't want from same
		 * container.
		 *
		 * Note that if global/container-init sees a sig_kernel_only()
		 * signal here, the signal must have been generated internally
		 * or must have come from an ancestor namespace. In either
		 * case, the signal cannot be dropped.
		 */
		if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
				!sig_kernel_only(signr))
			continue;

		if (sig_kernel_stop(signr)) {
			/*
			 * The default action is to stop all threads in
			 * the thread group.  The job control signals
			 * do nothing in an orphaned pgrp, but SIGSTOP
			 * always works.  Note that siglock needs to be
			 * dropped during the call to is_orphaned_pgrp()
			 * because of lock ordering with tasklist_lock.
			 * This allows an intervening SIGCONT to be posted.
			 * We need to check for that and bail out if necessary.
			 */
			if (signr != SIGSTOP) {
				spin_unlock_irq(&sighand->siglock);

				/* signals can be posted during this window */

				if (is_current_pgrp_orphaned())
					goto relock;

				spin_lock_irq(&sighand->siglock);
			}

			if (likely(do_signal_stop(ksig->info.si_signo))) {
				/* It released the siglock.  */
				goto relock;
			}

			/*
			 * We didn't actually stop, due to a race
			 * with SIGCONT or something like that.
			 */
			continue;
		}

		/*
		 * Anything else is fatal, maybe with a core dump.
		 */
		if (sig_kernel_coredump(signr)) {
			if (print_fatal_signals)
				print_fatal_signal(ksig->info.si_signo);
			proc_coredump_connector(current);
			/*
			 * If it was able to dump core, this kills all
			 * other threads in the group and synchronizes with
			 * their demise.  If we lost the race with another
			 * thread getting here, it set group_exit_code
			 * first and our do_group_exit call below will use
			 * that value and ignore the one we pass it.
			 */
			do_coredump(&ksig->info);
		}

		/*
		 * Death signals, no core dump.
		 */
		do_group_exit(ksig->info.si_signo);
		/* NOTREACHED */

	}
out:
	ksig->sig = signr;

	return ksig->sig > 0;
}
```

其基本思路就是遍历挂起的信号，并根据当前进程的进程描述符的**sighand**字段中的**action**信息，从而执行缺省操作，或返回执行用户自定义的**handler**


## 用户handler

由于可能需要执行**用户态**空间定义的信号handler，因此此过程涉及到频繁的**用户态**空间和**内核态**空间的转换，如下图所示

![调用用户handler栈变换](调用用户handler栈变换.png)
![调用用户handler流程](调用用户handler流程.png)

内核需要从内核态返回到用户态，执行**用户态**空间中定义的信号handler，之后回到**内核态**空间，并返回**中断**、**异常**或**系统调用**前的用户态上下文继续执行。

Linux内核的大体思路就是首先更改备份在**内核态**栈中的的**用户态**上下文**pt_regs**，然后覆盖该**用户态**上下文的执行流**(诸如ip字段)**为信号**handler**。当Linux内核从**内核态**返回到**用户态**时，其会从**内核态**栈恢复**用户态**上下文，从而执行**用户态**的信号handler。当执行完该handler后，其会再次陷入**内核态**，并恢复之前保存的原始**用户态**上下文，此时再次返回**用户态**，即返回到被**中断**、**异常**或**系统调用**打断前的**用户态**上下文


### 建立信号帧

根据前面的分析，Linux内核需要建立信号帧，用来备份**内核态**堆栈中保存的**用户态**上下文和设置相关执行流，其实现位于[arch/x86/kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/kernel/signal.c#L460)。其省略部分细节的逻辑如下所示

```c
static int __setup_rt_frame(int sig, struct ksignal *ksig,
			    sigset_t *set, struct pt_regs *regs)
{
	struct rt_sigframe __user *frame;

	frame = get_sigframe(&ksig->ka, regs, sizeof(struct rt_sigframe), &fp);
	uc_flags = frame_uc_flags(regs);

	/* Create the ucontext.  */
	unsafe_put_user(uc_flags, &frame->uc.uc_flags, Efault);
	unsafe_put_user(0, &frame->uc.uc_link, Efault);
	unsafe_save_altstack(&frame->uc.uc_stack, regs->sp, Efault);

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	unsafe_put_user(ksig->ka.sa.sa_restorer, &frame->pretcode, Efault);
	unsafe_put_sigcontext(&frame->uc.uc_mcontext, fp, regs, set, Efault);
	unsafe_put_sigmask(set, frame, Efault);
	user_access_end();

	/* Set up registers for signal handler */
	regs->di = sig;
	/* In case the signal handler was declared without prototypes */
	regs->ax = 0;

	if (ksig->ka.sa.sa_flags & SA_SIGINFO) {
		if (copy_siginfo_to_user(&frame->info, &ksig->info))
			return -EFAULT;
	}

	/* This also works for non SA_SIGINFO handlers because they expect the
	   next argument after the signal number on the stack. */
	regs->si = (unsigned long)&frame->info;
	regs->dx = (unsigned long)&frame->uc;
	regs->ip = (unsigned long) ksig->ka.sa.sa_handler;

	regs->sp = (unsigned long)frame;

	/*
	 * Set up the CS and SS registers to run signal handlers in
	 * 64-bit mode, even if the handler happens to be interrupting
	 * 32-bit or 16-bit code.
	 *
	 * SS is subtle.  In 64-bit mode, we don't need any particular
	 * SS descriptor, but we do need SS to be valid.  It's possible
	 * that the old SS is entirely bogus -- this can happen if the
	 * signal we're trying to deliver is #GP or #SS caused by a bad
	 * SS value.  We also have a compatibility issue here: DOSEMU
	 * relies on the contents of the SS register indicating the
	 * SS value at the time of the signal, even though that code in
	 * DOSEMU predates sigreturn's ability to restore SS.  (DOSEMU
	 * avoids relying on sigreturn to restore SS; instead it uses
	 * a trampoline.)  So we do our best: if the old SS was valid,
	 * we keep it.  Otherwise we replace it.
	 */
	regs->cs = __USER_CS;

}


static void __user *
get_sigframe(struct k_sigaction *ka, struct pt_regs *regs, size_t frame_size,
	     void __user **fpstate)
{
	unsigned long sp = regs->sp;
	sp = align_sigframe(sp - frame_size);
	return (void __user *)sp;
}
```

其基本思路就是在**内核态**堆栈保存的**用户态**栈上，分配一个[struct rt_sigframe](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/um/signal.c#L481)结构。并在该结构中备份**用户态**上下文，并更改当前的**用户态**上下文为信号handler的上下文即可。

其内核态堆栈变化如下所示
![信号处理堆栈变换](信号处理堆栈变化.png)


### 执行过程

实际上，当有了**内核态**堆栈和保存的**用户态**堆栈后，就可以静态的分析其执行过程了。

当其退出到**用户态**空间时，其从**内核态**堆栈中恢复上下文。
其中关键寄存器的值分别如下所示
- **rip**为**用户态**空间定义的信号handler
- **rdi**为信号标识值
- **rsi**为**frame->info**，也就是[struct siginfo](https://elixir.bootlin.com/linux/v5.17/source/include/uapi/asm-generic/siginfo.h#L138)结构体
- **rdx**为**frame->uc**，也就是[struct ucontext](https://elixir.bootlin.com/linux/v5.17/source/include/uapi/asm-generic/ucontext.h#L5)结构体
- **rsp**为伪造的**frame**，其栈顶即为handler执行完的返回地址**frame->pretcode**

首先考虑handler，Linux kernel定义位于[include/uapi/asm-generic/signal-defs.h](https://elixir.bootlin.com/linux/v5.17/source/include/uapi/asm-generic/signal-defs.h#L83)，而glibc定义位于[source/bits/sigaction.h](https://elixir.bootlin.com/glibc/glibc-2.35/source/bits/sigaction.h#L41)。可以看到，Linux内核中传递的实参类型都符合函数形参类型

而当handler执行完后，其**返回地址**为**rsp**栈顶，也就是之前的**frame->pretcode**，即**ksig->ka.sa.sa_restorer**，其具体执行地址如下所示

![指令内容](pretcode指向指令.png)

实际上用户在注册handler，同样需要提供**sigaction**的**sa_restorer**，一般是**glibc**会将其覆盖为该指令地址。

实际上，也就是其首先执行用户定义的**handler**，然后执行**rt_sigreturn**系统调用


### 返回过程

根据前面分析，其最后会调用**rt_sigreturn**系统调用，恢复初始的上下文，并再次退回到**用户态**。
Linux内核将**rt_sigreturn**函数服务例程定义在[arch/x86/kernel/signal.c](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/kernel/signal.c#L657)

其化简后的逻辑如下所示
```c
SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe __user *frame;
	sigset_t set;
	unsigned long uc_flags;

	frame = (struct rt_sigframe __user *)(regs->sp - sizeof(long));
	if (!access_ok(frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(*(__u64 *)&set, (__u64 __user *)&frame->uc.uc_sigmask))
		goto badframe;
	if (__get_user(uc_flags, &frame->uc.uc_flags))
		goto badframe;

	set_current_blocked(&set);

	if (!restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
		goto badframe;

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->ax;

badframe:
	signal_fault(regs, frame, "rt_sigreturn");
	return 0;
}
```

可以看到，其大体思路就是从**用户态**堆栈中恢复保存的**内核态**上下文即可

# 参考

> 1. https://juejin.cn/post/7081189234245107742