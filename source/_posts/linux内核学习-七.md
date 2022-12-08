---
title: linux内核学习-七
date: 2022-04-26 14:28:21
tags: ['linux', '内核']
categories: ['内核']
---

# 前言

前面的博客简单分析了Linux内核处理**中断**和**异常**的方法。
而Linux内核处理系统调用的机制，与处理中断和异常的机制十分相似，这里来介绍一下。


# 系统调用处理程序及服务例程

系统调用处理程序和其他的异常处理程序机制类似，其执行下述操作
1. 在内核态栈保存大部分寄存器的内容
2. 调用名为**系统调用服务例程**(System Call Service Routine)的相应C函数，从而进行处理
3. 用保存在内核栈中的值加载寄存器，CPU从内核态切换回到用户态

其具体关系如下图所示
![系统调用示意图](系统调用示意图.png)

正如前面分析的，Linux内核处理系统调用的机制和处理中断和异常的机制十分相似——其将**系统调用号**和**系统调用服务例程**，以数组的形式进行管理。从而根据相关的系统调用号，可以方便的找到对应的**handler**

该数组(**sys_call_table**)定义于[arch/x86/entry/syscall_64.c](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/syscall_64.c#L16)，其每个元素的定义是通过位于[scripts/syscalltbl.sh](https://elixir.bootlin.com/linux/v5.17/source/scripts/syscalltbl.sh)的**syscalltbl.sh**脚本，读取位于[arch/x86/entry/syscalls/syscall_64.tbl](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/syscalls/syscall_64.tbl)的**syscall_64.tbl**设置文件生成的

最终生成的数组定义样例如下所示
```c
// /arch/x86/entry/syscall_64.c

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL

#define __SYSCALL(nr, sym) __x64_##sym,
asmlinkage const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};


// arch/x86/include/generated/asm/syscalls_64.h
__SYSCALL(0, sys_read)
__SYSCALL(1, sys_write)
__SYSCALL(2, sys_open)
...
```

Linux内核在[include/linux/syscalls.h](https://elixir.bootlin.com/linux/v5.17/source/include/linux/syscalls.h#L315)中给出了系统调用及其信息，而具体的实现则是通过**SYSCALL_DEFINEx**宏和位于[arch/x86/include/asm/syscall_wrapper.h](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/include/asm/syscall_wrapper.h#L93)的**__SYSCALL_DEFINEx**宏包装的以**\_\_x64\_**为前缀的符号。其包装调用如下所示
```c
__x64_sys_$name
    __se_sys_$name
        __do_sys$name
```


# 进入和退出系统调用


## 进入系统调用
根据[intel手册](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)的1871页，其详细描述了64位的**syscall**指令，如下图所示
![syscall指令](syscall指令.png)

在**syscall**指令中，硬件会执行一系列相关的操作，从而跳转到系统调用处理进程的入口，会涉及到**模块集寄存器**，其在[arch/x86/kernel/cpu/common.c](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/kernel/cpu/common.c#L1802)的**void syscall_init(void)**函数中进行初始化。**syscall**指令将**MSR_STAR**的`47:32`值作为**CS**和**SS**段选择寄存器的值，将**MSR_LSTAR**的值作为**rip**寄存器的值。其将**返回地址**保存在**rcx**寄存器中，**rflags**状态保存在**r11**寄存器中，然后执行位于[arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/entry_64.S#L87)的**entry_SYSCALL_64**函数。其化简后的逻辑如下所示

```asm
UNWIND_HINT_EMPTY

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_safe_stack, SYM_L_GLOBAL)

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	movq	%rsp, %rdi
	/* Sign extend the lower 32bit as syscall numbers are treated as int */
	movslq	%eax, %rsi
	call	do_syscall_64		/* returns with IRQs disabled */
```

其中，**SWITCH_TO_KERNEL_CR3**、**PUSH_AND_CLEAR_REGS**等符号位于[arch/x86/entry/calling.h](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/calling.h)中
其基本思路就是构造**struct pt_regs**结构体，并作为相关参数传递给**do_syscall_64**函数即可。最终**struct pt_regs**结构体内容如下所示
![内核态栈布局](内核态栈布局.png)

## 执行系统调用服务例程

Linux内核通过位于[arch/x86/entry/common.c](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/common.c#L73)的**__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)**函数，最终调用相关的系统调用服务例程，从而完成系统调用。其化简后的逻辑如下所示
```c
__visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
{
	add_random_kstack_offset();
	nr = syscall_enter_from_user_mode(regs, nr);

	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
	}

	syscall_exit_to_user_mode(regs);
}
```

其基本思路就是根据系统调用号，从**sys_call_table**中找到**handler**地址，并执行即可


## 退出系统调用


即返回[arch/x86/entry/entry_64.S](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/entry_64.S#L125)的**entry_SYSCALL_64**符号剩余部分即可。其化简后的逻辑如下所示
```asm
	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11

	cmpq	%rcx, %r11	/* SYSRET requires RCX == RIP */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 *
	 * Change top bits to match most significant bit (47th or 56th bit
	 * depending on paging mode) in the address.
	 */
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx

	/* If this changed %rcx, it was not canonical */
	cmpq	%rcx, %r11
	jne	swapgs_restore_regs_and_return_to_usermode

	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

	movq	R11(%rsp), %r11
	cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * SYSCALL clears RF when it saves RFLAGS in R11 and SYSRET cannot
	 * restore RF properly. If the slowpath sets it for whatever reason, we
	 * need to restore it correctly.
	 *
	 * SYSRET can restore TF, but unlike IRET, restoring TF results in a
	 * trap from userspace immediately after SYSRET.  This would cause an
	 * infinite loop whenever #DB happens with register state that satisfies
	 * the opportunistic SYSRET conditions.  For example, single-stepping
	 * this user code:
	 *
	 *           movq	$stuck_here, %rcx
	 *           pushfq
	 *           popq %r11
	 *   stuck_here:
	 *
	 * would never get past 'stuck_here'.
	 */
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
	jnz	swapgs_restore_regs_and_return_to_usermode

	/* nothing to check for RSP */

	cmpq	$__USER_DS, SS(%rsp)		/* SS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * We win! This label is here just for ease of understanding
	 * perf profiles. Nothing jumps here.
	 */
syscall_return_via_sysret:
	/* rcx and r11 are already restored (see code above) */
	POP_REGS pop_rdi=0 skip_r11rcx=1

	/*
	 * Now all regs are restored except RSP and RDI.
	 * Save old stack pointer and switch to trampoline stack.
	 */
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_EMPTY

	pushq	RSP-RDI(%rdi)	/* RSP */
	pushq	(%rdi)		/* RDI */

	/*
	 * We are on the trampoline stack.  All regs except RDI are live.
	 * We can do future final exit work right here.
	 */
	STACKLEAK_ERASE_NOCLOBBER

	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	popq	%rdi
	popq	%rsp
	swapgs
	sysretq
```
其中，**SWITCH_TO_USER_CR3_STACK**、**POP_REGS**等符号位于[arch/x86/entry/calling.h](https://elixir.bootlin.com/linux/v5.17/source/arch/x86/entry/calling.h)中。
其大体思路就是进行一系列的检查，恢复关键的通用寄存器，然后执行**rsp**寄存器，最后调用**sysretq**指令(忽略错误处理和栈切换等介绍)。

根据[intel手册](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)的1880页，其详细描述了64位的**sysret**指令，如下图所示
![syscall指令](syscall指令.png)

**sysret**指令将**MSR_STAR**的`63:48`值作为**CS**和**SS**段选择寄存器的值，从**rcx**恢复**rip**寄存器的值，从**r11**恢复**rflags**寄存器。

# 参考

> 1. https://xinqiu.gitbooks.io/linux-insides-cn/content/SysCall/
> 2. https://blog.limx.dev/post/linux-kernel-practice-hijack-syscall/
> 3. https://blog.csdn.net/weixin_42915431/article/details/105747994