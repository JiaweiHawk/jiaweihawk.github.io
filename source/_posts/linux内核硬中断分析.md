---
title: linux内核硬中断分析
date: 2023-08-23 21:35:16
tags: ['linux', '内核']
categories: ['内核']
---

# 前言

最近几天的面试刚好问到了内核中断子系统的相关问题，发现自己对这部分了解的不是非常清晰，因此面试后就读了读[Linux 6.5-rc6](https://github.com/torvalds/linux/tree/2ccdd1b13c591d306f0401d98dedc4bdcd02b421)相关代码。结果发现这部分的代码逻辑并不是非常清楚，所以记录下这篇博客，帮助梳理一下Linux内核的x86-64架构的中断子系统的硬中断部分的逻辑，方便以后快速查阅这部分代码细节。

整个内核中断子系统，简单可以分为**上半部(硬中断)**和**下半部**。上半部中断可以理解为从CPU被中断到CPU从中断栈中退出的部分，一般处理一些中断任务中非常紧急的工作；其余工作会推迟到下半部中断，包括**softirq**、**tasklet**和**workqueue**等。

这篇文章主要分析**上半部**中断，也就是**硬中断**。

# 整体流程

硬件中断整体流程如![硬件中断整体流程图](硬中断整体流程图.png)所示，整体可以分为硬件保存/恢复现场，保存/恢复上下文等步骤。

# 硬件保存/恢复现场

这部分实际上完全是硬件的工作，我们阅读[Intel® 64 and IA-32 Architectures Software Developer’s Manual 3A](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)手册的**6.12 EXCEPTION AND INTERRUPT HANDLING**章节即可。

对于保存现场来说，硬件主要做了如下工作
1. 如果从用户态中断，切换到CPU对应的**trampoline栈**上。该中断栈地址存储在**TSS**的**sp0**或**IST**中，分别在[cpu_init()](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/kernel/cpu/common.c#L2263)和[cpu_init_exception_handling()](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/kernel/cpu/common.c#L2204)中初始化。
2. 将现场(即**SS**、**RSP**、**RFLAGS**、**CS**、**RIP**和**Error Code**)保存在**当前栈**上，如![用户态和内核态中断下保存现场示意图](保存现场.png)所示

根据中断信号的向量号，从![IDT](IDTR与IDT.png)中查找对应的中断处理函数并执行即可。**IDT**分多次设置，但原理是类似的，如[idt_setup_traps()](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/idt.c#L226)所示。

对于恢复现场来说，基本是保存现场的逆操作，这里就不赘述了。

# 中断入口声明/定义

前面分析到，CPU会从**IDT**中找到中断信号对应的**中断门**，然后执行其中中断处理函数。而这个中断处理函数的定义和声明非常的不直观，这里分析一下，方便以后阅读代码细节。

## 中断门

一般中断门使用**INTG**宏进行定义，如[Divide Error](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/kernel/idt.c#L84)所示

```c
// arch/x86/kernel/idt.c

#define G(_vector, _addr, _ist, _type, _dpl, _segment)	\
	{						\
		.vector		= _vector,		\
		.bits.ist	= _ist,			\
		.bits.type	= _type,		\
		.bits.dpl	= _dpl,			\
		.bits.p		= 1,			\
		.addr		= _addr,		\
		.segment	= _segment,		\
	}

/* Interrupt gate */
#define INTG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL0, __KERNEL_CS)

static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		asm_exc_divide_error),
    ...
};
```

因此，为了分析中断的具体处理逻辑， 我们需要知道**INTG**的中断处理函数的定义信息。

## 中断处理函数

实际上，Linux内核中，中断处理函数的声明和部分定义，都在[arch/x86/include/asm/idtentry.h](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h)中，感觉有一点点tricky。

整个部分是通过**__ASSEMBLY__**宏实现的。

因为中断处理函数包含多层wrapper，并且中间wrapper大部分都是C语言的，因此在[arch/x86/include/asm/idtentry.h](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h)中用```#ifndef __ASSEMBLY__```范围的```DECLARE_IDTENTRY```宏来声明中断处理函数的所有wrapper。

而中断处理函数的最外层用于保存/恢复上下文，需要汇编实现，因此在[arch/x86/include/asm/idtentry.h](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h)中使用```#ifdef __ASSEMBLY__```范围的```DECLARE_IDTENTRY```宏来定义中断处理函数的最外层。其余部分的定义，可以使用C语言进行实现，则使用```#ifndef __ASSEMBLY__```范围的```DEFINE_IDTENTRY```宏来定义。

### 声明

在Linux内核静态定义了[符号](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L545-L699)，但是解析的宏是[#ifndef __ASSEMBLY__](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L10-L408)范围的```DECLARE_IDTENTRY```，主要如下所示

```c
/**
 * DECLARE_IDTENTRY - Declare functions for simple IDT entry points
 *		      No error code pushed by hardware
 * @vector:	Vector number (ignored for C)
 * @func:	Function name of the entry point
 *
 * Declares three functions:
 * - The ASM entry point: asm_##func
 * - The XEN PV trap entry point: xen_##func (maybe unused)
 * - The C handler called from the ASM entry point
 *
 * Note: This is the C variant of DECLARE_IDTENTRY(). As the name says it
 * declares the entry points for usage in C code. There is an ASM variant
 * as well which is used to emit the entry stubs in entry_32/64.S.
 */
#define DECLARE_IDTENTRY(vector, func)					\
	asmlinkage void asm_##func(void);				\
	asmlinkage void xen_asm_##func(void);				\
	__visible void func(struct pt_regs *regs)

...
```

在这些静态[符号](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L545-L699)中，还有一些其他的宏，但基本都是```DECLARE_IDTENTRY```的包装，主要声明```asm_##func```，```xen_asm_##func```和```func```三个wrapper。根据注释和前面的**中断门**分析可知，中断处理函数应当以```asm_##func```汇编函数为入口，在```asm_##func```汇编函数中还会调用```func```C语言函数。

### 定义

前面分析了中断函数的声明，这里再看看这些函数是如何定义的，这才是我们最关心的。


1. 对于最外层wrapper的定义，即```asm_##func```的定义，仍然在Linux内核静态定义的[符号](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L545-L699)，但是解析的宏是[#ifdef __ASSEMBLY__](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L408-L529)范围的```DECLARE_IDTENTRY```宏，主要如下所示
```c
/*
 * The ASM variants for DECLARE_IDTENTRY*() which emit the ASM entry stubs.
 */
#define DECLARE_IDTENTRY(vector, func)					\
	idtentry vector asm_##func func has_error_code=0
```
而```idtentry```宏实际上是定义在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/entry/entry_64.S)的汇编宏，主要用于**保存/恢复上下文**工作并调用对应的wrapper，在后面部分介绍。

2. 对于其余的wrapper的定义，即```func```，解析的宏是[#ifndef __ASSEMBLY__](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L10-L408)范围的```DEFINE_IDTENTRY```宏，主要如下所示
```c
/**
 * DEFINE_IDTENTRY - Emit code for simple IDT entry points
 * @func:	Function name of the entry point
 *
 * @func is called from ASM entry code with interrupts disabled.
 *
 * The macro is written so it acts as function definition. Append the
 * body with a pair of curly brackets.
 *
 * irqentry_enter() contains common code which has to be invoked before
 * arbitrary code in the body. irqentry_exit() contains common code
 * which has to run before returning to the low level assembly code.
 */
#define DEFINE_IDTENTRY(func)						\
static __always_inline void __##func(struct pt_regs *regs);		\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
									\
	instrumentation_begin();					\
	__##func (regs);						\
	instrumentation_end();						\
	irqentry_exit(regs, state);					\
}									\
									\
static __always_inline void __##func(struct pt_regs *regs)
```

## 保存/恢复上下文

根据前面的分析，最后中断处理函数的入口点是[idtentry](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/entry/entry_64.S#L373-L419)宏定义的函数，如下所示
```c
/**
 * idtentry_body - Macro to emit code calling the C function
 * @cfunc:		C function to be called
 * @has_error_code:	Hardware pushed error code on stack
 */
.macro idtentry_body cfunc has_error_code:req

	/*
	 * Call error_entry() and switch to the task stack if from userspace.
	 *
	 * When in XENPV, it is already in the task stack, and it can't fault
	 * for native_iret() nor native_load_gs_index() since XENPV uses its
	 * own pvops for IRET and load_gs_index().  And it doesn't need to
	 * switch the CR3.  So it can skip invoking error_entry().
	 */
	ALTERNATIVE "call error_entry; movq %rax, %rsp", \
		    "call xen_error_entry", X86_FEATURE_XENPV

	ENCODE_FRAME_POINTER
	UNWIND_HINT_REGS

	movq	%rsp, %rdi			/* pt_regs pointer into 1st argument*/

	.if \has_error_code == 1
		movq	ORIG_RAX(%rsp), %rsi	/* get error code into 2nd argument*/
		movq	$-1, ORIG_RAX(%rsp)	/* no syscall to restart */
	.endif

	call	\cfunc

	/* For some configurations \cfunc ends up being a noreturn. */
	REACHABLE

	jmp	error_return
.endm


/**
 * idtentry - Macro to generate entry stubs for simple IDT entries
 * @vector:		Vector number
 * @asmsym:		ASM symbol for the entry point
 * @cfunc:		C function to be called
 * @has_error_code:	Hardware pushed error code on stack
 *
 * The macro emits code to set up the kernel context for straight forward
 * and simple IDT entries. No IST stack, no paranoid entry checks.
 */
.macro idtentry vector asmsym cfunc has_error_code:req
SYM_CODE_START(\asmsym)

	.if \vector == X86_TRAP_BP
		/* #BP advances %rip to the next instruction */
		UNWIND_HINT_IRET_ENTRY offset=\has_error_code*8 signal=0
	.else
		UNWIND_HINT_IRET_ENTRY offset=\has_error_code*8
	.endif

	ENDBR
	ASM_CLAC
	cld

	.if \has_error_code == 0
		pushq	$-1			/* ORIG_RAX: no syscall to restart */
	.endif

	.if \vector == X86_TRAP_BP
		/*
		 * If coming from kernel space, create a 6-word gap to allow the
		 * int3 handler to emulate a call instruction.
		 */
		testb	$3, CS-ORIG_RAX(%rsp)
		jnz	.Lfrom_usermode_no_gap_\@
		.rept	6
		pushq	5*8(%rsp)
		.endr
		UNWIND_HINT_IRET_REGS offset=8
.Lfrom_usermode_no_gap_\@:
	.endif

	idtentry_body \cfunc \has_error_code

_ASM_NOKPROBE(\asmsym)
SYM_CODE_END(\asmsym)
.endm
```

到这里，剩下的代码就非常容易分析了，这里主要分析一下保存/恢复上下文的代码，即```idtentry_body```和```error_entry```逻辑

1. 在当前栈上构造[struct pt_regs](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/ptrace.h)结构体
2. 如果从用户态中断，将**trampoline栈**上的```struct pt_regs```移动到内核栈上，并切换到内核栈上

总的来说，最后的效果是，将新的[struct pt_regs](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/ptrace.h)**push**到当前进程的内核栈中。

恢复上下文应该是其逆操作，这里就不在赘述了。

# 栈切换

根据上面的分析，对于普通的中断来说，其最多涉及到**trampoline栈**和**内核栈**的切换，实际上还可能有**中断栈**的切换，如[DEFINE_IDTENTRY_IRQ](https://github.com/torvalds/linux/blob/2ccdd1b13c591d306f0401d98dedc4bdcd02b421/arch/x86/include/asm/idtentry.h#L179-L207)宏所示，其在```func```的wrapper中，添加```run_irq_on_irqstack_cond()```，完成**中断栈**的切换

# 参考

1. [Interrupts and Interrupt Handling](https://xinqiu.gitbooks.io/linux-insides-cn/content/Interrupts/linux-interrupts-1.html)
2. [x86下系统调用](http://sholck.top/archives/20.html)
3. [Linux 中断/异常的准备与退出](https://zhuanlan.zhihu.com/p/121630145)
4. [深入理解Linux中断机制](https://heapdump.cn/article/4514433)