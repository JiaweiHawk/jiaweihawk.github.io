---
title: LinuxFoundation mentorship
date: 2022-08-26 09:39:34
tags: ['linux', '杂谈']
categories: ['杂谈']
---

# Introduce

My name is **Jiawei Hawkins**, and I am in my second year for my master school life. I am really appreciated for being selected to participate in the **Linux kernel Bug Fixing Summer 2022**. This mentorship is really a good oppotunity to join the linux kernel community, I also have a much deeper understanding on linux kernel by analysing linux kernel bug.

# what I Learned

To be honest, I am really confused at the beginning of this mentorship. I only have little knowledge about linux kernel, I even don't know how to find the linux kernel bug, how to analyse the kernel bug, how to submit the patch.

Yet with the help of the **Shuah**, this mentorship, and the welcoming people in linux kernel mailing list, I was able to learn these basic concepts gradually.

At the beginning, this mentorship provides me with some tasks to finish. These well-designed tasks are really a excellent guideline, to help newbies build the basic environment to develop linux kernel, and dirty our hands to practise some basic scripts and commands in linux kernel.

What's more, there are also useful materials in the mentorship, which give me a more detailed tutorial on how to analyse bug and what should do to submit a patch to community.

And the **Shuah**'s office hours also helps me a lot. These discussions between **Shuah** and other mentees really broaden my horizons on different linux subsystem.

# what I fixed

The most challenging bug I fixed is '**WARNING: refcount bug in sk_psock_get (2)**', which is reported by the syzkaller. Because it is my first bug, so I meet lots of trouble when analysing and patching it.

This is a bug in linux net subsystem. Yet the problem is that I am not very familiar with the net subsystem.

But luckily, with the help of the bisect's output and gdb, One can know which code results this bug by setting the breakpoint at the function in bisect. Then we find that it is **smc_switch_to_fallback()** causing the bug.

To be more specific, during **SMC** fallback process in connect syscall, kernel will replaces TCP with **SMC**. In order to forward wakeup **SMC** socket waitqueue after fallback, kernel will sets **clcsk->sk_user_data** to origin **SMC** socket in **smc_fback_replace_callbacks()**.

Later, in **shutdown** syscall, kernel will calls **sk_psock_get()**, which treats the **clcsk->sk_user_data** as **psock** type, triggering the refcnt warning.

So, the root cause is that **SMC** and **psock**, both will use **sk_user_data** field. So they will mismatch this field easily.

So we can solve this bug by using another bit(defined as **SK_USER_DATA_PSOCK**) in **PTRMASK**, to mark whether **sk_user_data** points to a **psock** object or not.

# summary 

The past few months leave me a really unforgettable impression! I really gain a lot in the past months from this mentorship.

I have a much deeper understanding on linux kernel during analysing bug, especially for net and file subsystem in linux kernel. And the review and comments from the mailing list also give me how others think about the same problem, which really helps me understand linux kernel!

Thanks for **Shuah** and your mentorship. With the help of your office hours and materials, I can gradually contribue to linux kernel!