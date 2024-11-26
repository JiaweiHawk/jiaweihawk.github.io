---
title: glib的事件循环
date: 2024-11-07 17:03:28
tags: ['虚拟化']
categories: ['虚拟化']
---

# 前言

QEMU和libvirt等虚拟化组件的事件循环架构都是基于glib的事件循环机制实现的，这里一同分析一下

# glib

整个glib的事件循环架构由三个概念构成，即**GMainLoop**、**GMainContext**和**GSource**

## GSource

glib用[**GSource**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.h?ref_type=heads#L266-289)表示每一个需要处理的事件源，其源代码如下所示
```c
struct _GSourceFuncs
{
  GSourceFuncsPrepareFunc prepare; /* Can be NULL */
  GSourceFuncsCheckFunc check;     /* Can be NULL */
  GSourceFuncsDispatchFunc dispatch;
  GSourceFuncsFinalizeFunc finalize; /* Can be NULL */

  /*< private >*/
  /* For use by g_source_set_closure */
  GSourceFunc     closure_callback;
  GSourceDummyMarshal closure_marshal; /* Really is of type GClosureMarshal */
};

struct _GSource
{
  ...
  const GSourceFuncs *source_funcs;
  ...
  GMainContext *context;
  ...
  GSList *poll_fds;
  ...
};
```

其中的重点是**poll_fds**字段和**source_funcs**字段。

linux中的事件指的是等待某个资源，而**poll_fds**则保存了事件源所等待的资源，例如文件描述符等。当glib使用**poll**系统调用判断关联的资源可用时，即表明有事件到达。

而**source_funcs**描述了在事件循环中如何操作定义的事件源。其中**prepare**在**poll**之前调用，用来检查是否已经有事件到达或准备后续**poll**所需要的资源；**check**在**poll**之后调用，用来确认是否有事件到达；**dispatch**在事件到达后用来处理事件；**finalize**在事件源注销时用来清理相关的资源。其各个操作的状态图如下所示

![gsource状态机](gsource状态机.png)

在初始状态中，首先调用自定义的**prepare()**，完成**poll**前的资源准备，状态转换为**prepared**；然后**poll**，状态转换为**polling**；在**poll**结束后，调用自定义的**check()**，确认事件源中所有可用的关联资源，状态转换为**dispatching**；最后，对于可用的资源调用**dispatch()**，完成到达事件处理

这里我们自定义一个事件源，让其等待标准输入描述符资源，相关代码如下所示

```c
typedef struct GSourceInput {
    GSource source;
    GPollFD *fd;
} GSourceInput;

/* 对于文件描述符的资源，prepare通常返回FALSE，
 * 因为其必须等poll结束后才能知道是否需要处理事件
 * 这里设置poll调用阻塞的超时时间为1000 ms
 */
gboolean g_source_input_prepare(GSource *source, gint *timeout)
{
    *timeout = 1000;
    debug("g_source_input_prepare() = FALSE");
    return FALSE;
}

gboolean g_source_input_check(GSource *source)
{
    GSourceInput *g_source_input = (GSourceInput*)source;

    if (g_source_input->fd->revents & G_IO_IN) {
        debug("g_source_input_check() = TRUE");
        return TRUE;
    }

    debug("g_source_input_check() = FALSE");
    return FALSE;
}

gboolean g_source_input_dispatch(GSource *source,
            GSourceFunc callback, gpointer user_data)
{
    char ch;
    GSourceInput *g_source_input = (GSourceInput*)source;

    read(g_source_input->fd->fd, &ch, 1);
    debug("g_source_input_dispatch() = %c", ch);

    // 停止事件循环
    if (ch == 'x') {
        g_main_loop_quit((GMainLoop*)user_data);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

void g_source_input_finalize(GSource *source)
{
    GSourceInput *g_source_input = (GSourceInput*)source;
    g_source_remove_unix_fd(source, g_source_input->fd);
}

GSourceFuncs g_source_input_funcs = {
    .prepare = g_source_input_prepare,
    .check = g_source_input_check,
    .dispatch = g_source_input_dispatch,
    .finalize = g_source_input_finalize,
};

int main(void) {

    GSourceInput *g_source_input;
    struct termios term;

    g_source_input = (GSourceInput *)g_source_new(&g_source_input_funcs,
                        sizeof(GSourceInput));
    g_source_input->fd = g_source_add_unix_fd((GSource*)g_source_input,
                            STDIN_FILENO, G_IO_IN);
    ...
}
```
可以看到，定义事件源就是定义上述的**source_funcs**。具体的，**g_source_input_prepare()**设置后续**poll**的超时时间为1s；而**poll**结束后，**g_source_input_check()**通过检查相关标志位判断标准输入描述符是否有输入；如果有，则继续调用**g_source_input_dispatch()**完成事件处理

最终效果如下图所示
![自定义GSource效果图](gsource效果图.png)

## GMainContext

考虑到用户可能会在一个线程中同时处理多个事件源(例如I/O线程)，因此glib提供了[**GMainContext**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.c#L183-222)来简单的处理多个事件源，其结构如下所示
```c
struct _GMainContext
{
  ...
  GQueue source_lists;
  ...
};
```

其关键字段是**source_lists**，其将所有关联的事件源存储在该链表中，方便后续进行遍历

glib使用[**g_main_context_iteration()**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.c#L4333-4346)来便捷的对**GMainContext**下所有的**GSource**进行一轮事件循环，如下所示
```c
gboolean
g_main_context_iteration (GMainContext *context, gboolean may_block)
{
  ...
  retval = g_main_context_iterate_unlocked (context, may_block, TRUE, G_THREAD_SELF);
  ...
}

/* HOLDS context lock */
static gboolean
g_main_context_iterate_unlocked (GMainContext *context,
                                 gboolean      block,
                                 gboolean      dispatch,
                                 GThread      *self)
{
  ...
  if (!context->cached_poll_array)
    {
      context->cached_poll_array_size = context->n_poll_records;
      context->cached_poll_array = g_new (GPollFD, context->n_poll_records);
    }

  allocated_nfds = context->cached_poll_array_size;
  fds = context->cached_poll_array;

  g_main_context_prepare_unlocked (context, &max_priority);

  while ((nfds = g_main_context_query_unlocked (
              context, max_priority, &timeout_usec, fds,
              allocated_nfds)) > allocated_nfds)
    {
      g_free (fds);
      context->cached_poll_array_size = allocated_nfds = nfds;
      context->cached_poll_array = fds = g_new (GPollFD, nfds);
    }

  if (!block)
    timeout_usec = 0;

  g_main_context_poll_unlocked (context, timeout_usec, max_priority, fds, nfds);

  some_ready = g_main_context_check_unlocked (context, max_priority, fds, nfds);

  if (dispatch)
    g_main_context_dispatch_unlocked (context);
  ...
  return some_ready;
}
```

可以看到，其一次事件循环和前面[GSource章节](#gsource)介绍的单个事件源循环是一致的，即包括**prepare**、**poll**、**check**和**dispatch**等步骤，只是**GMainContext**是对其下的多个**GSource**进行操作，以[**g_main_context_prepare_unlocked()**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.c#L3694-3839)为例
```c
static gboolean
g_main_context_prepare_unlocked (GMainContext *context,
                                 gint         *priority)
{
  ...
  g_source_iter_init (&iter, context, TRUE);
  while (g_source_iter_next (&iter, &source))
    {
      gint64 source_timeout_usec = -1;

      if (!(source->flags & G_SOURCE_READY))
	{
	  gboolean result;
	  gboolean (* prepare) (GSource  *source,
                                gint     *timeout);

          prepare = source->source_funcs->prepare;

          if (prepare)
            {
              gint64 begin_time_nsec G_GNUC_UNUSED;
              int source_timeout_msec = -1;

              context->in_check_or_prepare++;
              UNLOCK_CONTEXT (context);

              begin_time_nsec = G_TRACE_CURRENT_TIME;

              result = (*prepare) (source, &source_timeout_msec);
              TRACE (GLIB_MAIN_AFTER_PREPARE (source, prepare, source_timeout_msec));

              source_timeout_usec = extend_timeout_to_usec (source_timeout_msec);

              g_trace_mark (begin_time_nsec, G_TRACE_CURRENT_TIME - begin_time_nsec,
                            "GLib", "GSource.prepare",
                            "%s ⇒ %s",
                            (g_source_get_name (source) != NULL) ? g_source_get_name (source) : "(unnamed)",
                            result ? "ready" : "unready");

              LOCK_CONTEXT (context);
              context->in_check_or_prepare--;
            }
          else
            result = FALSE;
        ...
	  if (result)
	    {
	      GSource *ready_source = source;

	      while (ready_source)
		{
		  ready_source->flags |= G_SOURCE_READY;
		  ready_source = ready_source->priv->parent_source;
		}
	    }
	}

      if (source->flags & G_SOURCE_READY)
	{
	  n_ready++;
	  current_priority = source->priority;
	  context->timeout_usec = 0;
	}

      if (source_timeout_usec >= 0)
        {
          if (context->timeout_usec < 0)
            context->timeout_usec = source_timeout_usec;
          else
            context->timeout_usec = MIN (context->timeout_usec, source_timeout_usec);
        }
    }
  g_source_iter_clear (&iter);
  ...
  return (n_ready > 0);
}
```
可以看到，其确实会调用每一个**GSource**的**prepare**函数指针并根据返回值进行相关操作

## GMainLoop

前面**GMainContext**仅仅提供了一次事件循环的接口，而glib使用[**GMainLoop**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.c#L232-237)进行多次的时间循环，其结构如下所示
```c
struct _GMainLoop
{
  GMainContext *context;
  gboolean is_running; /* (atomic) */
  gint ref_count;  /* (atomic) */
};
```

其使用[**g_main_loop_run()**](https://gitlab.gnome.org/GNOME/glib/-/blob/main/glib/gmain.c#L4429-4486)作为多次循环的接口，如下所示
```c
void
g_main_loop_run (GMainLoop *loop)
{
  ...
  g_atomic_int_set (&loop->is_running, TRUE);
  while (g_atomic_int_get (&loop->is_running))
    g_main_context_iterate_unlocked (loop->context, TRUE, TRUE, self);

  g_main_context_release_unlocked (loop->context);

  UNLOCK_CONTEXT (loop->context);
  ...
}
```

将前面[自定义的GSource](#gsource)结合其余部分进行整理，即可得到[glib的事件循环demo](./glib_event_loop.tar.gz)，执行`tar -gxvf glib_event_loop.tar.gz && make -C glib_event_loop`即可完成编译运行

# qemu

Qemu使用事件循环机制可以提高设备模拟的效率。具体的，Qemu的线程模型如下所示

![qemu线程模型](qemu线程模型.png)

Qemu中有若干个线程，其中main loop线程会不断监听各种事件，iothread会单独用来处理设备I/O操作，每一个guest cpu都会有一个vcpu线程用来执行guest代码和设备模拟，还有一些诸如热迁移migration线程和远程连接VNC线程等辅助线程

当guest访问设备时，vcpu线程会捕获该访问并在vcpu线程中调用设备的相关回调函数。在设备的回调函数返回之前，vcpu线程无法恢复guest的代码执行，即设备的模拟会阻塞vcpu线程的执行

得益于事件循环机制，当guest访问设备时，vcpu线程会将设备模拟的耗时操作通过事件循环机制通知主循环线程或iothread线程，然后立即返回guest的代码执行。这样避免了设备模拟对于vcpu线程的阻塞，提高了guest的性能

## 自定义GSource

Qemu基于glib的事件循环机制，自定义了Qemu的事件源[**struct AioContext**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/block/aio.h#L125)，如下所示

```c
struct AioContext {
    GSource source;

    /* Used by AioContext users to protect from multi-threaded access.  */
    QemuRecMutex lock;
    ...
    /* The list of registered AIO handlers.  Protected by ctx->list_lock. */
    AioHandlerList aio_handlers;
    ...
    /* Used to avoid unnecessary event_notifier_set calls in aio_notify;
     * only written from the AioContext home thread, or under the BQL in
     * the case of the main AioContext.  However, it is read from any
     * thread so it is still accessed with atomic primitives.
     *
     * If this field is 0, everything (file descriptors, bottom halves,
     * timers) will be re-evaluated before the next blocking poll() or
     * io_uring wait; therefore, the event_notifier_set call can be
     * skipped.  If it is non-zero, you may need to wake up a concurrent
     * aio_poll or the glib main event loop, making event_notifier_set
     * necessary.
     *
     * Bit 0 is reserved for GSource usage of the AioContext, and is 1
     * between a call to aio_ctx_prepare and the next call to aio_ctx_check.
     * Bits 1-31 simply count the number of active calls to aio_poll
     * that are in the prepare or poll phase.
     *
     * The GSource and aio_poll must use a different mechanism because
     * there is no certainty that a call to GSource's prepare callback
     * (via g_main_context_prepare) is indeed followed by check and
     * dispatch.  It's not clear whether this would be a bug, but let's
     * play safe and allow it---it will just cause extra calls to
     * event_notifier_set until the next call to dispatch.
     *
     * Instead, the aio_poll calls include both the prepare and the
     * dispatch phase, hence a simple counter is enough for them.
     */
    uint32_t notify_me;
    ...
    /* Bottom Halves pending aio_bh_poll() processing */
    BHList bh_list;
    ...
    /* Used by aio_notify.
     *
     * "notified" is used to avoid expensive event_notifier_test_and_clear
     * calls.  When it is clear, the EventNotifier is clear, or one thread
     * is going to clear "notified" before processing more events.  False
     * positives are possible, i.e. "notified" could be set even though the
     * EventNotifier is clear.
     *
     * Note that event_notifier_set *cannot* be optimized the same way.  For
     * more information on the problem that would result, see "#ifdef BUG2"
     * in the docs/aio_notify_accept.promela formal model.
     */
    bool notified;
    EventNotifier notifier;
    ...
    /* TimerLists for calling timers - one per clock type.  Has its own
     * locking.
     */
    QEMUTimerListGroup tlg;
};
```

可以看到，其符合前面[glib自定义事件源](#gsource)的数据格式。其中**AioContext**事件源主要关心三类资源：
- [**struct AioHandler**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/aio-posix.h#L22)
```c
struct AioHandler {
    GPollFD pfd;
    IOHandler *io_read;
    IOHandler *io_write;
    AioPollFn *io_poll;
    IOHandler *io_poll_ready;
    IOHandler *io_poll_begin;
    IOHandler *io_poll_end;
    void *opaque;
    QLIST_ENTRY(AioHandler) node;
    QLIST_ENTRY(AioHandler) node_ready; /* only used during aio_poll() */
    QLIST_ENTRY(AioHandler) node_deleted;
    QLIST_ENTRY(AioHandler) node_poll;
#ifdef CONFIG_LINUX_IO_URING
    QSLIST_ENTRY(AioHandler) node_submitted;
    unsigned flags; /* see fdmon-io_uring.c */
#endif
    int64_t poll_idle_timeout; /* when to stop userspace polling */
    bool poll_ready; /* has polling detected an event? */
};
```
该资源即文件描述符类资源，提供了文件描述符的读/写回调函数用来处理事件
- [**struct QEMUBH**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L61)
```c
struct QEMUBH {
    AioContext *ctx;
    const char *name;
    QEMUBHFunc *cb;
    void *opaque;
    QSLIST_ENTRY(QEMUBH) next;
    unsigned flags;
    MemReentrancyGuard *reentrancy_guard;
};
```
这是Qemu模拟的内核的中断处理机制，即中断处理的bottom-half部分，用来实现异步调用功能。
概括来说，Qemu可以注册一个**QEMUBH**资源，并异步地设置**AioHandler**的**notifier**字段，用来通知该资源可用，从而调用**QEMUBH**的**cb**回调逻辑
- [**struct QEMUTimer**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qemu/timer.h#L84)
```c
struct QEMUTimer {
    int64_t expire_time;        /* in nanoseconds */
    QEMUTimerList *timer_list;
    QEMUTimerCB *cb;
    void *opaque;
    QEMUTimer *next;
    int attributes;
    int scale;
};
```
即定时器资源，当超时时调用定时器的**cb**回调函数来处理事件

## aio_source_funcs

参考前面[glib的GSource](#gsource)小节，Qemu中**AioContext**自定义事件源的操作接口是[**aio_source_funcs()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L423)
```c
static GSourceFuncs aio_source_funcs = {
    aio_ctx_prepare,
    aio_ctx_check,
    aio_ctx_dispatch,
    aio_ctx_finalize
};
```

这里我们分析一下[**aio_ctx_prepare()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L302)、[**aio_ctx_check**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L326)和[**aio_ctx_dispatch()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L353)，来更好的理解qemu的事件循环流程

### aio_ctx_prepare

```c
static gboolean
aio_ctx_prepare(GSource *source, gint    *timeout)
{
    AioContext *ctx = (AioContext *) source;

    qatomic_set(&ctx->notify_me, qatomic_read(&ctx->notify_me) | 1);

    /*
     * Write ctx->notify_me before computing the timeout
     * (reading bottom half flags, etc.).  Pairs with
     * smp_mb in aio_notify().
     */
    smp_mb();

    /* We assume there is no timeout already supplied */
    *timeout = qemu_timeout_ns_to_ms(aio_compute_timeout(ctx));

    if (aio_prepare(ctx)) {
        *timeout = 0;
    }

    return *timeout == 0;
}

int64_t
aio_compute_timeout(AioContext *ctx)
{
    BHListSlice *s;
    int64_t deadline;
    int timeout = -1;

    timeout = aio_compute_bh_timeout(&ctx->bh_list, timeout);
    if (timeout == 0) {
        return 0;
    }

    QSIMPLEQ_FOREACH(s, &ctx->bh_slice_list, next) {
        timeout = aio_compute_bh_timeout(&s->bh_list, timeout);
        if (timeout == 0) {
            return 0;
        }
    }

    deadline = timerlistgroup_deadline_ns(&ctx->tlg);
    if (deadline == 0) {
        return 0;
    } else {
        return qemu_soonest_timeout(timeout, deadline);
    }
}
```
可以看到，如果没有即时事件，则设置**poll**为**QEMUBH**和定时器等的最小超时时间即可

### aio_ctx_check

```c
static gboolean
aio_ctx_check(GSource *source)
{
    AioContext *ctx = (AioContext *) source;
    QEMUBH *bh;
    BHListSlice *s;

    /* Finish computing the timeout before clearing the flag.  */
    qatomic_store_release(&ctx->notify_me, qatomic_read(&ctx->notify_me) & ~1);
    aio_notify_accept(ctx);

    QSLIST_FOREACH_RCU(bh, &ctx->bh_list, next) {
        if ((bh->flags & (BH_SCHEDULED | BH_DELETED)) == BH_SCHEDULED) {
            return true;
        }
    }

    QSIMPLEQ_FOREACH(s, &ctx->bh_slice_list, next) {
        QSLIST_FOREACH_RCU(bh, &s->bh_list, next) {
            if ((bh->flags & (BH_SCHEDULED | BH_DELETED)) == BH_SCHEDULED) {
                return true;
            }
        }
    }
    return aio_pending(ctx) || (timerlistgroup_deadline_ns(&ctx->tlg) == 0);
}

bool aio_pending(AioContext *ctx)
{
    AioHandler *node;
    bool result = false;

    /*
     * We have to walk very carefully in case aio_set_fd_handler is
     * called while we're walking.
     */
    qemu_lockcnt_inc(&ctx->list_lock);

    QLIST_FOREACH_RCU(node, &ctx->aio_handlers, node) {
        int revents;

        /* TODO should this check poll ready? */
        revents = node->pfd.revents & node->pfd.events;
        if (revents & (G_IO_IN | G_IO_HUP | G_IO_ERR) && node->io_read) {
            result = true;
            break;
        }
        if (revents & (G_IO_OUT | G_IO_ERR) && node->io_write) {
            result = true;
            break;
        }
    }
    qemu_lockcnt_dec(&ctx->list_lock);

    return result;
}

int64_t timerlistgroup_deadline_ns(QEMUTimerListGroup *tlg)
{
    int64_t deadline = -1;
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        if (qemu_clock_use_for_deadline(type)) {
            deadline = qemu_soonest_timeout(deadline,
                                            timerlist_deadline_ns(tlg->tl[type]));
        }
    }
    return deadline;
}
```
可以看到，其检查了前面[AioContext中关注的资源](#自定义gsource)使用可用，即**aio_handlers**对应的文件描述符资源、**bh_list**对应的**QEMUBH**资源和**tlg**对应的定时器资源

### aio_ctx_dispatch

```c
static gboolean
aio_ctx_dispatch(GSource     *source,
                 GSourceFunc  callback,
                 gpointer     user_data)
{
    AioContext *ctx = (AioContext *) source;

    assert(callback == NULL);
    aio_dispatch(ctx);
    return true;
}

void aio_dispatch(AioContext *ctx)
{
    qemu_lockcnt_inc(&ctx->list_lock);
    aio_bh_poll(ctx);
    aio_dispatch_handlers(ctx);
    aio_free_deleted_handlers(ctx);
    qemu_lockcnt_dec(&ctx->list_lock);

    timerlistgroup_run_timers(&ctx->tlg);
}

int aio_bh_poll(AioContext *ctx)
{
    BHListSlice slice;
    BHListSlice *s;
    int ret = 0;

    /* Synchronizes with QSLIST_INSERT_HEAD_ATOMIC in aio_bh_enqueue().  */
    QSLIST_MOVE_ATOMIC(&slice.bh_list, &ctx->bh_list);

    /*
     * GCC13 [-Werror=dangling-pointer=] complains that the local variable
     * 'slice' is being stored in the global 'ctx->bh_slice_list' but the
     * list is emptied before this function returns.
     */
#if !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wdangling-pointer="
#endif
    QSIMPLEQ_INSERT_TAIL(&ctx->bh_slice_list, &slice, next);
#if !defined(__clang__)
#pragma GCC diagnostic pop
#endif

    while ((s = QSIMPLEQ_FIRST(&ctx->bh_slice_list))) {
        QEMUBH *bh;
        unsigned flags;

        bh = aio_bh_dequeue(&s->bh_list, &flags);
        if (!bh) {
            QSIMPLEQ_REMOVE_HEAD(&ctx->bh_slice_list, next);
            continue;
        }

        if ((flags & (BH_SCHEDULED | BH_DELETED)) == BH_SCHEDULED) {
            /* Idle BHs don't count as progress */
            if (!(flags & BH_IDLE)) {
                ret = 1;
            }
            aio_bh_call(bh);
        }
        if (flags & (BH_DELETED | BH_ONESHOT)) {
            g_free(bh);
        }
    }

    return ret;
}
```
可以看到，其会依次调用可用文件描述符资源、**QEMUBH**资源和定时器资源的回调函数

## 事件循环

由于Qemu自定义的事件源**AioContext**比较复杂，因此Qemu并没有直接使用glib的**g_main_loop_run()**接口进行事件循环，而是
使用自定义的[**qemu_main_loop()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/runstate.c#L778)，如下所示

```c
//#0  qemu_main_loop () at ../system/runstate.c:779
//#1  0x0000555555e9a002 in qemu_default_main () at ../system/main.c:37
//#2  0x0000555555e9a043 in main (argc=31, argv=0x7fffffffdbf8) at ../system/main.c:48
//#3  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555e9a016 <main>, argc=argc@entry=31, argv=argv@entry=0x7fffffffdbf8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#4  0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555e9a016 <main>, argc=31, argv=0x7fffffffdbf8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdbe8) at ../csu/libc-start.c:392
//#5  0x0000555555870675 in _start ()
int qemu_main_loop(void)
{
    int status = EXIT_SUCCESS;

    while (!main_loop_should_exit(&status)) {
        main_loop_wait(false);
    }

    return status;
}

void main_loop_wait(int nonblocking)
{
    ...
    ret = os_host_main_loop_wait(timeout_ns);
    ...
}

static int os_host_main_loop_wait(int64_t timeout)
{
    GMainContext *context = g_main_context_default();
    int ret;

    g_main_context_acquire(context);

    glib_pollfds_fill(&timeout);

    bql_unlock();
    replay_mutex_unlock();

    ret = qemu_poll_ns((GPollFD *)gpollfds->data, gpollfds->len, timeout);

    replay_mutex_lock();
    bql_lock();

    glib_pollfds_poll();

    g_main_context_release(context);

    return ret;
}

static void glib_pollfds_fill(int64_t *cur_timeout)
{
    GMainContext *context = g_main_context_default();
    int timeout = 0;
    int64_t timeout_ns;
    int n;

    g_main_context_prepare(context, &max_priority);

    glib_pollfds_idx = gpollfds->len;
    n = glib_n_poll_fds;
    do {
        GPollFD *pfds;
        glib_n_poll_fds = n;
        g_array_set_size(gpollfds, glib_pollfds_idx + glib_n_poll_fds);
        pfds = &g_array_index(gpollfds, GPollFD, glib_pollfds_idx);
        n = g_main_context_query(context, max_priority, &timeout, pfds,
                                 glib_n_poll_fds);
    } while (n != glib_n_poll_fds);

    if (timeout < 0) {
        timeout_ns = -1;
    } else {
        timeout_ns = (int64_t)timeout * (int64_t)SCALE_MS;
    }

    *cur_timeout = qemu_soonest_timeout(timeout_ns, *cur_timeout);
}

/* qemu implementation of g_poll which uses a nanosecond timeout but is
 * otherwise identical to g_poll
 */
int qemu_poll_ns(GPollFD *fds, guint nfds, int64_t timeout)
{
    if (timeout < 0) {
        return ppoll((struct pollfd *)fds, nfds, NULL, NULL);
    } else {
        struct timespec ts;
        int64_t tvsec = timeout / 1000000000LL;
        /* Avoid possibly overflowing and specifying a negative number of
         * seconds, which would turn a very long timeout into a busy-wait.
         */
        if (tvsec > (int64_t)INT32_MAX) {
            tvsec = INT32_MAX;
        }
        ts.tv_sec = tvsec;
        ts.tv_nsec = timeout % 1000000000LL;
        return ppoll((struct pollfd *)fds, nfds, &ts, NULL);
    }
}

static void glib_pollfds_poll(void)
{
    GMainContext *context = g_main_context_default();
    GPollFD *pfds = &g_array_index(gpollfds, GPollFD, glib_pollfds_idx);

    if (g_main_context_check(context, max_priority, pfds, glib_n_poll_fds)) {
        g_main_context_dispatch(context);
    }
}
```

可以看到，类似于前面[GMainContext的一轮事件循环](#gmaincontext)，Qemu在[**os_host_main_loop_wait()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/main-loop.c#L293)中完成一轮事件循环。
具体的，Qemu在[**glib_pollfds_fill()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/main-loop.c#L252)中获取**poll**的超时时间和文件描述符，然后在[**qemu_poll_ns()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/qemu-timer.c#L335)进行**poll**，并在[**glib_pollfds_poll**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/main-loop.c#L281)中对可用资源进行处理

[前面](#自定义gsource)介绍了**AioContext**事件源关心三类资源，这里具体分析一下这三类资源是如何完成事件循环的

### AioHandler

Qemu使用[**aio_set_fd_handler()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/aio-posix.c#L100)向**AioContext**中添加资源，如下所示

```c
void aio_set_fd_handler(AioContext *ctx,
                        int fd,
                        IOHandler *io_read,
                        IOHandler *io_write,
                        AioPollFn *io_poll,
                        IOHandler *io_poll_ready,
                        void *opaque)
{
    AioHandler *node;
    AioHandler *new_node = NULL;
    bool is_new = false;
    bool deleted = false;
    int poll_disable_change;

    if (io_poll && !io_poll_ready) {
        io_poll = NULL; /* polling only makes sense if there is a handler */
    }

    qemu_lockcnt_lock(&ctx->list_lock);

    node = find_aio_handler(ctx, fd);

    /* Are we deleting the fd handler? */
    if (!io_read && !io_write && !io_poll) {
        if (node == NULL) {
            qemu_lockcnt_unlock(&ctx->list_lock);
            return;
        }
        /* Clean events in order to unregister fd from the ctx epoll. */
        node->pfd.events = 0;

        poll_disable_change = -!node->io_poll;
    } else {
        poll_disable_change = !io_poll - (node && !node->io_poll);
        if (node == NULL) {
            is_new = true;
        }
        /* Alloc and insert if it's not already there */
        new_node = g_new0(AioHandler, 1);

        /* Update handler with latest information */
        new_node->io_read = io_read;
        new_node->io_write = io_write;
        new_node->io_poll = io_poll;
        new_node->io_poll_ready = io_poll_ready;
        new_node->opaque = opaque;

        if (is_new) {
            new_node->pfd.fd = fd;
        } else {
            new_node->pfd = node->pfd;
        }
        g_source_add_poll(&ctx->source, &new_node->pfd);

        new_node->pfd.events = (io_read ? G_IO_IN | G_IO_HUP | G_IO_ERR : 0);
        new_node->pfd.events |= (io_write ? G_IO_OUT | G_IO_ERR : 0);

        QLIST_INSERT_HEAD_RCU(&ctx->aio_handlers, new_node, node);
    }

    /* No need to order poll_disable_cnt writes against other updates;
     * the counter is only used to avoid wasting time and latency on
     * iterated polling when the system call will be ultimately necessary.
     * Changing handlers is a rare event, and a little wasted polling until
     * the aio_notify below is not an issue.
     */
    qatomic_set(&ctx->poll_disable_cnt,
               qatomic_read(&ctx->poll_disable_cnt) + poll_disable_change);

    ctx->fdmon_ops->update(ctx, node, new_node);
    if (node) {
        deleted = aio_remove_fd_handler(ctx, node);
    }
    qemu_lockcnt_unlock(&ctx->list_lock);
    aio_notify(ctx);

    if (deleted) {
        g_free(node);
    }
}
```
可以看到，Qemu会创建对应的**AioHandler**并插入到**ctx->aio_handlers**链表中，并将文件描述符使用**g_source_add_poll()**绑定到**AioContext**自定义事件源

根据前面的分析，在事件循环中，**glib_pollfds_fill()**会通过**g_main_context_query()**将该绑定的文件描述符填充到**poll**数组，并在**qemu_poll_ns**中进行**poll**操作，最后在**glib_pollfds_poll()**中检查**ctx->aio_handlers**并完成回调函数的相关处理

这里特别分析一下最后调用的[**aio_notify()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L487)，如下所示
```c
void aio_notify(AioContext *ctx)
{
    /*
     * Write e.g. ctx->bh_list before writing ctx->notified.  Pairs with
     * smp_mb() in aio_notify_accept().
     */
    smp_wmb();
    qatomic_set(&ctx->notified, true);

    /*
     * Write ctx->notified (and also ctx->bh_list) before reading ctx->notify_me.
     * Pairs with smp_mb() in aio_ctx_prepare or aio_poll.
     */
    smp_mb();
    if (qatomic_read(&ctx->notify_me)) {
        event_notifier_set(&ctx->notifier);
    }
}

int event_notifier_set(EventNotifier *e)
{
    static const uint64_t value = 1;
    ssize_t ret;

    if (!e->initialized) {
        return -1;
    }

    do {
        ret = write(e->wfd, &value, sizeof(value));
    } while (ret < 0 && errno == EINTR);

    /* EAGAIN is fine, a read must be pending.  */
    if (ret < 0 && errno != EAGAIN) {
        return -errno;
    }
    return 0;
}
```

其主要逻辑就是向**AioContext**的**notifier**字段写入数据。而**notifier**是[**eventfd**](https://man7.org/linux/man-pages/man2/eventfd.2.html)系统调用的包装，**AioContext**用其来立即退出**poll**并重新进入新的事件循环，避免在**glib_pollfds_fill()**之后添加的资源一直等不到处理，如下所示
```c
AioContext *aio_context_new(Error **errp)
{
    int ret;
    AioContext *ctx;

    ctx = (AioContext *) g_source_new(&aio_source_funcs, sizeof(AioContext));
    ...
    ret = event_notifier_init(&ctx->notifier, false);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to initialize event notifier");
        goto fail;
    }
    ...
    aio_set_event_notifier(ctx, &ctx->notifier,
                           aio_context_notifier_cb,
                           aio_context_notifier_poll,
                           aio_context_notifier_poll_ready);
    ...
}

int event_notifier_init(EventNotifier *e, int active)
{
    int fds[2];
    int ret;

    ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ...
    e->rfd = e->wfd = ret;
    e->initialized = true;
    ...
    return 0;
}

void aio_set_event_notifier(AioContext *ctx,
                            EventNotifier *notifier,
                            EventNotifierHandler *io_read,
                            AioPollFn *io_poll,
                            EventNotifierHandler *io_poll_ready)
{
    aio_set_fd_handler(ctx, event_notifier_get_fd(notifier),
                       (IOHandler *)io_read, NULL, io_poll,
                       (IOHandler *)io_poll_ready, notifier);
}
```

具体的，在创建**AioContext**时，其会通过**eventfd**系统调用创建**notifier**字段数据结构，并将**notifier**的文件描述符通过刚刚分析的[**aio_set_fd_handler()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/aio-posix.c#L100)添加到该**AioContext**的关心资源。之后，每当有线程调用[**aio_notify()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L487)，添加的文件描述符就有可读资源，从而立即从**poll**中退出。

### QEMUBH

Qemu使用[**aio_bh_enqueue()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/async.c#L72)即向**AioContext**中添加资源，又用来产生事件，如下所示

```c
/* Called concurrently from any thread */
static void aio_bh_enqueue(QEMUBH *bh, unsigned new_flags)
{
    AioContext *ctx = bh->ctx;
    unsigned old_flags;

    /*
     * Synchronizes with atomic_fetch_and() in aio_bh_dequeue(), ensuring that
     * insertion starts after BH_PENDING is set.
     */
    old_flags = qatomic_fetch_or(&bh->flags, BH_PENDING | new_flags);

    if (!(old_flags & BH_PENDING)) {
        /*
         * At this point the bottom half becomes visible to aio_bh_poll().
         * This insertion thus synchronizes with QSLIST_MOVE_ATOMIC in
         * aio_bh_poll(), ensuring that:
         * 1. any writes needed by the callback are visible from the callback
         *    after aio_bh_dequeue() returns bh.
         * 2. ctx is loaded before the callback has a chance to execute and bh
         *    could be freed.
         */
        QSLIST_INSERT_HEAD_ATOMIC(&ctx->bh_list, bh, next);
    }

    aio_notify(ctx);
    if (unlikely(icount_enabled())) {
        /*
         * Workaround for record/replay.
         * vCPU execution should be suspended when new BH is set.
         * This is needed to avoid guest timeouts caused
         * by the long cycles of the execution.
         */
        icount_notify_exit();
    }
}
```
可以看到，其将**QEMUBH**插入到**ctx->bh_list**链表中然后调用**aio_notify()**。基于[前面对aio_notify的介绍](#aiohandler)，其会立即退出**poll**，然后根据[前面aio_ctx_check](#aio_ctx_check)和[前面aio_ctx_dispatch](#aio_ctx_dispatch)查看**QEMUBH**的**flags**然后进行相应的操作。

即如果**aio_bh_enqueue()**的**new_flags**字段包含**BH_SCHEDULED**，会使**QEMUBH**资源可用并在时间循环中迅速被处理

### QEMUTimer

Qemu使用[**timer_mod_ns_locked()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/qemu-timer.c#L399)来向**AioContext**中添加资源，如下所示

```c
static bool timer_mod_ns_locked(QEMUTimerList *timer_list,
                                QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimer **pt, *t;

    /* add the timer in the sorted list */
    pt = &timer_list->active_timers;
    for (;;) {
        t = *pt;
        if (!timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }
    ts->expire_time = MAX(expire_time, 0);
    ts->next = *pt;
    qatomic_set(pt, ts);

    return pt == &timer_list->active_timers;
}
```

可以看到，其设置**QEMUTimer**的超时时间后，添加到**ctx->tlg**中的相关链表中，会在**expire_time**后产生事件。

而根据[前面aio_ctx_prepare](#aio_ctx_prepare)可知，其设置的**poll**时间不大于所有的**QEMUTimer**超时时间，从而确保在**glib_pollfds_poll()**中能按时的处理事件

# libvirt

libvirt项目比较复杂，并且相关的资料比较少，所以分析起来相对比较困难。

这里首先给出libvirt的整个框架，如下所示
![libvirt框架](libvirt框架.png)

可以看到，整个libvirt的核心就是**libvirtd**，其核心就是事件循环和线程池，如下所示

![libvirt事件循环框架](libvirt事件循环框架.png)

## 事件循环

libvirt直接使用了glib的事件循环机制，如[**virNetDaemonRun()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/rpc/virnetdaemon.c#L810)所示

```c
void
virNetDaemonRun(virNetDaemon *dmn)
{
    virThread shutdownThread;

    virObjectLock(dmn);

    if (dmn->srvObject) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Not all servers restored, cannot run server"));
        goto cleanup;
    }

    dmn->quit = false;
    dmn->finishTimer = -1;
    dmn->finished = false;
    dmn->graceful = false;
    dmn->running = true;

    /* We are accepting connections now. Notify systemd
     * so it can start dependent services. */
    virSystemdNotifyStartup();

    VIR_DEBUG("dmn=%p quit=%d", dmn, dmn->quit);
    while (!dmn->finished) {
        virNetDaemonShutdownTimerUpdate(dmn);

        virObjectUnlock(dmn);
        if (virEventRunDefaultImpl() < 0) {
            virObjectLock(dmn);
            VIR_DEBUG("Loop iteration error, exiting");
            break;
        }
        virObjectLock(dmn);

        virHashForEach(dmn->servers, daemonServerProcessClients, NULL);

        /* don't shutdown services when performing an exec-restart */
        if (dmn->quit && dmn->execRestart)
            goto cleanup;

        if (dmn->quit && dmn->finishTimer == -1) {
            virHashForEach(dmn->servers, daemonServerClose, NULL);
            if (dmn->shutdownPrepareCb && dmn->shutdownPrepareCb() < 0)
                break;

            if ((dmn->finishTimer = virEventAddTimeout(30 * 1000,
                                                       virNetDaemonFinishTimer,
                                                       dmn, NULL)) < 0) {
                VIR_WARN("Failed to register finish timer.");
                break;
            }

            if (virThreadCreateFull(&shutdownThread, true, daemonShutdownWait,
                                    "daemon-shutdown", false, dmn) < 0) {
                VIR_WARN("Failed to register join thread.");
                break;
            }
        }
    }

    if (dmn->graceful) {
        virThreadJoin(&shutdownThread);
    } else {
        VIR_WARN("Make forcefull daemon shutdown");
        exit(EXIT_FAILURE);
    }

 cleanup:
    virObjectUnlock(dmn);
}

/**
 * virEventRunDefaultImpl:
 *
 * Run one iteration of the event loop. Applications
 * will generally want to have a thread which invokes
 * this method in an infinite loop.  Furthermore, it is wise
 * to set up a pipe-to-self handler (via virEventAddHandle())
 * or a timeout (via virEventAddTimeout()) before calling this
 * function, as it will block forever if there are no
 * registered events.
 *
 *   static bool quit;
 *
 *   while (!quit) {
 *     if (virEventRunDefaultImpl() < 0)
 *       ...print error...
 *   }
 *
 * Returns 0 on success, -1 on failure.
 *
 * Since: 0.9.0
 */
int virEventRunDefaultImpl(void)
{
    VIR_DEBUG("running default event implementation");
    virResetLastError();

    return virEventGLibRunOnce();
}

int virEventGLibRunOnce(void)
{
    g_main_context_iteration(NULL, TRUE);

    return 0;
}
```

根据相关注释，libvirt使用[**virEventAddHandle()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L76)和[**virEventAddTimeout()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L152)添加关注资源。

### 文件描述符事件源

其中[**virEventAddHandle()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L76)绑定[**virEventGLibFDSourceFuncs**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/vireventglibwatch.c#L74)事件源来关注文件描述符类型资源

```c
/**
 * virEventAddHandle:
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from virEventHandleType constants
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 * @ff: callback to free opaque when handle is removed
 *
 * Register a callback for monitoring file handle events.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * @fd must always always be a C runtime file descriptor. On Windows
 * if the caller only has a HANDLE, the _open_osfhandle() method can
 * be used to open an associated C runtime file descriptor for use
 * with this API. After opening a runtime file descriptor, CloseHandle()
 * must not be used, instead close() will close the runtime file
 * descriptor and its original associated HANDLE.
 *
 * Returns -1 if the file handle cannot be registered, otherwise a handle
 * watch number to be used for updating and unregistering for events.
 *
 * Since: 0.9.3
 */
int
virEventAddHandle(int fd,
                  int events,
                  virEventHandleCallback cb,
                  void *opaque,
                  virFreeCallback ff)
{
    if (!addHandleImpl)
        return -1;

    return addHandleImpl(fd, events, cb, opaque, ff);
}

static gpointer virEventGLibRegisterOnce(gpointer data G_GNUC_UNUSED)
{
    eventlock = g_new0(GMutex, 1);
    timeouts = g_ptr_array_new_with_free_func(g_free);
    handles = g_ptr_array_new_with_free_func(g_free);
    virEventRegisterImpl(virEventGLibHandleAdd,
                         virEventGLibHandleUpdate,
                         virEventGLibHandleRemove,
                         virEventGLibTimeoutAdd,
                         virEventGLibTimeoutUpdate,
                         virEventGLibTimeoutRemove);
    return NULL;
}

static int
virEventGLibHandleAdd(int fd,
                      int events,
                      virEventHandleCallback cb,
                      void *opaque,
                      virFreeCallback ff)
{
    struct virEventGLibHandle *data;
    GIOCondition cond = virEventGLibEventsToCondition(events);
    int ret;

    g_mutex_lock(eventlock);

    data = g_new0(struct virEventGLibHandle, 1);

    data->watch = nextwatch++;
    data->fd = fd;
    data->events = events;
    data->cb = cb;
    data->opaque = opaque;
    data->ff = ff;

    VIR_DEBUG("Add handle data=%p watch=%d fd=%d events=%d opaque=%p",
              data, data->watch, data->fd, events, data->opaque);

    if (events != 0) {
        data->source = virEventGLibAddSocketWatch(
            fd, cond, NULL, virEventGLibHandleDispatch, data, NULL);
    }

    g_ptr_array_add(handles, data);

    ret = data->watch;

    PROBE(EVENT_GLIB_ADD_HANDLE,
          "watch=%d fd=%d events=%d cb=%p opaque=%p ff=%p",
          ret, fd, events, cb, opaque, ff);
    g_mutex_unlock(eventlock);

    return ret;
}

GSource *
virEventGLibAddSocketWatch(int fd,
                           GIOCondition condition,
                           GMainContext *context,
                           virEventGLibSocketFunc func,
                           gpointer opaque,
                           GDestroyNotify notify)
{
    GSource *source = NULL;

    source = virEventGLibCreateSocketWatch(fd, condition);
    g_source_set_callback(source, (GSourceFunc)func, opaque, notify);

    g_source_attach(source, context);

    return source;
}

GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition)
{
    GSource *source;
    virEventGLibFDSource *ssource;

    source = g_source_new(&virEventGLibFDSourceFuncs,
                          sizeof(virEventGLibFDSource));
    ssource = (virEventGLibFDSource *)source;

    ssource->condition = condition | G_IO_HUP | G_IO_ERR;
    ssource->fd = fd;

    ssource->pollfd.fd = fd;
    ssource->pollfd.events = condition | G_IO_HUP | G_IO_ERR;

    g_source_add_poll(source, &ssource->pollfd);

    return source;
}
```

可以看到，[**virEventAddHandle()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L76)最后调用glib的**g_source_attach()**等添加自定义事件源。

其中，**event**参数可以用来指定哪些文件描述符事件可以触发事件循环，例如当文件描述符有可读数据或是文件描述符可写等，如[**virEventGLibEventsToCondition()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/util/vireventglib.c#L73)中所示，其可以通过[**virEventUpdateHandle()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/util/virevent.c#L103)进行更改

```c
static GIOCondition
virEventGLibEventsToCondition(int events)
{
    GIOCondition cond = 0;
    if (events & VIR_EVENT_HANDLE_READABLE)
        cond |= G_IO_IN;
    if (events & VIR_EVENT_HANDLE_WRITABLE)
        cond |= G_IO_OUT;
    if (events & VIR_EVENT_HANDLE_ERROR)
        cond |= G_IO_ERR;
    if (events & VIR_EVENT_HANDLE_HANGUP)
        cond |= G_IO_HUP;
    return cond;
}

/**
 * virEventUpdateHandle:
 *
 * @watch: watch whose file handle to update
 * @events: bitset of events to watch from virEventHandleType constants
 *
 * Change event set for a monitored file handle.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Will not fail if fd exists.
 *
 * Since: 0.9.3
 */
void
virEventUpdateHandle(int watch, int events)
{
    if (updateHandleImpl)
        updateHandleImpl(watch, events);
}

static void
virEventGLibHandleUpdate(int watch,
                         int events)
{
    struct virEventGLibHandle *data;

    PROBE(EVENT_GLIB_UPDATE_HANDLE,
          "watch=%d events=%d",
          watch, events);
    g_mutex_lock(eventlock);

    data = virEventGLibHandleFind(watch);
    if (!data) {
        VIR_DEBUG("Update for missing handle watch=%d", watch);
        goto cleanup;
    }

    VIR_DEBUG("Update handle data=%p watch=%d fd=%d events=%d",
              data, watch, data->fd, events);

    if (events != 0) {
        GIOCondition cond = virEventGLibEventsToCondition(events);
        if (events == data->events)
            goto cleanup;

        if (data->source != NULL) {
            VIR_DEBUG("Removed old handle source=%p", data->source);
            g_source_destroy(data->source);
            vir_g_source_unref(data->source, NULL);
        }

        data->source = virEventGLibAddSocketWatch(
            data->fd, cond, NULL, virEventGLibHandleDispatch, data, NULL);

        data->events = events;
        VIR_DEBUG("Added new handle source=%p", data->source);
    } else {
        if (data->source == NULL)
            goto cleanup;

        VIR_DEBUG("Removed old handle source=%p", data->source);
        g_source_destroy(data->source);
        vir_g_source_unref(data->source, NULL);
        data->source = NULL;
        data->events = 0;
    }

 cleanup:
    g_mutex_unlock(eventlock);
}
```

### 定时器事件源

而[**virEventAddTimeout()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L152)会绑定定时器事件源来添加定时器资源

```c
/**
 * virEventAddTimeout:
 *
 * @timeout: time between events in milliseconds
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 * @ff: callback to free opaque when timeout is removed
 *
 * Register a callback for a timer event.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Setting @timeout to -1 will disable the timer. Setting @timeout
 * to zero will cause it to fire on every event loop iteration.
 *
 * Returns -1 if the timer cannot be registered, a positive
 * integer timer id upon success.
 *
 * Since: 0.9.3
 */
int
virEventAddTimeout(int timeout,
                   virEventTimeoutCallback cb,
                   void *opaque,
                   virFreeCallback ff)
{
    if (!addTimeoutImpl)
        return -1;

    return addTimeoutImpl(timeout, cb, opaque, ff);
}

static gpointer virEventGLibRegisterOnce(gpointer data G_GNUC_UNUSED)
{
    eventlock = g_new0(GMutex, 1);
    timeouts = g_ptr_array_new_with_free_func(g_free);
    handles = g_ptr_array_new_with_free_func(g_free);
    virEventRegisterImpl(virEventGLibHandleAdd,
                         virEventGLibHandleUpdate,
                         virEventGLibHandleRemove,
                         virEventGLibTimeoutAdd,
                         virEventGLibTimeoutUpdate,
                         virEventGLibTimeoutRemove);
    return NULL;
}

static int
virEventGLibTimeoutAdd(int interval,
                       virEventTimeoutCallback cb,
                       void *opaque,
                       virFreeCallback ff)
{
    struct virEventGLibTimeout *data;
    int ret;

    g_mutex_lock(eventlock);

    data = g_new0(struct virEventGLibTimeout, 1);
    data->timer = nexttimer++;
    data->interval = interval;
    data->cb = cb;
    data->opaque = opaque;
    data->ff = ff;
    if (interval >= 0)
        data->source = virEventGLibTimeoutCreate(interval, data);

    g_ptr_array_add(timeouts, data);

    VIR_DEBUG("Add timeout data=%p interval=%d ms cb=%p opaque=%p timer=%d",
              data, interval, cb, opaque, data->timer);

    ret = data->timer;

    PROBE(EVENT_GLIB_ADD_TIMEOUT,
          "timer=%d interval=%d cb=%p opaque=%p ff=%p",
          ret, interval, cb, opaque, ff);
    g_mutex_unlock(eventlock);

    return ret;
}

static GSource *
virEventGLibTimeoutCreate(int interval,
                          struct virEventGLibTimeout *data)
{
    GSource *source = g_timeout_source_new(interval);

    g_source_set_callback(source,
                          virEventGLibTimeoutDispatch,
                          data, NULL);
    g_source_attach(source, NULL);

    return source;
}
```

可以看到，libvirt最后使用glib的**g_timeout_source_new()**创建定时器事件源并使用**g_source_attach()**进行绑定

## 线程池

为了避免事件循环被阻塞在**dispatch**阶段，libvirt会将事件处理的逻辑offload到**worker**线程，而事件循环线程只用来唤醒**worker**线程，其大体的框架如下所示
1. **virsh**调用**Libvirt** API
2. **remote**驱动将API编码成**RPC**消息，并发送到**libvirtd**
3. **libvirtd**的事件循环**poll**发现关注资源可用
4. 事件循环唤醒**worker**线程，**worker**线程处理**RPC**消息
5. **worker**线程将处理结果返回给**virsh**客户端

### virThreadPoolNewFull()

而libvirt使用[**virThreadPoolNewFull()**](https://github.com/libvirt/libvirt/blob/94338f1375eb47467ce3efa415797b3851de70f5/src/util/virthreadpool.c#L220)创建线程池

```c
virThreadPool *
virThreadPoolNewFull(size_t minWorkers,
                     size_t maxWorkers,
                     size_t prioWorkers,
                     virThreadPoolJobFunc func,
                     const char *name,
                     virIdentity *identity,
                     void *opaque)
{
    virThreadPool *pool;

    if (minWorkers > maxWorkers)
        minWorkers = maxWorkers;

    pool = g_new0(virThreadPool, 1);

    pool->jobList.tail = pool->jobList.head = NULL;

    pool->jobFunc = func;
    pool->jobName = g_strdup(name);
    pool->jobOpaque = opaque;

    if (identity)
        pool->identity = g_object_ref(identity);

    if (virMutexInit(&pool->mutex) < 0)
        goto error;
    if (virCondInit(&pool->cond) < 0)
        goto error;
    if (virCondInit(&pool->prioCond) < 0)
        goto error;
    if (virCondInit(&pool->quit_cond) < 0)
        goto error;

    pool->minWorkers = minWorkers;
    pool->maxWorkers = maxWorkers;
    pool->maxPrioWorkers = prioWorkers;

    if ((minWorkers > 0) && virThreadPoolExpand(pool, minWorkers, false) < 0)
        goto error;

    if ((prioWorkers > 0) && virThreadPoolExpand(pool, prioWorkers, true) < 0)
        goto error;

    return pool;

 error:
    virThreadPoolFree(pool);
    return NULL;

}

static int
virThreadPoolExpand(virThreadPool *pool, size_t gain, bool priority)
{
    virThread **workers = priority ? &pool->prioWorkers : &pool->workers;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t i = 0;
    struct virThreadPoolWorkerData *data = NULL;

    VIR_REALLOC_N(*workers, *curWorkers + gain);

    for (i = 0; i < gain; i++) {
        g_autofree char *name = NULL;

        data = g_new0(struct virThreadPoolWorkerData, 1);
        data->pool = pool;
        data->cond = priority ? &pool->prioCond : &pool->cond;
        data->priority = priority;

        if (priority)
            name = g_strdup_printf("prio-%s", pool->jobName);
        else
            name = g_strdup(pool->jobName);

        if (virThreadCreateFull(&(*workers)[*curWorkers],
                                false,
                                virThreadPoolWorker,
                                name,
                                true,
                                data) < 0) {
            VIR_FREE(data);
            virReportSystemError(errno, "%s", _("Failed to create thread"));
            return -1;
        }

        (*curWorkers)++;
    }

    return 0;
}

int virThreadCreateFull(virThread *thread,
                        bool joinable,
                        virThreadFunc func,
                        const char *name,
                        bool worker,
                        void *opaque)
{
    struct virThreadArgs *args;
    pthread_attr_t attr;
    int ret = -1;
    int err;

    if ((err = pthread_attr_init(&attr)) != 0)
        goto cleanup;

    args = g_new0(struct virThreadArgs, 1);
    args->func = func;
    args->name = g_strdup(name);
    args->worker = worker;
    args->opaque = opaque;

    if (!joinable)
        pthread_attr_setdetachstate(&attr, 1);

    err = pthread_create(&thread->thread, &attr, virThreadHelper, args);
    if (err != 0) {
        g_free(args->name);
        g_free(args);
        goto cleanup;
    }
    /* New thread owns 'args' in success case, so don't free */

    ret = 0;
 cleanup:
    pthread_attr_destroy(&attr);
    if (ret < 0)
        errno = err;
    return ret;
}

static void *virThreadHelper(void *data)
{
    struct virThreadArgs *args = data;
    struct virThreadArgs local = *args;
    g_autofree char *thname = NULL;
    size_t maxname = virThreadMaxName();

    /* Free args early, rather than tying it up during the entire thread.  */
    g_free(args);

    if (local.worker)
        virThreadJobSetWorker(local.name);
    else
        virThreadJobSet(local.name);

    if (maxname) {
        thname = g_strndup(local.name, maxname);
    } else {
        thname = g_strdup(local.name);
    }

#if defined(__linux__) || defined(WIN32)
    pthread_setname_np(pthread_self(), thname);
#else
# ifdef __FreeBSD__
    pthread_set_name_np(pthread_self(), thname);
# else
#  ifdef __APPLE__
    pthread_setname_np(thname);
#  endif
# endif
#endif

    local.func(local.opaque);

    if (!local.worker)
        virThreadJobClear(0);

    g_free(local.name);
    return NULL;
}

static void virThreadPoolWorker(void *opaque)
{
    struct virThreadPoolWorkerData *data = opaque;
    virThreadPool *pool = data->pool;
    virCond *cond = data->cond;
    bool priority = data->priority;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t *maxLimit = priority ? &pool->maxPrioWorkers : &pool->maxWorkers;
    virThreadPoolJob *job = NULL;

    VIR_FREE(data);

    virMutexLock(&pool->mutex);

    if (pool->identity)
        virIdentitySetCurrent(pool->identity);

    while (1) {
        /* In order to support async worker termination, we need ensure that
         * both busy and free workers know if they need to terminated. Thus,
         * busy workers need to check for this fact before they start waiting for
         * another job (and before taking another one from the queue); and
         * free workers need to check for this right after waking up.
         */
        if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
            goto out;
        while (!pool->quit &&
               ((!priority && !pool->jobList.head) ||
                (priority && !pool->jobList.firstPrio))) {
            if (!priority)
                pool->freeWorkers++;
            if (virCondWait(cond, &pool->mutex) < 0) {
                if (!priority)
                    pool->freeWorkers--;
                goto out;
            }
            if (!priority)
                pool->freeWorkers--;

            if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
                goto out;
        }

        if (pool->quit)
            break;

        if (priority) {
            job = pool->jobList.firstPrio;
        } else {
            job = pool->jobList.head;
        }

        if (job == pool->jobList.firstPrio) {
            virThreadPoolJob *tmp = job->next;
            while (tmp) {
                if (tmp->priority)
                    break;
                tmp = tmp->next;
            }
            pool->jobList.firstPrio = tmp;
        }

        if (job->prev)
            job->prev->next = job->next;
        else
            pool->jobList.head = job->next;
        if (job->next)
            job->next->prev = job->prev;
        else
            pool->jobList.tail = job->prev;

        pool->jobQueueDepth--;

        virMutexUnlock(&pool->mutex);
        (pool->jobFunc)(job->data, pool->jobOpaque);
        VIR_FREE(job);
        virMutexLock(&pool->mutex);
    }

 out:
    if (priority)
        pool->nPrioWorkers--;
    else
        pool->nWorkers--;
    if (pool->nWorkers == 0 && pool->nPrioWorkers == 0)
        virCondSignal(&pool->quit_cond);
    virMutexUnlock(&pool->mutex);
}
```

可以看到，libvirt会在[**virThreadCreateFull()**](https://github.com/libvirt/libvirt/blob/94338f1375eb47467ce3efa415797b3851de70f5/src/util/virthread.c#L265)创建执行[**virThreadPoolWorker()**](https://github.com/libvirt/libvirt/blob/94338f1375eb47467ce3efa415797b3851de70f5/src/util/virthreadpool.c#L76)逻辑的线程，而[**virThreadPoolWorker()**](https://github.com/libvirt/libvirt/blob/94338f1375eb47467ce3efa415797b3851de70f5/src/util/virthreadpool.c#L76)逻辑就是依次执行**jobList**的**job**

而libvirt会使用[**virThreadPoolSendJob()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/util/virthreadpool.c#L369)添加**job**并唤醒线程池

```c
int virThreadPoolSendJob(virThreadPool *pool,
                         unsigned int priority,
                         void *jobData)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);
    virThreadPoolJob *job;

    if (pool->quit)
        return -1;

    if (pool->freeWorkers - pool->jobQueueDepth <= 0 &&
        pool->nWorkers < pool->maxWorkers &&
        virThreadPoolExpand(pool, 1, false) < 0)
        return -1;

    job = g_new0(virThreadPoolJob, 1);

    job->data = jobData;
    job->priority = priority;

    job->prev = pool->jobList.tail;
    if (pool->jobList.tail)
        pool->jobList.tail->next = job;
    pool->jobList.tail = job;

    if (!pool->jobList.head)
        pool->jobList.head = job;

    if (priority && !pool->jobList.firstPrio)
        pool->jobList.firstPrio = job;

    pool->jobQueueDepth++;

    virCondSignal(&pool->cond);
    if (priority)
        virCondSignal(&pool->prioCond);

    return 0;
}
```

### 样例

这里就以**libvirtd**处理**RPC**消息作为样例来分析libvirt的事件循环

1. **libvirtd**会在[**virNetServerNew()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L356)中创建**RPC**的线程池
```c
virNetServer *
virNetServerNew(const char *name,
                unsigned long long next_client_id,
                size_t min_workers,
                size_t max_workers,
                size_t priority_workers,
                size_t max_clients,
                size_t max_anonymous_clients,
                int keepaliveInterval,
                unsigned int keepaliveCount,
                virNetServerClientPrivNew clientPrivNew,
                virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                virFreeCallback clientPrivFree,
                void *clientPrivOpaque)
{
    g_autoptr(virNetServer) srv = NULL;
    g_autofree char *jobName = g_strdup_printf("rpc-%s", name);

    if (max_clients < max_anonymous_clients) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The overall maximum number of clients must not be less than the number of clients waiting for authentication"));
        return NULL;
    }

    if (virNetServerInitialize() < 0)
        return NULL;

    if (!(srv = virObjectLockableNew(virNetServerClass)))
        return NULL;

    if (!(srv->workers = virThreadPoolNewFull(min_workers, max_workers,
                                              priority_workers,
                                              virNetServerHandleJob,
                                              jobName,
                                              NULL,
                                              srv)))
        return NULL;

    srv->name = g_strdup(name);

    srv->next_client_id = next_client_id;
    srv->nclients_max = max_clients;
    srv->nclients_unauth_max = max_anonymous_clients;
    srv->keepaliveInterval = keepaliveInterval;
    srv->keepaliveCount = keepaliveCount;
    srv->clientPrivNew = clientPrivNew;
    srv->clientPrivPreExecRestart = clientPrivPreExecRestart;
    srv->clientPrivFree = clientPrivFree;
    srv->clientPrivOpaque = clientPrivOpaque;

    return g_steal_pointer(&srv);
}

static void
virNetServerHandleJob(void *jobOpaque,
                      void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerJob *job = jobOpaque;
    ...
    if (virNetServerProcessMsg(srv, job->client, job->prog, job->msg) < 0)
        goto error;

    virObjectUnref(job->prog);
    virObjectUnref(job->client);
    VIR_FREE(job);
    return;
    ...
}

static int
virNetServerProcessMsg(virNetServer *srv,
                       virNetServerClient *client,
                       virNetServerProgram *prog,
                       virNetMessage *msg)
{
    ...
    if (virNetServerProgramDispatch(prog,
                                    srv,
                                    client,
                                    msg) < 0)
        return -1;

    return 0;
}

/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming message packet, with header already decoded
 *
 * This function is intended to be called from worker threads
 * when an incoming message is ready to be dispatched for
 * execution.
 *
 * Upon successful return the '@msg' instance will be released
 * by this function (or more often, reused to send a reply).
 * Upon failure, the '@msg' must be freed by the caller.
 *
 * Returns 0 if the message was dispatched, -1 upon fatal error
 */
int virNetServerProgramDispatch(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg)
{
    ...
    switch (msg->header.type) {
    case VIR_NET_CALL:
    case VIR_NET_CALL_WITH_FDS:
        ret = virNetServerProgramDispatchCall(prog, server, client, msg);
        break;
    ...
    }

    return ret;
    ...
}

/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming method call, with header already decoded
 *
 * This method is used to dispatch a message representing an
 * incoming method call from a client. It decodes the payload
 * to obtain method call arguments, invokes the method and
 * then sends a reply packet with the return values
 *
 * Returns 0 if the reply was sent, or -1 upon fatal error
 */
static int
virNetServerProgramDispatchCall(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg)
{
    g_autofree char *arg = NULL;
    g_autofree char *ret = NULL;
    int rv = -1;
    virNetServerProgramProc *dispatcher = NULL;
    virNetMessageError rerr = { 0 };
    size_t i;
    g_autoptr(virIdentity) identity = NULL;

    if (msg->header.status != VIR_NET_OK) {
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %1$u"),
                       msg->header.status);
        goto error;
    }

    dispatcher = virNetServerProgramGetProc(prog, msg->header.proc);

    if (!dispatcher) {
        virReportError(VIR_ERR_RPC,
                       _("unknown procedure: %1$d"),
                       msg->header.proc);
        goto error;
    }

    /* If the client is not authenticated, don't allow any RPC ops
     * which are except for authentication ones */
    if (dispatcher->needAuth &&
        !virNetServerClientIsAuthenticated(client)) {
        /* Explicitly *NOT* calling  remoteDispatchAuthError() because
           we want back-compatibility with libvirt clients which don't
           support the VIR_ERR_AUTH_FAILED error code */
        virReportError(VIR_ERR_RPC,
                       "%s", _("authentication required"));
        goto error;
    }

    arg = g_new0(char, dispatcher->arg_len);
    ret = g_new0(char, dispatcher->ret_len);

    if (virNetMessageDecodePayload(msg, dispatcher->arg_filter, arg) < 0)
        goto error;

    if (!(identity = virNetServerClientGetIdentity(client)))
        goto error;

    if (virIdentitySetCurrent(identity) < 0)
        goto error;

    /*
     * When the RPC handler is called:
     *
     *  - Server object is unlocked
     *  - Client object is unlocked
     *
     * Without locking, it is safe to use:
     *
     *   'args and 'ret'
     */
    rv = (dispatcher->func)(server, client, msg, &rerr, arg, ret);

    if (virIdentitySetCurrent(NULL) < 0)
        goto error;

    /*
     * If rv == 1, this indicates the dispatch func has
     * populated 'msg' with a list of FDs to return to
     * the caller.
     *
     * Otherwise we must clear out the FDs we got from
     * the client originally.
     *
     */
    if (rv != 1) {
        for (i = 0; i < msg->nfds; i++)
            VIR_FORCE_CLOSE(msg->fds[i]);
        VIR_FREE(msg->fds);
        msg->nfds = 0;
    }

    if (rv < 0)
        goto error;

    /* Return header. We're re-using same message object, so
     * only need to tweak type/status fields */
    /*msg->header.prog = msg->header.prog;*/
    /*msg->header.vers = msg->header.vers;*/
    /*msg->header.proc = msg->header.proc;*/
    msg->header.type = msg->nfds ? VIR_NET_REPLY_WITH_FDS : VIR_NET_REPLY;
    /*msg->header.serial = msg->header.serial;*/
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, dispatcher->ret_filter, ret) < 0)
        goto error;

    xdr_free(dispatcher->arg_filter, arg);
    xdr_free(dispatcher->ret_filter, ret);

    /* Put reply on end of tx queue to send out  */
    return virNetServerClientSendMessage(client, msg);
}
```
每当有job时，线程池中的线程会执行[**virNetServerHandleJob()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L146)逻辑处理job。该逻辑最终会在[**virNetServerProgramDispatchCall()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverprogram.c#L249)中处理**RPC**消息，并将返回结果压到tx队列中

2. 在完成线程池的创建后，**libvirtd**在[**daemonSetupNetworking()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/remote/remote_daemon.c#L197)中绑定监听socket资源，从而当资源可用时唤醒线程池处理
```c
static int ATTRIBUTE_NONNULL(3)
daemonSetupNetworking(virNetServer *srv,
                      virNetServer *srvAdm,
                      struct daemonConfig *config,
                      const char *sock_path,
                      const char *sock_path_ro,
                      const char *sock_path_adm)
{
    gid_t unix_sock_gid = 0;
    int unix_sock_ro_mask = 0;
    int unix_sock_rw_mask = 0;
    int unix_sock_adm_mask = 0;
    g_autoptr(virSystemdActivation) act = NULL;

    if (virSystemdGetActivation(&act) < 0)
        return -1;

    if (config->unix_sock_group) {
        if (virGetGroupID(config->unix_sock_group, &unix_sock_gid) < 0)
            return -1;
    }

    if (virStrToLong_i(config->unix_sock_ro_perms, NULL, 8, &unix_sock_ro_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%1$s'"), config->unix_sock_ro_perms);
        return -1;
    }

    if (virStrToLong_i(config->unix_sock_admin_perms, NULL, 8, &unix_sock_adm_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%1$s'"), config->unix_sock_admin_perms);
        return -1;
    }

    if (virStrToLong_i(config->unix_sock_rw_perms, NULL, 8, &unix_sock_rw_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%1$s'"), config->unix_sock_rw_perms);
        return -1;
    }

    if (virNetServerAddServiceUNIX(srv,
                                   act,
                                   DAEMON_NAME ".socket",
                                   sock_path,
                                   unix_sock_rw_mask,
                                   unix_sock_gid,
                                   config->auth_unix_rw,
                                   NULL,
                                   false,
                                   config->max_queued_clients,
                                   config->max_client_requests) < 0)
        return -1;
    if (sock_path_ro &&
        virNetServerAddServiceUNIX(srv,
                                   act,
                                   DAEMON_NAME "-ro.socket",
                                   sock_path_ro,
                                   unix_sock_ro_mask,
                                   unix_sock_gid,
                                   config->auth_unix_ro,
                                   NULL,
                                   true,
                                   config->max_queued_clients,
                                   config->max_client_requests) < 0)
        return -1;

    if (sock_path_adm &&
        virNetServerAddServiceUNIX(srvAdm,
                                   act,
                                   DAEMON_NAME "-admin.socket",
                                   sock_path_adm,
                                   unix_sock_adm_mask,
                                   unix_sock_gid,
                                   REMOTE_AUTH_NONE,
                                   NULL,
                                   false,
                                   config->admin_max_queued_clients,
                                   config->admin_max_client_requests) < 0)
        return -1;

    if (act &&
        virSystemdActivationComplete(act) < 0)
        return -1;

    return 0;
}

int
virNetServerAddServiceUNIX(virNetServer *srv,
                           virSystemdActivation *act,
                           const char *actname,
                           const char *path,
                           mode_t mask,
                           gid_t grp,
                           int auth,
                           virNetTLSContext *tls,
                           bool readonly,
                           size_t max_queued_clients,
                           size_t nrequests_client_max)
{
    virNetServerService *svc = NULL;
    int ret;
    ...
    if (!(svc = virNetServerServiceNewUNIX(path,
                                           mask,
                                           grp,
                                           auth,
                                           tls,
                                           readonly,
                                           max_queued_clients,
                                           nrequests_client_max)))
        return -1;

    virNetServerAddService(srv, svc);
    virObjectUnref(svc);

    return 0;
}

virNetServerService *virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  virNetTLSContext *tls,
                                                  bool readonly,
                                                  size_t max_queued_clients,
                                                  size_t nrequests_client_max)
{
    virNetServerService *svc;
    virNetSocket *sock;

    VIR_DEBUG("Creating new UNIX server path='%s' mask=%o gid=%u",
              path, mask, grp);
    if (virNetSocketNewListenUNIX(path,
                                  mask,
                                  -1,
                                  grp,
                                  &sock) < 0)
        return NULL;

    svc = virNetServerServiceNewSocket(&sock,
                                       1,
                                       auth,
                                       tls,
                                       readonly,
                                       max_queued_clients,
                                       nrequests_client_max);

    virObjectUnref(sock);

    return svc;
}

static virNetServerService *
virNetServerServiceNewSocket(virNetSocket **socks,
                             size_t nsocks,
                             int auth,
                             virNetTLSContext *tls,
                             bool readonly,
                             size_t max_queued_clients,
                             size_t nrequests_client_max)
{
    virNetServerService *svc;
    size_t i;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    svc->socks = g_new0(virNetSocket *, nsocks);
    svc->nsocks = nsocks;
    for (i = 0; i < svc->nsocks; i++) {
        svc->socks[i] = socks[i];
        virObjectRef(svc->socks[i]);
    }
    svc->auth = auth;
    svc->readonly = readonly;
    svc->nrequests_client_max = nrequests_client_max;
    svc->tls = virObjectRef(tls);

    virObjectRef(svc);
    svc->timer = virEventAddTimeout(-1, virNetServerServiceTimerFunc,
                                    svc, virObjectUnref);
    if (svc->timer < 0) {
        virObjectUnref(svc);
        goto error;
    }

    for (i = 0; i < svc->nsocks; i++) {
        if (virNetSocketListen(svc->socks[i], max_queued_clients) < 0)
            goto error;

        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        virObjectRef(svc);
        if (virNetSocketAddIOCallback(svc->socks[i],
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectUnref) < 0) {
            virObjectUnref(svc);
            goto error;
        }
    }


    return svc;

 error:
    virObjectUnref(svc);
    return NULL;
}

int virNetSocketAddIOCallback(virNetSocket *sock,
                              int events,
                              virNetSocketIOFunc func,
                              void *opaque,
                              virFreeCallback ff)
{
    int ret = -1;

    virObjectRef(sock);
    virObjectLock(sock);
    if (sock->watch >= 0) {
        VIR_DEBUG("Watch already registered on socket %p", sock);
        goto cleanup;
    }

    if ((sock->watch = virEventAddHandle(sock->fd,
                                         events,
                                         virNetSocketEventHandle,
                                         sock,
                                         virNetSocketEventFree)) < 0) {
        VIR_DEBUG("Failed to register watch on socket %p", sock);
        goto cleanup;
    }
    sock->func = func;
    sock->opaque = opaque;
    sock->ff = ff;

    ret = 0;

 cleanup:
    virObjectUnlock(sock);
    if (ret != 0)
        virObjectUnref(sock);
    return ret;
}

static void virNetSocketEventHandle(int watch G_GNUC_UNUSED,
                                    int fd G_GNUC_UNUSED,
                                    int events,
                                    void *opaque)
{
    virNetSocket *sock = opaque;
    virNetSocketIOFunc func;
    void *eopaque;

    virObjectLock(sock);
    func = sock->func;
    eopaque = sock->opaque;
    virObjectUnlock(sock);

    if (func)
        func(sock, events, eopaque);
}
```
简单整理可知，**libvirtd**在[**virNetServerServiceNewSocket()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverservice.c#L125)中使用[**virNetSocketAddIOCallback()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetsocket.c#L2143)完成监听socket资源的绑定，即根据[前面libvirt文件描述符事件源小节](#文件描述符事件源)，其调用[**virEventAddHandle()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L76)来实现资源的绑定
3. 当virsh连接监听**socket**时，该**socket**资源可用，**libvirtd**的事件循环会捕获到该事件，并调用注册的[**virNetSocketEventHandle()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetsocket.c#L2106)handler来处理事件。该handler会回调在[**virNetSocketAddIOCallback()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetsocket.c#L2143)中注册的回调函数[**virNetServerServiceAccept()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverservice.c#L70)。该回调函数会调用server在[**virNetServerAddService()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L624)中初始化时注册的[**virNetServerDispatchNewClient()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L328)的dispatch函数
```c
//#0  virNetServerDispatchNewClient (svc=0x555555659810, clientsock=0x55555565a3b0, opaque=0x55555564c880) at ../src/rpc/virnetserver.c:331
//#1  0x00007ffff7c01522 in virNetServerServiceAccept (sock=0x55555565a050, events=<optimized out>, opaque=0x555555659810) at ../src/rpc/virnetserverservice.c:102
//#2  0x00007ffff7aed46e in virEventGLibHandleDispatch (fd=<optimized out>, condition=<optimized out>, opaque=0x555555659c80) at ../src/util/vireventglib.c:119
//#3  0x00007ffff7eb9c44 in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#4  0x00007ffff7f0f2b8 in  () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#5  0x00007ffff7eb73e3 in g_main_context_iteration () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#6  0x00007ffff7aee074 in virEventGLibRunOnce () at ../src/util/vireventglib.c:515
//#7  0x00007ffff7b4d349 in virEventRunDefaultImpl () at ../src/util/virevent.c:362
//#8  0x00007ffff7c05ed3 in virNetDaemonRun (dmn=0x55555564b870, dmn@entry=0x55555564c960) at ../src/rpc/virnetdaemon.c:837
//#9  0x000055555558d952 in main (argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../src/remote/remote_daemon.c:1214
//#10 0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x55555558c700 <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7429e40 in __libc_start_main_impl (main=0x55555558c700 <main>, argc=1, argv=0x7fffffffdf58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf48) at ../csu/libc-start.c:392
//#12 0x000055555558e2b5 in _start ()

static void virNetSocketEventHandle(int watch G_GNUC_UNUSED,
                                    int fd G_GNUC_UNUSED,
                                    int events,
                                    void *opaque)
{
    virNetSocket *sock = opaque;
    virNetSocketIOFunc func;
    void *eopaque;

    virObjectLock(sock);
    func = sock->func;
    eopaque = sock->opaque;
    virObjectUnlock(sock);

    if (func)
        func(sock, events, eopaque);
}

static void virNetServerServiceAccept(virNetSocket *sock,
                                      int events G_GNUC_UNUSED,
                                      void *opaque)
{
    virNetServerService *svc = opaque;
    virNetSocket *clientsock = NULL;
    int rc;

    rc = virNetSocketAccept(sock, &clientsock);
    if (rc < 0) {
        if (rc == -2) {
            /* Could not accept new client due to EMFILE. Suspend listening on
             * the socket and set up a timer to enable it later. Hopefully,
             * some FDs will be closed meanwhile. */
            VIR_DEBUG("Temporarily suspending listening on svc=%p because accept() on sock=%p failed (errno=%d)",
                      svc, sock, errno);

            virNetServerServiceToggle(svc, false);

            svc->timerActive = true;
            /* Retry in 5 seconds. */
            virEventUpdateTimeout(svc->timer, 5 * 1000);
        }
        goto cleanup;
    }

    if (!clientsock) /* Connection already went away */
        goto cleanup;

    if (!svc->dispatchFunc)
        goto cleanup;

    svc->dispatchFunc(svc, clientsock, svc->dispatchOpaque);

 cleanup:
    virObjectUnref(clientsock);
}

static int
virNetServerDispatchNewClient(virNetServerService *svc,
                              virNetSocket *clientsock,
                              void *opaque)
{
    virNetServer *srv = opaque;
    g_autoptr(virNetServerClient) client = NULL;

    if (!(client = virNetServerClientNew(virNetServerNextClientID(srv),
                                         clientsock,
                                         virNetServerServiceGetAuth(svc),
                                         virNetServerServiceIsReadonly(svc),
                                         virNetServerServiceGetMaxRequests(svc),
                                         virNetServerServiceGetTLSContext(svc),
                                         srv->clientPrivNew,
                                         srv->clientPrivPreExecRestart,
                                         srv->clientPrivFree,
                                         srv->clientPrivOpaque)))
        return -1;

    if (virNetServerAddClient(srv, client) < 0) {
        virNetServerClientClose(client);
        return -1;
    }
    return 0;
}

int
virNetServerAddClient(virNetServer *srv,
                      virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(srv);

    if (virNetServerClientInit(client) < 0)
        return -1;

    VIR_EXPAND_N(srv->clients, srv->nclients, 1);
    srv->clients[srv->nclients-1] = virObjectRef(client);

    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (virNetServerClientIsAuthPendingLocked(client))
            virNetServerTrackPendingAuthLocked(srv);
    }

    virNetServerCheckLimits(srv);

    virNetServerClientSetDispatcher(client, virNetServerDispatchNewMessage, srv);

    if (virNetServerClientInitKeepAlive(client, srv->keepaliveInterval,
                                        srv->keepaliveCount) < 0)
        return -1;

    return 0;
}

int virNetServerClientInit(virNetServerClient *client)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);
    int ret = -1;

    if (!client->tlsCtxt) {
        /* Plain socket, so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
        return 0;
    }

    if (!(client->tls = virNetTLSSessionNew(client->tlsCtxt, NULL)))
        goto error;

    virNetSocketSetTLSSession(client->sock, client->tls);

    /* Begin the TLS handshake. */
    VIR_WITH_OBJECT_LOCK_GUARD(client->tlsCtxt) {
        ret = virNetTLSSessionHandshake(client->tls);
    }

    if (ret == 0) {
        /* Unlikely, but ...  Next step is to check the certificate. */
        if (virNetServerClientCheckAccess(client) < 0)
            goto error;

        /* Handshake & cert check OK,  so prepare to read first message */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
    } else if (ret > 0) {
        /* Most likely, need to do more handshake data */
        if (virNetServerClientRegisterEvent(client) < 0)
            goto error;
    } else {
        goto error;
    }

    return 0;

 error:
    client->wantClose = true;
    return -1;
}

/*
 * @server: a locked or unlocked server object
 * @client: a locked client object
 */
static int virNetServerClientRegisterEvent(virNetServerClient *client)
{
    int mode = virNetServerClientCalculateHandleMode(client);

    if (!client->sock)
        return -1;

    virObjectRef(client);
    VIR_DEBUG("Registering client event callback %d", mode);
    if (virNetSocketAddIOCallback(client->sock,
                                  mode,
                                  virNetServerClientDispatchEvent,
                                  client,
                                  virObjectUnref) < 0) {
        virObjectUnref(client);
        return -1;
    }

    return 0;
}
```
在回调函数[**virNetServerDispatchNewClient()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L328)中，**libvirt**创建此次连接的socket，并在[**virNetServerAddClient()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L299)将该socket资源绑定到事件循环中。具体的，根据[前面libvirt文件描述符事件源小节](#文件描述符事件源)，其在[**virNetServerClientRegisterEvent()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L195)中调用[**virEventAddHandle()**](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/util/virevent.c#L76)来实现资源的绑定
4. 当virsh通过该**socket**发送**RPC**消息时，该**socket**可用，**libvirtd**的事件循环会捕获到该事件，并调用注册的[**virNetServerClientDispatchEvent()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L1412)handler来处理该事件。该回调函数会调用在[**virNetServerAddClient()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L299)中初始化时设置的[**virNetServerDispatchNewMessage()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserver.c#L195)的dispatch函数。该函数会通过[**virThreadPoolSendJob()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/util/virthreadpool.c#L369)唤醒**RPC**线程池进行处理，最终完成**RPC**消息的处理
```c
//#0  virNetServerDispatchNewMessage (client=0x555555660050, msg=0x55555564ad80, opaque=0x55555564c880) at ../src/rpc/virnetserver.c:198
//#1  0x00007ffff7aed46e in virEventGLibHandleDispatch (fd=<optimized out>, condition=<optimized out>, opaque=0x5555556431b0) at ../src/util/vireventglib.c:119
//#2  0x00007ffff7eb9c44 in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#3  0x00007ffff7f0f2b8 in  () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#4  0x00007ffff7eb73e3 in g_main_context_iteration () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#5  0x00007ffff7aee074 in virEventGLibRunOnce () at ../src/util/vireventglib.c:515
//#6  0x00007ffff7b4d349 in virEventRunDefaultImpl () at ../src/util/virevent.c:362
//#7  0x00007ffff7c05ed3 in virNetDaemonRun (dmn=0x55555564b870, dmn@entry=0x55555564c960) at ../src/rpc/virnetdaemon.c:837
//#8  0x000055555558d952 in main (argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../src/remote/remote_daemon.c:1214
//#9  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x55555558c700 <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#10 0x00007ffff7429e40 in __libc_start_main_impl (main=0x55555558c700 <main>, argc=1, argv=0x7fffffffdf58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf48) at ../csu/libc-start.c:392
//#11 0x000055555558e2b5 in _start ()

static void
virNetServerClientDispatchEvent(virNetSocket *sock, int events, void *opaque)
{
    virNetServerClient *client = opaque;
    virNetMessage *msg = NULL;

    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (client->sock != sock) {
            virNetSocketRemoveIOCallback(sock);
            return;
        }

        if (events & (VIR_EVENT_HANDLE_WRITABLE | VIR_EVENT_HANDLE_READABLE)) {
            if (client->tls &&
                virNetTLSSessionGetHandshakeStatus(client->tls) !=
                VIR_NET_TLS_HANDSHAKE_COMPLETE) {
                virNetServerClientDispatchHandshake(client);
            } else {
                if (events & VIR_EVENT_HANDLE_WRITABLE)
                    virNetServerClientDispatchWrite(client);
                if ((events & VIR_EVENT_HANDLE_READABLE) && client->rx)
                    msg = virNetServerClientDispatchRead(client);
            }
        }

        /* NB, will get HANGUP + READABLE at same time upon disconnect */
        if (events & (VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP))
            client->wantClose = true;
    }

    if (msg)
        virNetServerClientDispatchMessage(client, msg);
}

static void virNetServerClientDispatchMessage(virNetServerClient *client,
                                              virNetMessage *msg)
{
    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (!client->dispatchFunc) {
            virNetMessageFree(msg);
            client->wantClose = true;
            return;
        }
    }

    /* Accessing 'client' is safe, because virNetServerClientSetDispatcher
     * only permits setting 'dispatchFunc' once, so if non-NULL, it will
     * never change again
     */
    client->dispatchFunc(client, msg, client->dispatchOpaque);
}

static void
virNetServerDispatchNewMessage(virNetServerClient *client,
                               virNetMessage *msg,
                               void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerProgram *prog = NULL;
    unsigned int priority = 0;

    VIR_DEBUG("server=%p client=%p message=%p",
              srv, client, msg);

    VIR_WITH_OBJECT_LOCK_GUARD(srv) {
        prog = virNetServerGetProgramLocked(srv, msg);
        /* we can unlock @srv since @prog can only become invalid in case
         * of disposing @srv, but let's grab a ref first to ensure nothing
         * disposes of it before we use it. */
        virObjectRef(srv);
    }

    if (virThreadPoolGetMaxWorkers(srv->workers) > 0)  {
        virNetServerJob *job;

        job = g_new0(virNetServerJob, 1);

        job->client = virObjectRef(client);
        job->msg = msg;

        if (prog) {
            job->prog = virObjectRef(prog);
            priority = virNetServerProgramGetPriority(prog, msg->header.proc);
        }

        if (virThreadPoolSendJob(srv->workers, priority, job) < 0) {
            virObjectUnref(client);
            VIR_FREE(job);
            virObjectUnref(prog);
            goto error;
        }
    } else {
        if (virNetServerProcessMsg(srv, client, prog, msg) < 0)
            goto error;
    }

    virObjectUnref(srv);
    return;

 error:
    virNetMessageFree(msg);
    virNetServerClientClose(client);
    virObjectUnref(srv);
}
```
5. 根据前面分析，当**RPC**线程池完成RPC消息处理后，会使用[**virNetServerClientSendMessage()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L1471)将结果返回
```c
int virNetServerClientSendMessage(virNetServerClient *client,
                                  virNetMessage *msg)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(client);

    return virNetServerClientSendMessageLocked(client, msg);
}

static int
virNetServerClientSendMessageLocked(virNetServerClient *client,
                                    virNetMessage *msg)
{
    int ret = -1;
    VIR_DEBUG("msg=%p proc=%d len=%zu offset=%zu",
              msg, msg->header.proc,
              msg->bufferLength, msg->bufferOffset);

    msg->donefds = 0;
    if (client->sock && !client->wantClose) {
        PROBE(RPC_SERVER_CLIENT_MSG_TX_QUEUE,
              "client=%p len=%zu prog=%u vers=%u proc=%u type=%u status=%u serial=%u",
              client, msg->bufferLength,
              msg->header.prog, msg->header.vers, msg->header.proc,
              msg->header.type, msg->header.status, msg->header.serial);
        virNetMessageQueuePush(&client->tx, msg);

        virNetServerClientUpdateEvent(client);
        ret = 0;
    }

    return ret;
}

/*
 * @client: a locked client object
 */
static void virNetServerClientUpdateEvent(virNetServerClient *client)
{
    int mode;

    if (!client->sock)
        return;

    mode = virNetServerClientCalculateHandleMode(client);

    virNetSocketUpdateIOCallback(client->sock, mode);

    if (client->rx && virNetSocketHasCachedData(client->sock))
        virEventUpdateTimeout(client->sockTimer, 0);
}

/*
 * @client: a locked client object
 */
static int
virNetServerClientCalculateHandleMode(virNetServerClient *client)
{
    int mode = 0;


    VIR_DEBUG("tls=%p hs=%d, rx=%p tx=%p",
              client->tls,
              client->tls ? virNetTLSSessionGetHandshakeStatus(client->tls) : -1,
              client->rx,
              client->tx);
    if (!client->sock || client->wantClose)
        return 0;

    if (client->tls) {
        switch (virNetTLSSessionGetHandshakeStatus(client->tls)) {
        case VIR_NET_TLS_HANDSHAKE_RECVING:
            mode |= VIR_EVENT_HANDLE_READABLE;
            break;
        case VIR_NET_TLS_HANDSHAKE_SENDING:
            mode |= VIR_EVENT_HANDLE_WRITABLE;
            break;
        default:
        case VIR_NET_TLS_HANDSHAKE_COMPLETE:
            if (client->rx)
                mode |= VIR_EVENT_HANDLE_READABLE;
            if (client->tx)
                mode |= VIR_EVENT_HANDLE_WRITABLE;
        }
    } else {
        /* If there is a message on the rx queue, and
         * we're not in middle of a delayedClose, then
         * we're wanting more input */
        if (client->rx && !client->delayedClose)
            mode |= VIR_EVENT_HANDLE_READABLE;

        /* If there are one or more messages to send back to client,
           then monitor for writability on socket */
        if (client->tx)
            mode |= VIR_EVENT_HANDLE_WRITABLE;
    }
    VIR_DEBUG("mode=0%o", mode);
    return mode;
}
```
**RPC**线程池在[**virNetServerClientSendMessageLocked()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L1447)中将**RPC**返回消息压入**client->tx**中，且使用[**virNetServerClientUpdateEvent()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L219)添加**VIR_EVENT_HANDLE_WRITEABLE**标志到文件描述符事件源，根据[前面libvirt文件描述符事件源小节](#文件描述符事件源)可知，当文件描述符可写时也会触发文件描述符事件源的事件循环，从而最终在[**virNetServerClientDispatchEvent()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L1412)中调用[**virNetServerClientDispatchWrite()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/virnetserverclient.c#L1316)将**RPC**结果发送给virsh
```c
//#0  0x00007ffff7c022f3 in virNetServerClientDispatchWrite (client=<optimized out>) at ../src/rpc/virnetserverclient.c:1356
//#1  virNetServerClientDispatchEvent (sock=<optimized out>, events=1, opaque=0x555555660120) at ../src/rpc/virnetserverclient.c:1430
//#2  0x00007ffff7aed46e in virEventGLibHandleDispatch (fd=<optimized out>, condition=<optimized out>, opaque=0x555555663490) at ../src/util/vireventglib.c:119
//#3  0x00007ffff7eb9c44 in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#4  0x00007ffff7f0f2b8 in  () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#5  0x00007ffff7eb73e3 in g_main_context_iteration () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#6  0x00007ffff7aee074 in virEventGLibRunOnce () at ../src/util/vireventglib.c:515
//#7  0x00007ffff7b4d349 in virEventRunDefaultImpl () at ../src/util/virevent.c:362
//#8  0x00007ffff7c05ed3 in virNetDaemonRun (dmn=0x55555564b870, dmn@entry=0x55555564c960) at ../src/rpc/virnetdaemon.c:837
//#9  0x000055555558d952 in main (argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../src/remote/remote_daemon.c:1214
//#10 0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x55555558c700 <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffdf58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7429e40 in __libc_start_main_impl (main=0x55555558c700 <main>, argc=1, argv=0x7fffffffdf58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf48) at ../csu/libc-start.c:392
//#12 0x000055555558e2b5 in _start ()

static void
virNetServerClientDispatchEvent(virNetSocket *sock, int events, void *opaque)
{
    virNetServerClient *client = opaque;
    virNetMessage *msg = NULL;

    VIR_WITH_OBJECT_LOCK_GUARD(client) {
        if (client->sock != sock) {
            virNetSocketRemoveIOCallback(sock);
            return;
        }

        if (events & (VIR_EVENT_HANDLE_WRITABLE | VIR_EVENT_HANDLE_READABLE)) {
            if (client->tls &&
                virNetTLSSessionGetHandshakeStatus(client->tls) !=
                VIR_NET_TLS_HANDSHAKE_COMPLETE) {
                virNetServerClientDispatchHandshake(client);
            } else {
                if (events & VIR_EVENT_HANDLE_WRITABLE)
                    virNetServerClientDispatchWrite(client);
                if ((events & VIR_EVENT_HANDLE_READABLE) && client->rx)
                    msg = virNetServerClientDispatchRead(client);
            }
        }

        /* NB, will get HANGUP + READABLE at same time upon disconnect */
        if (events & (VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP))
            client->wantClose = true;
    }

    if (msg)
        virNetServerClientDispatchMessage(client, msg);
}

/*
 * Process all queued client->tx messages until
 * we would block on I/O
 */
static void
virNetServerClientDispatchWrite(virNetServerClient *client)
{
    while () {
        if (client->tx->bufferOffset < client->tx->bufferLength) {
            ssize_t ret;
            ret = virNetServerClientWrite(client);
            if (ret < 0) {
                client->wantClose = true;
                return;
            }
            if (ret == 0)
                return; /* Would block on write EAGAIN */
        }

        if (client->tx->bufferOffset == client->tx->bufferLength) {
            virNetMessage *msg;
            size_t i;

            for (i = client->tx->donefds; i < client->tx->nfds; i++) {
                int rv;
                if ((rv = virNetSocketSendFD(client->sock, client->tx->fds[i])) < 0) {
                    client->wantClose = true;
                    return;
                }
                if (rv == 0) /* Blocking */
                    return;
                client->tx->donefds++;
            }

#if WITH_SASL
            /* Completed this 'tx' operation, so now read for all
             * future rx/tx to be under a SASL SSF layer
             */
            if (client->sasl) {
                virNetSocketSetSASLSession(client->sock, client->sasl);
                g_clear_pointer(&client->sasl, virObjectUnref);
            }
#endif

            /* Get finished msg from head of tx queue */
            msg = virNetMessageQueueServe(&client->tx);

            if (msg->tracked) {
                client->nrequests--;
                /* See if the recv queue is currently throttled */
                if (!client->rx &&
                    client->nrequests < client->nrequests_max) {
                    /* Ready to recv more messages */
                    virNetMessageClear(msg);
                    msg->bufferLength = VIR_NET_MESSAGE_LEN_MAX;
                    msg->buffer = g_new0(char, msg->bufferLength);
                    client->rx = g_steal_pointer(&msg);
                    client->nrequests++;
                }
            }

            virNetMessageFree(msg);

            virNetServerClientUpdateEvent(client);

            if (client->delayedClose)
                client->wantClose = true;
         }
    }
}
```

# 参考

1. [The Main Event Loop](https://docs.gtk.org/glib/main-loop.html)
2. [GNOME Developer Documentation](https://developer.gnome.org/documentation/tutorials/main-contexts.html#what-is-gmaincontext)
3. [QEMU 中的线程和事件循环](https://martins3.github.io/qemu/threads.html)
4. [QEMU Internals: Event loops](http://blog.vmsplice.net/2020/08/qemu-internals-event-loops.html)
5. [QEMU 事件循环机制简析（二）：基本组成](https://blog.jjl9807.com/archives/9/)
6. [QEMU 事件循环机制简析（三）：下半部机制](https://blog.jjl9807.com/archives/10/)
7. [libvirt代码调用流程分析](https://qkxu.github.io/2019/11/05/libvirt%E4%BB%A3%E7%A0%81%E8%B0%83%E7%94%A8%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90.html)
8. [libvirt初始化流程分析](https://blog.csdn.net/qq_33970713/article/details/123903255)
9. [ 为 LibVirt 添加新的 API](https://arondight.me/2016/12/25/%E4%B8%BALibVirt%E6%B7%BB%E5%8A%A0%E6%96%B0%E7%9A%84API/#%E5%AE%9E%E7%8E%B0-remote-%E9%A9%B1%E5%8A%A8)
10. [Internals](https://libvirt.org/kbase/index.html#internals)
11. [libvirt RPC infrastructure](https://libvirt.org/kbase/internals/rpc.html)
12. [Libvirt's event loop](https://libvirt.org/kbase/internals/eventloop.html)
