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

# ~~libvirt~~

# 参考

1. [The Main Event Loop](https://docs.gtk.org/glib/main-loop.html)
2. [GNOME Developer Documentation](https://developer.gnome.org/documentation/tutorials/main-contexts.html#what-is-gmaincontext)
3. [QEMU 中的线程和事件循环](https://martins3.github.io/qemu/threads.html)
4. [QEMU Internals: Event loops](http://blog.vmsplice.net/2020/08/qemu-internals-event-loops.html)
5. [QEMU 事件循环机制简析（二）：基本组成](https://blog.jjl9807.com/archives/9/)
6. [QEMU 事件循环机制简析（三）：下半部机制](https://blog.jjl9807.com/archives/10/)
