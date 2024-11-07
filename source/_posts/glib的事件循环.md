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

# ~~qemu~~

# ~~libvirt~~

# 参考

1. [The Main Event Loop](https://docs.gtk.org/glib/main-loop.html)
2. [GNOME Developer Documentation](https://developer.gnome.org/documentation/tutorials/main-contexts.html#what-is-gmaincontext)
3. [QEMU 中的线程和事件循环](https://martins3.github.io/qemu/threads.html)
4. [QEMU Internals: Event loops](http://blog.vmsplice.net/2020/08/qemu-internals-event-loops.html)
