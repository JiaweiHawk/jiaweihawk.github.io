---
title: qemu内存模型
date: 2024-07-20 09:37:13
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

这里简单介绍一些**QEMU**的内存模型，即**QEMU**是如何管理gpa到hva的映射关系。

其内存模型主要由**RAMBlock**、**Memory Region**、**AddressSpace**和**FlatView**等结构构成。

# RAMBlock

无论如何，Qemu都需要申请一段内存空间用来存放虚拟机内存的真实数据，而这部分内存空间由[**struct RAMBLOCK**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/exec/ramblock.h#L27)来管理。

## struct RAMBlock

```c
struct RAMBlock {
    struct rcu_head rcu;
    struct MemoryRegion *mr;
    uint8_t *host;
    uint8_t *colo_cache; /* For colo, VM's ram cache */
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    /* Protected by the BQL.  */
    char idstr[256];
    /* RCU-enabled, writes protected by the ramlist lock */
    QLIST_ENTRY(RAMBlock) next;
    QLIST_HEAD(, RAMBlockNotifier) ramblock_notifiers;
    int fd;
    uint64_t fd_offset;
    size_t page_size;
    /* dirty bitmap used during migration */
    unsigned long *bmap;

    /*
     * Below fields are only used by mapped-ram migration
     */
    /* bitmap of pages present in the migration file */
    unsigned long *file_bmap;
    /*
     * offset in the file pages belonging to this ramblock are saved,
     * used only during migration to a file.
     */
    off_t bitmap_offset;
    uint64_t pages_offset;

    /* bitmap of already received pages in postcopy */
    unsigned long *receivedmap;

    /*
     * bitmap to track already cleared dirty bitmap.  When the bit is
     * set, it means the corresponding memory chunk needs a log-clear.
     * Set this up to non-NULL to enable the capability to postpone
     * and split clearing of dirty bitmap on the remote node (e.g.,
     * KVM).  The bitmap will be set only when doing global sync.
     *
     * It is only used during src side of ram migration, and it is
     * protected by the global ram_state.bitmap_mutex.
     *
     * NOTE: this bitmap is different comparing to the other bitmaps
     * in that one bit can represent multiple guest pages (which is
     * decided by the `clear_bmap_shift' variable below).  On
     * destination side, this should always be NULL, and the variable
     * `clear_bmap_shift' is meaningless.
     */
    unsigned long *clear_bmap;
    uint8_t clear_bmap_shift;

    /*
     * RAM block length that corresponds to the used_length on the migration
     * source (after RAM block sizes were synchronized). Especially, after
     * starting to run the guest, used_length and postcopy_length can differ.
     * Used to register/unregister uffd handlers and as the size of the received
     * bitmap. Receiving any page beyond this length will bail out, as it
     * could not have been valid on the source.
     */
    ram_addr_t postcopy_length;
};
```

其中，**host**指向Qemu申请的内存空间的虚拟地址，也就是**hva**。

而所有的**struct RAMBlock**由**next**指针形成单链表存储在[**ram_list**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L88)，如下图所示

```
         ram_list                 
       ┌───────┬──┐               
       │blocks │  ├────┐          
       └───────┴──┘    │          
                       │          
                       │          
      struct RAMBlock◄─┘          
      ┌─────┬──────┐              
      │idstr│pc.ram│              
      ├─────┼──────┤              
      │next │      ├─────┐        
      └─────┴──────┘     │        
                         │        
      struct RAMBlock◄───┘        
┌─────┬─────────────────────┐     
│idstr│0000:00:02.0/vga.vram│     
├─────┼─────────────────────┤     
│next │                     │     
└─────┴─────────────────────┘     
```

## 初始化

Qemu会通过[**qemu_ram_alloc_internal()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L2008)来分配和初始化**RAMBlock**数据，关键逻辑如下所示
```c
static
RAMBlock *qemu_ram_alloc_internal(ram_addr_t size, ram_addr_t max_size,
                                  void (*resized)(const char*,
                                                  uint64_t length,
                                                  void *host),
                                  void *host, uint32_t ram_flags,
                                  MemoryRegion *mr, Error **errp)
{
    RAMBlock *new_block;
    ...
    new_block = g_malloc0(sizeof(*new_block));
    new_block->host = host;
    ram_block_add(new_block, &local_err);
    ...
    return new_block;
}

static void ram_block_add(RAMBlock *new_block, Error **errp)
{
    RAMBlock *block;
    RAMBlock *last_block = NULL;

    qemu_mutex_lock_ramlist();
    new_block->host = qemu_anon_ram_alloc(new_block->max_length,
                                                  &new_block->mr->align,
                                                  shared, noreserve);

    /* Keep the list sorted from biggest to smallest block.  Unlike QTAILQ,
     * QLIST (which has an RCU-friendly variant) does not have insertion at
     * tail, so save the last element in last_block.
     */
    RAMBLOCK_FOREACH(block) {
        last_block = block;
        if (block->max_length < new_block->max_length) {
            break;
        }
    }
    if (block) {
        QLIST_INSERT_BEFORE_RCU(block, new_block, next);
    } else if (last_block) {
        QLIST_INSERT_AFTER_RCU(last_block, new_block, next);
    } else { /* list is empty */
        QLIST_INSERT_HEAD_RCU(&ram_list.blocks, new_block, next);
    }

    /* Write list before version */
    smp_wmb();
    ram_list.version++;
    qemu_mutex_unlock_ramlist();
}
```

其主要就是初始化**RAMBlock**，管理该**RAMBlock**对应的hva，并将其插入**ram_list**中

# ~~Memory Region~~

# ~~AddressSpace~~

# ~~FlatView~~

# 参考

1. [qemu对虚拟机的内存管理（一）](https://www.cnblogs.com/ccxikka/p/9477530.html)
2. [QEMU 的 memory model](https://martins3.github.io/qemu/memory.html)
3. [地址空间](https://richardweiyang-2.gitbook.io/understanding_qemu/00-as)
4. [QEMU的内存模拟](https://66ring.github.io/2021/04/13/universe/qemu/qemu_softmmu/)
5. [MemoryRegion模型原理，以及同FlatView模型的关系(QEMU2.0.0)](https://blog.csdn.net/leoufung/article/details/48781205)