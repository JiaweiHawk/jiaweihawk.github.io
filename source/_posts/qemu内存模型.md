---
title: qemu内存模型
date: 2024-07-20 09:37:13
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

这里简单介绍一些**QEMU**的内存模型，即**QEMU**是如何管理gpa到hva的映射关系。

其内存模型主要由**RAMBlock**、**MemoryRegion**、**AddressSpace**和**FlatView**等结构构成。

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

# MemoryRegion

实际上，不同区域的gpa有着不同的属性和功能，因此需要分开管理。

例如，对于如下e1000-mmio的gpa访问，实际上并不是内存的读写，而是对于设备的模拟操作，Qemu需要模拟设备处理guest的请求
```
00000000febc0000-00000000febdffff (prio 1, i/o): e1000-mmio
```

而对于如下的pc.ram的gpa访问，则只是单纯的内存访问，Qemu只需要简单的存取或读取数据即可
```
0000000000000000-00000000ffffffff (prio 0, ram): pc.ram
```

为此，Qemu使用[**struct MemoryRegion**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/exec/memory.h#L785)，以树状组织管理整个gpa。

## struct MemoryRegion

```c
/** MemoryRegion:
 *
 * A struct representing a memory region.
 */
struct MemoryRegion {
    Object parent_obj;

    /* private: */

    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool nonvolatile;
    bool rom_device;
    bool flush_coalesced_mmio;
    bool unmergeable;
    uint8_t dirty_log_mask;
    bool is_iommu;
    RAMBlock *ram_block;
    Object *owner;
    /* owner as TYPE_DEVICE. Used for re-entrancy checks in MR access hotpath */
    DeviceState *dev;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    int mapped_via_alias; /* Mapped via an alias, container might be NULL */
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    QTAILQ_HEAD(, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_HEAD(, CoalescedMemoryRange) coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    RamDiscardManager *rdm; /* Only for RAM */

    /* For devices designed to perform re-entrant IO into their own IO MRs */
    bool disable_reentrancy_guard;
};
```

其**addr**字段表明**MemoryRegion**起始gpa相对于**父MemoryRegion**起始gpa的相对偏移，而**size**表明这段内存区间的大小。

实际上，根据[Qemu官网](https://www.qemu.org/docs/master/devel/memory.html#types-of-regions)，**MemoryRegion**可以分为**RAM MemoryRegion**、**ROM MemoryRegion**、**MMIO MemoryRegion**、**ROM device MemoryRegion**、**IOMMU MemoryRegion**、**container MemoryRegion**、**alias MemoryRegion**和**reservation MemoryRegion**。

## MR间关系

### 树状结构

对于**container MemoryRegion**来说，其**subregions**字段包含了其他的**子MemoryRegion**，而这些**子MemoryRegion**的**container**字段则指向该**container MemoryRegion**。这些**子MemoryRegion**之间没有交集，通过[**memory_region_add_subregion()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L2648)初始化对应的**subregions**和**container**字段，从而构建出如下的树状结构

```
                              struct MemoryRegion                                      
                             ┌──────────┬────────┐                                     
                             │name      │io      │                                     
                             ├──────────┼────────┤                                     
                             │addr      │0       │                                     
                             ├──────────┼────────┤                                     
                             │size      │65536   │                                     
                             ├──────────┼────────┤                                     
                             │subregions│        │                                     
                             └──────────┴───┬────┘                                     
                                            │                                          
                          ┌─────────────────┴─────────────────┬────────────────────┬───
                          │                                   │                    │   
                          ▼                                   ▼                    ▼   
                struct MemoryRegion                 struct MemoryRegion                
               ┌──────────┬──────────┐             ┌──────────┬──────────┐             
               │name      │piix4-pm  │             │name      │pm-smbus  │             
               ├──────────┼──────────┤             ├──────────┼──────────┤             
               │addr      │1536      │             │addr      │45312     │             
               ├──────────┼──────────┤             ├──────────┼──────────┤             
               │size      │64        │             │size      │64        │             
               ├──────────┼──────────┤             ├──────────┼──────────┤             
               │subregions│          │             │subregions│NULL      │             
               └──────────┴─────┬────┘             └──────────┴──────────┘             
                                │                                                      
             ┌──────────────────┴──────────┬──────────────────┬───                     
             │                             │                  │                        
             ▼                             ▼                  ▼                        
 struct MemoryRegion            struct MemoryRegion                                    
┌──────────┬──────────┐        ┌──────────┬──────────┐                                 
│name      │acpi-cnt  │        │name      │acpi-evt  │                                 
├──────────┼──────────┤        ├──────────┼──────────┤                                 
│addr      │4         │        │addr      │0         │                                 
├──────────┼──────────┤        ├──────────┼──────────┤                                 
│size      │2         │        │size      │4         │                                 
├──────────┼──────────┤        ├──────────┼──────────┤                                 
│subregions│NULL      │        │subregions│NULL      │                                 
└──────────┴──────────┘        └──────────┴──────────┘                                 
```

### 交叠

通常情况下，MemoryRegion之间不会交叠：要么内含；要么不相交。

但是考虑到诸如pcie设备的地址空间是动态分配的，因此允许MemoryRegion交叠并通过优先级决定交叠部分的可见性会极大地简化这部分代码。可以通过[**memory_region_add_subregion_overlap()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L2656)来向一个**container MemoryRegion**中插入和其他**子MemoryRegion**交叠的MemoryRegion并声明优先级，如下所示

```
                   struct MemoryRegion                                         
                  ┌──────────┬──────────────────┐                              
                  │name      │pci               │                              
                  ├──────────┼──────────────────┤                              
                  │addr      │0                 │                              
                  ├──────────┼──────────────────┤                              
                  │size      │0xffffffffffffffff│                              
                  ├──────────┼──────────────────┤                              
                  │priority  │-1                │                              
                  ├──────────┼──────────────────┤                              
                  │subregions│                  │                              
                  └──────────┴───┬──────────────┘                              
                                 │                                             
               ┌─────────────────┴─────────┬───────────────────────────────►   
               │                           │                                   
               ▼                           ▼                                   
 struct MemoryRegion                                                           
┌──────────┬──────────────────┐                                                
│name      │vga-lowmem        │                                                
├──────────┼──────────────────┤                                                
│addr      │0xa0000           │                                                
├──────────┼──────────────────┤                                                
│size      │0x20000           │                                                
├──────────┼──────────────────┤                                                
│priority  │1                 │                                                
├──────────┼──────────────────┤                                                
│subregions│NULL              │                                                
└──────────┴──────────────────┘                                                
```

最终，其表现出来的结果是\[0, 0x9ffff\](pci)、\[0xa0000, 0xbffff\](vga-lowmem)和\[0xc0000, 0xffffffffffffffff\](pci)


# AddressSpace

对于Guest来说，相同的地址可能有不同的意义。例如port IO中的地址和内存中的地址，即使值相同表示的也不是同一个东西。

为此，Qemu使用[**struct AddressSpace**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/exec/memory.h#L1112)来管理不同类型的地址空间，主要包括[**address_space_memory**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L94)和[**address_space_io**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L93)。

## struct AddressSpace

```c
/**
 * struct AddressSpace: describes a mapping of addresses to #MemoryRegion objects
 */
struct AddressSpace {
    /* private: */
    struct rcu_head rcu;
    char *name;
    MemoryRegion *root;

    /* Accessed via RCU.  */
    struct FlatView *current_map;

    int ioeventfd_nb;
    int ioeventfd_notifiers;
    struct MemoryRegionIoeventfd *ioeventfds;
    QTAILQ_HEAD(, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};
```

其中，**root**字段指向该地址空间中的**MemoryRegion**资源，即树状**MemoryRegion**的根，从而可通过遍历树状**MemoryRegion**来访问地址空间中的所有地址。

## FlatView

Qemu处理Guest的内存操作时，都是基于对应**AddressSpace**，找到地址对应的**MemoryRegion**，完成最终的内存操作模拟。但考虑到**MemoryRegion**的树状结构，需要进行大量的计算才能获取地址实际对应的**MemoryRegion**。为了提高效率，Qemu在**AddressSpace**中添加了[**FlatView**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/exec/memory.h#L1134)来加快地址查找，其结构如下所示。

```c
/* Flattened global view of current active memory hierarchy.  Kept in sorted
 * order.
 */
struct FlatView {
    struct rcu_head rcu;
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
    struct AddressSpaceDispatch *dispatch;
    MemoryRegion *root;
};

/* Range of memory in the global map.  Addresses are absolute. */
struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    uint8_t dirty_log_mask;
    bool romd_mode;
    bool readonly;
    bool nonvolatile;
    bool unmergeable;
};
```

具体来说，**FlatView**由数个互相不重合的[**struct FlatRange**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L219)构成，每一个**FlatRange**包含地址空间和其实际对应的**MemoryRegion**，从而能表示**AddressSpace**中树状**MemoryRegion**经过平坦化后的最终线性地址空间，如下所示。

```
                                                                                           ┌─────────────────────────────────────────┐                               
                                                                                           │                                         │                               
                                                                                           │                                         │                               
                                                                                           │                          ┌──────────────▼─────────────┐                 
                                                                                           │                          │      struct FlatRange      │                 
                                                                                           │                          │ ┌──────┬─────────────────┐ │                 
                                                                                           │                          │ │start │0                │ │                 
                                                                                           │                          │ ├──────┼─────────────────┤ │                 
                                     struct AddressSpace                                   │                          │ │size  │1536             │ │                 
                                     ┌───────────┬────┐        ┌────►struct FlatView       │                          │ ├──────┼─────────────────┤ │                 
                                     │name       │I/O │        │      ┌──────┬─────┐       │            ┌─────────────┼─┤mr    │                 │ │                 
                                     ├───────────┼────┤        │      │ranges│     ├───────┘            │             │ └──────┴─────────────────┘ │                 
                                     │current_map│    ├────────┘      └──────┴─────┘                    │             │                            │                 
                                     ├───────────┼────┤                                                 │             ├────────────────────────────┤                 
                                     │root       │    │                                                 │             │      struct FlatRange      │                 
                                     └───────────┴─┬──┘                                                 │             │ ┌──────┬─────────────────┐ │                 
                                                   │                                                    │             │ │start │1536             │ │                 
                                                   │                                                    │             │ ├──────┼─────────────────┤ │                 
                                                   ▼                                                    │             │ │size  │4                │ │                 
                                     struct MemoryRegion◄───────────────────────────────────────────────┤             │ ├──────┼─────────────────┤ │                 
                                    ┌──────────┬────────┐                                               │             │ │mr    │                 ├─┼──────────────┐  
                                    │name      │io      │                                               │             │ └──────┴─────────────────┘ │              │  
                                    ├──────────┼────────┤                                               │             │                            │              │  
                                    │addr      │0       │                                               │             ├────────────────────────────┤              │  
                                    ├──────────┼────────┤                                               │             │      struct FlatRange      │              │  
                                    │size      │65536   │                                               │             │ ┌──────┬─────────────────┐ │              │  
                                    ├──────────┼────────┤                                               │             │ │start │1540             │ │              │  
                                    │subregions│        │                                               │             │ ├──────┼─────────────────┤ │              │  
                                    └──────────┴───┬────┘                                               │             │ │size  │2                │ │              │  
                                                   │                                                    │             │ ├──────┼─────────────────┤ │              │  
                                 ┌─────────────────┴─────────────────┬                                  │             │ │mr    │                 ├─┼──────────┐   │  
                                 │                                   │                                  │             │ └──────┴─────────────────┘ │          │   │  
                                 ▼                                   ▼                                  │             │                            │          │   │  
┌─────────────────────►struct MemoryRegion                 struct MemoryRegion◄─────┐                   │             ├────────────────────────────┤          │   │  
│                     ┌──────────┬──────────┐             ┌──────────┬──────────┐   │                   │             │      struct FlatRange      │          │   │  
│                     │name      │piix4-pm  │             │name      │pm-smbus  │   │                   │             │ ┌──────┬─────────────────┐ │          │   │  
│                     ├──────────┼──────────┤             ├──────────┼──────────┤   │                   │             │ │start │1542             │ │          │   │  
│                     │addr      │1536      │             │addr      │45312     │   │                   │             │ ├──────┼─────────────────┤ │          │   │  
│                     ├──────────┼──────────┤             ├──────────┼──────────┤   │                   │             │ │size  │58               │ │          │   │  
│                     │size      │64        │             │size      │64        │   │                   │             │ ├──────┼─────────────────┤ │          │   │  
│                     ├──────────┼──────────┤             ├──────────┼──────────┤   │                   │             │ │mr    │                 ├─┼──────┐   │   │  
│                     │subregions│          │             │subregions│NULL      │   │                   │             │ └──────┴─────────────────┘ │      │   │   │  
│                     └──────────┴─────┬────┘             └──────────┴──────────┘   │                   │             │                            │      │   │   │  
│                                      │                                            │                   │             ├────────────────────────────┤      │   │   │  
│                   ┌──────────────────┴──────────┬                                 │                   │             │      struct FlatRange      │      │   │   │  
│                   │                             │                                 │                   │             │ ┌──────┬─────────────────┐ │      │   │   │  
│                   ▼                             ▼                                 │                   │             │ │start │1600             │ │      │   │   │  
│   ┌──►struct MemoryRegion            struct MemoryRegion◄──────┐                  │                   │             │ ├──────┼─────────────────┤ │      │   │   │  
│   │  ┌──────────┬──────────┐        ┌──────────┬──────────┐    │                  │                   │             │ │size  │43712            │ │      │   │   │  
│   │  │name      │acpi-cnt  │        │name      │acpi-evt  │    │                  │                   │             │ ├──────┼─────────────────┤ │      │   │   │  
│   │  ├──────────┼──────────┤        ├──────────┼──────────┤    │                  │                   ├─────────────┼─┤mr    │                 │ │      │   │   │  
│   │  │addr      │4         │        │addr      │0         │    │                  │                   │             │ └──────┴─────────────────┘ │      │   │   │  
│   │  ├──────────┼──────────┤        ├──────────┼──────────┤    │                  │                   │             │                            │      │   │   │  
│   │  │size      │2         │        │size      │4         │    │                  │                   │             ├────────────────────────────┤      │   │   │  
│   │  ├──────────┼──────────┤        ├──────────┼──────────┤    │                  │                   │             │      struct FlatRange      │      │   │   │  
│   │  │subregions│NULL      │        │subregions│NULL      │    │                  │                   │             │ ┌──────┬─────────────────┐ │      │   │   │  
│   │  └──────────┴──────────┘        └──────────┴──────────┘    │                  │                   │             │ │start │45312            │ │      │   │   │  
│   │                                                            │                  │                   │             │ ├──────┼─────────────────┤ │      │   │   │  
│   │                                                            │                  │                   │             │ │size  │64               │ │      │   │   │  
│   │                                                            │                  │                   │             │ ├──────┼─────────────────┤ │      │   │   │  
│   │                                                            │                  │                   │             │ │mr    │                 ├─┼───┐  │   │   │  
│   │                                                            │                  │                   │             │ └──────┴─────────────────┘ │   │  │   │   │  
│   │                                                            │                  │                   │             │                            │   │  │   │   │  
│   │                                                            │                  │                   │             ├────────────────────────────┤   │  │   │   │  
│   │                                                            │                  │                   │             │      struct FlatRange      │   │  │   │   │  
│   │                                                            │                  │                   │             │ ┌──────┬─────────────────┐ │   │  │   │   │  
│   │                                                            │                  │                   │             │ │start │45376            │ │   │  │   │   │  
│   │                                                            │                  │                   │             │ ├──────┼─────────────────┤ │   │  │   │   │  
│   │                                                            │                  │                   │             │ │size  │20160            │ │   │  │   │   │  
│   │                                                            │                  │                   │             │ ├──────┼─────────────────┤ │   │  │   │   │  
│   │                                                            │                  │                   └─────────────┼─┤mr    │                 │ │   │  │   │   │  
│   │                                                            │                  │                                 │ └──────┴─────────────────┘ │   │  │   │   │  
│   │                                                            │                  │                                 │                            │   │  │   │   │  
│   │                                                            │                  │                                 └────────────────────────────┘   │  │   │   │  
│   │                                                            │                  │                                                                  │  │   │   │  
│   │                                                            │                  └──────────────────────────────────────────────────────────────────┘  │   │   │  
│   │                                                            │                                                                                        │   │   │  
└───┼────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────┘   │   │  
    │                                                            │                                                                                            │   │  
    └────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┘   │  
                                                                 │                                                                                                │  
                                                                 └────────────────────────────────────────────────────────────────────────────────────────────────┘  
```

而Qemu通过[**address_space_update_topology()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L1100)生成**AddressSpace**对应的**FlatView**
```c
static void address_space_update_topology(AddressSpace *as)
{
    MemoryRegion *physmr = memory_region_get_flatview_root(as->root);

    flatviews_init();
    if (!g_hash_table_lookup(flat_views, physmr)) {
        generate_memory_topology(physmr);
    }
    address_space_set_flatview(as);
}

/* Render a memory topology into a list of disjoint absolute ranges. */
static FlatView *generate_memory_topology(MemoryRegion *mr)
{
    int i;
    FlatView *view;

    view = flatview_new(mr);

    if (mr) {
        render_memory_region(view, mr, int128_zero(),
                             addrrange_make(int128_zero(), int128_2_64()),
                             false, false, false);
    }
    flatview_simplify(view);
    ...
    return view;
}

/* Render a memory region into the global view.  Ranges in @view obscure
 * ranges in @mr.
 */
static void render_memory_region(FlatView *view,
                                 MemoryRegion *mr,
                                 Int128 base,
                                 AddrRange clip,
                                 bool readonly,
                                 bool nonvolatile,
                                 bool unmergeable)
{
    MemoryRegion *subregion;
    unsigned i;
    hwaddr offset_in_region;
    Int128 remain;
    Int128 now;
    FlatRange fr;
    AddrRange tmp;

    if (!mr->enabled) {
        return;
    }

    int128_addto(&base, int128_make64(mr->addr));
    readonly |= mr->readonly;
    nonvolatile |= mr->nonvolatile;
    unmergeable |= mr->unmergeable;

    tmp = addrrange_make(base, mr->size);

    if (!addrrange_intersects(tmp, clip)) {
        return;
    }

    clip = addrrange_intersection(tmp, clip);

    if (mr->alias) {
        int128_subfrom(&base, int128_make64(mr->alias->addr));
        int128_subfrom(&base, int128_make64(mr->alias_offset));
        render_memory_region(view, mr->alias, base, clip,
                             readonly, nonvolatile, unmergeable);
        return;
    }

    /* Render subregions in priority order. */
    QTAILQ_FOREACH(subregion, &mr->subregions, subregions_link) {
        render_memory_region(view, subregion, base, clip,
                             readonly, nonvolatile, unmergeable);
    }

    if (!mr->terminates) {
        return;
    }

    offset_in_region = int128_get64(int128_sub(clip.start, base));
    base = clip.start;
    remain = clip.size;

    fr.mr = mr;
    fr.dirty_log_mask = memory_region_get_dirty_log_mask(mr);
    fr.romd_mode = mr->romd_mode;
    fr.readonly = readonly;
    fr.nonvolatile = nonvolatile;
    fr.unmergeable = unmergeable;

    /* Render the region itself into any gaps left by the current view. */
    for (i = 0; i < view->nr && int128_nz(remain); ++i) {
        if (int128_ge(base, addrrange_end(view->ranges[i].addr))) {
            continue;
        }
        if (int128_lt(base, view->ranges[i].addr.start)) {
            now = int128_min(remain,
                             int128_sub(view->ranges[i].addr.start, base));
            fr.offset_in_region = offset_in_region;
            fr.addr = addrrange_make(base, now);
            flatview_insert(view, i, &fr);
            ++i;
            int128_addto(&base, now);
            offset_in_region += int128_get64(now);
            int128_subfrom(&remain, now);
        }
        now = int128_sub(int128_min(int128_add(base, remain),
                                    addrrange_end(view->ranges[i].addr)),
                         base);
        int128_addto(&base, now);
        offset_in_region += int128_get64(now);
        int128_subfrom(&remain, now);
    }
    if (int128_nz(remain)) {
        fr.offset_in_region = offset_in_region;
        fr.addr = addrrange_make(base, remain);
        flatview_insert(view, i, &fr);
    }
}

/* Attempt to simplify a view by merging adjacent ranges */
static void flatview_simplify(FlatView *view)
{
    unsigned i, j, k;

    i = 0;
    while (i < view->nr) {
        j = i + 1;
        while (j < view->nr
               && can_merge(&view->ranges[j-1], &view->ranges[j])) {
            int128_addto(&view->ranges[i].addr.size, view->ranges[j].addr.size);
            ++j;
        }
        ++i;
        for (k = i; k < j; k++) {
            memory_region_unref(view->ranges[k].mr);
        }
        memmove(&view->ranges[i], &view->ranges[j],
                (view->nr - j) * sizeof(view->ranges[j]));
        view->nr -= j - i;
    }
}
```

可以看到，生成**FlatView**整体可分为两步，首先通过[**memory_region_get_flatview_root()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L708)获取**AddressSpace**对应的**树状MemoryRegion**根，其次通过[**generate_memory_topology()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/memory.c#L753)平坦化地址空间。

其中**generate_memory_topology**的逻辑也相对比较清晰:通过**DFS**遍历整棵树即可平坦化。

## 内存分派

虽然Qemu已经通过**FlatView**加快了**AddressSpace**地址对应的**MemoryRegion**的查找，但还可以使用[**struct AddressSpaceDispatch**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L130)以类似页表的形式进一步加快查找

```c
struct AddressSpaceDispatch {
    MemoryRegionSection *mru_section;
    /* This is a multi-level map on the physical address space.
     * The bottom level has pointers to MemoryRegionSections.
     */
    PhysPageEntry phys_map;
    PhysPageMap map;
};

/**
 * struct MemoryRegionSection: describes a fragment of a #MemoryRegion
 *
 * @mr: the region, or %NULL if empty
 * @fv: the flat view of the address space the region is mapped in
 * @offset_within_region: the beginning of the section, relative to @mr's start
 * @size: the size of the section; will not exceed @mr's boundaries
 * @offset_within_address_space: the address of the first byte of the section
 *     relative to the region's address space
 * @readonly: writes to this section are ignored
 * @nonvolatile: this section is non-volatile
 * @unmergeable: this section should not get merged with adjacent sections
 */
struct MemoryRegionSection {
    Int128 size;
    MemoryRegion *mr;
    FlatView *fv;
    hwaddr offset_within_region;
    hwaddr offset_within_address_space;
    bool readonly;
    bool nonvolatile;
    bool unmergeable;
};

struct PhysPageEntry {
    /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
    uint32_t skip : 6;
     /* index into phys_sections (!skip) or phys_map_nodes (skip) */
    uint32_t ptr : 26;
};

/* Size of the L2 (and L3, etc) page tables.  */
#define ADDR_SPACE_BITS 64
#define P_L2_BITS 9
#define P_L2_SIZE (1 << P_L2_BITS)
#define P_L2_LEVELS (((ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / P_L2_BITS) + 1)

typedef PhysPageEntry Node[P_L2_SIZE];


typedef struct PhysPageMap {
    struct rcu_head rcu;

    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;
```

Qemu使用[**address_space_lookup_region()**](https://elixir.bootlin.com/qemu/v8.2.2/source/system/physmem.c#L336)完成地址分派，逻辑如下所示
```c
/* Called from RCU critical section */
static MemoryRegionSection *address_space_lookup_region(AddressSpaceDispatch *d,
                                                        hwaddr addr,
                                                        bool resolve_subpage)
{
    MemoryRegionSection *section = qatomic_read(&d->mru_section);
    subpage_t *subpage;

    if (!section || section == &d->map.sections[PHYS_SECTION_UNASSIGNED] ||
        !section_covers_addr(section, addr)) {
        section = phys_page_find(d, addr);
        qatomic_set(&d->mru_section, section);
    }
    ...
    return section;
}

static MemoryRegionSection *phys_page_find(AddressSpaceDispatch *d, hwaddr addr)
{
    PhysPageEntry lp = d->phys_map, *p;
    Node *nodes = d->map.nodes;
    MemoryRegionSection *sections = d->map.sections;
    hwaddr index = addr >> TARGET_PAGE_BITS;
    int i;

    for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0;) {
        if (lp.ptr == PHYS_MAP_NODE_NIL) {
            return &sections[PHYS_SECTION_UNASSIGNED];
        }
        p = nodes[lp.ptr];
        lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
    }

    if (section_covers_addr(&sections[lp.ptr], addr)) {
        return &sections[lp.ptr];
    } else {
        return &sections[PHYS_SECTION_UNASSIGNED];
    }
}
```

类似于页表地址转换，内存分派使用了6级的map实现了地址到**MemoryRegionSection**的转换。具体来说，**map**中的**Node**类型类似于页表地址转换中的**中间项**，**map**中的**MemoryRegionSection**类似于页表地址转换中最后的物理页，**phys_map**则类似于页表地址转换中的**CR3**寄存器，即第一级Map。具体来说，**map**中的**nodes**数组存放着该**AddressSpace**所有的**Node**，而**sections**数组则存放着所有的**MemoryRegionSection**。**PhysPageEntry**的**ptr**在作为这些数组的下标进行索引，如下所示。
```
                                                               ┌─────────────────────┐                
                                                       ┌───────┼───►struct Node      │             gpa
                                                       │       │   ┌────────────┐    │              │ 
                                                       │       │ ┌─┼───         │◄───┼──────────────┘ 
                                                       │       │ │ ├────────────┤    │                
                                                       │       │ │ │   ......   │    │                
                                                       │       │ │ ├────────────┤    │                
                                                       │       │ │ │            │    │                
                                                       │       │ │ └────────────┘    │                
                                                       │       │ │                   │                
                                                       │       ├─┼───────────────────┤                
                         struct AddressSpaceDispatch   │       │ │   struct Node     │                
                              ┌────────┬─────┐         │       │ │  ┌────────────┐   │                
                              │phys_map│     ├─────────┘       │ └─►│         ───┼─┐ │                
                              ├────────┼─────┤                 │    ├────────────┤ │ │                
                              │map     │     ├──┐              │    │   ......   │ │ │                
                              └────────┴─────┘  │              │    ├────────────┤ │ │                
                                                │              │    │            │ │ │                
                                     ┌──────────┘              │    └────────────┘ │ │                
                                     │                         │                   │ │                
                                     ▼                         ├───────────────────┼─┤                
                            struct PhysPageMap                 │     struct Node   │ │                
                              ┌────────┬───┐                   │    ┌────────────┐ │ │                
                              │nodes   │   ├───────────────────►    │            │ │ │                
┌─────────────────────┐       ├────────┼───┤                   │    ├────────────┤ │ │                
│ MemoryReginSection  │◄──────┤sections│   │                   │    │   ......   │ │ │                
├─────────────────────┤       └────────┴───┘                   │    ├────────────┤ │ │                
│ MemoryReginSection  │                                        │ ┌──┼───         │◄┘ │                
├─────────────────────┤                                        │ │  └────────────┘   │                
│       ......        │                                        │ │                   │                
├─────────────────────┤                                        ├─┼───────────────────┤                
│ MemoryReginSection  │◄───────────┐                           │ │   struct Node     │                
└─────────────────────┘            │                           │ │  ┌────────────┐   │                
                                   │                           │ └─►│         ───┼─┐ │                
                                   │                           │    ├────────────┤ │ │                
                                   │                           │    │   ......   │ │ │                
                                   │                           │    ├────────────┤ │ │                
                                   │                           │    │            │ │ │                
                                   │                           │    └────────────┘ │ │                
                                   │                           │                   │ │                
                                   │                           ├───────────────────┼─┤                
                                   │                           │     struct Node   │ │                
                                   │                           │    ┌────────────┐ │ │                
                                   │                           │  ┌─┼───         │◄┘ │                
                                   │                           │  │ ├────────────┤   │                
                                   │                           │  │ │   ......   │   │                
                                   │                           │  │ ├────────────┤   │                
                                   │                           │  │ │            │   │                
                                   │                           │  │ └────────────┘   │                
                                   │                           │  │                  │                
                                   │                           ├──┼──────────────────┤                
                                   │                           │  │  ...........     │                
                                   │                           ├──┼──────────────────┤                
                                   │                           │  │  struct Node     │                
                                   │                           │  │ ┌────────────┐   │                
                                   │                           │  └►│         ───┼─┐ │                
                                   │                           │    ├────────────┤ │ │                
                                   │                           │    │   ......   │ │ │                
                                   │                           │    ├────────────┤ │ │                
                                   │                           │    │            │ │ │                
                                   │                           │    └────────────┘ │ │                
                                   │                           │                   │ │                
                                   │                           └───────────────────┼─┘                
                                   │                                               │                  
                                   └───────────────────────────────────────────────┘                  
```

# 参考

1. [qemu对虚拟机的内存管理（一）](https://www.cnblogs.com/ccxikka/p/9477530.html)
2. [QEMU 的 memory model](https://martins3.github.io/qemu/memory.html)
3. [地址空间](https://richardweiyang-2.gitbook.io/understanding_qemu/00-as)
4. [QEMU的内存模拟](https://66ring.github.io/2021/04/13/universe/qemu/qemu_softmmu/)
5. [MemoryRegion模型原理，以及同FlatView模型的关系(QEMU2.0.0)](https://blog.csdn.net/leoufung/article/details/48781205)
6. [The memory API](https://www.qemu.org/docs/master/devel/memory.html)
