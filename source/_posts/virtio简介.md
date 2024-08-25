---
title: virtio简介
date: 2024-08-23 23:05:52
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

在传统的设备模拟中，Qemu仿真完整的物理设备，每次**guest**的I/O操作都需要**vm_exit**和**vcpu irq**，如下所示
![全虚拟化示意图](全虚拟化.png)

为了提高虚拟机的I/O效率，virtio协议被制定出来。在该方案中，**guest**能够感知到自己处于虚拟化环境，并且会加载相应的virtio总线驱动和virtio设备驱动与virtio设备进行通信，避免了**guest**的每次I/O操作都需要**vm_exit**和**vcpu irq**(仍然需要**vm_exit**和**vcpu irq**，但是将传统模拟中极多的**vm_exit**转换为**virtio shared memory**通信)，如下所示
![virtio示意图](virtio示意图.png)

# virtio协议

根据[virtio标准2.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-100002)中的内容，virtio设备往往包含如下组件
- [One or more virtqueues](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-270006)
- [Device Configuration space](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-220005)
- [Notifications](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-180003)
- [Device status field](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-110001)
- [Feature bits](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-140002)

## virtqueue

**virtio设备**和**guest**批量数据传输的机制被称为**virtqueue**，驱动和**virtio设备**共享**virtqueue**内存，整体如下所示(这里仅仅介绍[split virtqueues](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-350007)，不介绍[packed virtqueues](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-720008))
![virtqueue示意图](virtqueue示意图.png)

当驱动希望将请求提供给设备时，它会从**descritor table**中选择一个空闲的buffer并添加到**available vring**，并选择性地触发一个事件，通过发送**通知**(在后续[notifications](#notifications)小节中介绍)给**virtio设备**，告知buffer已经准备好

设备在处理请求后，会将**available vring**中已使用的buffer添加到**used vring**中，并选择性地触发一个事件，发送**通知**给**guest**，表示该**buffer**已被使用过

根据[virtio标准2.6.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-270006)，**virtqueue**由**descriptor table**、**available ring**和**used ring**构成

### descriptor table

**descriptor table**指的是驱动为设备准备的buffer，其中每个元素形式如[virtio标准2.7.5.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-430005)中定义
```c
struct virtq_desc { 
        /* Address (guest-physical). */ 
        le64 addr; 
        /* Length. */ 
        le32 len; 
 
/* This marks a buffer as continuing via the next field. */ 
#define VIRTQ_DESC_F_NEXT   1 
/* This marks a buffer as device write-only (otherwise device read-only). */ 
#define VIRTQ_DESC_F_WRITE     2 
/* This means the buffer contains a list of buffer descriptors. */ 
#define VIRTQ_DESC_F_INDIRECT   4 
        /* The flags as indicated above. */ 
        le16 flags; 
        /* Next field if flags & NEXT */ 
        le16 next; 
}; 
```
其中，每个描述符描述一个buffer，**addr**是**guest**的物理地址。描述符可以通过**next**进行链式连接，其中每个描述符描述的buffer要么是设备只读guest只写的，要么是设备只写guest只读的(但无论那种其描述符都是设备只读的)，但一个描述符链可以同时包含两种buffer

buffer的具体内容取决于设备类型，最常见的做法是包含一个设备只读头部表明数据类型，并在其后添加一个设备只写尾部以便设备写入

### available ring

驱动使用**available ring**将可用buffer提供给设备，其形式如[virtio标准2.7.6.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-490006)所示
```c
struct virtq_avail { 
#define VIRTQ_AVAIL_F_NO_INTERRUPT      1 
        le16 flags; 
        le16 idx; 
        le16 ring[ /* Queue Size */ ]; 
        le16 used_event; /* Only if VIRTIO_F_EVENT_IDX */ 
}; 
```

其中，**ring**每个元素指向**descriptor table**中的描述符链，其仅由驱动写入，由设备读取

**idx**表示驱动将下一个**ring**元素的位置，仅由驱动维护。除此之外，设备会维护一个**last_avail_idx**，表示设备使用过的最后一个**ring**元素的位置，即**(last_avail_idx, idx)**时所有可用的**ring**元素

### used ring

类似的，设备使用**used ring**将已用buffer提供给设备，其形式如[virtio标准2.7.8.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-540008)所示
```c
struct virtq_used { 
#define VIRTQ_USED_F_NO_NOTIFY  1 
        le16 flags; 
        le16 idx; 
        struct virtq_used_elem ring[ /* Queue Size */]; 
        le16 avail_event; /* Only if VIRTIO_F_EVENT_IDX */ 
}; 
 
/* le32 is used here for ids for padding reasons. */ 
struct virtq_used_elem { 
        /* Index of start of used descriptor chain. */ 
        le32 id; 
        /* 
         * The number of bytes written into the device writable portion of 
         * the buffer described by the descriptor chain. 
         */ 
        le32 len; 
}; 
```

其中，**ring**每个元素包含指向**descriptor table**中描述符链的**id**和设备实际写入的字节数**len**，其仅由设备写入，由驱动读取

**idx**表示设备将下一个**ring**元素的位置，仅由设备维护。除此之外，驱动会维护一个**last_used_idx**，表示驱动使用过的最后一个**ring**元素的位置，即**(last_used_idx, idx)**时所有可用的**ring**元素

## device configuration space

**设备配置空间**通常用于那些很少更改或在初始化时设定的参数。不同于**PCI设备**的配置空间，其是设备相关的，即不同类型的设备有不同的**设备配置空间**，如**virtio-net**设备的**设备配置空间**如[virtio标准5.1.4.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-2230004)所示而**virtio-blk**设备的**设备配置空间**如[virtio标准5.2.4.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-2790004)所示。

## notifications

驱动和**virtio设备**通过**notifications**来向对方表明有信息需要传达，根据[virtio标准2.3.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-180003)可知，共有三种：
- 设备变更通知
- 可用buffer通知
- 已用buffer通知

这些通知在不同的设备接口下有不同的表现形式

### 设备变更通知

设备变更通知是由设备发送给**guest**，表示前面介绍的[设备配置空间](#device-configuration-space)发生了更改。

一般是Qemu利用硬件机制注入设置改变MSIx中断

### 已用buffer通知

类似的，已用buffer通知也是由设备发送给**guest**，表示前面介绍的[used vring](#used-ring)上更新了新的已用buffer。

一般是Qemu注入对应的MSIx中断

### 可用buffer通知

可用buffer通知则是由**guest**驱动发送给设备的，表示前面介绍的[available vring](#available-ring)上更新了新的可用buffer。

一般是Qemu设置一段特定的**MMIO**空间，驱动访问后触发**vm_exit**退出到**kvm**后利用ioeventfd机制通知Qemu

## device status field

在virtio驱动初始化设备期间，virtio驱动将按照[virtio标准3.1.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-1070001)中的步骤进行操作，而**device status field**提供了对初始化过程中已完成步骤的简单低级指示。可以将其想象成连接到控制台上的交通信号灯，每个信号灯表示一个设备的状态。

其初始化过程如下所示
1. 重置设备
2. 设置**ACKNOWLEDGE**状态位，表明**guest**已经检测到设备
3. 设置**DRIVER**状态位，表明**guest**知道是用什么驱动与设备交互
4. 读取设备**feature bits**，并将驱动理解的**feature bits**子集写入设备
5. 设置**FEATURES_OK**状态位。此步骤后，驱动不得接受新的**feature bits**
6. 重新读取**device status field**，确保**FEATURES_OK**状态位仍然设置着：否则设备不支持驱动设置的**feature bits**子集，设备将无法使用
7. 执行设备的相关设置，包括配置设备**virtqueue**等
8. 设置**DRIVER_OK**状态位。表示设备已经被初始化

**device status field**初始化为0，并在重置过程中由设备重新初始化为0

### ACKNOWLEDGE

**ACKNOWLEDGE**的值是1，该字段被设置表明**guest**已经检测到设备并将其识别为有效的**virtio设备**

### DRIVER

**DRIVER**的值是2，该字段被设置表明**guest**知道如何驱动该设备，即知道使用什么驱动与设备交互

### FAILED

**FAILED**的值是128，该字段被设置表明**guest**中有错误，已经放弃了该**virtio设备**。该错误可能是内部错误、驱动错误或者设备操作过程中发生的致命错误

### FEATURES_OK

**FEATURES_OK**的值是8，该字段被设置表明**guest**的驱动和设备的**feature bits**协商完成

### DRIVER_OK

**DRIVER_OK**的值是4，该字段被设置表明**guest**的驱动已经设置好设备，可以正常驱动设备

### DEVICE_NEEDS_RESET

**DRIVER_OK**的值是64，该字段被设置表明**virtio设备**遇到了无法恢复的错误

## feature bits

每个**virtio设备**都有自己支持的**feature bits**集合。

在设备初始化期间，驱动会读取这些**feature bits**集合，并告知设备驱动支持的子集。

这种机制支持前向和后向兼容性：即如果设备通过新增**feature bit**进行了增强，较旧的驱动程序不会将该新增的**feature bit**告知给设备；类似的，如果驱动新增了设备不支持的**feature bit**，则其无法从设备中读取到新增的**feature bit**

# ~~virtio驱动~~

# ~~virtio设备~~

# 参考

1. [Introduction to VirtIO](https://blogs.oracle.com/linux/post/introduction-to-virtio)
2. [半虚拟化技术 - VIRTIO 简介](https://tinylab.org/virtio-intro/)
3. [Virtual I/O Device (VIRTIO) Version 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
4. [Virtio](http://wiki.osdev.org/Virtio)
5. [Virtqueues and virtio ring: How the data travels](https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels)
6. [【原创】Linux虚拟化KVM-Qemu分析（十一）之virtqueue](https://www.cnblogs.com/LoyenWang/p/14589296.html)
7. [Virtio协议概述](https://www.openeuler.org/zh/blog/yorifang/virtio-spec-overview.html)
