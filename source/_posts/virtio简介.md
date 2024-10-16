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

# virtio transport

根据[virtio标准4.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-1140004)可知，**virtio协议**可以使用各种不同的总线，因此**virtio协议**被分为通用部分和总线相关部分。即**virtio协议**规定都需要有[前面小节](#virtio协议)介绍的5个组件，但驱动和**virtio**设备如何设置这些组件就是总线相关的。其主要可分为**Virtio Over PCI Bus**、**Virtio Over MMIO**和**Virtio Over Channel I/O**，而**virtio-net-pci设备**自然属于是**Virtio Over PCI BUS**。

根据[virtio标准4.1.3.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-1210003)可知，**Virtio Over PCI BUS**通过**PCI Capabilities**来设置**virtio协议**。根据{% post_link qemu的PCI设备 %}可知，标准的**PCI配置空间**如下图所示
![PCI配置空间](PCI配置空间.png)

其中**virtio协议**使用这些**PCI Capabilities**作为**virtio**结构的配置空间，如下所示
![virtio的PCI配置空间](virtio的PCI配置空间.png)

## capability

具体的，每个配置空间的位置由下述格式的**PCI Capabilities**指定
```c
struct virtio_pci_cap { 
        u8 cap_vndr;    /* Generic PCI field: PCI_CAP_ID_VNDR */ 
        u8 cap_next;    /* Generic PCI field: next ptr. */ 
        u8 cap_len;     /* Generic PCI field: capability length */ 
        u8 cfg_type;    /* Identifies the structure. */ 
        u8 bar;         /* Where to find it. */ 
        u8 id;          /* Multiple capabilities of the same type */ 
        u8 padding[2];  /* Pad to full dword. */ 
        le32 offset;    /* Offset within bar. */ 
        le32 length;    /* Length of the structure, in bytes. */ 
};
```
- **cap_vndr**字段值为0x9，用于标识vendor；**cap_next**字段指向下一个**PCI Capability**在**PCI设置空间**的偏移
- **cap_len**字段表示当前**capability**的长度，包括紧跟在**struct virtio_pci_cap**后的数据
- **cfg_type**字段表示**capability**配置空间的类型，包括**VIRTIO_PCI_CAP_COMMON_CFG**、**VIRTIO_PCI_CAP_NOTIFY_CFG**、**VIRTIO_PCI_CAP_ISR_CFG**、**VIRTIO_PCI_CAP_DEVICE_CFG**、**VIRTIO_PCI_CAP_PCI_CFG**、**VIRTIO_PCI_CAP_SHARED_MEMORY_CFG**和**VIRTIO_PCI_CAP_VENDOR_CFG**
- **bar**字段指向**PCI配置空间**的**BAR**寄存器，将组件配置空间映射到**BAR**寄存器指向的内存空间或I/O空间
- **id**字段用于唯一标识**capability**
- **offset**字段表示组件配置空间在**BAR**空间的起始偏移
- **length**字段表示组件配置空间在**BAR**空间的长度

其中，此结构根据**cfg_type**字段还会再数据结构后跟随额外的数据，例如**VIRTIO_PCI_CAP_NOTIFY_CFG**
```c
struct virtio_pci_notify_cap { 
        struct virtio_pci_cap cap; 
        le32 notify_off_multiplier; /* Multiplier for queue_notify_off. */ 
}; 
```

## 配置空间

根据前面的描述，**capability**配置空间包含**VIRTIO_PCI_CAP_COMMON_CFG**、**VIRTIO_PCI_CAP_NOTIFY_CFG**、**VIRTIO_PCI_CAP_ISR_CFG**、**VIRTIO_PCI_CAP_DEVICE_CFG**、**VIRTIO_PCI_CAP_PCI_CFG**、**VIRTIO_PCI_CAP_SHARED_MEMORY_CFG**和**VIRTIO_PCI_CAP_VENDOR_CFG**等。

这里以最重要的**VIRTIO_PCI_CAP_COMMON_CFG**配置空间为例，根据[virtio标准4.1.4.3.](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-1270003)，其配置空间结构如下所示
```c
struct virtio_pci_common_cfg { 
        /* About the whole device. */ 
        le32 device_feature_select;     /* read-write */ 
        le32 device_feature;            /* read-only for driver */ 
        le32 driver_feature_select;     /* read-write */ 
        le32 driver_feature;            /* read-write */ 
        le16 config_msix_vector;        /* read-write */ 
        le16 num_queues;                /* read-only for driver */ 
        u8 device_status;               /* read-write */ 
        u8 config_generation;           /* read-only for driver */ 
 
        /* About a specific virtqueue. */ 
        le16 queue_select;              /* read-write */ 
        le16 queue_size;                /* read-write */ 
        le16 queue_msix_vector;         /* read-write */ 
        le16 queue_enable;              /* read-write */ 
        le16 queue_notify_off;          /* read-only for driver */ 
        le64 queue_desc;                /* read-write */ 
        le64 queue_driver;              /* read-write */ 
        le64 queue_device;              /* read-write */ 
        le16 queue_notify_data;         /* read-only for driver */ 
        le16 queue_reset;               /* read-write */ 
}; 
```
可以看到，其包含了前面[virtqueue](#virtqueue)、[device status field](#device-status-field)和[feature bits](#feature-bits)等相关信息。具体的，其每个字段含义如下所示
- **device_feature_select**字段被驱动用来选择读取设备哪些[**feature bits**](#feature-bits)。例如值0表示读取低32位的[**feature bits**](#feature-bits)，值1表示读取高32位的[**feature bits**](#feature-bits)
- **device_feature**字段则是驱动通过**device_feature_select**选择的设备的对应[**feature bits**](#feature-bits)
- **driver_feature_select**字段类似**device_feature_select**字段，被驱动用来选择想写入设备的[**feature bits**](#feature-bits)范围。值0表示写入低32位的[**feature bits**](#feature-bits)，值1表示写入高32位的[**feature bits**](#feature-bits)
- **driver_feature**字段则是驱动通过**driver_feature_select**选择的写入设备的对应[**feature bits**](#feature-bits)
- **config_msix_vector**字段用来设置MSI-X的**Configuration Vector**
- **num_queues**字段表示设备支持的[**virtqueues**](#virtqueue)最大数量
- **device_status**字段用来设置[**device status**](#device-status-field)
- **config_generation**字段会被设备每次更改设置后变化
- **queue_select**字段用来表示后续**queue_**字段所设置的[**virtqueue**](#virtqueue)序号
- **queue_size**字段用来表示**queue_select**指定的[**virtqueue**](#virtqueue)的大小
- **queue_msix_vector**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)的MSI-X向量
- **queue_enable**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)是否被启用
- **queue_notify_off**字段用来计算**queue_select**指定的[**virtqueue**](#virtqueue)的**notification**在**VIRTIO_PCI_CAP_NOTIFY_CFG**配置空间的偏移
- **queue_desc**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)的**descriptor table**的物理地址
- **queue_driver**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)的**available ring**的物理地址
- **queue_device**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)的**used ring**的物理地址
- **queue_reset**字段用来指定**queue_select**指定的[**virtqueue**](#virtqueue)是否需要被重置

可以看到，基本包含了之前接介绍的[virtio协议组件](#virtio协议)的设置内容

# virtio设备

这里我们以**virtio-net-pci**为例，分析一下Qemu中的**virtio**协议

**virtio-pci**类型的设备并没有静态的**TypeInfo**变量，其是通过[**virtio_pci_types_register()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2569)动态生成并注册对应的**TypeInfo**。**virtio-net-pci**就是让**virtio_pci_types_register()**基于[**virtio_net_pci_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L93)生成对应的**TypeInfo**变量并注册，如下所示
```c
static const VirtioPCIDeviceTypeInfo virtio_net_pci_info = {
    .base_name             = TYPE_VIRTIO_NET_PCI,
    .generic_name          = "virtio-net-pci",
    .transitional_name     = "virtio-net-pci-transitional",
    .non_transitional_name = "virtio-net-pci-non-transitional",
    .instance_size = sizeof(VirtIONetPCI),
    .instance_init = virtio_net_pci_instance_init,
    .class_init    = virtio_net_pci_class_init,
};

static void virtio_net_pci_register(void)
{
    virtio_pci_types_register(&virtio_net_pci_info);
}

void virtio_pci_types_register(const VirtioPCIDeviceTypeInfo *t)
{
    char *base_name = NULL;
    TypeInfo base_type_info = {
        .name          = t->base_name,
        .parent        = t->parent ? t->parent : TYPE_VIRTIO_PCI,
        .instance_size = t->instance_size,
        .instance_init = t->instance_init,
        .instance_finalize = t->instance_finalize,
        .class_size    = t->class_size,
        .abstract      = true,
        .interfaces    = t->interfaces,
    };
    TypeInfo generic_type_info = {
        .name = t->generic_name,
        .parent = base_type_info.name,
        .class_init = virtio_pci_generic_class_init,
        .interfaces = (InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { INTERFACE_CONVENTIONAL_PCI_DEVICE },
            { }
        },
    };

    if (!base_type_info.name) {
        /* No base type -> register a single generic device type */
        /* use intermediate %s-base-type to add generic device props */
        base_name = g_strdup_printf("%s-base-type", t->generic_name);
        base_type_info.name = base_name;
        base_type_info.class_init = virtio_pci_generic_class_init;

        generic_type_info.parent = base_name;
        generic_type_info.class_init = virtio_pci_base_class_init;
        generic_type_info.class_data = (void *)t;

        assert(!t->non_transitional_name);
        assert(!t->transitional_name);
    } else {
        base_type_info.class_init = virtio_pci_base_class_init;
        base_type_info.class_data = (void *)t;
    }

    type_register(&base_type_info);
    if (generic_type_info.name) {
        type_register(&generic_type_info);
    }
    ...
}
```

实际最后会生成如下的**TypeInfo**
```bash
pwndbg> frame 
#0  virtio_pci_types_register (t=0x555556ed8840 <virtio_net_pci_info>) at ../../qemu/hw/virtio/virtio-pci.c:2616
2616	    if (t->non_transitional_name) {

pwndbg> p generic_type_info 
$1 = {
  name = 0x5555562ddbf5 "virtio-net-pci",
  parent = 0x5555562ddbb6 "virtio-net-pci-base",
  instance_size = 0,
  instance_align = 0,
  instance_init = 0x0,
  instance_post_init = 0x0,
  instance_finalize = 0x0,
  abstract = false,
  class_size = 0,
  class_init = 0x555555b74f0b <virtio_pci_generic_class_init>,
  class_base_init = 0x0,
  class_data = 0x0,
  interfaces = 0x7fffffffd700
}
```

## 初始化

要想分析**virtio设备**的初始化过程，需要罗列相关的**TypeInfo**变量，如下所示
```bash
pwndbg> p generic_type_info 
$4 = {
  name = 0x5555562ddbf5 "virtio-net-pci",
  parent = 0x5555562ddbb6 "virtio-net-pci-base",
  instance_size = 0,
  instance_align = 0,
  instance_init = 0x0,
  instance_post_init = 0x0,
  instance_finalize = 0x0,
  abstract = false,
  class_size = 0,
  class_init = 0x555555b74f0b <virtio_pci_generic_class_init>,
  class_base_init = 0x0,
  class_data = 0x0,
  interfaces = 0x7fffffffd700
}

pwndbg> p base_type_info 
$5 = {
  name = 0x5555562ddbb6 "virtio-net-pci-base",
  parent = 0x55555626674d "virtio-pci",
  instance_size = 43376,
  instance_align = 0,
  instance_init = 0x555555e0fa2b <virtio_net_pci_instance_init>,
  instance_post_init = 0x0,
  instance_finalize = 0x0,
  abstract = true,
  class_size = 0,
  class_init = 0x555555b74ec1 <virtio_pci_base_class_init>,
  class_base_init = 0x0,
  class_data = 0x555556ed8840 <virtio_net_pci_info>,
  interfaces = 0x0
}

pwndbg> p virtio_pci_info 
$6 = {
  name = 0x55555626674d "virtio-pci",
  parent = 0x5555562666ba "pci-device",
  instance_size = 34032,
  instance_align = 0,
  instance_init = 0x0,
  instance_post_init = 0x0,
  instance_finalize = 0x0,
  abstract = true,
  class_size = 248,
  class_init = 0x555555b74dd1 <virtio_pci_class_init>,
  class_base_init = 0x0,
  class_data = 0x0,
  interfaces = 0x0
}

pwndbg> p pci_device_type_info
$7 = {
  name = 0x55555623a47a "pci-device",
  parent = 0x55555623a35d "device",
  instance_size = 2608,
  instance_align = 0,
  instance_init = 0x0,
  instance_post_init = 0x0,
  instance_finalize = 0x0,
  abstract = true,
  class_size = 232,
  class_init = 0x555555a9c002 <pci_device_class_init>,
  class_base_init = 0x555555a9c07d <pci_device_class_base_init>,
  class_data = 0x0,
  interfaces = 0x0
}

pwndbg> p device_type_info 
$8 = {
  name = 0x5555562f9c0d "device",
  parent = 0x5555562f9f27 "object",
  instance_size = 160,
  instance_align = 0,
  instance_init = 0x555555e9ca7f <device_initfn>,
  instance_post_init = 0x555555e9caf9 <device_post_init>,
  instance_finalize = 0x555555e9cb30 <device_finalize>,
  abstract = true,
  class_size = 176,
  class_init = 0x555555e9cf54 <device_class_init>,
  class_base_init = 0x555555e9cd10 <device_class_base_init>,
  class_data = 0x0,
  interfaces = 0x5555570085a0 <__compound_literal.0>
}
```

可以看到，**virtio_pci_info**的**class_size**字段非0，因此**virtio设备**使用[**struct VirtioPCIClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/virtio/virtio-pci.h#L108)表征其类信息；**base_type_info**的**instance_size**字段非0，根据前面[virtio设备](#virtio设备)小节的内容，因此**virtio设备**使用[**struct VirtIONetPCI**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L36)表征其对象信息。

### 类初始化

根据[前面小节](#初始化)的内容，**virtio设备**使用[**virtio_pci_generic_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2546)、[**virtio_pci_base_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2538)、[**virtio_pci_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2504)、[**pci_device_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci.c#L2628)和[**device_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L801)分别初始化对应的类数据结构，如下所示
```c
static void virtio_pci_generic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_pci_generic_properties);
}


static void virtio_pci_base_class_init(ObjectClass *klass, void *data)
{
    const VirtioPCIDeviceTypeInfo *t = data;
    if (t->class_init) {
        t->class_init(klass, NULL);
    }
}

static void virtio_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    VirtioPCIClass *vpciklass = VIRTIO_PCI_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    device_class_set_props(dc, virtio_pci_properties);
    k->realize = virtio_pci_realize;
    k->exit = virtio_pci_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->revision = VIRTIO_PCI_ABI_VERSION;
    k->class_id = PCI_CLASS_OTHERS;
    device_class_set_parent_realize(dc, virtio_pci_dc_realize,
                                    &vpciklass->parent_dc_realize);
    rc->phases.hold = virtio_pci_bus_reset_hold;
}

static void pci_device_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);

    k->realize = pci_qdev_realize;
    k->unrealize = pci_qdev_unrealize;
    k->bus_type = TYPE_PCI_BUS;
    device_class_set_props(k, pci_props);
}

static void device_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    VMStateIfClass *vc = VMSTATE_IF_CLASS(class);
    ResettableClass *rc = RESETTABLE_CLASS(class);

    class->unparent = device_unparent;

    /* by default all devices were considered as hotpluggable,
     * so with intent to check it in generic qdev_unplug() /
     * device_set_realized() functions make every device
     * hotpluggable. Devices that shouldn't be hotpluggable,
     * should override it in their class_init()
     */
    dc->hotpluggable = true;
    dc->user_creatable = true;
    vc->get_id = device_vmstate_if_get_id;
    rc->get_state = device_get_reset_state;
    rc->child_foreach = device_reset_child_foreach;

    /*
     * @device_phases_reset is put as the default reset method below, allowing
     * to do the multi-phase transition from base classes to leaf classes. It
     * allows a legacy-reset Device class to extend a multi-phases-reset
     * Device class for the following reason:
     * + If a base class B has been moved to multi-phase, then it does not
     *   override this default reset method and may have defined phase methods.
     * + A child class C (extending class B) which uses
     *   device_class_set_parent_reset() (or similar means) to override the
     *   reset method will still work as expected. @device_phases_reset function
     *   will be registered as the parent reset method and effectively call
     *   parent reset phases.
     */
    dc->reset = device_phases_reset;
    rc->get_transitional_function = device_get_transitional_reset;

    object_class_property_add_bool(class, "realized",
                                   device_get_realized, device_set_realized);
    object_class_property_add_bool(class, "hotpluggable",
                                   device_get_hotpluggable, NULL);
    object_class_property_add_bool(class, "hotplugged",
                                   device_get_hotplugged, NULL);
    object_class_property_add_link(class, "parent_bus", TYPE_BUS,
                                   offsetof(DeviceState, parent_bus), NULL, 0);
}
```
其中，根据[前面初始化](#初始化)的内容，**virtio_pci_base_class_init()**的参数是[**virtio_net_pci_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L93)，其**class_init**字段为[**virtio_net_pci_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L67)，如下所示
```c
static void virtio_net_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    VirtioPCIClass *vpciklass = VIRTIO_PCI_CLASS(klass);

    k->romfile = "efi-virtio.rom";
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->device_id = PCI_DEVICE_ID_VIRTIO_NET;
    k->revision = VIRTIO_PCI_ABI_VERSION;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    device_class_set_props(dc, virtio_net_properties);
    vpciklass->realize = virtio_net_pci_realize;
}
```
可以看到，这些类的初始化基本就是覆盖父类的**realize**函数指针或当前类的**parent_dc_realize**函数指针，从而在实例化时执行相关的逻辑

### 对象初始化

**virtio设备**使用[**virtio_net_pci_instance_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L83)和[**device_initfn()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L652)来初始化对应的对象数据结构，如下所示
```c
//#0  virtio_net_pci_instance_init (obj=0x5555580bdd70) at ../../qemu/hw/virtio/virtio-net-pci.c:85
//#1  0x0000555555ea793a in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570e88f0) at ../../qemu/qom/object.c:429
//#2  0x0000555555ea791c in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570e8ab0) at ../../qemu/qom/object.c:425
//#3  0x0000555555ea7f00 in object_initialize_with_type (obj=0x5555580bdd70, size=43376, type=0x5555570e8ab0) at ../../qemu/qom/object.c:571
//#4  0x0000555555ea86cf in object_new_with_type (type=0x5555570e8ab0) at ../../qemu/qom/object.c:791
//#5  0x0000555555ea873b in object_new (typename=0x5555580bbfd0 "virtio-net-pci") at ../../qemu/qom/object.c:806
//#6  0x0000555555e9ff6a in qdev_new (name=0x5555580bbfd0 "virtio-net-pci") at ../../qemu/hw/core/qdev.c:166
//#7  0x0000555555bd01c4 in qdev_device_add_from_qdict (opts=0x5555580bc3b0, from_json=false, errp=0x7fffffffd6a0) at ../../qemu/system/qdev-monitor.c:681
//#8  0x0000555555bd03d9 in qdev_device_add (opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#9  0x0000555555bda4e7 in device_init_func (opaque=0x0, opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:1200
//#10 0x00005555560c2a63 in qemu_opts_foreach (list=0x555556f53ec0 <qemu_device_opts>, func=0x555555bda4bc <device_init_func>, opaque=0x0, errp=0x55555706a160 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#11 0x0000555555bde1b8 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#12 0x0000555555bde3fe in qmp_x_exit_preconfig (errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:2706
//#13 0x0000555555be0db6 in qemu_init (argc=39, argv=0x7fffffffdae8) at ../../qemu/system/vl.c:3739
//#14 0x0000555555e9b7ed in main (argc=39, argv=0x7fffffffdae8) at ../../qemu/system/main.c:47
//#15 0x00007ffff7629d90 in __libc_start_call_main (main=main@entry=0x555555e9b7c9 <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffdae8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#16 0x00007ffff7629e40 in __libc_start_main_impl (main=0x555555e9b7c9 <main>, argc=39, argv=0x7fffffffdae8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdad8) at ../csu/libc-start.c:392
//#17 0x000055555586f0d5 in _start ()
static void virtio_net_pci_instance_init(Object *obj)
{
    VirtIONetPCI *dev = VIRTIO_NET_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_NET);
    object_property_add_alias(obj, "bootindex", OBJECT(&dev->vdev),
                              "bootindex");
}

//#0  device_initfn (obj=0x5555580bdd70) at ../../qemu/hw/core/qdev.c:654
//#1  0x0000555555ea793a in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570ec4a0) at ../../qemu/qom/object.c:429
//#2  0x0000555555ea791c in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570a7830) at ../../qemu/qom/object.c:425
//#3  0x0000555555ea791c in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570b5a80) at ../../qemu/qom/object.c:425
//#4  0x0000555555ea791c in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570e88f0) at ../../qemu/qom/object.c:425
//#5  0x0000555555ea791c in object_init_with_type (obj=0x5555580bdd70, ti=0x5555570e8ab0) at ../../qemu/qom/object.c:425
//#6  0x0000555555ea7f00 in object_initialize_with_type (obj=0x5555580bdd70, size=43376, type=0x5555570e8ab0) at ../../qemu/qom/object.c:571
//#7  0x0000555555ea86cf in object_new_with_type (type=0x5555570e8ab0) at ../../qemu/qom/object.c:791
//#8  0x0000555555ea873b in object_new (typename=0x5555580bbfd0 "virtio-net-pci") at ../../qemu/qom/object.c:806
//#9  0x0000555555e9ff6a in qdev_new (name=0x5555580bbfd0 "virtio-net-pci") at ../../qemu/hw/core/qdev.c:166
//#10 0x0000555555bd01c4 in qdev_device_add_from_qdict (opts=0x5555580bc3b0, from_json=false, errp=0x7fffffffd690) at ../../qemu/system/qdev-monitor.c:681
//#11 0x0000555555bd03d9 in qdev_device_add (opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#12 0x0000555555bda4e7 in device_init_func (opaque=0x0, opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:1200
//#13 0x00005555560c2a63 in qemu_opts_foreach (list=0x555556f53ec0 <qemu_device_opts>, func=0x555555bda4bc <device_init_func>, opaque=0x0, errp=0x55555706a160 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#14 0x0000555555bde1b8 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#15 0x0000555555bde3fe in qmp_x_exit_preconfig (errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:2706
//#16 0x0000555555be0db6 in qemu_init (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/vl.c:3739
//#17 0x0000555555e9b7ed in main (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/main.c:47
//#18 0x00007ffff7629d90 in __libc_start_call_main (main=main@entry=0x555555e9b7c9 <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffdad8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#19 0x00007ffff7629e40 in __libc_start_main_impl (main=0x555555e9b7c9 <main>, argc=39, argv=0x7fffffffdad8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdac8) at ../csu/libc-start.c:392
//#20 0x000055555586f0d5 in _start ()
static void device_initfn(Object *obj)
{
    DeviceState *dev = DEVICE(obj);

    if (phase_check(PHASE_MACHINE_READY)) {
        dev->hotplugged = 1;
        qdev_hot_added = true;
    }

    dev->instance_id_alias = -1;
    dev->realized = false;
    dev->allow_unplug_during_migration = false;

    QLIST_INIT(&dev->gpios);
    QLIST_INIT(&dev->clocks);
}
```
这里仅仅是初始化了必要的字段。

## 实例化

根据前面[类初始化](#类初始化)的内容，**virtio**设备将其父类数据结构的**realize**函数指针依次设置为了[**virtio_pci_dc_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2490)、[**virtio_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2272)和[**virtio_net_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L49)，而**virtio-pci**类的**parent_dc_realize**字段为[**pci_qdev_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci.c#L2031)
```c
//#0  virtio_net_pci_realize (vpci_dev=0x5555580a4fa0, errp=0x7fffffffd2f0) at ../../qemu/hw/virtio/virtio-net-pci.c:51
//#1  0x0000555555b749a9 in virtio_pci_realize (pci_dev=0x5555580a4fa0, errp=0x7fffffffd2f0) at ../../qemu/hw/virtio/virtio-pci.c:2407
//#2  0x0000555555a9a921 in pci_qdev_realize (qdev=0x5555580a4fa0, errp=0x7fffffffd3b0) at ../../qemu/hw/pci/pci.c:2093
//#3  0x0000555555b74dc4 in virtio_pci_dc_realize (qdev=0x5555580a4fa0, errp=0x7fffffffd3b0) at ../../qemu/hw/virtio/virtio-pci.c:2501
//#4  0x0000555555e9c4f4 in device_set_realized (obj=0x5555580a4fa0, value=true, errp=0x7fffffffd620) at ../../qemu/hw/core/qdev.c:510
//#5  0x0000555555ea7cfb in property_set_bool (obj=0x5555580a4fa0, v=0x5555580b51a0, name=0x5555562f9dd1 "realized", opaque=0x5555570f4510, errp=0x7fffffffd620) at ../../qemu/qom/object.c:2358
//#6  0x0000555555ea5891 in object_property_set (obj=0x5555580a4fa0, name=0x5555562f9dd1 "realized", v=0x5555580b51a0, errp=0x7fffffffd620) at ../../qemu/qom/object.c:1472
//#7  0x0000555555eaa4ca in object_property_set_qobject (obj=0x5555580a4fa0, name=0x5555562f9dd1 "realized", value=0x5555580b3d60, errp=0x7fffffffd620) at ../../qemu/qom/qom-qobject.c:28
//#8  0x0000555555ea5c4a in object_property_set_bool (obj=0x5555580a4fa0, name=0x5555562f9dd1 "realized", value=true, errp=0x7fffffffd620) at ../../qemu/qom/object.c:1541
//#9  0x0000555555e9bc0e in qdev_realize (dev=0x5555580a4fa0, bus=0x555557415420, errp=0x7fffffffd620) at ../../qemu/hw/core/qdev.c:292
//#10 0x0000555555bcdee9 in qdev_device_add_from_qdict (opts=0x5555580a31b0, from_json=false, errp=0x7fffffffd620) at ../../qemu/system/qdev-monitor.c:718
//#11 0x0000555555bcdf99 in qdev_device_add (opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#12 0x0000555555bd80a7 in device_init_func (opaque=0x0, opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:1200
//#13 0x00005555560be1e2 in qemu_opts_foreach (list=0x555556f4bec0 <qemu_device_opts>, func=0x555555bd807c <device_init_func>, opaque=0x0, errp=0x555557061f60 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#14 0x0000555555bdbd46 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#15 0x0000555555bdbf8c in qmp_x_exit_preconfig (errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:2706
//#16 0x0000555555bde944 in qemu_init (argc=35, argv=0x7fffffffda68) at ../../qemu/system/vl.c:3739
//#17 0x0000555555e96f93 in main (argc=35, argv=0x7fffffffda68) at ../../qemu/system/main.c:47
//#18 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffda68) at ../sysdeps/nptl/libc_start_call_main.h:58
//#19 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffda68, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffda58) at ../csu/libc-start.c:392
//#20 0x000055555586cc95 in _start ()
static void virtio_net_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    DeviceState *qdev = DEVICE(vpci_dev);
    VirtIONetPCI *dev = VIRTIO_NET_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtIONet *net = VIRTIO_NET(vdev);

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = 2 * MAX(net->nic_conf.peers.queues, 1)
            + 1 /* Config interrupt */
            + 1 /* Control vq */;
    }

    virtio_net_set_netclient_name(&dev->vdev, qdev->id,
                                  object_get_typename(OBJECT(qdev)));
    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void virtio_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    VirtIOPCIProxy *proxy = VIRTIO_PCI(pci_dev);
    VirtioPCIClass *k = VIRTIO_PCI_GET_CLASS(pci_dev);
    bool pcie_port = pci_bus_is_express(pci_get_bus(pci_dev)) &&
                     !pci_bus_is_root(pci_get_bus(pci_dev));

    /* fd-based ioevents can't be synchronized in record/replay */
    if (replay_mode != REPLAY_MODE_NONE) {
        proxy->flags &= ~VIRTIO_PCI_FLAG_USE_IOEVENTFD;
    }

    /*
     * virtio pci bar layout used by default.
     * subclasses can re-arrange things if needed.
     *
     *   region 0   --  virtio legacy io bar
     *   region 1   --  msi-x bar
     *   region 2   --  virtio modern io bar (off by default)
     *   region 4+5 --  virtio modern memory (64bit) bar
     *
     */
    proxy->legacy_io_bar_idx  = 0;
    proxy->msix_bar_idx       = 1;
    proxy->modern_io_bar_idx  = 2;
    proxy->modern_mem_bar_idx = 4;

    proxy->common.offset = 0x0;
    proxy->common.size = 0x1000;
    proxy->common.type = VIRTIO_PCI_CAP_COMMON_CFG;

    proxy->isr.offset = 0x1000;
    proxy->isr.size = 0x1000;
    proxy->isr.type = VIRTIO_PCI_CAP_ISR_CFG;

    proxy->device.offset = 0x2000;
    proxy->device.size = 0x1000;
    proxy->device.type = VIRTIO_PCI_CAP_DEVICE_CFG;

    proxy->notify.offset = 0x3000;
    proxy->notify.size = virtio_pci_queue_mem_mult(proxy) * VIRTIO_QUEUE_MAX;
    proxy->notify.type = VIRTIO_PCI_CAP_NOTIFY_CFG;

    proxy->notify_pio.offset = 0x0;
    proxy->notify_pio.size = 0x4;
    proxy->notify_pio.type = VIRTIO_PCI_CAP_NOTIFY_CFG;

    /* subclasses can enforce modern, so do this unconditionally */
    if (!(proxy->flags & VIRTIO_PCI_FLAG_VDPA)) {
        memory_region_init(&proxy->modern_bar, OBJECT(proxy), "virtio-pci",
                           /* PCI BAR regions must be powers of 2 */
                           pow2ceil(proxy->notify.offset + proxy->notify.size));
    } else {
        proxy->lm.offset = proxy->notify.offset + proxy->notify.size;
        proxy->lm.size = 0x20 + VIRTIO_QUEUE_MAX * 4;
        memory_region_init(&proxy->modern_bar, OBJECT(proxy), "virtio-pci",
                           /* PCI BAR regions must be powers of 2 */
                           pow2ceil(proxy->lm.offset + proxy->lm.size));
    }

    if (proxy->disable_legacy == ON_OFF_AUTO_AUTO) {
        proxy->disable_legacy = pcie_port ? ON_OFF_AUTO_ON : ON_OFF_AUTO_OFF;
    }

    if (!virtio_pci_modern(proxy) && !virtio_pci_legacy(proxy)) {
        error_setg(errp, "device cannot work as neither modern nor legacy mode"
                   " is enabled");
        error_append_hint(errp, "Set either disable-modern or disable-legacy"
                          " to off\n");
        return;
    }

    if (pcie_port && pci_is_express(pci_dev)) {
        int pos;
        uint16_t last_pcie_cap_offset = PCI_CONFIG_SPACE_SIZE;

        pos = pcie_endpoint_cap_init(pci_dev, 0);
        assert(pos > 0);

        pos = pci_add_capability(pci_dev, PCI_CAP_ID_PM, 0,
                                 PCI_PM_SIZEOF, errp);
        if (pos < 0) {
            return;
        }

        pci_dev->exp.pm_cap = pos;

        /*
         * Indicates that this function complies with revision 1.2 of the
         * PCI Power Management Interface Specification.
         */
        pci_set_word(pci_dev->config + pos + PCI_PM_PMC, 0x3);

        if (proxy->flags & VIRTIO_PCI_FLAG_AER) {
            pcie_aer_init(pci_dev, PCI_ERR_VER, last_pcie_cap_offset,
                          PCI_ERR_SIZEOF, NULL);
            last_pcie_cap_offset += PCI_ERR_SIZEOF;
        }

        if (proxy->flags & VIRTIO_PCI_FLAG_INIT_DEVERR) {
            /* Init error enabling flags */
            pcie_cap_deverr_init(pci_dev);
        }

        if (proxy->flags & VIRTIO_PCI_FLAG_INIT_LNKCTL) {
            /* Init Link Control Register */
            pcie_cap_lnkctl_init(pci_dev);
        }

        if (proxy->flags & VIRTIO_PCI_FLAG_INIT_PM) {
            /* Init Power Management Control Register */
            pci_set_word(pci_dev->wmask + pos + PCI_PM_CTRL,
                         PCI_PM_CTRL_STATE_MASK);
        }

        if (proxy->flags & VIRTIO_PCI_FLAG_ATS) {
            pcie_ats_init(pci_dev, last_pcie_cap_offset,
                          proxy->flags & VIRTIO_PCI_FLAG_ATS_PAGE_ALIGNED);
            last_pcie_cap_offset += PCI_EXT_CAP_ATS_SIZEOF;
        }

        if (proxy->flags & VIRTIO_PCI_FLAG_INIT_FLR) {
            /* Set Function Level Reset capability bit */
            pcie_cap_flr_init(pci_dev);
        }
    } else {
        /*
         * make future invocations of pci_is_express() return false
         * and pci_config_size() return PCI_CONFIG_SPACE_SIZE.
         */
        pci_dev->cap_present &= ~QEMU_PCI_CAP_EXPRESS;
    }

    virtio_pci_bus_new(&proxy->bus, sizeof(proxy->bus), proxy);
    if (k->realize) {
        k->realize(proxy, errp);
    }
}

static void pci_qdev_realize(DeviceState *qdev, Error **errp)
{
    PCIDevice *pci_dev = (PCIDevice *)qdev;
    PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(pci_dev);
    ObjectClass *klass = OBJECT_CLASS(pc);
    Error *local_err = NULL;
    bool is_default_rom;
    uint16_t class_id;

    /*
     * capped by systemd (see: udev-builtin-net_id.c)
     * as it's the only known user honor it to avoid users
     * misconfigure QEMU and then wonder why acpi-index doesn't work
     */
    if (pci_dev->acpi_index > ONBOARD_INDEX_MAX) {
        error_setg(errp, "acpi-index should be less or equal to %u",
                   ONBOARD_INDEX_MAX);
        return;
    }

    /*
     * make sure that acpi-index is unique across all present PCI devices
     */
    if (pci_dev->acpi_index) {
        GSequence *used_indexes = pci_acpi_index_list();

        if (g_sequence_lookup(used_indexes,
                              GINT_TO_POINTER(pci_dev->acpi_index),
                              g_cmp_uint32, NULL)) {
            error_setg(errp, "a PCI device with acpi-index = %" PRIu32
                       " already exist", pci_dev->acpi_index);
            return;
        }
        g_sequence_insert_sorted(used_indexes,
                                 GINT_TO_POINTER(pci_dev->acpi_index),
                                 g_cmp_uint32, NULL);
    }

    if (pci_dev->romsize != -1 && !is_power_of_2(pci_dev->romsize)) {
        error_setg(errp, "ROM size %u is not a power of two", pci_dev->romsize);
        return;
    }

    /* initialize cap_present for pci_is_express() and pci_config_size(),
     * Note that hybrid PCIs are not set automatically and need to manage
     * QEMU_PCI_CAP_EXPRESS manually */
    if (object_class_dynamic_cast(klass, INTERFACE_PCIE_DEVICE) &&
       !object_class_dynamic_cast(klass, INTERFACE_CONVENTIONAL_PCI_DEVICE)) {
        pci_dev->cap_present |= QEMU_PCI_CAP_EXPRESS;
    }

    if (object_class_dynamic_cast(klass, INTERFACE_CXL_DEVICE)) {
        pci_dev->cap_present |= QEMU_PCIE_CAP_CXL;
    }

    pci_dev = do_pci_register_device(pci_dev,
                                     object_get_typename(OBJECT(qdev)),
                                     pci_dev->devfn, errp);
    if (pci_dev == NULL)
        return;

    if (pc->realize) {
        pc->realize(pci_dev, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            do_pci_unregister_device(pci_dev);
            return;
        }
    }

    /*
     * A PCIe Downstream Port that do not have ARI Forwarding enabled must
     * associate only Device 0 with the device attached to the bus
     * representing the Link from the Port (PCIe base spec rev 4.0 ver 0.3,
     * sec 7.3.1).
     * With ARI, PCI_SLOT() can return non-zero value as the traditional
     * 5-bit Device Number and 3-bit Function Number fields in its associated
     * Routing IDs, Requester IDs and Completer IDs are interpreted as a
     * single 8-bit Function Number. Hence, ignore ARI capable devices.
     */
    if (pci_is_express(pci_dev) &&
        !pcie_find_capability(pci_dev, PCI_EXT_CAP_ID_ARI) &&
        pcie_has_upstream_port(pci_dev) &&
        PCI_SLOT(pci_dev->devfn)) {
        warn_report("PCI: slot %d is not valid for %s,"
                    " parent device only allows plugging into slot 0.",
                    PCI_SLOT(pci_dev->devfn), pci_dev->name);
    }

    if (pci_dev->failover_pair_id) {
        if (!pci_bus_is_express(pci_get_bus(pci_dev))) {
            error_setg(errp, "failover primary device must be on "
                             "PCIExpress bus");
            pci_qdev_unrealize(DEVICE(pci_dev));
            return;
        }
        class_id = pci_get_word(pci_dev->config + PCI_CLASS_DEVICE);
        if (class_id != PCI_CLASS_NETWORK_ETHERNET) {
            error_setg(errp, "failover primary device is not an "
                             "Ethernet device");
            pci_qdev_unrealize(DEVICE(pci_dev));
            return;
        }
        if ((pci_dev->cap_present & QEMU_PCI_CAP_MULTIFUNCTION)
            || (PCI_FUNC(pci_dev->devfn) != 0)) {
            error_setg(errp, "failover: primary device must be in its own "
                              "PCI slot");
            pci_qdev_unrealize(DEVICE(pci_dev));
            return;
        }
        qdev->allow_unplug_during_migration = true;
    }

    /* rom loading */
    is_default_rom = false;
    if (pci_dev->romfile == NULL && pc->romfile != NULL) {
        pci_dev->romfile = g_strdup(pc->romfile);
        is_default_rom = true;
    }

    pci_add_option_rom(pci_dev, is_default_rom, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        pci_qdev_unrealize(DEVICE(pci_dev));
        return;
    }

    pci_set_power(pci_dev, true);

    pci_dev->msi_trigger = pci_msi_trigger;
}

static void virtio_pci_dc_realize(DeviceState *qdev, Error **errp)
{
    VirtioPCIClass *vpciklass = VIRTIO_PCI_GET_CLASS(qdev);
    VirtIOPCIProxy *proxy = VIRTIO_PCI(qdev);
    PCIDevice *pci_dev = &proxy->pci_dev;

    if (!(proxy->flags & VIRTIO_PCI_FLAG_DISABLE_PCIE) &&
        virtio_pci_modern(proxy)) {
        pci_dev->cap_present |= QEMU_PCI_CAP_EXPRESS;
    }

    vpciklass->parent_dc_realize(qdev, errp);
}
```
可以看到，在实例化设备时，基于[**device_set_realized()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L470)，不停调用子类在类初始化时覆盖的**realize**函数指针/**parent_dc_realize**函数，从而完成最终的实例化。

具体的，由于**virtio-net-pci设备**属于**Virtio Over PCI BUS**，因此**VirtIONetPCI**对象中包含**VirtIOPCIProxy**对象，即[**virtio-pci-bus**总线](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2719)的**PCIDevice**对象，其相关的实例化在[**virtio_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2272)，其分配了**VIRTIO_PCI_CAP_COMMON_CFG**、**VIRTIO_PCI_CAP_ISR_CFG**、**VIRTIO_PCI_CAP_DEVICE_CFG**和io的**VIRTIO_PCI_CAP_NOTIFY_CFG**等配置空间，并使用[**virtio_pci_bus_new()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2682)初始化**VirtIOPCIProxy**总线。但此时还未完成与**guest驱动**的协商，因此此时并不会正常使用，为了与**guest驱动**进行通信协商，还需要实例化**virtio设备**相关信息，其在[**virtio_net_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L49)中通过实例化**VirtIONet**对象实现。该对象的**TypeInfo**变量是[virtio_net_info](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L4052)，如下所示
```c
static const TypeInfo virtio_net_info = {
    .name = TYPE_VIRTIO_NET,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIONet),
    .instance_init = virtio_net_instance_init,
    .class_init = virtio_net_class_init,
};

static const TypeInfo virtio_device_info = {
    .name = TYPE_VIRTIO_DEVICE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(VirtIODevice),
    .class_init = virtio_device_class_init,
    .instance_finalize = virtio_device_instance_finalize,
    .abstract = true,
    .class_size = sizeof(VirtioDeviceClass),
};
```

其**class_init**函数指针分别设置对应的父类**realize**函数指针为[virtio_device_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio.c#L3738)和[virtio_net_device_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L3656)，如下所示
```c
//#0  virtio_net_device_realize (dev=0x5555580c6260, errp=0x7fffffffd030) at ../../qemu/hw/net/virtio-net.c:3657
//#1  0x0000555555df39c2 in virtio_device_realize (dev=0x5555580c6260, errp=0x7fffffffd090) at ../../qemu/hw/virtio/virtio.c:3748
//#2  0x0000555555ea0d4e in device_set_realized (obj=0x5555580c6260, value=true, errp=0x7fffffffd360) at ../../qemu/hw/core/qdev.c:510
//#3  0x0000555555eac555 in property_set_bool (obj=0x5555580c6260, v=0x5555580d4190, name=0x555556300c31 "realized", opaque=0x5555570fc6e0, errp=0x7fffffffd360) at ../../qemu/qom/object.c:2358
//#4  0x0000555555eaa0eb in object_property_set (obj=0x5555580c6260, name=0x555556300c31 "realized", v=0x5555580d4190, errp=0x7fffffffd360) at ../../qemu/qom/object.c:1472
//#5  0x0000555555eaed24 in object_property_set_qobject (obj=0x5555580c6260, name=0x555556300c31 "realized", value=0x5555580d40d0, errp=0x7fffffffd360) at ../../qemu/qom/qom-qobject.c:28
//#6  0x0000555555eaa4a4 in object_property_set_bool (obj=0x5555580c6260, name=0x555556300c31 "realized", value=true, errp=0x7fffffffd360) at ../../qemu/qom/object.c:1541
//#7  0x0000555555ea0468 in qdev_realize (dev=0x5555580c6260, bus=0x5555580c61e0, errp=0x7fffffffd360) at ../../qemu/hw/core/qdev.c:292
//#8  0x0000555555e141a8 in virtio_net_pci_realize (vpci_dev=0x5555580bdd70, errp=0x7fffffffd360) at ../../qemu/hw/virtio/virtio-net-pci.c:64
//#9  0x0000555555b76de9 in virtio_pci_realize (pci_dev=0x5555580bdd70, errp=0x7fffffffd360) at ../../qemu/hw/virtio/virtio-pci.c:2407
//#10 0x0000555555a9cd61 in pci_qdev_realize (qdev=0x5555580bdd70, errp=0x7fffffffd420) at ../../qemu/hw/pci/pci.c:2093
//#11 0x0000555555b77204 in virtio_pci_dc_realize (qdev=0x5555580bdd70, errp=0x7fffffffd420) at ../../qemu/hw/virtio/virtio-pci.c:2501
//#12 0x0000555555ea0d4e in device_set_realized (obj=0x5555580bdd70, value=true, errp=0x7fffffffd690) at ../../qemu/hw/core/qdev.c:510
//#13 0x0000555555eac555 in property_set_bool (obj=0x5555580bdd70, v=0x5555580cdea0, name=0x555556300c31 "realized", opaque=0x5555570fc6e0, errp=0x7fffffffd690) at ../../qemu/qom/object.c:2358
//#14 0x0000555555eaa0eb in object_property_set (obj=0x5555580bdd70, name=0x555556300c31 "realized", v=0x5555580cdea0, errp=0x7fffffffd690) at ../../qemu/qom/object.c:1472
//#15 0x0000555555eaed24 in object_property_set_qobject (obj=0x5555580bdd70, name=0x555556300c31 "realized", value=0x5555580cca90, errp=0x7fffffffd690) at ../../qemu/qom/qom-qobject.c:28
//#16 0x0000555555eaa4a4 in object_property_set_bool (obj=0x5555580bdd70, name=0x555556300c31 "realized", value=true, errp=0x7fffffffd690) at ../../qemu/qom/object.c:1541
//#17 0x0000555555ea0468 in qdev_realize (dev=0x5555580bdd70, bus=0x555557430730, errp=0x7fffffffd690) at ../../qemu/hw/core/qdev.c:292
//#18 0x0000555555bd0329 in qdev_device_add_from_qdict (opts=0x5555580bc3b0, from_json=false, errp=0x7fffffffd690) at ../../qemu/system/qdev-monitor.c:718
//#19 0x0000555555bd03d9 in qdev_device_add (opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#20 0x0000555555bda4e7 in device_init_func (opaque=0x0, opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:1200
//#21 0x00005555560c2a63 in qemu_opts_foreach (list=0x555556f53ec0 <qemu_device_opts>, func=0x555555bda4bc <device_init_func>, opaque=0x0, errp=0x55555706a160 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#22 0x0000555555bde1b8 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#23 0x0000555555bde3fe in qmp_x_exit_preconfig (errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:2706
//#24 0x0000555555be0db6 in qemu_init (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/vl.c:3739
//#25 0x0000555555e9b7ed in main (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/main.c:47
//#26 0x00007ffff7629d90 in __libc_start_call_main (main=main@entry=0x555555e9b7c9 <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffdad8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#27 0x00007ffff7629e40 in __libc_start_main_impl (main=0x555555e9b7c9 <main>, argc=39, argv=0x7fffffffdad8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdac8) at ../csu/libc-start.c:392
//#28 0x000055555586f0d5 in _start ()
static void virtio_net_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIONet *n = VIRTIO_NET(dev);
    NetClientState *nc;
    int i;

    if (n->net_conf.mtu) {
        n->host_features |= (1ULL << VIRTIO_NET_F_MTU);
    }

    if (n->net_conf.duplex_str) {
        if (strncmp(n->net_conf.duplex_str, "half", 5) == 0) {
            n->net_conf.duplex = DUPLEX_HALF;
        } else if (strncmp(n->net_conf.duplex_str, "full", 5) == 0) {
            n->net_conf.duplex = DUPLEX_FULL;
        } else {
            error_setg(errp, "'duplex' must be 'half' or 'full'");
            return;
        }
        n->host_features |= (1ULL << VIRTIO_NET_F_SPEED_DUPLEX);
    } else {
        n->net_conf.duplex = DUPLEX_UNKNOWN;
    }

    if (n->net_conf.speed < SPEED_UNKNOWN) {
        error_setg(errp, "'speed' must be between 0 and INT_MAX");
        return;
    }
    if (n->net_conf.speed >= 0) {
        n->host_features |= (1ULL << VIRTIO_NET_F_SPEED_DUPLEX);
    }

    if (n->failover) {
        n->primary_listener.hide_device = failover_hide_primary_device;
        qatomic_set(&n->failover_primary_hidden, true);
        device_listener_register(&n->primary_listener);
        migration_add_notifier(&n->migration_state,
                               virtio_net_migration_state_notifier);
        n->host_features |= (1ULL << VIRTIO_NET_F_STANDBY);
    }

    virtio_net_set_config_size(n, n->host_features);
    virtio_init(vdev, VIRTIO_ID_NET, n->config_size);

    /*
     * We set a lower limit on RX queue size to what it always was.
     * Guests that want a smaller ring can always resize it without
     * help from us (using virtio 1 and up).
     */
    if (n->net_conf.rx_queue_size < VIRTIO_NET_RX_QUEUE_MIN_SIZE ||
        n->net_conf.rx_queue_size > VIRTQUEUE_MAX_SIZE ||
        !is_power_of_2(n->net_conf.rx_queue_size)) {
        error_setg(errp, "Invalid rx_queue_size (= %" PRIu16 "), "
                   "must be a power of 2 between %d and %d.",
                   n->net_conf.rx_queue_size, VIRTIO_NET_RX_QUEUE_MIN_SIZE,
                   VIRTQUEUE_MAX_SIZE);
        virtio_cleanup(vdev);
        return;
    }

    if (n->net_conf.tx_queue_size < VIRTIO_NET_TX_QUEUE_MIN_SIZE ||
        n->net_conf.tx_queue_size > virtio_net_max_tx_queue_size(n) ||
        !is_power_of_2(n->net_conf.tx_queue_size)) {
        error_setg(errp, "Invalid tx_queue_size (= %" PRIu16 "), "
                   "must be a power of 2 between %d and %d",
                   n->net_conf.tx_queue_size, VIRTIO_NET_TX_QUEUE_MIN_SIZE,
                   virtio_net_max_tx_queue_size(n));
        virtio_cleanup(vdev);
        return;
    }

    n->max_ncs = MAX(n->nic_conf.peers.queues, 1);

    /*
     * Figure out the datapath queue pairs since the backend could
     * provide control queue via peers as well.
     */
    if (n->nic_conf.peers.queues) {
        for (i = 0; i < n->max_ncs; i++) {
            if (n->nic_conf.peers.ncs[i]->is_datapath) {
                ++n->max_queue_pairs;
            }
        }
    }
    n->max_queue_pairs = MAX(n->max_queue_pairs, 1);

    if (n->max_queue_pairs * 2 + 1 > VIRTIO_QUEUE_MAX) {
        error_setg(errp, "Invalid number of queue pairs (= %" PRIu32 "), "
                   "must be a positive integer less than %d.",
                   n->max_queue_pairs, (VIRTIO_QUEUE_MAX - 1) / 2);
        virtio_cleanup(vdev);
        return;
    }
    n->vqs = g_new0(VirtIONetQueue, n->max_queue_pairs);
    n->curr_queue_pairs = 1;
    n->tx_timeout = n->net_conf.txtimer;

    if (n->net_conf.tx && strcmp(n->net_conf.tx, "timer")
                       && strcmp(n->net_conf.tx, "bh")) {
        warn_report("virtio-net: "
                    "Unknown option tx=%s, valid options: \"timer\" \"bh\"",
                    n->net_conf.tx);
        error_printf("Defaulting to \"bh\"");
    }

    n->net_conf.tx_queue_size = MIN(virtio_net_max_tx_queue_size(n),
                                    n->net_conf.tx_queue_size);

    for (i = 0; i < n->max_queue_pairs; i++) {
        virtio_net_add_queue(n, i);
    }

    n->ctrl_vq = virtio_add_queue(vdev, 64, virtio_net_handle_ctrl);
    qemu_macaddr_default_if_unset(&n->nic_conf.macaddr);
    memcpy(&n->mac[0], &n->nic_conf.macaddr, sizeof(n->mac));
    n->status = VIRTIO_NET_S_LINK_UP;
    qemu_announce_timer_reset(&n->announce_timer, migrate_announce_params(),
                              QEMU_CLOCK_VIRTUAL,
                              virtio_net_announce_timer, n);
    n->announce_timer.round = 0;

    if (n->netclient_type) {
        /*
         * Happen when virtio_net_set_netclient_name has been called.
         */
        n->nic = qemu_new_nic(&net_virtio_info, &n->nic_conf,
                              n->netclient_type, n->netclient_name,
                              &dev->mem_reentrancy_guard, n);
    } else {
        n->nic = qemu_new_nic(&net_virtio_info, &n->nic_conf,
                              object_get_typename(OBJECT(dev)), dev->id,
                              &dev->mem_reentrancy_guard, n);
    }

    for (i = 0; i < n->max_queue_pairs; i++) {
        n->nic->ncs[i].do_not_pad = true;
    }

    peer_test_vnet_hdr(n);
    if (peer_has_vnet_hdr(n)) {
        for (i = 0; i < n->max_queue_pairs; i++) {
            qemu_using_vnet_hdr(qemu_get_subqueue(n->nic, i)->peer, true);
        }
        n->host_hdr_len = sizeof(struct virtio_net_hdr);
    } else {
        n->host_hdr_len = 0;
    }

    qemu_format_nic_info_str(qemu_get_queue(n->nic), n->nic_conf.macaddr.a);

    n->vqs[0].tx_waiting = 0;
    n->tx_burst = n->net_conf.txburst;
    virtio_net_set_mrg_rx_bufs(n, 0, 0, 0);
    n->promisc = 1; /* for compatibility */

    n->mac_table.macs = g_malloc0(MAC_TABLE_ENTRIES * ETH_ALEN);

    n->vlans = g_malloc0(MAX_VLAN >> 3);

    nc = qemu_get_queue(n->nic);
    nc->rxfilter_notify_enabled = 1;

   if (nc->peer && nc->peer->info->type == NET_CLIENT_DRIVER_VHOST_VDPA) {
        struct virtio_net_config netcfg = {};
        memcpy(&netcfg.mac, &n->nic_conf.macaddr, ETH_ALEN);
        vhost_net_set_config(get_vhost_net(nc->peer),
            (uint8_t *)&netcfg, 0, ETH_ALEN, VHOST_SET_CONFIG_TYPE_FRONTEND);
    }
    QTAILQ_INIT(&n->rsc_chains);
    n->qdev = dev;

    net_rx_pkt_init(&n->rx_pkt);

    if (virtio_has_feature(n->host_features, VIRTIO_NET_F_RSS)) {
        virtio_net_load_ebpf(n, errp);
    }
}

static void virtio_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(dev);
    Error *err = NULL;

    /* Devices should either use vmsd or the load/save methods */
    assert(!vdc->vmsd || !vdc->load);

    if (vdc->realize != NULL) {
        vdc->realize(dev, &err);
        if (err != NULL) {
            error_propagate(errp, err);
            return;
        }
    }

    virtio_bus_device_plugged(vdev, &err);
    if (err != NULL) {
        error_propagate(errp, err);
        vdc->unrealize(dev);
        return;
    }

    vdev->listener.commit = virtio_memory_listener_commit;
    vdev->listener.name = "virtio";
    memory_listener_register(&vdev->listener, vdev->dma_as);
}
```

可以看到，这里实例化了**virtio设备**具体的组件，诸如**virtquues**、**feature bits**等。除此之外，根据{% post_link qemu的PCI设备 %}，其需要实例化**PCI配置空间**，是在上述[virtio_net_device_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L3656)中调用[**virtio_bus_device_plugged()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-bus.c#L43)中实现的。该函数会调用**virtio设备**所在的**bus**的**device_plugged**函数指针进行，而前面[**virtio_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2272)将**VirtIOPCIProxy**对象设置为[**virtio-pci-bus总线**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2719)，并在[**virtio_net_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L49)中将**virtio设备**，即**VirtIONet**对象的总线类型也设为[**virtio-pci-bus总线**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2719)，其在类初始化时将**device_plugged**函数指针设置为[**virtio_pci_device_plugged()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2089)

```c
//#0  virtio_pci_device_plugged (d=0x5555580bdd70, errp=0x7fffffffcfd8) at ../../qemu/hw/virtio/virtio-pci.c:2090
//#1  0x0000555555b6fb63 in virtio_bus_device_plugged (vdev=0x5555580c6260, errp=0x7fffffffd030) at ../../qemu/hw/virtio/virtio-bus.c:74
//#2  0x0000555555df39f6 in virtio_device_realize (dev=0x5555580c6260, errp=0x7fffffffd090) at ../../qemu/hw/virtio/virtio.c:3755
//#3  0x0000555555ea0d4e in device_set_realized (obj=0x5555580c6260, value=true, errp=0x7fffffffd360) at ../../qemu/hw/core/qdev.c:510
//#4  0x0000555555eac555 in property_set_bool (obj=0x5555580c6260, v=0x5555580d4190, name=0x555556300c31 "realized", opaque=0x5555570fc6e0, errp=0x7fffffffd360) at ../../qemu/qom/object.c:2358
//#5  0x0000555555eaa0eb in object_property_set (obj=0x5555580c6260, name=0x555556300c31 "realized", v=0x5555580d4190, errp=0x7fffffffd360) at ../../qemu/qom/object.c:1472
//#6  0x0000555555eaed24 in object_property_set_qobject (obj=0x5555580c6260, name=0x555556300c31 "realized", value=0x5555580d40d0, errp=0x7fffffffd360) at ../../qemu/qom/qom-qobject.c:28
//#7  0x0000555555eaa4a4 in object_property_set_bool (obj=0x5555580c6260, name=0x555556300c31 "realized", value=true, errp=0x7fffffffd360) at ../../qemu/qom/object.c:1541
//#8  0x0000555555ea0468 in qdev_realize (dev=0x5555580c6260, bus=0x5555580c61e0, errp=0x7fffffffd360) at ../../qemu/hw/core/qdev.c:292
//#9  0x0000555555e141a8 in virtio_net_pci_realize (vpci_dev=0x5555580bdd70, errp=0x7fffffffd360) at ../../qemu/hw/virtio/virtio-net-pci.c:64
//#10 0x0000555555b76de9 in virtio_pci_realize (pci_dev=0x5555580bdd70, errp=0x7fffffffd360) at ../../qemu/hw/virtio/virtio-pci.c:2407
//#11 0x0000555555a9cd61 in pci_qdev_realize (qdev=0x5555580bdd70, errp=0x7fffffffd420) at ../../qemu/hw/pci/pci.c:2093
//#12 0x0000555555b77204 in virtio_pci_dc_realize (qdev=0x5555580bdd70, errp=0x7fffffffd420) at ../../qemu/hw/virtio/virtio-pci.c:2501
//#13 0x0000555555ea0d4e in device_set_realized (obj=0x5555580bdd70, value=true, errp=0x7fffffffd690) at ../../qemu/hw/core/qdev.c:510
//#14 0x0000555555eac555 in property_set_bool (obj=0x5555580bdd70, v=0x5555580cdea0, name=0x555556300c31 "realized", opaque=0x5555570fc6e0, errp=0x7fffffffd690) at ../../qemu/qom/object.c:2358
//#15 0x0000555555eaa0eb in object_property_set (obj=0x5555580bdd70, name=0x555556300c31 "realized", v=0x5555580cdea0, errp=0x7fffffffd690) at ../../qemu/qom/object.c:1472
//#16 0x0000555555eaed24 in object_property_set_qobject (obj=0x5555580bdd70, name=0x555556300c31 "realized", value=0x5555580cca90, errp=0x7fffffffd690) at ../../qemu/qom/qom-qobject.c:28
//#17 0x0000555555eaa4a4 in object_property_set_bool (obj=0x5555580bdd70, name=0x555556300c31 "realized", value=true, errp=0x7fffffffd690) at ../../qemu/qom/object.c:1541
//#18 0x0000555555ea0468 in qdev_realize (dev=0x5555580bdd70, bus=0x555557430730, errp=0x7fffffffd690) at ../../qemu/hw/core/qdev.c:292
//#19 0x0000555555bd0329 in qdev_device_add_from_qdict (opts=0x5555580bc3b0, from_json=false, errp=0x7fffffffd690) at ../../qemu/system/qdev-monitor.c:718
//#20 0x0000555555bd03d9 in qdev_device_add (opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#21 0x0000555555bda4e7 in device_init_func (opaque=0x0, opts=0x5555570f7230, errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:1200
//#22 0x00005555560c2a63 in qemu_opts_foreach (list=0x555556f53ec0 <qemu_device_opts>, func=0x555555bda4bc <device_init_func>, opaque=0x0, errp=0x55555706a160 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#23 0x0000555555bde1b8 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#24 0x0000555555bde3fe in qmp_x_exit_preconfig (errp=0x55555706a160 <error_fatal>) at ../../qemu/system/vl.c:2706
//#25 0x0000555555be0db6 in qemu_init (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/vl.c:3739
//#26 0x0000555555e9b7ed in main (argc=39, argv=0x7fffffffdad8) at ../../qemu/system/main.c:47
//#27 0x00007ffff7629d90 in __libc_start_call_main (main=main@entry=0x555555e9b7c9 <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffdad8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#28 0x00007ffff7629e40 in __libc_start_main_impl (main=0x555555e9b7c9 <main>, argc=39, argv=0x7fffffffdad8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdac8) at ../csu/libc-start.c:392
//#29 0x000055555586f0d5 in _start ()

/* This is called by virtio-bus just after the device is plugged. */
static void virtio_pci_device_plugged(DeviceState *d, Error **errp)
{
    VirtIOPCIProxy *proxy = VIRTIO_PCI(d);
    VirtioBusState *bus = &proxy->bus;
    bool legacy = virtio_pci_legacy(proxy);
    bool modern;
    bool modern_pio = proxy->flags & VIRTIO_PCI_FLAG_MODERN_PIO_NOTIFY;
    uint8_t *config;
    uint32_t size;
    VirtIODevice *vdev = virtio_bus_get_device(bus);

    /*
     * Virtio capabilities present without
     * VIRTIO_F_VERSION_1 confuses guests
     */
    if (!proxy->ignore_backend_features &&
            !virtio_has_feature(vdev->host_features, VIRTIO_F_VERSION_1)) {
        virtio_pci_disable_modern(proxy);

        if (!legacy) {
            error_setg(errp, "Device doesn't support modern mode, and legacy"
                             " mode is disabled");
            error_append_hint(errp, "Set disable-legacy to off\n");

            return;
        }
    }

    modern = virtio_pci_modern(proxy);

    config = proxy->pci_dev.config;
    if (proxy->class_code) {
        pci_config_set_class(config, proxy->class_code);
    }

    if (legacy) {
        if (!virtio_legacy_allowed(vdev)) {
            /*
             * To avoid migration issues, we allow legacy mode when legacy
             * check is disabled in the old machine types (< 5.1).
             */
            if (virtio_legacy_check_disabled(vdev)) {
                warn_report("device is modern-only, but for backward "
                            "compatibility legacy is allowed");
            } else {
                error_setg(errp,
                           "device is modern-only, use disable-legacy=on");
                return;
            }
        }
        if (virtio_host_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM)) {
            error_setg(errp, "VIRTIO_F_IOMMU_PLATFORM was supported by"
                       " neither legacy nor transitional device");
            return;
        }
        /*
         * Legacy and transitional devices use specific subsystem IDs.
         * Note that the subsystem vendor ID (config + PCI_SUBSYSTEM_VENDOR_ID)
         * is set to PCI_SUBVENDOR_ID_REDHAT_QUMRANET by default.
         */
        pci_set_word(config + PCI_SUBSYSTEM_ID, virtio_bus_get_vdev_id(bus));
        if (proxy->trans_devid) {
            pci_config_set_device_id(config, proxy->trans_devid);
        }
    } else {
        /* pure virtio-1.0 */
        pci_set_word(config + PCI_VENDOR_ID,
                     PCI_VENDOR_ID_REDHAT_QUMRANET);
        pci_set_word(config + PCI_DEVICE_ID,
                     PCI_DEVICE_ID_VIRTIO_10_BASE + virtio_bus_get_vdev_id(bus));
        pci_config_set_revision(config, 1);
    }
    config[PCI_INTERRUPT_PIN] = 1;


    if (modern) {
        struct virtio_pci_cap cap = {
            .cap_len = sizeof cap,
        };
        struct virtio_pci_notify_cap notify = {
            .cap.cap_len = sizeof notify,
            .notify_off_multiplier =
                cpu_to_le32(virtio_pci_queue_mem_mult(proxy)),
        };
        struct virtio_pci_cfg_cap cfg = {
            .cap.cap_len = sizeof cfg,
            .cap.cfg_type = VIRTIO_PCI_CAP_PCI_CFG,
        };
        struct virtio_pci_notify_cap notify_pio = {
            .cap.cap_len = sizeof notify,
            .notify_off_multiplier = cpu_to_le32(0x0),
        };

        struct virtio_pci_cfg_cap *cfg_mask;

        virtio_pci_modern_regions_init(proxy, vdev->name);

        virtio_pci_modern_mem_region_map(proxy, &proxy->common, &cap);
        virtio_pci_modern_mem_region_map(proxy, &proxy->isr, &cap);
        virtio_pci_modern_mem_region_map(proxy, &proxy->device, &cap);
        virtio_pci_modern_mem_region_map(proxy, &proxy->notify, &notify.cap);
        if (proxy->flags & VIRTIO_PCI_FLAG_VDPA) {
            memory_region_add_subregion(&proxy->modern_bar,
                                        proxy->lm.offset, &proxy->lm.mr);
        }

        if (modern_pio) {
            memory_region_init(&proxy->io_bar, OBJECT(proxy),
                               "virtio-pci-io", 0x4);

            pci_register_bar(&proxy->pci_dev, proxy->modern_io_bar_idx,
                             PCI_BASE_ADDRESS_SPACE_IO, &proxy->io_bar);

            virtio_pci_modern_io_region_map(proxy, &proxy->notify_pio,
                                            &notify_pio.cap);
        }

        pci_register_bar(&proxy->pci_dev, proxy->modern_mem_bar_idx,
                         PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         &proxy->modern_bar);

        proxy->config_cap = virtio_pci_add_mem_cap(proxy, &cfg.cap);
        cfg_mask = (void *)(proxy->pci_dev.wmask + proxy->config_cap);
        pci_set_byte(&cfg_mask->cap.bar, ~0x0);
        pci_set_long((uint8_t *)&cfg_mask->cap.offset, ~0x0);
        pci_set_long((uint8_t *)&cfg_mask->cap.length, ~0x0);
        pci_set_long(cfg_mask->pci_cfg_data, ~0x0);
    }

    if (proxy->nvectors) {
        int err = msix_init_exclusive_bar(&proxy->pci_dev, proxy->nvectors,
                                          proxy->msix_bar_idx, NULL);
        if (err) {
            /* Notice when a system that supports MSIx can't initialize it */
            if (err != -ENOTSUP) {
                warn_report("unable to init msix vectors to %" PRIu32,
                            proxy->nvectors);
            }
            proxy->nvectors = 0;
        }
    }

    proxy->pci_dev.config_write = virtio_write_config;
    proxy->pci_dev.config_read = virtio_read_config;

    if (legacy) {
        size = VIRTIO_PCI_REGION_SIZE(&proxy->pci_dev)
            + virtio_bus_get_vdev_config_len(bus);
        size = pow2ceil(size);

        memory_region_init_io(&proxy->bar, OBJECT(proxy),
                              &virtio_pci_config_ops,
                              proxy, "virtio-pci", size);

        pci_register_bar(&proxy->pci_dev, proxy->legacy_io_bar_idx,
                         PCI_BASE_ADDRESS_SPACE_IO, &proxy->bar);
    }
}

/* A VirtIODevice is being plugged */
void virtio_bus_device_plugged(VirtIODevice *vdev, Error **errp)
{
    DeviceState *qdev = DEVICE(vdev);
    BusState *qbus = BUS(qdev_get_parent_bus(qdev));
    VirtioBusState *bus = VIRTIO_BUS(qbus);
    VirtioBusClass *klass = VIRTIO_BUS_GET_CLASS(bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    bool has_iommu = virtio_host_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM);
    bool vdev_has_iommu;
    Error *local_err = NULL;

    DPRINTF("%s: plug device.\n", qbus->name);
    ...
    if (klass->device_plugged != NULL) {
        klass->device_plugged(qbus->parent, &local_err);
    }
    ...
}
```

可以看到，在[**virtio_pci_device_plugged()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2089)中完成了**PCI配置空间**的设置。

整体来看，**virtio设备**实例化时会分别实例化**virtio transport**和**virtio设备**，这样子具有更好的拓展性。

## virtio设置

在qemu实例化完**virtio-net-pci**设备后，需要与**guest驱动**通信完成**virtio**的设置，即virtio各个组件的设置

### virtio结构的配置空间

根据前面[virtio transport](#virtio-transport)章节可知，**virtio-net-pci**设备**PCI配置空间**的capability指定着virtio各个组件的配置空间

![virtio的PCI配置空间](virtio的PCI配置空间.png)

因此首先就需要设置**virtio结构的配置空间**，即根据capability确定组件配置空间的**BAR**。

在前面[virtio设备的实例化](#实例化)中，[**virtio_pci_device_plugged()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2089)将所有capability配置空间设置在**proxy->modern_bar**上。
```c
/* This is called by virtio-bus just after the device is plugged. */
static void virtio_pci_device_plugged(DeviceState *d, Error **errp)
{
    ...
    struct virtio_pci_cap cap = {
        .cap_len = sizeof cap,
    };
    struct virtio_pci_notify_cap notify = {
        .cap.cap_len = sizeof notify,
        .notify_off_multiplier =
            cpu_to_le32(virtio_pci_queue_mem_mult(proxy)),
    };
    struct virtio_pci_cfg_cap cfg = {
        .cap.cap_len = sizeof cfg,
        .cap.cfg_type = VIRTIO_PCI_CAP_PCI_CFG,
    };
    struct virtio_pci_notify_cap notify_pio = {
        .cap.cap_len = sizeof notify,
        .notify_off_multiplier = cpu_to_le32(0x0),
    };

    struct virtio_pci_cfg_cap *cfg_mask;
    ...
    virtio_pci_modern_mem_region_map(proxy, &proxy->common, &cap);
    virtio_pci_modern_mem_region_map(proxy, &proxy->isr, &cap);
    virtio_pci_modern_mem_region_map(proxy, &proxy->device, &cap);
    virtio_pci_modern_mem_region_map(proxy, &proxy->notify, &notify.cap);
    ...
    pci_register_bar(&proxy->pci_dev, proxy->modern_mem_bar_idx,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_PREFETCH |
                     PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &proxy->modern_bar);
}

static void virtio_pci_modern_mem_region_map(VirtIOPCIProxy *proxy,
                                             VirtIOPCIRegion *region,
                                             struct virtio_pci_cap *cap)
{
    virtio_pci_modern_region_map(proxy, region, cap,
                                 &proxy->modern_bar, proxy->modern_mem_bar_idx);
}

static void virtio_pci_modern_region_map(VirtIOPCIProxy *proxy,
                                         VirtIOPCIRegion *region,
                                         struct virtio_pci_cap *cap,
                                         MemoryRegion *mr,
                                         uint8_t bar)
{
    memory_region_add_subregion(mr, region->offset, &region->mr);

    cap->cfg_type = region->type;
    cap->bar = bar;
    cap->offset = cpu_to_le32(region->offset);
    cap->length = cpu_to_le32(region->size);
    virtio_pci_add_mem_cap(proxy, cap);

}
```

而**proxy->modern_mem_bar_idx**在[**virtio_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2272)中被设置为4，即capability配置空间被设置在**BAR4**上
```c
static void virtio_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    ...
    /*
     * virtio pci bar layout used by default.
     * subclasses can re-arrange things if needed.
     *
     *   region 0   --  virtio legacy io bar
     *   region 1   --  msi-x bar
     *   region 2   --  virtio modern io bar (off by default)
     *   region 4+5 --  virtio modern memory (64bit) bar
     *
     */
    proxy->modern_mem_bar_idx = 4;
    ...
}
```

根据{% post_link qemu的PCI设备 %}可知，**guest驱动**在**PCI配置空间**中设置**BAR4**的物理地址即可完成virtio结构的配置空间的设置
```c
//#0  pci_default_write_config (d=0x5555580bdd70, addr=32, val_in=4294967295, l=4) at ../../qemu/hw/pci/pci.c:1594
//#1  0x0000555555b729ad in virtio_write_config (pci_dev=0x5555580bdd70, address=32, val=4294967295, len=4) at ../../qemu/hw/virtio/virtio-pci.c:747
//#2  0x0000555555aa0c9a in pci_host_config_write_common (pci_dev=0x5555580bdd70, addr=32, limit=256, val=4294967295, len=4) at ../../qemu/hw/pci/pci_host.c:96
//#3  0x0000555555aa0ee6 in pci_data_write (s=0x555557430730, addr=2147489824, val=4294967295, len=4) at ../../qemu/hw/pci/pci_host.c:138
//#4  0x0000555555aa10bb in pci_host_data_write (opaque=0x5555573f9ad0, addr=0, val=4294967295, len=4) at ../../qemu/hw/pci/pci_host.c:188
//#5  0x0000555555e1e25a in memory_region_write_accessor (mr=0x5555573f9f10, addr=0, value=0x7ffff65ff598, size=4, shift=0, mask=4294967295, attrs=...) at ../../qemu/system/memory.c:497
//#6  0x0000555555e1e593 in access_with_adjusted_size (addr=0, value=0x7ffff65ff598, size=4, access_size_min=1, access_size_max=4, access_fn=0x555555e1e160 <memory_region_write_accessor>, mr=0x5555573f9f10, attrs=...) at ../../qemu/system/memory.c:573
//#7  0x0000555555e218ad in memory_region_dispatch_write (mr=0x5555573f9f10, addr=0, data=4294967295, op=MO_32, attrs=...) at ../../qemu/system/memory.c:1521
//#8  0x0000555555e2fffa in flatview_write_continue_step (attrs=..., buf=0x7ffff7f8a000 "\377\377\377\377", len=4, mr_addr=0, l=0x7ffff65ff680, mr=0x5555573f9f10) at ../../qemu/system/physmem.c:2713
//#9  0x0000555555e300ca in flatview_write_continue (fv=0x7ffee8043b90, addr=3324, attrs=..., ptr=0x7ffff7f8a000, len=4, mr_addr=0, l=4, mr=0x5555573f9f10) at ../../qemu/system/physmem.c:2743
//#10 0x0000555555e301dc in flatview_write (fv=0x7ffee8043b90, addr=3324, attrs=..., buf=0x7ffff7f8a000, len=4) at ../../qemu/system/physmem.c:2774
//#11 0x0000555555e3062a in address_space_write (as=0x555557055e80 <address_space_io>, addr=3324, attrs=..., buf=0x7ffff7f8a000, len=4) at ../../qemu/system/physmem.c:2894
//#12 0x0000555555e306a6 in address_space_rw (as=0x555557055e80 <address_space_io>, addr=3324, attrs=..., buf=0x7ffff7f8a000, len=4, is_write=true) at ../../qemu/system/physmem.c:2904
//#13 0x0000555555e89cd0 in kvm_handle_io (port=3324, attrs=..., data=0x7ffff7f8a000, direction=1, size=4, count=1) at ../../qemu/accel/kvm/kvm-all.c:2631
//#14 0x0000555555e8a640 in kvm_cpu_exec (cpu=0x5555573bc6a0) at ../../qemu/accel/kvm/kvm-all.c:2903
//#15 0x0000555555e8d712 in kvm_vcpu_thread_fn (arg=0x5555573bc6a0) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#16 0x00005555560b6f08 in qemu_thread_start (args=0x5555573c5850) at ../../qemu/util/qemu-thread-posix.c:541
//#17 0x00007ffff7694ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#18 0x00007ffff7726850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
void pci_default_write_config(PCIDevice *d, uint32_t addr, uint32_t val_in, int l)
{
    ...
    if (ranges_overlap(addr, l, PCI_BASE_ADDRESS_0, 24) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS, 4) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS1, 4) ||
        range_covers_byte(addr, l, PCI_COMMAND))
        pci_update_mappings(d);
    ...
}
```

### virtio组件

根据前面[virtio transport](#virtio-transport)章节，virtio组件通过对应的配置空间进行设置。而virtio结构的配置空间在前面[virtio结构的配置空间](#virtio结构的配置空间)完成初始化，映射入**AddressSpace**中。 此时**guest**即可通过读写组件的配置空间完成组件的设置

具体的，在实例化时[**virtio_pci_device_plugged()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L2089)为每一个virito结构的配置空间分配了一个单独的MemoryRegion，则**guest**读写组件的配置空间即可触发对应MemoryRegion的回调函数，完成virtio组件的设置
```c
/* This is called by virtio-bus just after the device is plugged. */
static void virtio_pci_device_plugged(DeviceState *d, Error **errp)
{
    ...
    virtio_pci_modern_regions_init(proxy, vdev->name);
    ...
}

static void virtio_pci_modern_regions_init(VirtIOPCIProxy *proxy,
                                           const char *vdev_name)
{
    static const MemoryRegionOps common_ops = {
        .read = virtio_pci_common_read,
        .write = virtio_pci_common_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    static const MemoryRegionOps isr_ops = {
        .read = virtio_pci_isr_read,
        .write = virtio_pci_isr_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    static const MemoryRegionOps device_ops = {
        .read = virtio_pci_device_read,
        .write = virtio_pci_device_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    static const MemoryRegionOps notify_ops = {
        .read = virtio_pci_notify_read,
        .write = virtio_pci_notify_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    static const MemoryRegionOps notify_pio_ops = {
        .read = virtio_pci_notify_read,
        .write = virtio_pci_notify_write_pio,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    static const MemoryRegionOps lm_ops = {
        .read = virtio_pci_lm_read,
        .write = virtio_pci_lm_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };
    g_autoptr(GString) name = g_string_new(NULL);

    g_string_printf(name, "virtio-pci-common-%s", vdev_name);
    memory_region_init_io(&proxy->common.mr, OBJECT(proxy),
                          &common_ops,
                          proxy,
                          name->str,
                          proxy->common.size);

    g_string_printf(name, "virtio-pci-isr-%s", vdev_name);
    memory_region_init_io(&proxy->isr.mr, OBJECT(proxy),
                          &isr_ops,
                          proxy,
                          name->str,
                          proxy->isr.size);

    g_string_printf(name, "virtio-pci-device-%s", vdev_name);
    memory_region_init_io(&proxy->device.mr, OBJECT(proxy),
                          &device_ops,
                          proxy,
                          name->str,
                          proxy->device.size);

    g_string_printf(name, "virtio-pci-notify-%s", vdev_name);
    memory_region_init_io(&proxy->notify.mr, OBJECT(proxy),
                          &notify_ops,
                          proxy,
                          name->str,
                          proxy->notify.size);

    g_string_printf(name, "virtio-pci-notify-pio-%s", vdev_name);
    memory_region_init_io(&proxy->notify_pio.mr, OBJECT(proxy),
                          &notify_pio_ops,
                          proxy,
                          name->str,
                          proxy->notify_pio.size);
    if (proxy->flags & VIRTIO_PCI_FLAG_VDPA) {
        g_string_printf(name, "virtio-pci-lm-%s", vdev_name);
        memory_region_init_io(&proxy->lm.mr, OBJECT(proxy),
                          &lm_ops,
                          proxy,
                          name->str,
                          proxy->lm.size);
    }
}
```

这里重点介绍一下**VIRTIO_PCI_CAP_COMMON_CFG**设置空间的回调函数，根据前面[VIRTIO_PCI_CAP_COMMON_CFG配置空间](#配置空间)章节可知，读写其字段可以设置**virtqueue**和**feature bits**等组件。根据前面[virtio组件](#virtio组件)章节中代码可知，qemu使用[**virtio_pci_common_writes()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L1686)来进行设置的

```c
//#0  virtio_pci_common_write (opaque=0x5555580bdd70, addr=22, val=0, size=2) at ../../qemu/hw/virtio/virtio-pci.c:1689
//#1  0x0000555555e1e25a in memory_region_write_accessor (mr=0x5555580be8b0, addr=22, value=0x7ffff5bff5d8, size=2, shift=0, mask=65535, attrs=...) at ../../qemu/system/memory.c:497
//#2  0x0000555555e1e593 in access_with_adjusted_size (addr=22, value=0x7ffff5bff5d8, size=2, access_size_min=1, access_size_max=4, access_fn=0x555555e1e160 <memory_region_write_accessor>, mr=0x5555580be8b0, attrs=...) at ../../qemu/system/memory.c:573
//#3  0x0000555555e218ad in memory_region_dispatch_write (mr=0x5555580be8b0, addr=22, data=0, op=MO_16, attrs=...) at ../../qemu/system/memory.c:1521
//#4  0x0000555555e2fffa in flatview_write_continue_step (attrs=..., buf=0x7ffff7f86028 "", len=2, mr_addr=22, l=0x7ffff5bff6c0, mr=0x5555580be8b0) at ../../qemu/system/physmem.c:2713
//#5  0x0000555555e300ca in flatview_write_continue (fv=0x7ffee0703240, addr=481036337174, attrs=..., ptr=0x7ffff7f86028, len=2, mr_addr=22, l=2, mr=0x5555580be8b0) at ../../qemu/system/physmem.c:2743
//#6  0x0000555555e301dc in flatview_write (fv=0x7ffee0703240, addr=481036337174, attrs=..., buf=0x7ffff7f86028, len=2) at ../../qemu/system/physmem.c:2774
//#7  0x0000555555e3062a in address_space_write (as=0x555557055ee0 <address_space_memory>, addr=481036337174, attrs=..., buf=0x7ffff7f86028, len=2) at ../../qemu/system/physmem.c:2894
//#8  0x0000555555e306a6 in address_space_rw (as=0x555557055ee0 <address_space_memory>, addr=481036337174, attrs=..., buf=0x7ffff7f86028, len=2, is_write=true) at ../../qemu/system/physmem.c:2904
//#9  0x0000555555e8a690 in kvm_cpu_exec (cpu=0x5555573ef900) at ../../qemu/accel/kvm/kvm-all.c:2912
//#10 0x0000555555e8d712 in kvm_vcpu_thread_fn (arg=0x5555573ef900) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#11 0x00005555560b6f08 in qemu_thread_start (args=0x5555573f8ad0) at ../../qemu/util/qemu-thread-posix.c:541
//#12 0x00007ffff7694ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#13 0x00007ffff7726850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static void virtio_pci_common_write(void *opaque, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    VirtIOPCIProxy *proxy = opaque;
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    uint16_t vector;

    if (vdev == NULL) {
        return;
    }

    switch (addr) {
    case VIRTIO_PCI_COMMON_DFSELECT:
        proxy->dfselect = val;
        break;
    case VIRTIO_PCI_COMMON_GFSELECT:
        proxy->gfselect = val;
        break;
    case VIRTIO_PCI_COMMON_GF:
        if (proxy->gfselect < ARRAY_SIZE(proxy->guest_features)) {
            proxy->guest_features[proxy->gfselect] = val;
            virtio_set_features(vdev,
                                (((uint64_t)proxy->guest_features[1]) << 32) |
                                proxy->guest_features[0]);
        }
        break;
    case VIRTIO_PCI_COMMON_MSIX:
        if (vdev->config_vector != VIRTIO_NO_VECTOR) {
            msix_vector_unuse(&proxy->pci_dev, vdev->config_vector);
        }
        /* Make it possible for guest to discover an error took place. */
        if (val < proxy->nvectors) {
            msix_vector_use(&proxy->pci_dev, val);
        } else {
            val = VIRTIO_NO_VECTOR;
        }
        vdev->config_vector = val;
        break;
    case VIRTIO_PCI_COMMON_STATUS:
        if (!(val & VIRTIO_CONFIG_S_DRIVER_OK)) {
            virtio_pci_stop_ioeventfd(proxy);
        }

        virtio_set_status(vdev, val & 0xFF);

        if (val & VIRTIO_CONFIG_S_DRIVER_OK) {
            virtio_pci_start_ioeventfd(proxy);
        }

        if (vdev->status == 0) {
            virtio_pci_reset(DEVICE(proxy));
        }

        break;
    case VIRTIO_PCI_COMMON_Q_SELECT:
        if (val < VIRTIO_QUEUE_MAX) {
            vdev->queue_sel = val;
        }
        break;
    case VIRTIO_PCI_COMMON_Q_SIZE:
        proxy->vqs[vdev->queue_sel].num = val;
        virtio_queue_set_num(vdev, vdev->queue_sel,
                             proxy->vqs[vdev->queue_sel].num);
        virtio_init_region_cache(vdev, vdev->queue_sel);
        break;
    case VIRTIO_PCI_COMMON_Q_MSIX:
        vector = virtio_queue_vector(vdev, vdev->queue_sel);
        if (vector != VIRTIO_NO_VECTOR) {
            msix_vector_unuse(&proxy->pci_dev, vector);
        }
        /* Make it possible for guest to discover an error took place. */
        if (val < proxy->nvectors) {
            msix_vector_use(&proxy->pci_dev, val);
        } else {
            val = VIRTIO_NO_VECTOR;
        }
        virtio_queue_set_vector(vdev, vdev->queue_sel, val);
        break;
    case VIRTIO_PCI_COMMON_Q_ENABLE:
        if (val == 1) {
            virtio_queue_set_num(vdev, vdev->queue_sel,
                                 proxy->vqs[vdev->queue_sel].num);
            virtio_queue_set_rings(vdev, vdev->queue_sel,
                       ((uint64_t)proxy->vqs[vdev->queue_sel].desc[1]) << 32 |
                       proxy->vqs[vdev->queue_sel].desc[0],
                       ((uint64_t)proxy->vqs[vdev->queue_sel].avail[1]) << 32 |
                       proxy->vqs[vdev->queue_sel].avail[0],
                       ((uint64_t)proxy->vqs[vdev->queue_sel].used[1]) << 32 |
                       proxy->vqs[vdev->queue_sel].used[0]);
            proxy->vqs[vdev->queue_sel].enabled = 1;
            proxy->vqs[vdev->queue_sel].reset = 0;
            virtio_queue_enable(vdev, vdev->queue_sel);
        } else {
            virtio_error(vdev, "wrong value for queue_enable %"PRIx64, val);
        }
        break;
    case VIRTIO_PCI_COMMON_Q_DESCLO:
        proxy->vqs[vdev->queue_sel].desc[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_DESCHI:
        proxy->vqs[vdev->queue_sel].desc[1] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILLO:
        proxy->vqs[vdev->queue_sel].avail[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILHI:
        proxy->vqs[vdev->queue_sel].avail[1] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_USEDLO:
        proxy->vqs[vdev->queue_sel].used[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_USEDHI:
        proxy->vqs[vdev->queue_sel].used[1] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_RESET:
        if (val == 1) {
            proxy->vqs[vdev->queue_sel].reset = 1;

            virtio_queue_reset(vdev, vdev->queue_sel);

            proxy->vqs[vdev->queue_sel].reset = 0;
            proxy->vqs[vdev->queue_sel].enabled = 0;
        }
        break;
    default:
        break;
    }
}
```

## 数据处理

实际上数据处理包括数据传输和通知两部分，数据传输是通过内存共享实现的，而通知是通过内核的[eventfd机制](https://juejin.cn/post/6989608237226000391)实现的

### 数据传输

由于**guest**物理地址空间位于qemu的进程地址空间中，因此qemu天然就可以访问**guest**的任意物理地址。
因此，只要知道**guest**中为**virtqueue**分配的物理地址空间，**virtio设备**即可找到这些空间在**qemu**进程空间中的**hva**，即可完成访问，这是在[**virtio_queue_set_rings()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio.c#L2178)中完成的

具体的，根据前面[virtio组件](#virtio组件)小节可知，当**guest**设置**VIRTIO_PCI_COMMON_Q_ENABLE**字段来完成virtqueue的设置时，qemu会调用[**virtio_queue_set_rings()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio.c#L2178)，如下所示
```c
void virtio_queue_set_rings(VirtIODevice *vdev, int n, hwaddr desc,
                            hwaddr avail, hwaddr used)
{
    if (!vdev->vq[n].vring.num) {
        return;
    }
    vdev->vq[n].vring.desc = desc;
    vdev->vq[n].vring.avail = avail;
    vdev->vq[n].vring.used = used;
    virtio_init_region_cache(vdev, n);
}

void virtio_init_region_cache(VirtIODevice *vdev, int n)
{
    VirtQueue *vq = &vdev->vq[n];
    VRingMemoryRegionCaches *old = vq->vring.caches;
    VRingMemoryRegionCaches *new = NULL;
    hwaddr addr, size;
    int64_t len;
    bool packed;

    ...
    new = g_new0(VRingMemoryRegionCaches, 1);
    size = virtio_queue_get_desc_size(vdev, n);
    packed = virtio_vdev_has_feature(vq->vdev, VIRTIO_F_RING_PACKED) ?
                                   true : false;
    len = address_space_cache_init(&new->desc, vdev->dma_as,
                                   addr, size, packed);
    if (len < size) {
        virtio_error(vdev, "Cannot map desc");
        goto err_desc;
    }

    size = virtio_queue_get_used_size(vdev, n);
    len = address_space_cache_init(&new->used, vdev->dma_as,
                                   vq->vring.used, size, true);
    if (len < size) {
        virtio_error(vdev, "Cannot map used");
        goto err_used;
    }

    size = virtio_queue_get_avail_size(vdev, n);
    len = address_space_cache_init(&new->avail, vdev->dma_as,
                                   vq->vring.avail, size, false);
    if (len < size) {
        virtio_error(vdev, "Cannot map avail");
        goto err_avail;
    }

    qatomic_rcu_set(&vq->vring.caches, new);
    if (old) {
        call_rcu(old, virtio_free_region_cache, rcu);
    }
    return;
    ...
}

int64_t address_space_cache_init(MemoryRegionCache *cache,
                                 AddressSpace *as,
                                 hwaddr addr,
                                 hwaddr len,
                                 bool is_write)
{
    AddressSpaceDispatch *d;
    hwaddr l;
    MemoryRegion *mr;
    Int128 diff;

    assert(len > 0);

    l = len;
    cache->fv = address_space_get_flatview(as);
    d = flatview_to_dispatch(cache->fv);
    cache->mrs = *address_space_translate_internal(d, addr, &cache->xlat, &l, true);

    /*
     * cache->xlat is now relative to cache->mrs.mr, not to the section itself.
     * Take that into account to compute how many bytes are there between
     * cache->xlat and the end of the section.
     */
    diff = int128_sub(cache->mrs.size,
                      int128_make64(cache->xlat - cache->mrs.offset_within_region));
    l = int128_get64(int128_min(diff, int128_make64(l)));

    mr = cache->mrs.mr;
    memory_region_ref(mr);
    if (memory_access_is_direct(mr, is_write)) {
        /* We don't care about the memory attributes here as we're only
         * doing this if we found actual RAM, which behaves the same
         * regardless of attributes; so UNSPECIFIED is fine.
         */
        l = flatview_extend_translation(cache->fv, addr, len, mr,
                                        cache->xlat, l, is_write,
                                        MEMTXATTRS_UNSPECIFIED);
        cache->ptr = qemu_ram_ptr_length(mr->ram_block, cache->xlat, &l, true);
    } else {
        cache->ptr = NULL;
    }

    cache->len = l;
    cache->is_write = is_write;
    return l;
}
```

根据{% post_link qemu内存模型 %}可知，这里直接将**virtqueue**对应的**gpa**转换为qemu中的**hva**存储在**VRingMemoryRegionCaches**结构中。因此**virito设备**可通过该结构直接访问**virtiqueue**中的数据，而**guest**通过**gpa**直接访问**virtqueue**中的数据，从而实现数据传输

### 数据通知

通知包括两部分——**guest**通知**virtio设备**(ioeventfd)、**virtio设备**中断**guest**(ioctl)。

其中前半部分是由内核的**eventfd**机制实现

> eventfd() creates an "eventfd object" that can be used as an
> event wait/notify mechanism by user-space applications, and by
> the kernel to notify user-space applications of events.

而后半部分则是由硬件提供的机制实现的，即cpu提供了向**guest**注入中断的接口，则**virtio设备**通过ioctl调用该接口即可

#### 通知设备

ioeventfd机制的示意图如下图所示
![ioeventfd示意图](ioeventfd示意图.png)

根据前面[virtio组件](#virtio组件)小节可知，当**guest**设置**VIRTIO_PCI_COMMON_STATUS**字段来完成virtio设备的设置时，qemu会调用[**virtio_pci_start_ioeventfd()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-pci.c#L373)设置**eventfd**，如下所示
```c
//#0  virtio_bus_start_ioeventfd (bus=0x5555580b8df0) at ../../qemu/hw/virtio/virtio-bus.c:220
//#1  0x0000555555b6f952 in virtio_pci_start_ioeventfd (proxy=0x5555580b0900) at ../../qemu/hw/virtio/virtio-pci.c:375
//#2  0x0000555555b72cae in virtio_pci_common_write (opaque=0x5555580b0900, addr=20, val=15, size=1) at ../../qemu/hw/virtio/virtio-pci.c:1732
//#3  0x0000555555e19a00 in memory_region_write_accessor (mr=0x5555580b1440, addr=20, value=0x7ffff65ff5d8, size=1, shift=0, mask=255, attrs=...) at ../../qemu/system/memory.c:497
//#4  0x0000555555e19d39 in access_with_adjusted_size (addr=20, value=0x7ffff65ff5d8, size=1, access_size_min=1, access_size_max=4, access_fn=0x555555e19906 <memory_region_write_accessor>, mr=0x5555580b1440, attrs=...) at ../../qemu/system/memory.c:573
//#5  0x0000555555e1d053 in memory_region_dispatch_write (mr=0x5555580b1440, addr=20, data=15, op=MO_8, attrs=...) at ../../qemu/system/memory.c:1521
//#6  0x0000555555e2b7a0 in flatview_write_continue_step (attrs=..., buf=0x7ffff7f89028 "\017", len=1, mr_addr=20, l=0x7ffff65ff6c0, mr=0x5555580b1440) at ../../qemu/system/physmem.c:2713
//#7  0x0000555555e2b870 in flatview_write_continue (fv=0x7ffee8000c10, addr=30786325577748, attrs=..., ptr=0x7ffff7f89028, len=1, mr_addr=20, l=1, mr=0x5555580b1440) at ../../qemu/system/physmem.c:2743
//#8  0x0000555555e2b982 in flatview_write (fv=0x7ffee8000c10, addr=30786325577748, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2774
//#9  0x0000555555e2bdd0 in address_space_write (as=0x55555704dce0 <address_space_memory>, addr=30786325577748, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2894
//#10 0x0000555555e2be4c in address_space_rw (as=0x55555704dce0 <address_space_memory>, addr=30786325577748, attrs=..., buf=0x7ffff7f89028, len=1, is_write=true) at ../../qemu/system/physmem.c:2904
//#11 0x0000555555e85e36 in kvm_cpu_exec (cpu=0x5555573b4110) at ../../qemu/accel/kvm/kvm-all.c:2912
//#12 0x0000555555e88eb8 in kvm_vcpu_thread_fn (arg=0x5555573b4110) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#13 0x00005555560b2687 in qemu_thread_start (args=0x5555573bd220) at ../../qemu/util/qemu-thread-posix.c:541
//#14 0x00007ffff7894ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#15 0x00007ffff7926850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static void virtio_pci_start_ioeventfd(VirtIOPCIProxy *proxy)
{
    virtio_bus_start_ioeventfd(&proxy->bus);
}

int virtio_bus_start_ioeventfd(VirtioBusState *bus)
{
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(bus);
    DeviceState *proxy = DEVICE(BUS(bus)->parent);
    VirtIODevice *vdev = virtio_bus_get_device(bus);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_GET_CLASS(vdev);
    int r;

    if (!k->ioeventfd_assign || !k->ioeventfd_enabled(proxy)) {
        return -ENOSYS;
    }
    if (bus->ioeventfd_started) {
        return 0;
    }

    /* Only set our notifier if we have ownership.  */
    if (!bus->ioeventfd_grabbed) {
        r = vdc->start_ioeventfd(vdev);
        if (r < 0) {
            error_report("%s: failed. Fallback to userspace (slower).", __func__);
            return r;
        }
    }
    bus->ioeventfd_started = true;
    return 0;
}

static int virtio_device_start_ioeventfd_impl(VirtIODevice *vdev)
{
    VirtioBusState *qbus = VIRTIO_BUS(qdev_get_parent_bus(DEVICE(vdev)));
    int i, n, r, err;

    /*
     * Batch all the host notifiers in a single transaction to avoid
     * quadratic time complexity in address_space_update_ioeventfds().
     */
    memory_region_transaction_begin();
    for (n = 0; n < VIRTIO_QUEUE_MAX; n++) {
        VirtQueue *vq = &vdev->vq[n];
        if (!virtio_queue_get_num(vdev, n)) {
            continue;
        }
        r = virtio_bus_set_host_notifier(qbus, n, true);
        if (r < 0) {
            err = r;
            goto assign_error;
        }
        event_notifier_set_handler(&vq->host_notifier,
                                   virtio_queue_host_notifier_read);
    }
    ...
    memory_region_transaction_commit();
    return 0;
    ...
}
```

其可划分两部分——[**virtio_bus_set_host_notifier()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-bus.c#L276)向kvm注册eventfd、[**event_notifier_set_handler()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/main-loop.c#L648)注册等待线程

```c
//#0  memory_region_add_eventfd (mr=0x55555820ae80, addr=0, size=0, match_data=false, data=0, e=0x55555821cbb4) at ../../qemu/system/memory.c:2565
//#1  0x0000555555b6f81c in virtio_pci_ioeventfd_assign (d=0x555558209fe0, notifier=0x55555821cbb4, n=0, assign=true) at ../../qemu/hw/virtio/virtio-pci.c:345
//#2  0x0000555555b6df98 in virtio_bus_set_host_notifier (bus=0x555558212450, n=0, assign=true) at ../../qemu/hw/virtio/virtio-bus.c:296
//#3  0x0000555555def47c in virtio_device_start_ioeventfd_impl (vdev=0x5555582124d0) at ../../qemu/hw/virtio/virtio.c:3833
//#4  0x0000555555b6dd54 in virtio_bus_start_ioeventfd (bus=0x555558212450) at ../../qemu/hw/virtio/virtio-bus.c:236
//#5  0x0000555555b6f952 in virtio_pci_start_ioeventfd (proxy=0x555558209fe0) at ../../qemu/hw/virtio/virtio-pci.c:375
//#6  0x0000555555b72cae in virtio_pci_common_write (opaque=0x555558209fe0, addr=20, val=15, size=1) at ../../qemu/hw/virtio/virtio-pci.c:1732
//#7  0x0000555555e19a00 in memory_region_write_accessor (mr=0x55555820ab20, addr=20, value=0x7ffff65ff5d8, size=1, shift=0, mask=255, attrs=...) at ../../qemu/system/memory.c:497
//#8  0x0000555555e19d39 in access_with_adjusted_size (addr=20, value=0x7ffff65ff5d8, size=1, access_size_min=1, access_size_max=4, access_fn=0x555555e19906 <memory_region_write_accessor>, mr=0x55555820ab20, attrs=...) at ../../qemu/system/memory.c:573
//#9  0x0000555555e1d053 in memory_region_dispatch_write (mr=0x55555820ab20, addr=20, data=15, op=MO_8, attrs=...) at ../../qemu/system/memory.c:1521
//#10 0x0000555555e2b7a0 in flatview_write_continue_step (attrs=..., buf=0x7ffff7f89028 "\017", len=1, mr_addr=20, l=0x7ffff65ff6c0, mr=0x55555820ab20) at ../../qemu/system/physmem.c:2713
//#11 0x0000555555e2b870 in flatview_write_continue (fv=0x7ffee8000c10, addr=30786325594132, attrs=..., ptr=0x7ffff7f89028, len=1, mr_addr=20, l=1, mr=0x55555820ab20) at ../../qemu/system/physmem.c:2743
//#12 0x0000555555e2b982 in flatview_write (fv=0x7ffee8000c10, addr=30786325594132, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2774
//#13 0x0000555555e2bdd0 in address_space_write (as=0x55555704dce0 <address_space_memory>, addr=30786325594132, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2894
//#14 0x0000555555e2be4c in address_space_rw (as=0x55555704dce0 <address_space_memory>, addr=30786325594132, attrs=..., buf=0x7ffff7f89028, len=1, is_write=true) at ../../qemu/system/physmem.c:2904
//#15 0x0000555555e85e36 in kvm_cpu_exec (cpu=0x5555573b4110) at ../../qemu/accel/kvm/kvm-all.c:2912
//#16 0x0000555555e88eb8 in kvm_vcpu_thread_fn (arg=0x5555573b4110) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#17 0x00005555560b2687 in qemu_thread_start (args=0x5555573bd220) at ../../qemu/util/qemu-thread-posix.c:541
//#18 0x00007ffff7894ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#19 0x00007ffff7926850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
int virtio_bus_set_host_notifier(VirtioBusState *bus, int n, bool assign)
{
    VirtIODevice *vdev = virtio_bus_get_device(bus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(bus);
    DeviceState *proxy = DEVICE(BUS(bus)->parent);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_host_notifier(vq);

    ...
    r = event_notifier_init(notifier, 1);
    if (r < 0) {
        error_report("%s: unable to init event notifier: %s (%d)",
                     __func__, strerror(-r), r);
        return r;
    }
    r = k->ioeventfd_assign(proxy, notifier, n, true);
    ...
    return r;
}

int event_notifier_init(EventNotifier *e, int active)
{
    int fds[2];
    int ret;

    ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ...
    e->rfd = e->wfd = ret;
    e->initialized = true;
    event_notifier_set(e);
    return 0;
}

int event_notifier_set(EventNotifier *e)
{
    static const uint64_t value = 1;
    ssize_t ret;

    ...
    do {
        ret = write(e->wfd, &value, sizeof(value));
    } while (ret < 0 && errno == EINTR);
    ...
    return 0;
}

static int virtio_pci_ioeventfd_assign(DeviceState *d, EventNotifier *notifier,
                                       int n, bool assign)
{
    VirtIOPCIProxy *proxy = to_virtio_pci_proxy(d);
    VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);
    VirtQueue *vq = virtio_get_queue(vdev, n);
    bool modern = virtio_pci_modern(proxy);
    MemoryRegion *modern_mr = &proxy->notify.mr;
    hwaddr modern_addr = virtio_pci_queue_mem_mult(proxy) *
                         virtio_get_queue_index(vq);
    hwaddr legacy_addr = VIRTIO_PCI_QUEUE_NOTIFY;
    ...
    memory_region_add_eventfd(modern_mr, modern_addr, 0,
                              false, n, notifier);
    ...
    return 0;
}

void memory_region_add_eventfd(MemoryRegion *mr,
                               hwaddr addr,
                               unsigned size,
                               bool match_data,
                               uint64_t data,
                               EventNotifier *e)
{
    MemoryRegionIoeventfd mrfd = {
        .addr.start = int128_make64(addr),
        .addr.size = int128_make64(size),
        .match_data = match_data,
        .data = data,
        .e = e,
    };
    unsigned i;

    if (size) {
        adjust_endianness(mr, &mrfd.data, size_memop(size) | MO_TE);
    }
    memory_region_transaction_begin();
    for (i = 0; i < mr->ioeventfd_nb; ++i) {
        if (memory_region_ioeventfd_before(&mrfd, &mr->ioeventfds[i])) {
            break;
        }
    }
    ++mr->ioeventfd_nb;
    mr->ioeventfds = g_realloc(mr->ioeventfds,
                                  sizeof(*mr->ioeventfds) * mr->ioeventfd_nb);
    memmove(&mr->ioeventfds[i+1], &mr->ioeventfds[i],
            sizeof(*mr->ioeventfds) * (mr->ioeventfd_nb-1 - i));
    mr->ioeventfds[i] = mrfd;
    ioeventfd_update_pending |= mr->enabled;
    memory_region_transaction_commit();
}

//#0  kvm_set_ioeventfd_mmio (fd=28, addr=481036349440, val=0, assign=true, size=0, datamatch=false) at ../../qemu/accel/kvm/kvm-all.c:1187
//#1  0x0000555555e8764a in kvm_mem_ioeventfd_add (listener=0x555557101240, section=0x7ffff65ff290, match_data=false, data=0, e=0x5555580d4334) at ../../qemu/accel/kvm/kvm-all.c:1655
//#2  0x0000555555e1f689 in address_space_add_del_ioeventfds (as=0x555557055ee0 <address_space_memory>, fds_new=0x7ffee0417450, fds_new_nb=5, fds_old=0x7ffee00533a0, fds_old_nb=2) at ../../qemu/system/memory.c:818
//#3  0x0000555555e1fa13 in address_space_update_ioeventfds (as=0x555557055ee0 <address_space_memory>) at ../../qemu/system/memory.c:883
//#4  0x0000555555e208e4 in memory_region_transaction_commit () at ../../qemu/system/memory.c:1140
//#5  0x0000555555df3d83 in virtio_device_start_ioeventfd_impl (vdev=0x5555580c6260) at ../../qemu/hw/virtio/virtio.c:3850
//#6  0x0000555555b70194 in virtio_bus_start_ioeventfd (bus=0x5555580c61e0) at ../../qemu/hw/virtio/virtio-bus.c:236
//#7  0x0000555555b71d92 in virtio_pci_start_ioeventfd (proxy=0x5555580bdd70) at ../../qemu/hw/virtio/virtio-pci.c:375
//#8  0x0000555555b750ee in virtio_pci_common_write (opaque=0x5555580bdd70, addr=20, val=15, size=1) at ../../qemu/hw/virtio/virtio-pci.c:1732
//#9  0x0000555555e1e25a in memory_region_write_accessor (mr=0x5555580be8b0, addr=20, value=0x7ffff65ff5d8, size=1, shift=0, mask=255, attrs=...) at ../../qemu/system/memory.c:497
//#10 0x0000555555e1e593 in access_with_adjusted_size (addr=20, value=0x7ffff65ff5d8, size=1, access_size_min=1, access_size_max=4, access_fn=0x555555e1e160 <memory_region_write_accessor>, mr=0x5555580be8b0, attrs=...) at ../../qemu/system/memory.c:573
//#11 0x0000555555e218ad in memory_region_dispatch_write (mr=0x5555580be8b0, addr=20, data=15, op=MO_8, attrs=...) at ../../qemu/system/memory.c:1521
//#12 0x0000555555e2fffa in flatview_write_continue_step (attrs=..., buf=0x7ffff7f89028 "\017", len=1, mr_addr=20, l=0x7ffff65ff6c0, mr=0x5555580be8b0) at ../../qemu/system/physmem.c:2713
//#13 0x0000555555e300ca in flatview_write_continue (fv=0x7ffee80eb500, addr=481036337172, attrs=..., ptr=0x7ffff7f89028, len=1, mr_addr=20, l=1, mr=0x5555580be8b0) at ../../qemu/system/physmem.c:2743
//#14 0x0000555555e301dc in flatview_write (fv=0x7ffee80eb500, addr=481036337172, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2774
//#15 0x0000555555e3062a in address_space_write (as=0x555557055ee0 <address_space_memory>, addr=481036337172, attrs=..., buf=0x7ffff7f89028, len=1) at ../../qemu/system/physmem.c:2894
//#16 0x0000555555e306a6 in address_space_rw (as=0x555557055ee0 <address_space_memory>, addr=481036337172, attrs=..., buf=0x7ffff7f89028, len=1, is_write=true) at ../../qemu/system/physmem.c:2904
//#17 0x0000555555e8a690 in kvm_cpu_exec (cpu=0x5555573bc6a0) at ../../qemu/accel/kvm/kvm-all.c:2912
//#18 0x0000555555e8d712 in kvm_vcpu_thread_fn (arg=0x5555573bc6a0) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#19 0x00005555560b6f08 in qemu_thread_start (args=0x5555573c5850) at ../../qemu/util/qemu-thread-posix.c:541
//#20 0x00007ffff7694ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#21 0x00007ffff7726850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static void address_space_update_ioeventfds(AddressSpace *as)
{
    FlatView *view;
    FlatRange *fr;
    unsigned ioeventfd_nb = 0;
    unsigned ioeventfd_max;
    MemoryRegionIoeventfd *ioeventfds;
    AddrRange tmp;
    unsigned i;

    if (!as->ioeventfd_notifiers) {
        return;
    }

    /*
     * It is likely that the number of ioeventfds hasn't changed much, so use
     * the previous size as the starting value, with some headroom to avoid
     * gratuitous reallocations.
     */
    ioeventfd_max = QEMU_ALIGN_UP(as->ioeventfd_nb, 4);
    ioeventfds = g_new(MemoryRegionIoeventfd, ioeventfd_max);

    view = address_space_get_flatview(as);
    FOR_EACH_FLAT_RANGE(fr, view) {
        for (i = 0; i < fr->mr->ioeventfd_nb; ++i) {
            tmp = addrrange_shift(fr->mr->ioeventfds[i].addr,
                                  int128_sub(fr->addr.start,
                                             int128_make64(fr->offset_in_region)));
            if (addrrange_intersects(fr->addr, tmp)) {
                ++ioeventfd_nb;
                if (ioeventfd_nb > ioeventfd_max) {
                    ioeventfd_max = MAX(ioeventfd_max * 2, 4);
                    ioeventfds = g_realloc(ioeventfds,
                            ioeventfd_max * sizeof(*ioeventfds));
                }
                ioeventfds[ioeventfd_nb-1] = fr->mr->ioeventfds[i];
                ioeventfds[ioeventfd_nb-1].addr = tmp;
            }
        }
    }

    address_space_add_del_ioeventfds(as, ioeventfds, ioeventfd_nb,
                                     as->ioeventfds, as->ioeventfd_nb);

    g_free(as->ioeventfds);
    as->ioeventfds = ioeventfds;
    as->ioeventfd_nb = ioeventfd_nb;
    flatview_unref(view);
}

static void address_space_add_del_ioeventfds(AddressSpace *as,
                                             MemoryRegionIoeventfd *fds_new,
                                             unsigned fds_new_nb,
                                             MemoryRegionIoeventfd *fds_old,
                                             unsigned fds_old_nb)
{
    unsigned iold, inew;
    MemoryRegionIoeventfd *fd;
    MemoryRegionSection section;

    /* Generate a symmetric difference of the old and new fd sets, adding
     * and deleting as necessary.
     */

    iold = inew = 0;
    while (iold < fds_old_nb || inew < fds_new_nb) {
        if (iold < fds_old_nb
            && (inew == fds_new_nb
                || memory_region_ioeventfd_before(&fds_old[iold],
                                                  &fds_new[inew]))) {
            fd = &fds_old[iold];
            section = (MemoryRegionSection) {
                .fv = address_space_to_flatview(as),
                .offset_within_address_space = int128_get64(fd->addr.start),
                .size = fd->addr.size,
            };
            MEMORY_LISTENER_CALL(as, eventfd_del, Forward, &section,
                                 fd->match_data, fd->data, fd->e);
            ++iold;
        } else if (inew < fds_new_nb
                   && (iold == fds_old_nb
                       || memory_region_ioeventfd_before(&fds_new[inew],
                                                         &fds_old[iold]))) {
            fd = &fds_new[inew];
            section = (MemoryRegionSection) {
                .fv = address_space_to_flatview(as),
                .offset_within_address_space = int128_get64(fd->addr.start),
                .size = fd->addr.size,
            };
            MEMORY_LISTENER_CALL(as, eventfd_add, Reverse, &section,
                                 fd->match_data, fd->data, fd->e);
            ++inew;
        } else {
            ++iold;
            ++inew;
        }
    }
}

static void kvm_mem_ioeventfd_add(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    r = kvm_set_ioeventfd_mmio(fd, section->offset_within_address_space,
                               data, true, int128_get64(section->size),
                               match_data);
    ...
}

int event_notifier_get_fd(const EventNotifier *e)
{
    return e->rfd;
}

static int kvm_set_ioeventfd_mmio(int fd, hwaddr addr, uint32_t val,
                                  bool assign, uint32_t size, bool datamatch)
{
    int ret;
    struct kvm_ioeventfd iofd = {
        .datamatch = datamatch ? adjust_ioeventfd_endianness(val, size) : 0,
        .addr = addr,
        .len = size,
        .flags = 0,
        .fd = fd,
    };
    ...
    ret = kvm_vm_ioctl(kvm_state, KVM_IOEVENTFD, &iofd);
    ...
}
```

简单来说，其在[**event_notifier_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/event_notifier-posix.c#L35)中调用**eventfd**系统调用并获取对应的文件描述符，然后在[**kvm_mem_ioeventfd_add()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/accel/kvm/kvm-all.c#L1647)中将该文件描述符通过**ioctl**传递给**kvm内核模块**，后续**kvm内核模块**可以唤醒被阻塞的用于轮询的**virtio设备**的任务，完成**guest**通知**virtio设备**

下面分析一下**virtio设备**如何将**eventfd**的文件描述符绑定到等待线程任务上的，其相关代码如下所示
```c
//#0  aio_set_event_notifier (ctx=0x5555570ea810, notifier=0x5555580ca6e4, io_read=0x555555deed70 <virtio_queue_host_notifier_read>, io_poll=0x0, io_poll_ready=0x0) at ../../qemu/util/aio-posix.c:201
//#1  0x00005555560ce889 in event_notifier_set_handler (e=0x5555580ca6e4, handler=0x555555deed70 <virtio_queue_host_notifier_read>) at ../../qemu/util/main-loop.c:652
//#2  0x0000555555def4b1 in virtio_device_start_ioeventfd_impl (vdev=0x5555580b8df0) at ../../qemu/hw/virtio/virtio.c:3838
//#3  0x0000555555b6dd54 in virtio_bus_start_ioeventfd (bus=0x5555580b8d70) at ../../qemu/hw/virtio/virtio-bus.c:236
//#4  0x0000555555b6f952 in virtio_pci_start_ioeventfd (proxy=0x5555580b0900) at ../../qemu/hw/virtio/virtio-pci.c:375
//#5  0x0000555555b72cae in virtio_pci_common_write (opaque=0x5555580b0900, addr=20, val=15, size=1) at ../../qemu/hw/virtio/virtio-pci.c:1732
//#6  0x0000555555e19a00 in memory_region_write_accessor (mr=0x5555580b1440, addr=20, value=0x7ffff5bff5d8, size=1, shift=0, mask=255, attrs=...) at ../../qemu/system/memory.c:497
//#7  0x0000555555e19d39 in access_with_adjusted_size (addr=20, value=0x7ffff5bff5d8, size=1, access_size_min=1, access_size_max=4, access_fn=0x555555e19906 <memory_region_write_accessor>, mr=0x5555580b1440, attrs=...) at ../../qemu/system/memory.c:573
//#8  0x0000555555e1d053 in memory_region_dispatch_write (mr=0x5555580b1440, addr=20, data=15, op=MO_8, attrs=...) at ../../qemu/system/memory.c:1521
//#9  0x0000555555e2b7a0 in flatview_write_continue_step (attrs=..., buf=0x7ffff7f86028 "\017\020", len=1, mr_addr=20, l=0x7ffff5bff6c0, mr=0x5555580b1440) at ../../qemu/system/physmem.c:2713
//#10 0x0000555555e2b870 in flatview_write_continue (fv=0x7ffee0040190, addr=30786325577748, attrs=..., ptr=0x7ffff7f86028, len=1, mr_addr=20, l=1, mr=0x5555580b1440) at ../../qemu/system/physmem.c:2743
//#11 0x0000555555e2b982 in flatview_write (fv=0x7ffee0040190, addr=30786325577748, attrs=..., buf=0x7ffff7f86028, len=1) at ../../qemu/system/physmem.c:2774
//#12 0x0000555555e2bdd0 in address_space_write (as=0x55555704dce0 <address_space_memory>, addr=30786325577748, attrs=..., buf=0x7ffff7f86028, len=1) at ../../qemu/system/physmem.c:2894
//#13 0x0000555555e2be4c in address_space_rw (as=0x55555704dce0 <address_space_memory>, addr=30786325577748, attrs=..., buf=0x7ffff7f86028, len=1, is_write=true) at ../../qemu/system/physmem.c:2904
//#14 0x0000555555e85e36 in kvm_cpu_exec (cpu=0x5555573e72d0) at ../../qemu/accel/kvm/kvm-all.c:2912
//#15 0x0000555555e88eb8 in kvm_vcpu_thread_fn (arg=0x5555573e72d0) at ../../qemu/accel/kvm/kvm-accel-ops.c:50
//#16 0x00005555560b2687 in qemu_thread_start (args=0x5555573f04a0) at ../../qemu/util/qemu-thread-posix.c:541
//#17 0x00007ffff7894ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#18 0x00007ffff7926850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
void event_notifier_set_handler(EventNotifier *e,
                                EventNotifierHandler *handler)
{
    iohandler_init();
    aio_set_event_notifier(iohandler_ctx, e, handler, NULL, NULL);
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

可以看到，其在[**event_notifier_set_handler**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/main-loop.c#L648)中将**eventfd**的文件描述符绑定到**io-handler**任务上，并注册[**virtio_queue_host_notifier_read()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio.c#L3667)为对应的**read**回调函数，即当**kvm内核模块**唤醒等待线程时，**qemu**会执行如下的回调函数
```c
//#0  virtio_net_handle_tx_bh (vdev=0x5555580b8df0, vq=0x5555580ca708) at ../../qemu/hw/net/virtio-net.c:2865
//#1  0x0000555555deb477 in virtio_queue_notify_vq (vq=0x5555580ca708) at ../../qemu/hw/virtio/virtio.c:2268
//#2  0x0000555555deedb0 in virtio_queue_host_notifier_read (n=0x5555580ca77c) at ../../qemu/hw/virtio/virtio.c:3671
//#3  0x00005555560acf67 in aio_dispatch_handler (ctx=0x5555570ea810, node=0x7ffee0c08b20) at ../../qemu/util/aio-posix.c:372
//#4  0x00005555560ad116 in aio_dispatch_handlers (ctx=0x5555570ea810) at ../../qemu/util/aio-posix.c:414
//#5  0x00005555560ad176 in aio_dispatch (ctx=0x5555570ea810) at ../../qemu/util/aio-posix.c:424
//#6  0x00005555560cce95 in aio_ctx_dispatch (source=0x5555570ea810, callback=0x0, user_data=0x0) at ../../qemu/util/async.c:360
//#7  0x00007ffff7b86d3b in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#8  0x00005555560ce520 in glib_pollfds_poll () at ../../qemu/util/main-loop.c:287
//#9  0x00005555560ce5ab in os_host_main_loop_wait (timeout=79205277539000) at ../../qemu/util/main-loop.c:310
//#10 0x00005555560ce6d7 in main_loop_wait (nonblocking=0) at ../../qemu/util/main-loop.c:589
//#11 0x0000555555bd4e54 in qemu_main_loop () at ../../qemu/system/runstate.c:783
//#12 0x0000555555e96f5b in qemu_default_main () at ../../qemu/system/main.c:37
//#13 0x0000555555e96f9c in main (argc=39, argv=0x7fffffffd9e8) at ../../qemu/system/main.c:48
//#14 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffd9e8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#15 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=39, argv=0x7fffffffd9e8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd9d8) at ../csu/libc-start.c:392
//#16 0x000055555586cc95 in _start ()
void virtio_queue_host_notifier_read(EventNotifier *n)
{
    VirtQueue *vq = container_of(n, VirtQueue, host_notifier);
    if (event_notifier_test_and_clear(n)) {
        virtio_queue_notify_vq(vq);
    }
}

int event_notifier_test_and_clear(EventNotifier *e)
{
    int value;
    ssize_t len;
    char buffer[512];

    if (!e->initialized) {
        return 0;
    }

    /* Drain the notify pipe.  For eventfd, only 8 bytes will be read.  */
    value = 0;
    do {
        len = read(e->rfd, buffer, sizeof(buffer));
        value |= (len > 0);
    } while ((len == -1 && errno == EINTR) || len == sizeof(buffer));

    return value;
}

static void virtio_queue_notify_vq(VirtQueue *vq)
{
    if (vq->vring.desc && vq->handle_output) {
        VirtIODevice *vdev = vq->vdev;

        if (unlikely(vdev->broken)) {
            return;
        }

        trace_virtio_queue_notify(vdev, vq - vdev->vq, vq);
        vq->handle_output(vdev, vq);

        if (unlikely(vdev->start_on_kick)) {
            virtio_set_started(vdev, true);
        }
    }
}

static void virtio_net_handle_tx_bh(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    VirtIONetQueue *q = &n->vqs[vq2q(virtio_get_queue_index(vq))];
    ...
    virtio_queue_set_notification(vq, 0);
    qemu_bh_schedule(q->tx_bh);
}

//#0  virtio_net_tx_bh (opaque=0x5555580f06e0) at ../../qemu/hw/net/virtio-net.c:2941
//#1  0x00005555560cc8d9 in aio_bh_call (bh=0x5555580c4380) at ../../qemu/util/async.c:171
//#2  0x00005555560cca00 in aio_bh_poll (ctx=0x5555570f0bf0) at ../../qemu/util/async.c:218
//#3  0x00005555560ad16a in aio_dispatch (ctx=0x5555570f0bf0) at ../../qemu/util/aio-posix.c:423
//#4  0x00005555560cce95 in aio_ctx_dispatch (source=0x5555570f0bf0, callback=0x0, user_data=0x0) at ../../qemu/util/async.c:360
//#5  0x00007ffff7b86d3b in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#6  0x00005555560ce520 in glib_pollfds_poll () at ../../qemu/util/main-loop.c:287
//#7  0x00005555560ce5ab in os_host_main_loop_wait (timeout=0) at ../../qemu/util/main-loop.c:310
//#8  0x00005555560ce6d7 in main_loop_wait (nonblocking=0) at ../../qemu/util/main-loop.c:589
//#9  0x0000555555bd4e54 in qemu_main_loop () at ../../qemu/system/runstate.c:783
//#10 0x0000555555e96f5b in qemu_default_main () at ../../qemu/system/main.c:37
//#11 0x0000555555e96f9c in main (argc=39, argv=0x7fffffffd9e8) at ../../qemu/system/main.c:48
//#12 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffd9e8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#13 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=39, argv=0x7fffffffd9e8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd9d8) at ../csu/libc-start.c:392
//#14 0x000055555586cc95 in _start ()
static void virtio_net_tx_bh(void *opaque)
{
    ...
    ret = virtio_net_flush_tx(q);
    if (ret == -EBUSY || ret == -EINVAL) {
        return; /* Notification re-enable handled by tx_complete or device
                 * broken */
    }
    ...
}
```
在前面[实例化](#实例化)中，其**handle_output**字段在[**virtio_net_add_queue()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2988)中注册为[**virtio_net_handle_tx_bh()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2863)，并将对应的**bottom half**设置为[**virtio_net_tx_timer()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2889)

所以当**kvm内核模块**唤醒等待线程时，[**virtio_queue_host_notifier_read()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio.c#L3667)被回调，并在[**virtio_net_handle_tx_bh()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2863)中唤醒对应的**bottom half**任务，执行[**virtio_net_tx_timer()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2889)最终处理**virtqueue**中传递的数据

#### 通知guest

根据前面[virtio标准](#可用buffer通知)小节可知，一般是Qemu注入对应的MSIx中断来通知**guest**，msix中断通知的示意图如下所示
![msix中断示意图](msi中断示意图.png)

由于**msix中断**涉及中断虚拟化等多方面的内容，这里不详细分析，只简单介绍一下。

**msix中断**是**pci协议**为了绕过较慢的**ioapic**中断处理器直接将设备中断发送到处理速度更快的**lapic**中断处理器的机制。具体来说，**pci设备**根据PCI设置空间的**msix table**中指定的地址(即**lapic**映射到的地址空间)中写入数据，从而触发**lapic**中断。

而qemu模拟了该操作，其**msix table**中指定的地址空间属于**apic设备**，该地址的写由对应**MemoryRegion**的回调函数[**kvm_apic_mem_write()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/i386/kvm/apic.c#L206)处理
```C
//#0  kvm_irqchip_send_msi (s=0x5555570f9160, msg=...) at ../../qemu/accel/kvm/kvm-all.c:1951
//#1  0x0000555555ce262c in kvm_send_msi (msg=0x7fffffff5300) at ../../qemu/hw/i386/kvm/apic.c:193
//#2  0x0000555555ce26d6 in kvm_apic_mem_write (opaque=0x555557276400, addr=4096, data=36, size=4) at ../../qemu/hw/i386/kvm/apic.c:211
//#3  0x0000555555e19a00 in memory_region_write_accessor (mr=0x5555572764a0, addr=4096, value=0x7fffffff5428, size=4, shift=0, mask=4294967295, attrs=...) at ../../qemu/system/memory.c:497
//#4  0x0000555555e19d39 in access_with_adjusted_size (addr=4096, value=0x7fffffff5428, size=4, access_size_min=1, access_size_max=4, access_fn=0x555555e19906 <memory_region_write_accessor>, mr=0x5555572764a0, attrs=...) at ../../qemu/system/memory.c:573
//#5  0x0000555555e1d053 in memory_region_dispatch_write (mr=0x5555572764a0, addr=4096, data=36, op=MO_32, attrs=...) at ../../qemu/system/memory.c:1521
//#6  0x0000555555e2d666 in address_space_stl_internal (as=0x5555580b58e0, addr=4276097024, val=36, attrs=..., result=0x0, endian=DEVICE_LITTLE_ENDIAN) at ../../qemu/system/memory_ldst.c.inc:319
//#7  0x0000555555e2d7c5 in address_space_stl_le (as=0x5555580b58e0, addr=4276097024, val=36, attrs=..., result=0x0) at ../../qemu/system/memory_ldst.c.inc:357
//#8  0x0000555555a96287 in pci_msi_trigger (dev=0x5555580b56a0, msg=...) at ../../qemu/hw/pci/pci.c:364
//#9  0x0000555555a92222 in msi_send_message (dev=0x5555580b56a0, msg=...) at ../../qemu/hw/pci/msi.c:380
//#10 0x0000555555a93f21 in msix_notify (dev=0x5555580b56a0, vector=2) at ../../qemu/hw/pci/msix.c:542
//#11 0x0000555555b6f142 in virtio_pci_notify (d=0x5555580b56a0, vector=2) at ../../qemu/hw/virtio/virtio-pci.c:77
//#12 0x0000555555dea808 in virtio_notify_vector (vdev=0x5555580bdb90, vector=2) at ../../qemu/hw/virtio/virtio.c:2001
//#13 0x0000555555debf63 in virtio_irq (vq=0x5555580e4738) at ../../qemu/hw/virtio/virtio.c:2491
//#14 0x0000555555dec011 in virtio_notify (vdev=0x5555580bdb90, vq=0x5555580e4738) at ../../qemu/hw/virtio/virtio.c:2503
//#15 0x0000555555db2d6b in virtio_net_flush_tx (q=0x5555580cb6f0) at ../../qemu/hw/net/virtio-net.c:2822
//#16 0x0000555555db3271 in virtio_net_tx_bh (opaque=0x5555580cb6f0) at ../../qemu/hw/net/virtio-net.c:2960
//#17 0x00005555560cc8d9 in aio_bh_call (bh=0x5555580c5390) at ../../qemu/util/async.c:171
//#18 0x00005555560cca00 in aio_bh_poll (ctx=0x5555570f0bf0) at ../../qemu/util/async.c:218
//#19 0x00005555560ad16a in aio_dispatch (ctx=0x5555570f0bf0) at ../../qemu/util/aio-posix.c:423
//#20 0x00005555560cce95 in aio_ctx_dispatch (source=0x5555570f0bf0, callback=0x0, user_data=0x0) at ../../qemu/util/async.c:360
//#21 0x00007ffff7b88d3b in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#22 0x00005555560ce520 in glib_pollfds_poll () at ../../qemu/util/main-loop.c:287
//#23 0x00005555560ce5ab in os_host_main_loop_wait (timeout=0) at ../../qemu/util/main-loop.c:310
//#24 0x00005555560ce6d7 in main_loop_wait (nonblocking=0) at ../../qemu/util/main-loop.c:589
//#25 0x0000555555bd4e54 in qemu_main_loop () at ../../qemu/system/runstate.c:783
//#26 0x0000555555e96f5b in qemu_default_main () at ../../qemu/system/main.c:37
//#27 0x0000555555e96f9c in main (argc=39, argv=0x7fffffffdac8) at ../../qemu/system/main.c:48
//#28 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=39, argv=argv@entry=0x7fffffffdac8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#29 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=39, argv=0x7fffffffdac8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdab8) at ../csu/libc-start.c:392
//#30 0x000055555586cc95 in _start ()
static void pci_msi_trigger(PCIDevice *dev, MSIMessage msg)
{
    MemTxAttrs attrs = {};

    /*
     * Xen uses the high bits of the address to contain some of the bits
     * of the PIRQ#. Therefore we can't just send the write cycle and
     * trust that it's caught by the APIC at 0xfee00000 because the
     * target of the write might be e.g. 0x0x1000fee46000 for PIRQ#4166.
     * So we intercept the delivery here instead of in kvm_send_msi().
     */
    if (xen_mode == XEN_EMULATE &&
        xen_evtchn_deliver_pirq_msi(msg.address, msg.data)) {
        return;
    }
    attrs.requester_id = pci_requester_id(dev);
    address_space_stl_le(&dev->bus_master_as, msg.address, msg.data,
                         attrs, NULL);
}

static void kvm_apic_mem_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    MSIMessage msg = { .address = addr, .data = data };

    kvm_send_msi(&msg);
}

static void kvm_send_msi(MSIMessage *msg)
{
    int ret;

    /*
     * The message has already passed through interrupt remapping if enabled,
     * but the legacy extended destination ID in low bits still needs to be
     * handled.
     */
    msg->address = kvm_swizzle_msi_ext_dest_id(msg->address);

    ret = kvm_irqchip_send_msi(kvm_state, *msg);
    ...
}

int kvm_irqchip_send_msi(KVMState *s, MSIMessage msg)
{
    struct kvm_msi msi;

    msi.address_lo = (uint32_t)msg.address;
    msi.address_hi = msg.address >> 32;
    msi.data = le32_to_cpu(msg.data);
    msi.flags = 0;
    memset(msi.pad, 0, sizeof(msi.pad));

    return kvm_vm_ioctl(s, KVM_SIGNAL_MSI, &msi);
}
```
可以看到，最后其通过**ioctl()**，陷入**kvm内核模块**，让**kvm内核模块**根据cpu提供的中断注入接口向**guest**注入中断。

# virtio驱动

这里主要介绍一下**guest驱动**设置virtio组件和数据处理的逻辑

## virtio设置

**guest驱动**主要的任务是申请资源地址空间，并将对应的资源空间按照前面[virtio transport](#virtio-transport)小节的协议传递给**virtio设备**，即通过读写**PCI设置空间**和**virtio配置空间**将资源gpa传递给**virtio设备**

因为**virtio-net-pci设备**即包含**virtio-pci**的**virtio transport**，也包含**virtio-net**的**virtio设备**，因此其由[**virtio_pci_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_common.c#L555)和[**virtnet_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L4624)共同设置，

```c
//#0  virtio_pci_probe (pci_dev=0xffff888100941000, id=0xffffffff82299f00 <virtio_pci_id_table>) at /home/hawk/Desktop/mqemu/kernel/drivers/virtio/virtio_pci_common.c:557
//#1  0xffffffff816050a2 in local_pci_probe (_ddi=_ddi@entry=0xffffc90000013d40) at /home/hawk/Desktop/mqemu/kernel/drivers/pci/pci-driver.c:324
//#2  0xffffffff81605fdd in pci_call_probe (id=<optimized out>, dev=0xffff888100941000, drv=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/drivers/pci/pci-driver.c:392
//#3  __pci_device_probe (pci_dev=0xffff888100941000, drv=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/drivers/pci/pci-driver.c:417
//#4  pci_device_probe (dev=0xffff8881009410c0) at /home/hawk/Desktop/mqemu/kernel/drivers/pci/pci-driver.c:451
//#5  0xffffffff8193dd1c in call_driver_probe (drv=0xffffffff82be1a88 <virtio_pci_driver+104>, dev=0xffff8881009410c0) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:578
//#6  really_probe (dev=dev@entry=0xffff8881009410c0, drv=drv@entry=0xffffffff82be1a88 <virtio_pci_driver+104>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:656
//#7  0xffffffff8193df8e in __driver_probe_device (drv=drv@entry=0xffffffff82be1a88 <virtio_pci_driver+104>, dev=dev@entry=0xffff8881009410c0) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:798
//#8  0xffffffff8193e069 in driver_probe_device (drv=drv@entry=0xffffffff82be1a88 <virtio_pci_driver+104>, dev=dev@entry=0xffff8881009410c0) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:828
//#9  0xffffffff8193e2e5 in __driver_attach (data=0xffffffff82be1a88 <virtio_pci_driver+104>, dev=0xffff8881009410c0) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1214
//#10 __driver_attach (dev=0xffff8881009410c0, data=0xffffffff82be1a88 <virtio_pci_driver+104>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1154
//#11 0xffffffff8193bab7 in bus_for_each_dev (bus=<optimized out>, start=start@entry=0x0 <fixed_percpu_data>, data=data@entry=0xffffffff82be1a88 <virtio_pci_driver+104>, fn=fn@entry=0xffffffff8193e260 <__driver_attach>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/bus.c:368
//#12 0xffffffff8193d6f9 in driver_attach (drv=drv@entry=0xffffffff82be1a88 <virtio_pci_driver+104>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1231
//#13 0xffffffff8193ce97 in bus_add_driver (drv=drv@entry=0xffffffff82be1a88 <virtio_pci_driver+104>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/bus.c:673
//#14 0xffffffff8193f48b in driver_register (drv=0xffffffff82be1a88 <virtio_pci_driver+104>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/driver.c:246
//#15 0xffffffff81001a63 in do_one_initcall (fn=0xffffffff832dfeb0 <virtio_pci_driver_init>) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1238
//#16 0xffffffff8328d1d7 in do_initcall_level (command_line=0xffff88810033a140 "rdinit", level=6) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1300
//#17 do_initcalls () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1316
//#18 do_basic_setup () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1335
//#19 kernel_init_freeable () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1548
//#20 0xffffffff81f657a5 in kernel_init (unused=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1437
//#21 0xffffffff810baddf in ret_from_fork (prev=<optimized out>, regs=0xffffc90000013f58, fn=0xffffffff81f65790 <kernel_init>, fn_arg=0x0 <fixed_percpu_data>) at /home/hawk/Desktop/mqemu/kernel/arch/x86/kernel/process.c:147
//#22 0xffffffff8100244a in ret_from_fork_asm () at /home/hawk/Desktop/mqemu/kernel/arch/x86/entry/entry_64.S:243
//#23 0x0000000000000000 in ?? ()
static int virtio_pci_probe(struct pci_dev *pci_dev,
			    const struct pci_device_id *id)
{
    ...
	rc = virtio_pci_modern_probe(vp_dev);
    ...
}

int virtio_pci_modern_probe(struct virtio_pci_device *vp_dev)
{
    ...
	err = vp_modern_probe(mdev);
    ...
	vp_dev->vdev.config = &virtio_pci_config_ops;
	vp_dev->config_vector = vp_config_vector;
	vp_dev->setup_vq = setup_vq;
	vp_dev->del_vq = del_vq;
	vp_dev->is_avq = vp_is_avq;
	vp_dev->isr = mdev->isr;
    ...
	return 0;
}

int vp_modern_probe(struct virtio_pci_modern_device *mdev)
{
    ...
	/* check for a common config: if not, use legacy mode (bar 0). */
	common = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_COMMON_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);
    ...
	/* If common is there, these should be too... */
	isr = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_ISR_CFG,
					 IORESOURCE_IO | IORESOURCE_MEM,
					 &mdev->modern_bars);
	notify = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_NOTIFY_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);
    ...
	/* Device capability is only mandatory for devices that have
	 * device-specific configuration.
	 */
	device = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_DEVICE_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &mdev->modern_bars);

    ...
	mdev->common = vp_modern_map_capability(mdev, common,
			      sizeof(struct virtio_pci_common_cfg), 4, 0,
			      offsetofend(struct virtio_pci_modern_common_cfg,
					  admin_queue_num),
			      &mdev->common_len, NULL);
    ...
	mdev->isr = vp_modern_map_capability(mdev, isr, sizeof(u8), 1,
					     0, 1,
					     NULL, NULL);

	/* Read notify_off_multiplier from config space. */
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						notify_off_multiplier),
			      &mdev->notify_offset_multiplier);
	/* Read notify length and offset from config space. */
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.length),
			      &notify_length);

	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.offset),
			      &notify_offset);

    ...
	/* We don't know how many VQs we'll map, ahead of the time.
	 * If notify length is small, map it all now.
	 * Otherwise, map each VQ individually later.
	 */
	if ((u64)notify_length + (notify_offset % PAGE_SIZE) <= PAGE_SIZE) {
		mdev->notify_base = vp_modern_map_capability(mdev, notify,
							     2, 2,
							     0, notify_length,
							     &mdev->notify_len,
							     &mdev->notify_pa);
		if (!mdev->notify_base)
			goto err_map_notify;
	} else {
		mdev->notify_map_cap = notify;
	}

	/* Again, we don't know how much we should map, but PAGE_SIZE
	 * is more than enough for all existing devices.
	 */
	if (device) {
		mdev->device = vp_modern_map_capability(mdev, device, 0, 4,
							0, PAGE_SIZE,
							&mdev->device_len,
							NULL);
		if (!mdev->device)
			goto err_map_device;
	}

	return 0;
}
```
根据{% post_link qemu的PCI设备 %}可知，**acpi(Advanced Configuration and Power Interface)**驱动会将**PCI配置空间**设置好，接着这里的[**vp_modern_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_modern_dev.c#L223)会解析**PCI配置空间**(capability)并解析各个**virtio配置空间**。但此时未进行设置，仅仅注册了[**virtio_pci_config_ops**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_modern.c#L800)、[**setup_vq()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_modern.c#L530)和[**vp_config_vector()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_modern.c#L516)的函数指针，等后续[**virtnet_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L4624)继续设置

```c
//#0  virtnet_probe (vdev=0xffff888100953000) at /home/hawk/Desktop/mqemu/kernel/drivers/net/virtio_net.c:4625
//#1  0xffffffff81692f5e in virtio_dev_probe (_d=0xffff888100953010) at /home/hawk/Desktop/mqemu/kernel/drivers/virtio/virtio.c:311
//#2  0xffffffff8193dd1c in call_driver_probe (drv=0xffffffff82c0ffa0 <virtio_net_driver>, dev=0xffff888100953010) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:578
//#3  really_probe (dev=dev@entry=0xffff888100953010, drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:656
//#4  0xffffffff8193df8e in __driver_probe_device (drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>, dev=dev@entry=0xffff888100953010) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:798
//#5  0xffffffff8193e069 in driver_probe_device (drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>, dev=dev@entry=0xffff888100953010) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:828
//#6  0xffffffff8193e2e5 in __driver_attach (data=0xffffffff82c0ffa0 <virtio_net_driver>, dev=0xffff888100953010) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1214
//#7  __driver_attach (dev=0xffff888100953010, data=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1154
//#8  0xffffffff8193bab7 in bus_for_each_dev (bus=<optimized out>, start=start@entry=0x0 <fixed_percpu_data>, data=data@entry=0xffffffff82c0ffa0 <virtio_net_driver>, fn=fn@entry=0xffffffff8193e260 <__driver_attach>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/bus.c:368
//#9  0xffffffff8193d6f9 in driver_attach (drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/dd.c:1231
//#10 0xffffffff8193ce97 in bus_add_driver (drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/bus.c:673
//#11 0xffffffff8193f48b in driver_register (drv=drv@entry=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/base/driver.c:246
//#12 0xffffffff816926bb in register_virtio_driver (driver=driver@entry=0xffffffff82c0ffa0 <virtio_net_driver>) at /home/hawk/Desktop/mqemu/kernel/drivers/virtio/virtio.c:370
//#13 0xffffffff832ea609 in virtio_net_driver_init () at /home/hawk/Desktop/mqemu/kernel/drivers/net/virtio_net.c:5050
//#14 0xffffffff81001a63 in do_one_initcall (fn=0xffffffff832ea580 <virtio_net_driver_init>) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1238
//#15 0xffffffff8328d1d7 in do_initcall_level (command_line=0xffff88810033a140 "rdinit", level=6) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1300
//#16 do_initcalls () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1316
//#17 do_basic_setup () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1335
//#18 kernel_init_freeable () at /home/hawk/Desktop/mqemu/kernel/init/main.c:1548
//#19 0xffffffff81f657a5 in kernel_init (unused=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/init/main.c:1437
//#20 0xffffffff810baddf in ret_from_fork (prev=<optimized out>, regs=0xffffc90000013f58, fn=0xffffffff81f65790 <kernel_init>, fn_arg=0x0 <fixed_percpu_data>) at /home/hawk/Desktop/mqemu/kernel/arch/x86/kernel/process.c:147
//#21 0xffffffff8100244a in ret_from_fork_asm () at /home/hawk/Desktop/mqemu/kernel/arch/x86/entry/entry_64.S:243
//#22 0x0000000000000000 in ?? ()
static int virtnet_probe(struct virtio_device *vdev)
{
    ...
	dev->netdev_ops = &virtnet_netdev;
    ...
	/* Enable multiqueue by default */
	if (num_online_cpus() >= max_queue_pairs)
		vi->curr_queue_pairs = max_queue_pairs;
	else
		vi->curr_queue_pairs = num_online_cpus();
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
    ...
	return 0;
}

static int init_vqs(struct virtnet_info *vi)
{
	int ret;

	/* Allocate send & receive queues */
	ret = virtnet_alloc_queues(vi);
	if (ret)
		goto err;

	ret = virtnet_find_vqs(vi);
	if (ret)
		goto err_free;
    ...
	return 0;
}

static int virtnet_find_vqs(struct virtnet_info *vi)
{
	/* We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by
	 * possible N-1 RX/TX queue pairs used in multiqueue mode, followed by
	 * possible control vq.
	 */
	total_vqs = vi->max_queue_pairs * 2 +
		    virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ);

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
    ...
	ret = virtio_find_vqs_ctx(vi->vdev, total_vqs, vqs, callbacks,
				  names, ctx, NULL);
    ...
}

static inline
int virtio_find_vqs_ctx(struct virtio_device *vdev, unsigned nvqs,
			struct virtqueue *vqs[], vq_callback_t *callbacks[],
			const char * const names[], const bool *ctx,
			struct irq_affinity *desc)
{
	return vdev->config->find_vqs(vdev, nvqs, vqs, callbacks, names, ctx,
				      desc);
}

static int vp_modern_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
			      struct virtqueue *vqs[],
			      vq_callback_t *callbacks[],
			      const char * const names[], const bool *ctx,
			      struct irq_affinity *desc)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtqueue *vq;
	int rc = vp_find_vqs(vdev, nvqs, vqs, callbacks, names, ctx, desc);

	if (rc)
		return rc;

	/* Select and activate all queues. Has to be done last: once we do
	 * this, there's no way to go back except reset.
	 */
	list_for_each_entry(vq, &vdev->vqs, list)
		vp_modern_set_queue_enable(&vp_dev->mdev, vq->index, true);

	return 0;
}

int vp_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
		struct virtqueue *vqs[], vq_callback_t *callbacks[],
		const char * const names[], const bool *ctx,
		struct irq_affinity *desc)
{
	/* Try MSI-X with one vector per queue. */
	err = vp_find_vqs_msix(vdev, nvqs, vqs, callbacks, names, true, ctx, desc);
	if (!err)
		return 0;
    ...
}

static int vp_find_vqs_msix(struct virtio_device *vdev, unsigned int nvqs,
		struct virtqueue *vqs[], vq_callback_t *callbacks[],
		const char * const names[], bool per_vq_vectors,
		const bool *ctx,
		struct irq_affinity *desc)
{
    ...
	allocated_vectors = vp_dev->msix_used_vectors;
	for (i = 0; i < nvqs; ++i) {
        ...
		vqs[i] = vp_setup_vq(vdev, queue_idx++, callbacks[i], names[i],
				     ctx ? ctx[i] : false,
				     msix_vec);
	}
	return 0;
    ...
}

static struct virtqueue *vp_setup_vq(struct virtio_device *vdev, unsigned int index,
				     void (*callback)(struct virtqueue *vq),
				     const char *name,
				     bool ctx,
				     u16 msix_vec)
{
    ...
	vq = vp_dev->setup_vq(vp_dev, info, index, callback, name, ctx,
			      msix_vec);
	info->vq = vq;
    ...
	vp_dev->vqs[index] = info;
	return vq;
    ...
}

static struct virtqueue *setup_vq(struct virtio_pci_device *vp_dev,
				  struct virtio_pci_vq_info *info,
				  unsigned int index,
				  void (*callback)(struct virtqueue *vq),
				  const char *name,
				  bool ctx,
				  u16 msix_vec)
{
    ...
	/* create the vring */
	vq = vring_create_virtqueue(index, num,
				    SMP_CACHE_BYTES, &vp_dev->vdev,
				    true, true, ctx,
				    notify, callback, name);
    ...
	err = vp_active_vq(vq, msix_vec);
    ...
	vq->priv = (void __force *)vp_modern_map_vq_notify(mdev, index, NULL);
    ...
}

static int vp_active_vq(struct virtqueue *vq, u16 msix_vec)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vq->vdev);
	struct virtio_pci_modern_device *mdev = &vp_dev->mdev;
	unsigned long index;

	index = vq->index;

	/* activate the queue */
	vp_modern_set_queue_size(mdev, index, virtqueue_get_vring_size(vq));
	vp_modern_queue_address(mdev, index, virtqueue_get_desc_addr(vq),
				virtqueue_get_avail_addr(vq),
				virtqueue_get_used_addr(vq));

	if (msix_vec != VIRTIO_MSI_NO_VECTOR) {
		msix_vec = vp_modern_queue_vector(mdev, index, msix_vec);
		if (msix_vec == VIRTIO_MSI_NO_VECTOR)
			return -EBUSY;
	}

	return 0;
}

void vp_modern_set_queue_size(struct virtio_pci_modern_device *mdev, u16 index, u16 size)
{
	vp_iowrite16(index, &mdev->common->queue_select);
	vp_iowrite16(size, &mdev->common->queue_size);

}

void vp_modern_queue_address(struct virtio_pci_modern_device *mdev,
			     u16 index, u64 desc_addr, u64 driver_addr,
			     u64 device_addr)
{
	struct virtio_pci_common_cfg __iomem *cfg = mdev->common;

	vp_iowrite16(index, &cfg->queue_select);

	vp_iowrite64_twopart(desc_addr, &cfg->queue_desc_lo,
			     &cfg->queue_desc_hi);
	vp_iowrite64_twopart(driver_addr, &cfg->queue_avail_lo,
			     &cfg->queue_avail_hi);
	vp_iowrite64_twopart(device_addr, &cfg->queue_used_lo,
			     &cfg->queue_used_hi);
}

void vp_modern_set_queue_enable(struct virtio_pci_modern_device *mdev,
				u16 index, bool enable)
{
	vp_iowrite16(index, &mdev->common->queue_select);
	vp_iowrite16(enable, &mdev->common->queue_enable);
}
```
可以看到，这里分配了对应的**virtqueue**数据，并向[**vp_modern_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_pci_modern_dev.c#L223)中解析的**VIRTIO_PCI_CAP_COMMON_CFG配置空间**写入对应的信息，符合前面[virtio设备的virtio组件设置](#virtio组件)部分的分析

## 数据处理

### 数据传输

根据前面[virtio设备的数据传输](#数据传输)章节，由于**guest**的pva就是**qemu**进程空间的**hva**，因此对于**guest**来说，正常访问前面分配的**virtqueue**地址即可和**virtio设备**正常进行数据通信。

这里分析**guest**发送数据的代码来加以确认。在前面[guest的virtio设置](#virtio设置-1)小结简单介绍了[**virtnet_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L4624)，其中其替换了**struct net_device**结构体的**netdev_ops**字段为[**virtnet_netdev**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L4169)，如下所示
```c
static int virtnet_probe(struct virtio_device *vdev)
{
	struct net_device *dev;
    ...
	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE |
			   IFF_TX_SKB_NO_LINEAR;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
    ...
}

static const struct net_device_ops virtnet_netdev = {
	.ndo_open            = virtnet_open,
	.ndo_stop   	     = virtnet_close,
	.ndo_start_xmit      = start_xmit,
	.ndo_validate_addr   = eth_validate_addr,
	.ndo_set_mac_address = virtnet_set_mac_address,
	.ndo_set_rx_mode     = virtnet_set_rx_mode,
	.ndo_get_stats64     = virtnet_stats,
	.ndo_vlan_rx_add_vid = virtnet_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = virtnet_vlan_rx_kill_vid,
	.ndo_bpf		= virtnet_xdp,
	.ndo_xdp_xmit		= virtnet_xdp_xmit,
	.ndo_features_check	= passthru_features_check,
	.ndo_get_phys_port_name	= virtnet_get_phys_port_name,
	.ndo_set_features	= virtnet_set_features,
	.ndo_tx_timeout		= virtnet_tx_timeout,
};
```

其中[**start_xmit**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L2402)就是发送数据包的回调函数，如下所示
```c
//#0  0xffffffff816969a8 in virtqueue_add (gfp=<optimized out>, ctx=<optimized out>, data=<optimized out>, in_sgs=0, out_sgs=1, total_sg=1, sgs=0xffffc90000003b98, _vq=0xffff88810096f900) at /home/hawk/Desktop/mqemu/kernel/drivers/virtio/virtio_ring.c:2209
//#1  virtqueue_add_outbuf (vq=0xffff88810096f900, sg=sg@entry=0xffff888100370808, num=1, data=data@entry=0xffff88801cefb500, gfp=gfp@entry=2080) at /home/hawk/Desktop/mqemu/kernel/drivers/virtio/virtio_ring.c:2267
//#2  0xffffffff819ed584 in xmit_skb (skb=0xffff88801cefb500, sq=0xffff888100370800) at /home/hawk/Desktop/mqemu/kernel/drivers/net/virtio_net.c:2399
//#3  start_xmit (skb=0xffff88801cefb500, dev=0xffff88810793c000) at /home/hawk/Desktop/mqemu/kernel/drivers/net/virtio_net.c:2426
//#4  0xffffffff81c11797 in __netdev_start_xmit (more=false, dev=0xffff88810793c000, skb=0xffff88801cefb500, ops=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/include/linux/netdevice.h:4903
//#5  netdev_start_xmit (more=false, txq=0xffff88810080f200, dev=0xffff88810793c000, skb=0xffff88801cefb500) at /home/hawk/Desktop/mqemu/kernel/include/linux/netdevice.h:4917
//#6  xmit_one (more=false, txq=0xffff88810080f200, dev=0xffff88810793c000, skb=0xffff88801cefb500) at /home/hawk/Desktop/mqemu/kernel/net/core/dev.c:3531
//#7  dev_hard_start_xmit (first=first@entry=0xffff88801cefb500, dev=dev@entry=0xffff88810793c000, txq=txq@entry=0xffff88810080f200, ret=ret@entry=0xffffc90000003c64) at /home/hawk/Desktop/mqemu/kernel/net/core/dev.c:3547
//#8  0xffffffff81c66525 in sch_direct_xmit (skb=skb@entry=0xffff88801cefb500, q=q@entry=0xffff8880289bbc00, dev=dev@entry=0xffff88810793c000, txq=txq@entry=0xffff88810080f200, root_lock=root_lock@entry=0x0 <fixed_percpu_data>, validate=validate@entry=true) at /home/hawk/Desktop/mqemu/kernel/net/sched/sch_generic.c:343
//#9  0xffffffff81c11e7e in __dev_xmit_skb (txq=0xffff88810080f200, dev=0xffff88810793c000, q=0xffff8880289bbc00, skb=0xffff88801cefb500) at /home/hawk/Desktop/mqemu/kernel/net/core/dev.c:3760
//#10 __dev_queue_xmit (skb=skb@entry=0xffff88801cefb500, sb_dev=sb_dev@entry=0x0 <fixed_percpu_data>) at /home/hawk/Desktop/mqemu/kernel/net/core/dev.c:4301
//#11 0xffffffff81d6d34a in dev_queue_xmit (skb=0xffff88801cefb500) at /home/hawk/Desktop/mqemu/kernel/include/linux/netdevice.h:3091
//#12 neigh_hh_output (skb=<optimized out>, hh=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/include/net/neighbour.h:526
//#13 neigh_output (skip_cache=false, skb=0xffff88801cefb500, n=0xffff888028686800) at /home/hawk/Desktop/mqemu/kernel/include/net/neighbour.h:540
//#14 ip6_finish_output2 (net=<optimized out>, sk=<optimized out>, skb=0xffff88801cefb500) at /home/hawk/Desktop/mqemu/kernel/net/ipv6/ip6_output.c:137
//#15 0xffffffff81d949a5 in ndisc_send_skb (skb=0xffff88801cefb500, daddr=<optimized out>, saddr=0xffffc90000003e80) at /home/hawk/Desktop/mqemu/kernel/net/ipv6/ndisc.c:509
//#16 0xffffffff81d97afa in ndisc_send_rs (dev=<optimized out>, saddr=<optimized out>, daddr=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/net/ipv6/ndisc.c:719
//#17 0xffffffff81d7c143 in addrconf_rs_timer (t=0xffff8881070a63b0) at /home/hawk/Desktop/mqemu/kernel/net/ipv6/addrconf.c:4037
//#18 0xffffffff811b64a5 in call_timer_fn (timer=timer@entry=0xffff8881070a63b0, fn=fn@entry=0xffffffff81d7c070 <addrconf_rs_timer>, baseclk=baseclk@entry=4294687232) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:1793
//#19 0xffffffff811b6782 in expire_timers (head=0xffffc90000003f10, base=0xffff88813bc1e1c0) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:1844
//#20 __run_timers (base=0xffff88813bc1e1c0) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:2418
//#21 __run_timer_base (base=0xffff88813bc1e1c0) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:2429
//#22 0xffffffff811b688c in __run_timer_base (base=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:2424
//#23 run_timer_base (index=1) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:2438
//#24 run_timer_softirq (h=<optimized out>) at /home/hawk/Desktop/mqemu/kernel/kernel/time/timer.c:2448
//#25 0xffffffff81f6f6af in __do_softirq () at /home/hawk/Desktop/mqemu/kernel/kernel/softirq.c:554
//#26 0xffffffff8110e814 in invoke_softirq () at /home/hawk/Desktop/mqemu/kernel/kernel/softirq.c:428
//#27 __irq_exit_rcu () at /home/hawk/Desktop/mqemu/kernel/kernel/softirq.c:633
//#28 irq_exit_rcu () at /home/hawk/Desktop/mqemu/kernel/kernel/softirq.c:645
//#29 0xffffffff81f63220 in instr_sysvec_apic_timer_interrupt (regs=0xffffffff82a03de8) at /home/hawk/Desktop/mqemu/kernel/arch/x86/kernel/apic/apic.c:1043
//#30 sysvec_apic_timer_interrupt (regs=0xffffffff82a03de8) at /home/hawk/Desktop/mqemu/kernel/arch/x86/kernel/apic/apic.c:1043
static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct send_queue *sq = &vi->sq[qnum];
    ...
	/* Try to transmit */
	err = xmit_skb(sq, skb);
    ...
}

static int xmit_skb(struct send_queue *sq, struct sk_buff *skb)
{
    ...
	return virtqueue_add_outbuf(sq->vq, sq->sg, num_sg, skb, GFP_ATOMIC);
}

int virtqueue_add_outbuf(struct virtqueue *vq,
			 struct scatterlist *sg, unsigned int num,
			 void *data,
			 gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 1, 0, data, NULL, gfp);
}

static inline int virtqueue_add(struct virtqueue *_vq,
				struct scatterlist *sgs[],
				unsigned int total_sg,
				unsigned int out_sgs,
				unsigned int in_sgs,
				void *data,
				void *ctx,
				gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? virtqueue_add_packed(_vq, sgs, total_sg,
					out_sgs, in_sgs, data, ctx, gfp) :
				 virtqueue_add_split(_vq, sgs, total_sg,
					out_sgs, in_sgs, data, ctx, gfp);
}

static inline int virtqueue_add_split(struct virtqueue *_vq,
				      struct scatterlist *sgs[],
				      unsigned int total_sg,
				      unsigned int out_sgs,
				      unsigned int in_sgs,
				      void *data,
				      void *ctx,
				      gfp_t gfp)
{
    ...
	dma_addr_t addr;

	if (vring_map_one_sg(vq, sg, DMA_TO_DEVICE, &addr))
		goto unmap_release;

	prev = i;
	/* Note that we trust indirect descriptor
	 * table since it use stream DMA mapping.
	 */
	i = virtqueue_add_desc_split(_vq, desc, i, addr, sg->length,
				     VRING_DESC_F_NEXT,
				     indirect);
    ...
}

static inline unsigned int virtqueue_add_desc_split(struct virtqueue *vq,
						    struct vring_desc *desc,
						    unsigned int i,
						    dma_addr_t addr,
						    unsigned int len,
						    u16 flags,
						    bool indirect)
{
	struct vring_virtqueue *vring = to_vvq(vq);
	struct vring_desc_extra *extra = vring->split.desc_extra;
	u16 next;

	desc[i].flags = cpu_to_virtio16(vq->vdev, flags);
	desc[i].addr = cpu_to_virtio64(vq->vdev, addr);
	desc[i].len = cpu_to_virtio32(vq->vdev, len);

	if (!indirect) {
		next = extra[i].next;
		desc[i].next = cpu_to_virtio16(vq->vdev, next);

		extra[i].addr = addr;
		extra[i].len = len;
		extra[i].flags = flags;
	} else
		next = virtio16_to_cpu(vq->vdev, desc[i].next);

	return next;
}
```
这里**virtqueue**就是[**virtnet_probe()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/net/virtio_net.c#L4624)逻辑中绑定的
```c
static int virtnet_find_vqs(struct virtnet_info *vi)
{
    ...
	ret = virtio_find_vqs_ctx(vi->vdev, total_vqs, vqs, callbacks,
				  names, ctx, NULL);
    ...
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].vq = vqs[rxq2vq(i)];
		vi->rq[i].min_buf_len = mergeable_min_buf_len(vi, vi->rq[i].vq);
		vi->sq[i].vq = vqs[txq2vq(i)];
	}
    ...
}
```

可以看到，最后确实是通过[**virtqueue_add()**](https://elixir.bootlin.com/linux/v6.9-rc2/source/drivers/virtio/virtio_ring.c#L2197)向**virtqueue**内存处读写完成数据传输。

### ~~数据通知~~

# 参考

1. [Introduction to VirtIO](https://blogs.oracle.com/linux/post/introduction-to-virtio)
2. [半虚拟化技术 - VIRTIO 简介](https://tinylab.org/virtio-intro/)
3. [Virtual I/O Device (VIRTIO) Version 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
4. [Virtio](http://wiki.osdev.org/Virtio)
5. [Virtqueues and virtio ring: How the data travels](https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels)
6. [【原创】Linux虚拟化KVM-Qemu分析（十一）之virtqueue](https://www.cnblogs.com/LoyenWang/p/14589296.html)
7. [Virtio协议概述](https://www.openeuler.org/zh/blog/yorifang/virtio-spec-overview.html)
8. [VirtIO实现原理——PCI基础](https://blog.csdn.net/huang987246510/article/details/103379926)
9. [qemu-kvm的ioeventfd机制](https://www.cnblogs.com/haiyonghao/p/14440743.html)
10. [qemu-kvm的irqfd机制](https://www.cnblogs.com/haiyonghao/p/14440723.html)
11. [深入分析Linux虚拟化KVM-Qemu之ioeventfd与irqfd](https://www.bilibili.com/read/cv22112391/)
12. [中断虚拟化-内核端(一)](https://www.cnblogs.com/haiyonghao/p/14440424.html)
13. [KVM IO虚拟化](https://blog.csdn.net/home19900111/article/details/128610752)
14. [Qemu/kernel混合模拟](https://richardweiyang-2.gitbook.io/understanding_qemu/00-advance_interrupt_controller/02-qemu_kernel_emulate)
15. [深入理解 MSI/MSI-X 中断和中断虚拟化](http://liujunming.top/pdf/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3MSI-X%E4%B8%AD%E6%96%AD%E5%92%8C%E4%B8%AD%E6%96%AD%E8%99%9A%E6%8B%9F%E5%8C%96.pdf)
