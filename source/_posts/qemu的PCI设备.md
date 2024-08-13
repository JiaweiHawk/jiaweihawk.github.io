---
title: qemu的PCI设备
date: 2024-08-04 12:33:06
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

PCI(Peripheral Component Interconnect)是一种连接电脑主板和外部设备的总线标准，其从1992年提出之后就逐渐取代了其他各种总线，被各种处理器所支持，在x86硬件体系结构中几乎所有设备都以各种形式连接到PCI设备树上。因为，想要更好的了解Qemu设备模拟的细节就需要从PCI入手。

# PCI基础

## PCI总线结构

下图是一个经典的PCI总线架构图
![PCI总线架构图](pci总线架构.png)

可以看到，PCI总线由三个基本组件构成
- PCI设备(PCI device)
    符合[PCI总线标准](https://members.pcisig.com/wg/PCI-SIG/document/download/8237)(这里额外说明一下，PCI标准文档只允许PCI-SIG成员访问，可以尝试用公司邮箱登录访问)的设备就称为PCI设备，其能按照PCI总线标准进行交互。
- PCI总线(PCI bus)
    用以连接多个PCI设备/PCI桥的通信干道
- PCI桥(PCI bridge)
    总线之间的链接枢纽，可以连接CPU与PCI总线、PCI主总线与PCI次总线等

## PCI设备编号

每个PCI设备在系统中的位置由总线编号(Bus Number)、设备编号(Device Number)和功能编号(Function Number)唯一确定

## PCI配置空间

每个PCI设备都有单独的存储空间，被称为PCI配置空间。

操作系统可以通过**pio**命令，通过访问**CONFIG_ADDRESS(0xcf8)**和**CONFIG_DATA(0xcfc)**寄存器来与PCI配置空间进行交互。这两个寄存器都是32bit，其中**CONFIG_ADDRESS**寄存器格式如下所示
![CONFIG_ADDRESS寄存器格式](CONFIG_ADDRESS寄存器格式.png)
- bit31是**CONFIG_DATA**寄存器的使能位
- bit30~24为保留位
- bit23~16为总线编号
- bit15~11为设备编号
- bit10~8为功能编号
- bit7~2为配置空间中32bit寄存器编号
- bit1-0为只读0

而**CONFIG_DATA**寄存器中的值是**CONFIG_ADDRESS**寄存器中指定配置空间内指定寄存器的数值。因此，操作系统与PCI设备配置空间的交互方式为
- 向**CONFIG_ADDRESS**寄存器中写入要读/写的位置
- 从**CONFIG_DATA**寄存器中读/写数据

PCI配置空间有多种格式，其中所有PCI设备的配置空间都有如下的Type 00格式头
![PCI设备配置空间头](PCI设备配置空间头.png)

这里着重说明一下配置空间头的**BAR(Base Address Register)**寄存器，其用来定义该PCI设备占用的地址空间信息，格式如下所示
![BAR格式](BAR格式.png)

# Qemu模拟

根据[PCI总线结构](#PCI总线结构)中的介绍，一个经典的PCI总线包含PCI设备、PCI桥和PCI总线等三部分，则Qemu对这些部分都有相应的模拟。

## PCI桥

实际上，PCI桥也分多种类型，包括PCI-Host桥和PCI-PCI桥等。这里主要介绍PCI-Host桥，即连接CPU与PCI总线。

Qemu使用**PCIHost**对其进行模拟，其**TypeInfo**变量[**pci_host_type_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci_host.c#L257)如下所示
```c
static const TypeInfo pci_host_type_info = {
    .name = TYPE_PCI_HOST_BRIDGE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .abstract = true,
    .class_size = sizeof(PCIHostBridgeClass),
    .instance_size = sizeof(PCIHostState),
    .class_init = pci_host_class_init,
};
```

### 数据结构

Qemu使用[**struct PCIHostBridgeClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_host.h#L53)和[**struct PCIHostState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_host.h#L39)来表征**PCIHost**

#### struct PCIHostBridgeClass

```c
struct PCIHostBridgeClass {
    SysBusDeviceClass parent_class;

    const char *(*root_bus_path)(PCIHostState *, PCIBus *);
};
```

#### struct PCIHostState

```c
struct PCIHostState {
    SysBusDevice busdev;

    MemoryRegion conf_mem;
    MemoryRegion data_mem;
    MemoryRegion mmcfg;
    uint32_t config_reg;
    bool mig_enabled;
    PCIBus *bus;
    bool bypass_iommu;

    QLIST_ENTRY(PCIHostState) next;
};
```
其中**conf_mem**字段是前面[PCI配置空间](#PCI配置空间)中**CONFIG_ADDRESS**地址空间的**MemoryRegion**，**config_reg**是该地址空间的数据。**data_mem**字段是**CONFIG_DATA**地址空间的**MemoryRegion**，而该地址空间是**CONFIG_ADDRESS**指定的设备的配置空间寄存器，自然应当在指定PCI设备的数据结构中而不在这里存储。

### 初始化

由于**PCIHost**仅仅是一个接口类，没有具体内容，这里用**I440FX-PCIHost**进行分析，其**TypeInfo**变量[**i440fx_pcihost_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci-host/i440fx.c#L397)如下所示
```c
static const TypeInfo i440fx_pcihost_info = {
    .name          = TYPE_I440FX_PCI_HOST_BRIDGE,
    .parent        = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(I440FXState),
    .instance_init = i440fx_pcihost_initfn,
    .class_init    = i440fx_pcihost_class_init,
};
```

#### 类初始化

Qemu使用[**i440fx_pcihost_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci-host/i440fx.c#L368)

```c
static void i440fx_pcihost_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIHostBridgeClass *hc = PCI_HOST_BRIDGE_CLASS(klass);

    hc->root_bus_path = i440fx_pcihost_root_bus_path;
    dc->realize = i440fx_pcihost_realize;
    dc->fw_name = "pci";
    device_class_set_props(dc, i440fx_props);
    /* Reason: needs to be wired up by pc_init1 */
    dc->user_creatable = false;

    object_class_property_add(klass, PCI_HOST_PROP_PCI_HOLE_START, "uint32",
                              i440fx_pcihost_get_pci_hole_start,
                              NULL, NULL, NULL);

    object_class_property_add(klass, PCI_HOST_PROP_PCI_HOLE_END, "uint32",
                              i440fx_pcihost_get_pci_hole_end,
                              NULL, NULL, NULL);

    object_class_property_add(klass, PCI_HOST_PROP_PCI_HOLE64_START, "uint64",
                              i440fx_pcihost_get_pci_hole64_start,
                              NULL, NULL, NULL);

    object_class_property_add(klass, PCI_HOST_PROP_PCI_HOLE64_END, "uint64",
                              i440fx_pcihost_get_pci_hole64_end,
                              NULL, NULL, NULL);
}
```
其主要设置了****的**realize**函数指针为[**i440fx_pcihost_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci-host/i440fx.c#L249)

#### 对象初始化

Qemu使用[**i440fx_pcihost_initfn()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci-host/i440fx.c#L368)初始化对象
```c
static void i440fx_pcihost_initfn(Object *obj)
{
    I440FXState *s = I440FX_PCI_HOST_BRIDGE(obj);
    PCIHostState *phb = PCI_HOST_BRIDGE(obj);

    memory_region_init_io(&phb->conf_mem, obj, &pci_host_conf_le_ops, phb,
                          "pci-conf-idx", 4);
    memory_region_init_io(&phb->data_mem, obj, &pci_host_data_le_ops, phb,
                          "pci-conf-data", 4);

    object_property_add_link(obj, PCI_HOST_PROP_RAM_MEM, TYPE_MEMORY_REGION,
                             (Object **) &s->ram_memory,
                             qdev_prop_allow_set_link_before_realize, 0);

    object_property_add_link(obj, PCI_HOST_PROP_PCI_MEM, TYPE_MEMORY_REGION,
                             (Object **) &s->pci_address_space,
                             qdev_prop_allow_set_link_before_realize, 0);

    object_property_add_link(obj, PCI_HOST_PROP_SYSTEM_MEM, TYPE_MEMORY_REGION,
                             (Object **) &s->system_memory,
                             qdev_prop_allow_set_link_before_realize, 0);

    object_property_add_link(obj, PCI_HOST_PROP_IO_MEM, TYPE_MEMORY_REGION,
                             (Object **) &s->io_memory,
                             qdev_prop_allow_set_link_before_realize, 0);
}
```

可以看到，其使用[**pci_host_conf_le_ops**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci_host.c#L202)和[**pci_host_data_le_ops**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci_host.c#L214)初始化了**PCIHost**的**conf_mem**字段和**data_mem**字段，这些回调函数的内容如下所示
```c
const MemoryRegionOps pci_host_conf_be_ops = {
    .read = pci_host_config_read,
    .write = pci_host_config_write,
    .endianness = DEVICE_BIG_ENDIAN,
};

const MemoryRegionOps pci_host_data_le_ops = {
    .read = pci_host_data_read,
    .write = pci_host_data_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void pci_host_config_write(void *opaque, hwaddr addr,
                                  uint64_t val, unsigned len)
{
    PCIHostState *s = opaque;

    PCI_DPRINTF("%s addr " HWADDR_FMT_plx " len %d val %"PRIx64"\n",
                __func__, addr, len, val);
    if (addr != 0 || len != 4) {
        return;
    }
    s->config_reg = val;
}

static uint64_t pci_host_config_read(void *opaque, hwaddr addr,
                                     unsigned len)
{
    PCIHostState *s = opaque;
    uint32_t val = s->config_reg;

    PCI_DPRINTF("%s addr " HWADDR_FMT_plx " len %d val %"PRIx32"\n",
                __func__, addr, len, val);
    return val;
}

static void pci_host_data_write(void *opaque, hwaddr addr,
                                uint64_t val, unsigned len)
{
    PCIHostState *s = opaque;

    if (s->config_reg & (1u << 31))
        pci_data_write(s->bus, s->config_reg | (addr & 3), val, len);
}

static uint64_t pci_host_data_read(void *opaque,
                                   hwaddr addr, unsigned len)
{
    PCIHostState *s = opaque;

    if (!(s->config_reg & (1U << 31))) {
        return 0xffffffff;
    }
    return pci_data_read(s->bus, s->config_reg | (addr & 3), len);
}

void pci_data_write(PCIBus *s, uint32_t addr, uint32_t val, unsigned len)
{
    PCIDevice *pci_dev = pci_dev_find_by_addr(s, addr);
    uint32_t config_addr = addr & (PCI_CONFIG_SPACE_SIZE - 1);

    if (!pci_dev) {
        trace_pci_cfg_write("empty", extract32(addr, 16, 8),
                            extract32(addr, 11, 5), extract32(addr, 8, 3),
                            config_addr, val);
        return;
    }

    pci_host_config_write_common(pci_dev, config_addr, PCI_CONFIG_SPACE_SIZE,
                                 val, len);
}

uint32_t pci_data_read(PCIBus *s, uint32_t addr, unsigned len)
{
    PCIDevice *pci_dev = pci_dev_find_by_addr(s, addr);
    uint32_t config_addr = addr & (PCI_CONFIG_SPACE_SIZE - 1);

    if (!pci_dev) {
        trace_pci_cfg_read("empty", extract32(addr, 16, 8),
                           extract32(addr, 11, 5), extract32(addr, 8, 3),
                           config_addr, ~0x0);
        return ~0x0;
    }

    return pci_host_config_read_common(pci_dev, config_addr,
                                       PCI_CONFIG_SPACE_SIZE, len);
}
```
可以看到，这里就是Qemu模拟的前面[PCI配置空间](#PCI配置空间)中**CONFIG_ADDRESS**和**CONFIG_DATA**的逻辑。但这里未将**MemoryRegion**绑定到对应的地址空间，那只能是在实例化的时候绑定的

#### 实例化

```c
//#0  i440fx_pcihost_realize (dev=0x5555573de800, errp=0x7fffffffd420) at ../../qemu/hw/pci-host/i440fx.c:250
//#1  0x0000555555e9c4f4 in device_set_realized (obj=0x5555573de800, value=true, errp=0x7fffffffd530) at ../../qemu/hw/core/qdev.c:510
//#2  0x0000555555ea7cfb in property_set_bool (obj=0x5555573de800, v=0x5555573dfd30, name=0x5555562f9dd1 "realized", opaque=0x5555570f4510, errp=0x7fffffffd530) at ../../qemu/qom/object.c:2358
//#3  0x0000555555ea5891 in object_property_set (obj=0x5555573de800, name=0x5555562f9dd1 "realized", v=0x5555573dfd30, errp=0x7fffffffd530) at ../../qemu/qom/object.c:1472
//#4  0x0000555555eaa4ca in object_property_set_qobject (obj=0x5555573de800, name=0x5555562f9dd1 "realized", value=0x5555573dfa50, errp=0x555557061f60 <error_fatal>) at ../../qemu/qom/qom-qobject.c:28
//#5  0x0000555555ea5c4a in object_property_set_bool (obj=0x5555573de800, name=0x5555562f9dd1 "realized", value=true, errp=0x555557061f60 <error_fatal>) at ../../qemu/qom/object.c:1541
//#6  0x0000555555e9bc0e in qdev_realize (dev=0x5555573de800, bus=0x555557360240, errp=0x555557061f60 <error_fatal>) at ../../qemu/hw/core/qdev.c:292
//#7  0x0000555555e9bc47 in qdev_realize_and_unref (dev=0x5555573de800, bus=0x555557360240, errp=0x555557061f60 <error_fatal>) at ../../qemu/hw/core/qdev.c:299
//#8  0x0000555555966b7a in sysbus_realize_and_unref (dev=0x5555573de800, errp=0x555557061f60 <error_fatal>) at ../../qemu/hw/core/sysbus.c:261
//#9  0x0000555555cb292b in pc_init1 (machine=0x555557357800, pci_type=0x5555562ab7db "i440FX") at ../../qemu/hw/i386/pc_piix.c:212
//#10 0x0000555555cb35e3 in pc_init_v9_0 (machine=0x555557357800) at ../../qemu/hw/i386/pc_piix.c:523
//#11 0x000055555595f8be in machine_run_board_init (machine=0x555557357800, mem_path=0x0, errp=0x7fffffffd810) at ../../qemu/hw/core/machine.c:1547
//#12 0x0000555555bdbc78 in qemu_init_board () at ../../qemu/system/vl.c:2613
//#13 0x0000555555bdbf87 in qmp_x_exit_preconfig (errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:2705
//#14 0x0000555555bde944 in qemu_init (argc=35, argv=0x7fffffffdb48) at ../../qemu/system/vl.c:3739
//#15 0x0000555555e96f93 in main (argc=35, argv=0x7fffffffdb48) at ../../qemu/system/main.c:47
//#16 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffdb48) at ../sysdeps/nptl/libc_start_call_main.h:58
//#17 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffdb48, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb38) at ../csu/libc-start.c:392
//#18 0x000055555586cc95 in _start ()
static void i440fx_pcihost_realize(DeviceState *dev, Error **errp)
{
    ERRP_GUARD();
    I440FXState *s = I440FX_PCI_HOST_BRIDGE(dev);
    PCIHostState *phb = PCI_HOST_BRIDGE(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    PCIBus *b;
    PCIDevice *d;
    PCII440FXState *f;
    unsigned i;

    memory_region_add_subregion(s->io_memory, 0xcf8, &phb->conf_mem);
    sysbus_init_ioports(sbd, 0xcf8, 4);

    memory_region_add_subregion(s->io_memory, 0xcfc, &phb->data_mem);
    sysbus_init_ioports(sbd, 0xcfc, 4);

    /* register i440fx 0xcf8 port as coalesced pio */
    memory_region_set_flush_coalesced(&phb->data_mem);
    memory_region_add_coalescing(&phb->conf_mem, 0, 4);

    b = pci_root_bus_new(dev, NULL, s->pci_address_space,
                         s->io_memory, 0, TYPE_PCI_BUS);
    phb->bus = b;

    d = pci_create_simple(b, 0, s->pci_type);
    f = I440FX_PCI_DEVICE(d);

    range_set_bounds(&s->pci_hole, s->below_4g_mem_size,
                     IO_APIC_DEFAULT_ADDRESS - 1);

    /* setup pci memory mapping */
    pc_pci_as_mapping_init(s->system_memory, s->pci_address_space);

    /* if *disabled* show SMRAM to all CPUs */
    memory_region_init_alias(&f->smram_region, OBJECT(d), "smram-region",
                             s->pci_address_space, SMRAM_C_BASE, SMRAM_C_SIZE);
    memory_region_add_subregion_overlap(s->system_memory, SMRAM_C_BASE,
                                        &f->smram_region, 1);
    memory_region_set_enabled(&f->smram_region, true);

    /* smram, as seen by SMM CPUs */
    memory_region_init(&f->smram, OBJECT(d), "smram", 4 * GiB);
    memory_region_set_enabled(&f->smram, true);
    memory_region_init_alias(&f->low_smram, OBJECT(d), "smram-low",
                             s->ram_memory, SMRAM_C_BASE, SMRAM_C_SIZE);
    memory_region_set_enabled(&f->low_smram, true);
    memory_region_add_subregion(&f->smram, SMRAM_C_BASE, &f->low_smram);
    object_property_add_const_link(qdev_get_machine(), "smram",
                                   OBJECT(&f->smram));

    init_pam(&f->pam_regions[0], OBJECT(d), s->ram_memory, s->system_memory,
             s->pci_address_space, PAM_BIOS_BASE, PAM_BIOS_SIZE);
    for (i = 0; i < ARRAY_SIZE(f->pam_regions) - 1; ++i) {
        init_pam(&f->pam_regions[i + 1], OBJECT(d), s->ram_memory,
                 s->system_memory, s->pci_address_space,
                 PAM_EXPAN_BASE + i * PAM_EXPAN_SIZE, PAM_EXPAN_SIZE);
    }

    ram_addr_t ram_size = s->below_4g_mem_size + s->above_4g_mem_size;
    ram_size = ram_size / 8 / 1024 / 1024;
    if (ram_size > 255) {
        ram_size = 255;
    }
    d->config[I440FX_COREBOOT_RAM_SIZE] = ram_size;

    i440fx_update_memory_mappings(f);
}
```
可以看到，确实如前面[对象初始化](#对象初始化)中分析的，是在实例化中绑定的**MemoryRegion**

## PCI总线

根据前面[PCI设备编号](#PCI设备编号)可知，由总线编号、设备编号和功能编号可唯一确定一个PCI设备，则PCI总线需要模拟该功能，即通过这些信息能唯一定位一个PCI设备

Qemu中表示PCI总线的**TypeInfo**变量[**struct pci_bus_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci.c#L219)如下所示
```c
static const TypeInfo pci_bus_info = {
    .name = TYPE_PCI_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(PCIBus),
    .class_size = sizeof(PCIBusClass),
    .class_init = pci_bus_class_init,
};
```

### 数据结构

Qemu使用[**struct PCIBusClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_bus.h#L13)和[**struct PCIBus**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_bus.h#L33)来表征PCI总线

#### struct PCIBusClass

```c
/*
 * PCI Bus datastructures.
 *
 * Do not access the following members directly;
 * use accessor functions in pci.h
 */

struct PCIBusClass {
    /*< private >*/
    BusClass parent_class;
    /*< public >*/

    int (*bus_num)(PCIBus *bus);
    uint16_t (*numa_node)(PCIBus *bus);
};
```
其主要包含一些成员变量的访问函数

#### struct PCIBus

```c
struct PCIBus {
    BusState qbus;
    enum PCIBusFlags flags;
    const PCIIOMMUOps *iommu_ops;
    void *iommu_opaque;
    uint8_t devfn_min;
    uint32_t slot_reserved_mask;
    pci_set_irq_fn set_irq;
    pci_map_irq_fn map_irq;
    pci_route_irq_fn route_intx_to_irq;
    void *irq_opaque;
    PCIDevice *devices[PCI_SLOT_MAX * PCI_FUNC_MAX];
    PCIDevice *parent_dev;
    MemoryRegion *address_space_mem;
    MemoryRegion *address_space_io;

    QLIST_HEAD(, PCIBus) child; /* this will be replaced by qdev later */
    QLIST_ENTRY(PCIBus) sibling;/* this will be replaced by qdev later */

    /* The bus IRQ state is the logical OR of the connected devices.
       Keep a count of the number of devices with raised IRQs.  */
    int nirq;
    int *irq_count;

    Notifier machine_done;
};
```
其除了保存挂载的设备**devices**外，还记录了子总线**child**

### 初始化

根据[pci总线](#PCI总线)中的**pci_bus_info**可知，PCI总线只有[**pci_bus_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci/pci.c#L201)来进行对象初始化。

#### 对象初始化

```c
static void pci_bus_class_init(ObjectClass *klass, void *data)
{
    BusClass *k = BUS_CLASS(klass);
    PCIBusClass *pbc = PCI_BUS_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    k->print_dev = pcibus_dev_print;
    k->get_dev_path = pcibus_get_dev_path;
    k->get_fw_dev_path = pcibus_get_fw_dev_path;
    k->realize = pci_bus_realize;
    k->unrealize = pci_bus_unrealize;

    rc->phases.hold = pcibus_reset_hold;

    pbc->bus_num = pcibus_num;
    pbc->numa_node = pcibus_numa_node;
}
```
可以看到，其主要初始化了相关的函数指针，而这些函数指针会用于定位PCI设备，如下所示
```c
/*
 * PCI address
 * bit 16 - 24: bus number
 * bit  8 - 15: devfun number
 * bit  0 -  7: offset in configuration space of a given pci device
 */

/* the helper function to get a PCIDevice* for a given pci address */
static inline PCIDevice *pci_dev_find_by_addr(PCIBus *bus, uint32_t addr)
{
    uint8_t bus_num = addr >> 16;
    uint8_t devfn = addr >> 8;

    return pci_find_device(bus, bus_num, devfn);
}

PCIDevice *pci_find_device(PCIBus *bus, int bus_num, uint8_t devfn)
{
    bus = pci_find_bus_nr(bus, bus_num);

    if (!bus)
        return NULL;

    return bus->devices[devfn];
}

PCIBus *pci_find_bus_nr(PCIBus *bus, int bus_num)
{
    PCIBus *sec;

    if (!bus) {
        return NULL;
    }

    if (pci_bus_num(bus) == bus_num) {
        return bus;
    }

    /* Consider all bus numbers in range for the host pci bridge. */
    if (!pci_bus_is_root(bus) &&
        !pci_secondary_bus_in_range(bus->parent_dev, bus_num)) {
        return NULL;
    }

    /* try child bus */
    for (; bus; bus = sec) {
        QLIST_FOREACH(sec, &bus->child, sibling) {
            if (pci_bus_num(sec) == bus_num) {
                return sec;
            }
            /* PXB buses assumed to be children of bus 0 */
            if (pci_bus_is_root(sec)) {
                if (pci_root_bus_in_range(sec, bus_num)) {
                    break;
                }
            } else {
                if (pci_secondary_bus_in_range(sec->parent_dev, bus_num)) {
                    break;
                }
            }
        }
    }

    return NULL;
}

int pci_bus_num(PCIBus *s)
{
    return PCI_BUS_GET_CLASS(s)->bus_num(s);
}
```

## PCI设备

这里就以**e1000**为例，通过分析其代码来学习Qemu对于PCI设备的模拟逻辑

根据[*e1000_register_types()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1763)的逻辑，其**struct TypeInfo**如下所示
```c
static const TypeInfo device_type_info = {
    .name = TYPE_DEVICE,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(DeviceState),
    .instance_init = device_initfn,
    .instance_post_init = device_post_init,
    .instance_finalize = device_finalize,
    .class_base_init = device_class_base_init,
    .class_init = device_class_init,
    .abstract = true,
    .class_size = sizeof(DeviceClass),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_VMSTATE_IF },
        { TYPE_RESETTABLE_INTERFACE },
        { }
    }
};

static const TypeInfo pci_device_type_info = {
    .name = TYPE_PCI_DEVICE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(PCIDevice),
    .abstract = true,
    .class_size = sizeof(PCIDeviceClass),
    .class_init = pci_device_class_init,
    .class_base_init = pci_device_class_base_init,
};

static const TypeInfo e1000_base_info = {
    .name          = TYPE_E1000_BASE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .instance_init = e1000_instance_init,
    .class_size    = sizeof(E1000BaseClass),
    .abstract      = true,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static const TypeInfo = {
    .name          = "e1000",
    .parent        = TYPE_E1000_BASE,
    .class_data    = &e1000_devices[0],
    .class_init    = e1000_class_init,
};
```

### 数据结构

可以看到，虽然**e1000**的Typeinfo信息很少，没有指明对应的类和对象的数据结构。但**QOM**会在初始化类时将父类的相关信息填充到当前的**TypeImpl**中，如下所示
```c
static size_t type_class_get_size(TypeImpl *ti)
{
    if (ti->class_size) {
        return ti->class_size;
    }

    if (type_has_parent(ti)) {
        return type_class_get_size(type_get_parent(ti));
    }

    return sizeof(ObjectClass);
}

static void type_initialize(TypeImpl *ti)
{
    ti->class_size = type_class_get_size(ti);
    ...
    ti->class = g_malloc0(ti->class_size);
    ...
}
```

因此，实际上**e1000**就是在使用**e1000_base_info**中说明的[**E1000State**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L80)和[**E1000BaseClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L146)来表征**e1000**，如下的gdb结果也证实了
```c
//pwndbg> bt
//#0  e1000_instance_init (obj=0x7ffff587d010) at ../../qemu/hw/net/e1000.c:1723
//#1  0x0000555555ea30e0 in object_init_with_type (obj=0x7ffff587d010, ti=0x55555709bc20) at ../../qemu/qom/object.c:429
//#2  0x0000555555ea30c2 in object_init_with_type (obj=0x7ffff587d010, ti=0x55555709be00) at ../../qemu/qom/object.c:425
//#3  0x0000555555ea36a6 in object_initialize_with_type (obj=0x7ffff587d010, size=208592, type=0x55555709be00) at ../../qemu/qom/object.c:571
//#4  0x0000555555ea3e75 in object_new_with_type (type=0x55555709be00) at ../../qemu/qom/object.c:791
//#5  0x0000555555ea3eb1 in object_new_with_class (klass=0x5555572bc2d0) at ../../qemu/qom/object.c:799
//#6  0x0000555555c3d234 in qemu_get_nic_models (device_type=0x55555623a47a "pci-device") at ../../qemu/net/net.c:968
//#7  0x0000555555c3db78 in qemu_create_nic_bus_devices (bus=0x5555574157d0, parent_type=0x55555623a47a "pci-device", default_model=0x5555562ab765 "e1000", alias=0x55555623b21d "virtio", alias_target=0x55555623b20e "virtio-net-pci") at ../../qemu/net/net.c:1188
//#8  0x0000555555a9a0da in pci_init_nic_devices (bus=0x5555574157d0, default_model=0x5555562ab765 "e1000") at ../../qemu/hw/pci/pci.c:1861
//#9  0x0000555555cd3d69 in pc_nic_init (pcmc=0x5555572bb030, isa_bus=0x555557163a00, pci_bus=0x5555574157d0) at ../../qemu/hw/i386/pc.c:1283
//#10 0x0000555555cb2ed4 in pc_init1 (machine=0x555557357800, pci_type=0x5555562ab7db "i440FX") at ../../qemu/hw/i386/pc_piix.c:323
//#11 0x0000555555cb35e3 in pc_init_v9_0 (machine=0x555557357800) at ../../qemu/hw/i386/pc_piix.c:523
//#12 0x000055555595f8be in machine_run_board_init (machine=0x555557357800, mem_path=0x0, errp=0x7fffffffd820) at ../../qemu/hw/core/machine.c:1547
//#13 0x0000555555bdbc78 in qemu_init_board () at ../../qemu/system/vl.c:2613
//#14 0x0000555555bdbf87 in qmp_x_exit_preconfig (errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:2705
//#15 0x0000555555bde944 in qemu_init (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/vl.c:3739
//#16 0x0000555555e96f93 in main (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/main.c:47
//#17 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffdb58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#18 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffdb58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb48) at ../csu/libc-start.c:392
//#19 0x000055555586cc95 in _start ()
//pwndbg> p *ti
//$8 = {
//  name = 0x55555709bf80 "e1000",
//  class_size = 240,
//  instance_size = 208592,
//  instance_align = 0,
//  class_init = 0x555555a0fa01 <e1000_class_init>,
//  class_base_init = 0x0,
//  class_data = 0x555556dfa700 <e1000_devices>,
//  instance_init = 0x0,
//  instance_post_init = 0x0,
//  instance_finalize = 0x0,
//  abstract = false,
//  parent = 0x55555709bfa0 "e1000-base",
//  parent_type = 0x55555709bc20,
//  class = 0x5555572bc2d0,
//  num_interfaces = 0,
//  interfaces = {{
//      typename = 0x0
//    } <repeats 32 times>}
//}
//pwndbg> p sizeof(E1000State)
//$9 = 208592
//pwndbg> p sizeof(E1000BaseClass)
//$10 = 240
```

#### E1000BaseClass

```c
/**
 * struct DeviceClass - The base class for all devices.
 * @props: Properties accessing state fields.
 * @realize: Callback function invoked when the #DeviceState:realized
 * property is changed to %true.
 * @unrealize: Callback function invoked when the #DeviceState:realized
 * property is changed to %false.
 * @hotpluggable: indicates if #DeviceClass is hotpluggable, available
 * as readonly "hotpluggable" property of #DeviceState instance
 *
 */
struct DeviceClass {
    /* private: */
    ObjectClass parent_class;

    /* public: */

    /**
     * @categories: device categories device belongs to
     */
    DECLARE_BITMAP(categories, DEVICE_CATEGORY_MAX);
    /**
     * @fw_name: name used to identify device to firmware interfaces
     */
    const char *fw_name;
    /**
     * @desc: human readable description of device
     */
    const char *desc;

    /**
     * @props_: properties associated with device, should only be
     * assigned by using device_class_set_props(). The underscore
     * ensures a compile-time error if someone attempts to assign
     * dc->props directly.
     */
    Property *props_;

    /**
     * @user_creatable: Can user instantiate with -device / device_add?
     *
     * All devices should support instantiation with device_add, and
     * this flag should not exist.  But we're not there, yet.  Some
     * devices fail to instantiate with cryptic error messages.
     * Others instantiate, but don't work.  Exposing users to such
     * behavior would be cruel; clearing this flag will protect them.
     * It should never be cleared without a comment explaining why it
     * is cleared.
     *
     * TODO remove once we're there
     */
    bool user_creatable;
    bool hotpluggable;

    /* callbacks */
    /**
     * @reset: deprecated device reset method pointer
     *
     * Modern code should use the ResettableClass interface to
     * implement a multi-phase reset.
     *
     * TODO: remove once every reset callback is unused
     */
    DeviceReset reset;
    DeviceRealize realize;
    DeviceUnrealize unrealize;

    /**
     * @vmsd: device state serialisation description for
     * migration/save/restore
     */
    const VMStateDescription *vmsd;

    /**
     * @bus_type: bus type
     * private: to qdev / bus.
     */
    const char *bus_type;
};

struct PCIDeviceClass {
    DeviceClass parent_class;

    void (*realize)(PCIDevice *dev, Error **errp);
    PCIUnregisterFunc *exit;
    PCIConfigReadFunc *config_read;
    PCIConfigWriteFunc *config_write;

    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t revision;
    uint16_t class_id;
    uint16_t subsystem_vendor_id;       /* only for header type = 0 */
    uint16_t subsystem_id;              /* only for header type = 0 */

    const char *romfile;                /* rom bar */
};

struct E1000BaseClass {
    PCIDeviceClass parent_class;
    uint16_t phy_id2;
};
```
这里除了父类外，没有太多与**PCI设备**相关的内容。

#### E1000State

```c
/**
 * struct DeviceState - common device state, accessed with qdev helpers
 *
 * This structure should not be accessed directly.  We declare it here
 * so that it can be embedded in individual device state structures.
 */
struct DeviceState {
    /* private: */
    Object parent_obj;
    /* public: */

    /**
     * @id: global device id
     */
    char *id;
    /**
     * @canonical_path: canonical path of realized device in the QOM tree
     */
    char *canonical_path;
    /**
     * @realized: has device been realized?
     */
    bool realized;
    /**
     * @pending_deleted_event: track pending deletion events during unplug
     */
    bool pending_deleted_event;
    /**
     * @pending_deleted_expires_ms: optional timeout for deletion events
     */
    int64_t pending_deleted_expires_ms;
    /**
     * @opts: QDict of options for the device
     */
    QDict *opts;
    /**
     * @hotplugged: was device added after PHASE_MACHINE_READY?
     */
    int hotplugged;
    /**
     * @allow_unplug_during_migration: can device be unplugged during migration
     */
    bool allow_unplug_during_migration;
    /**
     * @parent_bus: bus this device belongs to
     */
    BusState *parent_bus;
    /**
     * @gpios: QLIST of named GPIOs the device provides.
     */
    NamedGPIOListHead gpios;
    /**
     * @clocks: QLIST of named clocks the device provides.
     */
    NamedClockListHead clocks;
    /**
     * @child_bus: QLIST of child buses
     */
    BusStateHead child_bus;
    /**
     * @num_child_bus: number of @child_bus entries
     */
    int num_child_bus;
    /**
     * @instance_id_alias: device alias for handling legacy migration setups
     */
    int instance_id_alias;
    /**
     * @alias_required_for_version: indicates @instance_id_alias is
     * needed for migration
     */
    int alias_required_for_version;
    /**
     * @reset: ResettableState for the device; handled by Resettable interface.
     */
    ResettableState reset;
    /**
     * @unplug_blockers: list of reasons to block unplugging of device
     */
    GSList *unplug_blockers;
    /**
     * @mem_reentrancy_guard: Is the device currently in mmio/pio/dma?
     *
     * Used to prevent re-entrancy confusing things.
     */
    MemReentrancyGuard mem_reentrancy_guard;
};

struct PCIDevice {
    DeviceState qdev;
    bool partially_hotplugged;
    bool has_power;

    /* PCI config space */
    uint8_t *config;

    /*
     * Used to enable config checks on load. Note that writable bits are
     * never checked even if set in cmask.
     */
    uint8_t *cmask;

    /* Used to implement R/W bytes */
    uint8_t *wmask;

    /* Used to implement RW1C(Write 1 to Clear) bytes */
    uint8_t *w1cmask;

    /* Used to allocate config space for capabilities. */
    uint8_t *used;

    /* the following fields are read only */
    int32_t devfn;
    /*
     * Cached device to fetch requester ID from, to avoid the PCI tree
     * walking every time we invoke PCI request (e.g., MSI). For
     * conventional PCI root complex, this field is meaningless.
     */
    PCIReqIDCache requester_id_cache;
    char name[64];
    PCIIORegion io_regions[PCI_NUM_REGIONS];
    AddressSpace bus_master_as;
    MemoryRegion bus_master_container_region;
    MemoryRegion bus_master_enable_region;

    /* do not access the following fields */
    PCIConfigReadFunc *config_read;
    PCIConfigWriteFunc *config_write;

    /* Legacy PCI VGA regions */
    MemoryRegion *vga_regions[QEMU_PCI_VGA_NUM_REGIONS];
    bool has_vga;

    /* Current IRQ levels.  Used internally by the generic PCI code.  */
    uint8_t irq_state;

    /* Capability bits */
    uint32_t cap_present;

    /* Offset of MSI-X capability in config space */
    uint8_t msix_cap;

    /* MSI-X entries */
    int msix_entries_nr;

    /* Space to store MSIX table & pending bit array */
    uint8_t *msix_table;
    uint8_t *msix_pba;

    /* May be used by INTx or MSI during interrupt notification */
    void *irq_opaque;

    MSITriggerFunc *msi_trigger;
    MSIPrepareMessageFunc *msi_prepare_message;
    MSIxPrepareMessageFunc *msix_prepare_message;

    /* MemoryRegion container for msix exclusive BAR setup */
    MemoryRegion msix_exclusive_bar;
    /* Memory Regions for MSIX table and pending bit entries. */
    MemoryRegion msix_table_mmio;
    MemoryRegion msix_pba_mmio;
    /* Reference-count for entries actually in use by driver. */
    unsigned *msix_entry_used;
    /* MSIX function mask set or MSIX disabled */
    bool msix_function_masked;
    /* Version id needed for VMState */
    int32_t version_id;

    /* Offset of MSI capability in config space */
    uint8_t msi_cap;

    /* PCI Express */
    PCIExpressDevice exp;

    /* SHPC */
    SHPCDevice *shpc;

    /* Location of option rom */
    char *romfile;
    uint32_t romsize;
    bool has_rom;
    MemoryRegion rom;
    uint32_t rom_bar;

    /* INTx routing notifier */
    PCIINTxRoutingNotifier intx_routing_notifier;

    /* MSI-X notifiers */
    MSIVectorUseNotifier msix_vector_use_notifier;
    MSIVectorReleaseNotifier msix_vector_release_notifier;
    MSIVectorPollNotifier msix_vector_poll_notifier;

    /* ID of standby device in net_failover pair */
    char *failover_pair_id;
    uint32_t acpi_index;
};

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows, Linux, and OS X <= 10.8
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  E1000_DEV_ID_82545EM_COPPER works with Linux and OS X >= 10.6
 *  Others never tested
 */

struct E1000State_st {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[0x8000];
    uint16_t phy_reg[0x20];
    uint16_t eeprom_data[64];

    uint32_t rxbuf_size;
    uint32_t rxbuf_min_shift;
    struct e1000_tx {
        unsigned char header[256];
        unsigned char vlan_header[4];
        /* Fields vlan and data must not be reordered or separated. */
        unsigned char vlan[4];
        unsigned char data[0x10000];
        uint16_t size;
        unsigned char vlan_needed;
        unsigned char sum_needed;
        bool cptse;
        e1000x_txd_props props;
        e1000x_txd_props tso_props;
        uint16_t tso_frames;
        bool busy;
    } tx;

    struct {
        uint32_t val_in;    /* shifted in from guest driver */
        uint16_t bitnum_in;
        uint16_t bitnum_out;
        uint16_t reading;
        uint32_t old_eecd;
    } eecd_state;

    QEMUTimer *autoneg_timer;

    QEMUTimer *mit_timer;      /* Mitigation timer. */
    bool mit_timer_on;         /* Mitigation timer is running. */
    bool mit_irq_level;        /* Tracks interrupt pin level. */
    uint32_t mit_ide;          /* Tracks E1000_TXD_CMD_IDE bit. */

    QEMUTimer *flush_queue_timer;

/* Compatibility flags for migration to/from qemu 1.3.0 and older */
#define E1000_FLAG_MAC_BIT 2
#define E1000_FLAG_TSO_BIT 3
#define E1000_FLAG_VET_BIT 4
#define E1000_FLAG_MAC (1 << E1000_FLAG_MAC_BIT)
#define E1000_FLAG_TSO (1 << E1000_FLAG_TSO_BIT)
#define E1000_FLAG_VET (1 << E1000_FLAG_VET_BIT)

    uint32_t compat_flags;
    bool received_tx_tso;
    bool use_tso_for_migration;
    e1000x_txd_props mig_props;
};
```
其**mmio**和**io**的MemoryRegion就是前面[pci配置空间](#PCI配置空间)中的**BAR**，其**parent_obj**中的**config**则是前面[pci配置空间](#PCI配置空间)的配置头

### 初始化

#### 类初始化

**e1000**使用[**e1000_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1698)初始化类
```c
//#0  e1000_class_init (klass=0x555557242140, data=0x555556dfa710 <e1000_devices+16>) at ../../qemu/hw/net/e1000.c:1700
//#1  0x0000555555ea306a in type_initialize (ti=0x55555709bfc0) at ../../qemu/qom/object.c:418
//#2  0x0000555555ea4a1d in object_class_foreach_tramp (key=0x55555709c140, value=0x55555709bfc0, opaque=0x7fffffffd7a0) at ../../qemu/qom/object.c:1133
//#3  0x00007ffff7b6c6b8 in g_hash_table_foreach () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#4  0x0000555555ea4b0d in object_class_foreach (fn=0x555555ea4c98 <object_class_get_list_tramp>, implements_type=0x555556279512 "machine", include_abstract=false, opaque=0x7fffffffd7f0) at ../../qemu/qom/object.c:1155
//#5  0x0000555555ea4d26 in object_class_get_list (implements_type=0x555556279512 "machine", include_abstract=false) at ../../qemu/qom/object.c:1212
//#6  0x0000555555bd9434 in select_machine (qdict=0x5555570ebce0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:1661
//#7  0x0000555555bda5fd in qemu_create_machine (qdict=0x5555570ebce0) at ../../qemu/system/vl.c:2101
//#8  0x0000555555bde7b1 in qemu_init (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/vl.c:3664
//#9  0x0000555555e96f93 in main (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/main.c:47
//#10 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffdb58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffdb58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb48) at ../csu/libc-start.c:392
//#12 0x000055555586cc95 in _start ()
static void e1000_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    E1000BaseClass *e = E1000_CLASS(klass);
    const E1000Info *info = data;

    k->realize = pci_e1000_realize;
    k->exit = pci_e1000_uninit;
    k->romfile = "efi-e1000.rom";
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = info->device_id;
    k->revision = info->revision;
    e->phy_id2 = info->phy_id2;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    rc->phases.hold = e1000_reset_hold;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Intel Gigabit Ethernet";
    dc->vmsd = &vmstate_e1000;
    device_class_set_props(dc, e1000_properties);
}
```
可以看到，其在[**object_class_foreach()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1148)初始化所有注册的类时，初始化了**PCIDeviceClass**父类相关字段，并设置了实例化函数指针。

#### 对象初始化

根据前面[数据结构](#数据结构-2)，虽然**e1000**的**struct TypeInfo**并未设置对象初始化函数，但**QOM**会使用其父类的对象初始化函数[e1000_instance_init()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1721)
```c
//#0  e1000_instance_init (obj=0x5555580d01f0) at ../../qemu/hw/net/e1000.c:1723
//#1  0x0000555555ea30e0 in object_init_with_type (obj=0x5555580d01f0, ti=0x55555709bc20) at ../../qemu/qom/object.c:429
//#2  0x0000555555ea30c2 in object_init_with_type (obj=0x5555580d01f0, ti=0x55555709be00) at ../../qemu/qom/object.c:425
//#3  0x0000555555ea36a6 in object_initialize_with_type (obj=0x5555580d01f0, size=208592, type=0x55555709be00) at ../../qemu/qom/object.c:571
//#4  0x0000555555ea3e75 in object_new_with_type (type=0x55555709be00) at ../../qemu/qom/object.c:791
//#5  0x0000555555ea3ee1 in object_new (typename=0x5555580c2180 "e1000") at ../../qemu/qom/object.c:806
//#6  0x0000555555e9b710 in qdev_new (name=0x5555580c2180 "e1000") at ../../qemu/hw/core/qdev.c:166
//#7  0x0000555555bcdd84 in qdev_device_add_from_qdict (opts=0x5555580c2500, from_json=false, errp=0x7fffffffd710) at ../../qemu/system/qdev-monitor.c:681
//#8  0x0000555555bcdf99 in qdev_device_add (opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#9  0x0000555555bd80a7 in device_init_func (opaque=0x0, opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:1200
//#10 0x00005555560be1e2 in qemu_opts_foreach (list=0x555556f4bec0 <qemu_device_opts>, func=0x555555bd807c <device_init_func>, opaque=0x0, errp=0x555557061f60 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#11 0x0000555555bdbd46 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#12 0x0000555555bdbf8c in qmp_x_exit_preconfig (errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:2706
//#13 0x0000555555bde944 in qemu_init (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/vl.c:3739
//#14 0x0000555555e96f93 in main (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/main.c:47
//#15 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffdb58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#16 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffdb58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb48) at ../csu/libc-start.c:392
//#17 0x000055555586cc95 in _start ()
static void e1000_instance_init(Object *obj)
{
    E1000State *n = E1000(obj);
    device_add_bootindex_property(obj, &n->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(n));
}
```
其在解析Qemu参数时初始化**e1000**对象，其中没有过多的**PCI设备**相关的信息，这些被放到了实例化中进行

### 实例化

根据前面[类初始化](#类初始化-1)内容，Qemu使用[pci_e1000_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1637)函数来实例化**e1000**
```c
//#0  pci_e1000_realize (pci_dev=0x5555580d01f0, errp=0x7fffffffd420) at ../../qemu/hw/net/e1000.c:1639
//#1  0x0000555555a9a921 in pci_qdev_realize (qdev=0x5555580d01f0, errp=0x7fffffffd4a0) at ../../qemu/hw/pci/pci.c:2093
//#2  0x0000555555e9c4f4 in device_set_realized (obj=0x5555580d01f0, value=true, errp=0x7fffffffd710) at ../../qemu/hw/core/qdev.c:510
//#3  0x0000555555ea7cfb in property_set_bool (obj=0x5555580d01f0, v=0x5555580c5590, name=0x5555562f9dd1 "realized", opaque=0x5555570f4510, errp=0x7fffffffd710) at ../../qemu/qom/object.c:2358
//#4  0x0000555555ea5891 in object_property_set (obj=0x5555580d01f0, name=0x5555562f9dd1 "realized", v=0x5555580c5590, errp=0x7fffffffd710) at ../../qemu/qom/object.c:1472
//#5  0x0000555555eaa4ca in object_property_set_qobject (obj=0x5555580d01f0, name=0x5555562f9dd1 "realized", value=0x5555580c35d0, errp=0x7fffffffd710) at ../../qemu/qom/qom-qobject.c:28
//#6  0x0000555555ea5c4a in object_property_set_bool (obj=0x5555580d01f0, name=0x5555562f9dd1 "realized", value=true, errp=0x7fffffffd710) at ../../qemu/qom/object.c:1541
//#7  0x0000555555e9bc0e in qdev_realize (dev=0x5555580d01f0, bus=0x5555574157d0, errp=0x7fffffffd710) at ../../qemu/hw/core/qdev.c:292
//#8  0x0000555555bcdee9 in qdev_device_add_from_qdict (opts=0x5555580c2500, from_json=false, errp=0x7fffffffd710) at ../../qemu/system/qdev-monitor.c:718
//#9  0x0000555555bcdf99 in qdev_device_add (opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/qdev-monitor.c:737
//#10 0x0000555555bd80a7 in device_init_func (opaque=0x0, opts=0x5555570ef1c0, errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:1200
//#11 0x00005555560be1e2 in qemu_opts_foreach (list=0x555556f4bec0 <qemu_device_opts>, func=0x555555bd807c <device_init_func>, opaque=0x0, errp=0x555557061f60 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
//#12 0x0000555555bdbd46 in qemu_create_cli_devices () at ../../qemu/system/vl.c:2637
//#13 0x0000555555bdbf8c in qmp_x_exit_preconfig (errp=0x555557061f60 <error_fatal>) at ../../qemu/system/vl.c:2706
//#14 0x0000555555bde944 in qemu_init (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/vl.c:3739
//#15 0x0000555555e96f93 in main (argc=35, argv=0x7fffffffdb58) at ../../qemu/system/main.c:47
//#16 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e96f6f <main>, argc=argc@entry=35, argv=argv@entry=0x7fffffffdb58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#17 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e96f6f <main>, argc=35, argv=0x7fffffffdb58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdb48) at ../csu/libc-start.c:392
//#18 0x000055555586cc95 in _start ()
static void pci_e1000_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    E1000State *d = E1000(pci_dev);
    uint8_t *pci_conf;
    uint8_t *macaddr;

    pci_dev->config_write = e1000_write_config;

    pci_conf = pci_dev->config;

    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);

    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;

    e1000x_core_prepare_eeprom(d->eeprom_data,
                               e1000_eeprom_template,
                               sizeof(e1000_eeprom_template),
                               PCI_DEVICE_GET_CLASS(pci_dev)->device_id,
                               macaddr);

    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          object_get_typename(OBJECT(d)), dev->id,
                          &dev->mem_reentrancy_guard, d);

    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);

    d->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, e1000_autoneg_timer, d);
    d->mit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, e1000_mit_timer, d);
    d->flush_queue_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        e1000_flush_queue_timer, d);
}

static void pci_qdev_realize(DeviceState *qdev, Error **errp)
{
    PCIDevice *pci_dev = (PCIDevice *)qdev;

    ...
    pci_dev = do_pci_register_device(pci_dev,
                                     object_get_typename(OBJECT(qdev)),
                                     pci_dev->devfn, errp);
    ...
    if (pc->realize) {
        pc->realize(pci_dev, &local_err);
        ...
    }
    ...
}

bool qdev_realize(DeviceState *dev, BusState *bus, Error **errp)
{
    assert(!dev->realized && !dev->parent_bus);

    if (bus) {
        if (!qdev_set_parent_bus(dev, bus, errp)) {
            return false;
        }
    } else {
        assert(!DEVICE_GET_CLASS(dev)->bus_type);
    }

    return object_property_set_bool(OBJECT(dev), "realized", true, errp);
}

DeviceState *qdev_device_add_from_qdict(const QDict *opts,
                                        bool from_json, Error **errp)
{
    DeviceClass *dc;
    const char *driver, *path;
    char *id;
    DeviceState *dev = NULL;
    BusState *bus = NULL;

    driver = qdict_get_try_str(opts, "driver");
    if (!driver) {
        error_setg(errp, QERR_MISSING_PARAMETER, "driver");
        return NULL;
    }

    /* find driver */
    dc = qdev_get_device_class(&driver, errp);
    if (!dc) {
        return NULL;
    }

    /* find bus */
    path = qdict_get_try_str(opts, "bus");
    if (path != NULL) {
        bus = qbus_find(path, errp);
        if (!bus) {
            return NULL;
        }
        if (!object_dynamic_cast(OBJECT(bus), dc->bus_type)) {
            error_setg(errp, "Device '%s' can't go on %s bus",
                       driver, object_get_typename(OBJECT(bus)));
            return NULL;
        }
    } else if (dc->bus_type != NULL) {
        bus = qbus_find_recursive(sysbus_get_default(), NULL, dc->bus_type);
        if (!bus || qbus_is_full(bus)) {
            error_setg(errp, "No '%s' bus found for device '%s'",
                       dc->bus_type, driver);
            return NULL;
        }
    }
    ...
    /* create device */
    dev = qdev_new(driver);
    ...

    if (!qdev_realize(dev, bus, errp)) {
        goto err_del_dev;
    }
    return dev;
    ...
}
```
可以看到，在初始化**e1000**对象后，其又被迅速实例化。根据{% post_link qemu设备模型 %}中类初始化可知，**DeviceClass**类在实例化时会调用类初始化设置的**realized**属性的setter方法[**device_set_realized()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L470)，并在该方法中调用类的**realize**函数指针，即[pci_e1000_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1637)函数

其中，在[**qdev_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L280)和[**do_pci_register_device()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L280)中完成了**PCI设备**的编号，从而可以让前面介绍的[PCI桥](#对象初始化-1)根据PCI设备编号定位**PCI设备**

除此之外，[pci_e1000_realize()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/e1000.c#L1637)还初始化了其**PCI设置空间**，包括**配置空间头**(**config**字段)、**mmio bar**和**pio bar**。但需要注意的是，这里仅仅是初始化了**bar**的相关数据结构，但并没有映射到设备的地址空间，也就是**guest**此时是看不到**bar**对应的地址空间，需要后续**guest**配置完**PCI设置空间**后才会完成映射。

### ~~PCI配置~~

# 参考
1. [用QEMU来体会PCI/PCIE设备 ](https://www.owalle.com/2021/12/09/qemu-pci/)
2. [PCI Local Bus Specification Revision 3.0](https://members.pcisig.com/wg/PCI-SIG/document/download/8237)
3. [A deep dive into QEMU: PCI host bridge controller](https://airbus-seclab.github.io/qemu_blog/pci.html)
4. [【HARDWARE.0x00】PCI 设备简易食用手册](https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/)
5. [x86 计算机的 PCI 总线结构](https://shaocheng.li/posts/2017/11/27/)
6. [QEMU总线模拟 ](https://66ring.github.io/2021/09/10/universe/qemu/qemu_bus_simulate/)
7. [PCI设备的创建与初始化](https://github.com/GiantVM/doc/blob/master/pci.md)
8. [QEMU - e1000全虚拟化前端与TAP/TUN后端流程简析](https://blog.csdn.net/vertor11/article/details/135942748)
