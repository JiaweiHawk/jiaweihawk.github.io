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

根据[PCI总线结构](#pci总线结构)中的介绍，一个经典的PCI总线包含PCI设备、PCI桥和PCI总线等三部分，则Qemu对这些部分都有相应的模拟。

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
其中**conf_mem**字段是前面[PCI配置空间](#pci配置空间)中**CONFIG_ADDRESS**地址空间的**MemoryRegion**，**config_reg**是该地址空间的数据。**data_mem**字段是**CONFIG_DATA**地址空间的**MemoryRegion**，而该地址空间是**CONFIG_ADDRESS**指定的设备的配置空间寄存器，自然应当在指定PCI设备的数据结构中而不在这里存储。

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
其主要设置了类的**realize**函数指针为[**i440fx_pcihost_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/pci-host/i440fx.c#L249)

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
可以看到，这里就是Qemu模拟的前面[PCI配置空间](#pci配置空间)中**CONFIG_ADDRESS**和**CONFIG_DATA**的逻辑。但这里未将**MemoryRegion**绑定到对应的地址空间，那只能是在实例化的时候绑定的

#### 实例化

```c
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

## ~~PCI总线~~

## ~~PCI设备~~

# 参考
1. [用QEMU来体会PCI/PCIE设备 ](https://www.owalle.com/2021/12/09/qemu-pci/)
2. [PCI Local Bus Specification Revision 3.0](https://members.pcisig.com/wg/PCI-SIG/document/download/8237)
3. [A deep dive into QEMU: PCI host bridge controller](https://airbus-seclab.github.io/qemu_blog/pci.html)
4. [【HARDWARE.0x00】PCI 设备简易食用手册](https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/)
5. [x86 计算机的 PCI 总线结构](https://shaocheng.li/posts/2017/11/27/)
6. [QEMU总线模拟 ](https://66ring.github.io/2021/09/10/universe/qemu/qemu_bus_simulate/)
7. [PCI设备的创建与初始化](https://github.com/GiantVM/doc/blob/master/pci.md)
