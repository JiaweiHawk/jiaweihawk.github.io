---
title: qemu设备模型
date: 2024-07-31 23:38:12
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

Qemu支持种类繁多的外部设备，并且支持多种架构，这些架构和设备的模拟在Qemu的代码中占了大头。

这里简单介绍一下Qemu中用于设备模拟的模型，主要分为**总线**、**设备前端**和**设备后端**。

# 总线

实际上，PC中各组件是通过总线互联通信的。再具体的说，设备与总线是交替的，总线下面只能连接设备，设备也只能连接到总线上，总线与总线、设备与设备之间是不能直接连接的，如下图所示。
![Qemu官网的架构图](https://wiki.qemu.org/images/4/4f/Kvm_model.png)

参考之前的{% post_link qemu基本知识 %}中对象初始化内容，根据总线的**TypeInfo**，即[**bus_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/bus.c#L254)，即可了解总线对象的相关信息。
```c
static const TypeInfo bus_info = {
    .name = TYPE_BUS,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(BusState),
    .abstract = true,
    .class_size = sizeof(BusClass),
    .instance_init = qbus_initfn,
    .instance_finalize = qbus_finalize,
    .class_init = bus_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_RESETTABLE_INTERFACE },
        { }
    },
};
```

可以看到，Qemu使用[**struct BusClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/qdev-core.h#L318)和[**struct BusState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/qdev-core.h#L372)来模拟PC中的总线。

## 数据结构

### struct BusClass

```c
struct BusClass {
    ObjectClass parent_class;

    /* FIXME first arg should be BusState */
    void (*print_dev)(Monitor *mon, DeviceState *dev, int indent);
    char *(*get_dev_path)(DeviceState *dev);

    /*
     * This callback is used to create Open Firmware device path in accordance
     * with OF spec http://forthworks.com/standards/of1275.pdf. Individual bus
     * bindings can be found at http://playground.sun.com/1275/bindings/.
     */
    char *(*get_fw_dev_path)(DeviceState *dev);

    /*
     * Return whether the device can be added to @bus,
     * based on the address that was set (via device properties)
     * before realize.  If not, on return @errp contains the
     * human-readable error message.
     */
    bool (*check_address)(BusState *bus, DeviceState *dev, Error **errp);

    BusRealize realize;
    BusUnrealize unrealize;

    /* maximum devices allowed on the bus, 0: no limit. */
    int max_dev;
    /* number of automatically allocated bus ids (e.g. ide.0) */
    int automatic_ids;
};
```

**struct BusClass**是总线的类结构体，其中重要的是实例化时的**realize**回调函数和销毁时的**unrealize**回调函数。

### struct BusState

```c
/**
 * struct BusState:
 * @obj: parent object
 * @parent: parent Device
 * @name: name of bus
 * @hotplug_handler: link to a hotplug handler associated with bus.
 * @max_index: max number of child buses
 * @realized: is the bus itself realized?
 * @full: is the bus full?
 * @num_children: current number of child buses
 */
struct BusState {
    /* private: */
    Object obj;
    /* public: */
    DeviceState *parent;
    char *name;
    HotplugHandler *hotplug_handler;
    int max_index;
    bool realized;
    bool full;
    int num_children;

    /**
     * @children: an RCU protected QTAILQ, thus readers must use RCU
     * to access it, and writers must hold the big qemu lock
     */
    BusChildHead children;
    /**
     * @sibling: next bus
     */
    BusStateEntry sibling;
    /**
     * @reset: ResettableState for the bus; handled by Resettable interface.
     */
    ResettableState reset;
};
```

**struct BusState**是总线的对象结构体。

**parent**字段指向的是总线的父设备。正如前面介绍的，总线和设备是交替的，而且总线不能独立产生，必须依赖于一个设备，例如USB总线是由USB控制器产生的，PCI总线是由PCI桥产生的。
**children**指向当前总线下的所有设备链表，而**sibling**则指向该总线父设备下的其他总线。

## 初始化

根据[前面](#总线)内容可知，总线对象使用[**bus_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/bus.c#L235)初始化类，使用[**qbus_initfn()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/bus.c#L216)初始化对象。

### 类初始化

```c
static void bus_class_init(ObjectClass *class, void *data)
{
    BusClass *bc = BUS_CLASS(class);
    ResettableClass *rc = RESETTABLE_CLASS(class);

    class->unparent = bus_unparent;
    bc->get_fw_dev_path = default_bus_get_fw_dev_path;

    rc->get_state = bus_get_reset_state;
    rc->child_foreach = bus_reset_child_foreach;
}
```

总线的类初始化很简单，只是初始化了几个函数指针和接口。

### 对象初始化

```c
static void qbus_initfn(Object *obj)
{
    BusState *bus = BUS(obj);

    QTAILQ_INIT(&bus->children);
    object_property_add_link(obj, QDEV_HOTPLUG_HANDLER_PROPERTY,
                             TYPE_HOTPLUG_HANDLER,
                             (Object **)&bus->hotplug_handler,
                             object_property_allow_set_link,
                             0);
    object_property_add_bool(obj, "realized",
                             bus_get_realized, bus_set_realized);
}
```

总线的对象初始化也很简单，添加了相关的属性并初始化**children**字段。

## 实例化

Qemu中对象初始化仅仅是指初始化好了必要的数据结构信息，还无法直接使用。例如PCI设备只有根据PCI协议完成交互后才能使用，则PCI设备对象则在初始化完后还需要进行协议交互，然后才能正常进行后续的模拟功能。因此对象初始化结束后还需要进行实例化。

根据[总线对象初始化](#对象初始化)的内容，在对象初始化时设置了对象实例化的函数，即[**bus_set_realized**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/bus.c#L189)

```c
//#0  bus_set_realized (obj=0x5555573ffd70, value=true, errp=0x7fffffffd4d0) at ../../qemu/hw/core/bus.c:190
//#1  0x0000555555ea3595 in property_set_bool (obj=0x5555573ffd70, v=0x555557746e50, name=0x5555562f3718 "realized", opaque=0x555557400840, errp=0x7fffffffd4d0) at ../../qemu/qom/object.c:2358
//#2  0x0000555555ea112b in object_property_set (obj=0x5555573ffd70, name=0x5555562f3718 "realized", v=0x555557746e50, errp=0x7fffffffd4d0) at ../../qemu/qom/object.c:1472
//#3  0x0000555555ea5d64 in object_property_set_qobject (obj=0x5555573ffd70, name=0x5555562f3718 "realized", value=0x555557746cb0, errp=0x7fffffffd4d0) at ../../qemu/qom/qom-qobject.c:28
//#4  0x0000555555ea14e4 in object_property_set_bool (obj=0x5555573ffd70, name=0x5555562f3718 "realized", value=true, errp=0x7fffffffd4d0) at ../../qemu/qom/object.c:1541
//#5  0x0000555555e9321b in qbus_realize (bus=0x5555573ffd70, errp=0x7fffffffd4d0) at ../../qemu/hw/core/bus.c:174
//#6  0x0000555555e97f04 in device_set_realized (obj=0x5555573c9100, value=true, errp=0x7fffffffd4d0) at ../../qemu/hw/core/qdev.c:550
//#7  0x0000555555ea3595 in property_set_bool (obj=0x5555573c9100, v=0x5555573ca630, name=0x5555562f4071 "realized", opaque=0x5555570ee010, errp=0x7fffffffd4d0) at ../../qemu/qom/object.c:2358
//#8  0x0000555555ea112b in object_property_set (obj=0x5555573c9100, name=0x5555562f4071 "realized", v=0x5555573ca630, errp=0x7fffffffd4d0) at ../../qemu/qom/object.c:1472
//#9  0x0000555555ea5d64 in object_property_set_qobject (obj=0x5555573c9100, name=0x5555562f4071 "realized", value=0x5555573ca350, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/qom-qobject.c:28
//#10 0x0000555555ea14e4 in object_property_set_bool (obj=0x5555573c9100, name=0x5555562f4071 "realized", value=true, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/object.c:1541
//#11 0x0000555555e974a8 in qdev_realize (dev=0x5555573c9100, bus=0x55555735b0a0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:292
//#12 0x0000555555e974e1 in qdev_realize_and_unref (dev=0x5555573c9100, bus=0x55555735b0a0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:299
//#13 0x00005555559658fa in sysbus_realize_and_unref (dev=0x5555573c9100, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/sysbus.c:261
//#14 0x0000555555cae1c5 in pc_init1 (machine=0x555557352820, pci_type=0x5555562a5bbb "i440FX") at ../../qemu/hw/i386/pc_piix.c:212
//#15 0x0000555555caee7d in pc_init_v9_0 (machine=0x555557352820) at ../../qemu/hw/i386/pc_piix.c:523
//#16 0x000055555595e63e in machine_run_board_init (machine=0x555557352820, mem_path=0x0, errp=0x7fffffffd7b0) at ../../qemu/hw/core/machine.c:1547
//#17 0x0000555555bda9d6 in qemu_init_board () at ../../qemu/system/vl.c:2613
//#18 0x0000555555bdace5 in qmp_x_exit_preconfig (errp=0x55555705bca0 <error_fatal>) at ../../qemu/system/vl.c:2705
//#19 0x0000555555bdd6a2 in qemu_init (argc=31, argv=0x7fffffffdae8) at ../../qemu/system/vl.c:3739
//#20 0x0000555555e9282d in main (argc=31, argv=0x7fffffffdae8) at ../../qemu/system/main.c:47
//#21 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=31, argv=argv@entry=0x7fffffffdae8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#22 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=31, argv=0x7fffffffdae8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdad8) at ../csu/libc-start.c:392
//#23 0x000055555586ba15 in _start ()
static void bus_set_realized(Object *obj, bool value, Error **errp)
{
    BusState *bus = BUS(obj);
    BusClass *bc = BUS_GET_CLASS(bus);
    BusChild *kid;

    if (value && !bus->realized) {
        if (bc->realize) {
            bc->realize(bus, errp);
        }

        /* TODO: recursive realization */
    } else if (!value && bus->realized) {
        WITH_RCU_READ_LOCK_GUARD() {
            QTAILQ_FOREACH_RCU(kid, &bus->children, sibling) {
                DeviceState *dev = kid->child;
                qdev_unrealize(dev);
            }
        }
        if (bc->unrealize) {
            bc->unrealize(bus);
        }
    }

    bus->realized = value;
}
```

其逻辑也很简单，在实例化时即调用类的**realize**函数；而在销毁时递归调用总线上设备的**unrealize**函数然后再调用类的**unrealize**函数即可

# 前端

Qemu在设备模拟上采用了前端和后端分离的设计模式。

具体的，设备前端指的是Qemu模拟设备如何呈现给Guest，呈现的设备类型应该与Guest预期看到的硬件相匹配。设备后端指的是Qemu如何处理来自设备前端的数据。

其中，Qemu设备前端都可以通过`-device`命令行进行设置，涉及到Qemu的[**struct DeviceClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/qdev-core.h#L110)和[**struct DeviceState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/qdev-core.h#L215)结构。

其**TypeInfo**为[**device_type_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L903)，如下所示
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
```

## 数据结构

### struct DeviceClass

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
```
其中比较重要的是**reset**、**realize**和**unrealize**字段，即重置函数、实例化函数和销毁函数。

### struct DeviceState

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
```
其中比较重要的是**parent_bus**，即设备挂载的总线信息。

## 初始化

根据[前端](#前端)可知，Qemu使用[**device_class_base_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L713)和[**device_class_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L801)初始化类，用[**device_initfn()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L652)和[**device_post_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L669)初始化对象。

### 类初始化

**TypeInfo**的**class_base_init**字段，即**device_class_base_init()**函数是初始化父类之后但**class_init**之前调用，而**class_init**字段，即**device_class_init()**就是普通的初始化函数
```c
static void device_class_base_init(ObjectClass *class, void *data)
{
    DeviceClass *klass = DEVICE_CLASS(class);

    /* We explicitly look up properties in the superclasses,
     * so do not propagate them to the subclasses.
     */
    klass->props_ = NULL;
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
可以看到，其主要就是初始化相关的字段和函数指针

### 对象初始化

而**TypeInfo**的**instance_init**字段，即**device_initfn()**是普通的对象初始化函数，而**instance_post_init**字段，即**device_post_init()**函数，是在初始化完父类对象之后再调用。
```c
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

static void device_post_init(Object *obj)
{
    /*
     * Note: ordered so that the user's global properties take
     * precedence.
     */
    object_apply_compat_props(obj);
    qdev_prop_set_globals(DEVICE(obj));
}
```
可以看到，其主要就是初始化一些相关字段。

## 实例化

类似于总线，根据[类初始化](#类初始化-1)的内容，Qemu使用[**device_set_realized()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/qdev.c#L470)来进行实例化

```c
//#0  device_set_realized (obj=0x55555782e5e0, value=true, errp=0x7fffffffd330) at ../../qemu/hw/core/qdev.c:477
//#1  0x0000555555ea3595 in property_set_bool (obj=0x55555782e5e0, v=0x55555782ed80, name=0x5555562f4071 "realized", opaque=0x5555570ee010, errp=0x7fffffffd330) at ../../qemu/qom/object.c:2358
//#2  0x0000555555ea112b in object_property_set (obj=0x55555782e5e0, name=0x5555562f4071 "realized", v=0x55555782ed80, errp=0x7fffffffd330) at ../../qemu/qom/object.c:1472
//#3  0x0000555555ea5d64 in object_property_set_qobject (obj=0x55555782e5e0, name=0x5555562f4071 "realized", value=0x55555782ecc0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/qom-qobject.c:28
//#4  0x0000555555ea14e4 in object_property_set_bool (obj=0x55555782e5e0, name=0x5555562f4071 "realized", value=true, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/object.c:1541
//#5  0x0000555555e974a8 in qdev_realize (dev=0x55555782e5e0, bus=0x55555735b0a0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:292
//#6  0x0000555555e974e1 in qdev_realize_and_unref (dev=0x55555782e5e0, bus=0x55555735b0a0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:299
//#7  0x00005555559658fa in sysbus_realize_and_unref (dev=0x55555782e5e0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/sysbus.c:261
//#8  0x0000555555a8dd7c in fw_cfg_init_io_dma (iobase=1296, dma_iobase=1300, dma_as=0x555557047a20 <address_space_memory>) at ../../qemu/hw/nvram/fw_cfg.c:1158
//#9  0x0000555555c9d759 in fw_cfg_arch_create (ms=0x555557352820, boot_cpus=2, apic_id_limit=2) at ../../qemu/hw/i386/fw_cfg.c:118
//#10 0x0000555555ccead1 in pc_memory_init (pcms=0x555557352820, system_memory=0x555557272800, rom_memory=0x555557391400, pci_hole64_size=2147483648) at ../../qemu/hw/i386/pc.c:1024
//#11 0x0000555555cae267 in pc_init1 (machine=0x555557352820, pci_type=0x5555562a5bbb "i440FX") at ../../qemu/hw/i386/pc_piix.c:226
//#12 0x0000555555caee7d in pc_init_v9_0 (machine=0x555557352820) at ../../qemu/hw/i386/pc_piix.c:523
//#13 0x000055555595e63e in machine_run_board_init (machine=0x555557352820, mem_path=0x0, errp=0x7fffffffd7b0) at ../../qemu/hw/core/machine.c:1547
//#14 0x0000555555bda9d6 in qemu_init_board () at ../../qemu/system/vl.c:2613
//#15 0x0000555555bdace5 in qmp_x_exit_preconfig (errp=0x55555705bca0 <error_fatal>) at ../../qemu/system/vl.c:2705
//#16 0x0000555555bdd6a2 in qemu_init (argc=31, argv=0x7fffffffdae8) at ../../qemu/system/vl.c:3739
//#17 0x0000555555e9282d in main (argc=31, argv=0x7fffffffdae8) at ../../qemu/system/main.c:47
//#18 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=31, argv=argv@entry=0x7fffffffdae8) at ../sysdeps/nptl/libc_start_call_main.h:58
//#19 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=31, argv=0x7fffffffdae8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdad8) at ../csu/libc-start.c:392
//#20 0x000055555586ba15 in _start ()
static void device_set_realized(Object *obj, bool value, Error **errp)
{
    DeviceState *dev = DEVICE(obj);
    DeviceClass *dc = DEVICE_GET_CLASS(dev);
    HotplugHandler *hotplug_ctrl;
    BusState *bus;
    NamedClockList *ncl;
    Error *local_err = NULL;
    bool unattached_parent = false;
    static int unattached_count;

    if (dev->hotplugged && !dc->hotpluggable) {
        error_setg(errp, QERR_DEVICE_NO_HOTPLUG, object_get_typename(obj));
        return;
    }

    if (value && !dev->realized) {
        if (!check_only_migratable(obj, errp)) {
            goto fail;
        }

        if (!obj->parent) {
            gchar *name = g_strdup_printf("device[%d]", unattached_count++);

            object_property_add_child(container_get(qdev_get_machine(),
                                                    "/unattached"),
                                      name, obj);
            unattached_parent = true;
            g_free(name);
        }

        hotplug_ctrl = qdev_get_hotplug_handler(dev);
        if (hotplug_ctrl) {
            hotplug_handler_pre_plug(hotplug_ctrl, dev, &local_err);
            if (local_err != NULL) {
                goto fail;
            }
        }

        if (dc->realize) {
            dc->realize(dev, &local_err);
            if (local_err != NULL) {
                goto fail;
            }
        }

        DEVICE_LISTENER_CALL(realize, Forward, dev);

        /*
         * always free/re-initialize here since the value cannot be cleaned up
         * in device_unrealize due to its usage later on in the unplug path
         */
        g_free(dev->canonical_path);
        dev->canonical_path = object_get_canonical_path(OBJECT(dev));
        QLIST_FOREACH(ncl, &dev->clocks, node) {
            if (ncl->alias) {
                continue;
            } else {
                clock_setup_canonical_path(ncl->clock);
            }
        }

        if (qdev_get_vmsd(dev)) {
            if (vmstate_register_with_alias_id(VMSTATE_IF(dev),
                                               VMSTATE_INSTANCE_ID_ANY,
                                               qdev_get_vmsd(dev), dev,
                                               dev->instance_id_alias,
                                               dev->alias_required_for_version,
                                               &local_err) < 0) {
                goto post_realize_fail;
            }
        }

        /*
         * Clear the reset state, in case the object was previously unrealized
         * with a dirty state.
         */
        resettable_state_clear(&dev->reset);

        QLIST_FOREACH(bus, &dev->child_bus, sibling) {
            if (!qbus_realize(bus, errp)) {
                goto child_realize_fail;
            }
        }
        if (dev->hotplugged) {
            /*
             * Reset the device, as well as its subtree which, at this point,
             * should be realized too.
             */
            resettable_assert_reset(OBJECT(dev), RESET_TYPE_COLD);
            resettable_change_parent(OBJECT(dev), OBJECT(dev->parent_bus),
                                     NULL);
            resettable_release_reset(OBJECT(dev), RESET_TYPE_COLD);
        }
        dev->pending_deleted_event = false;

        if (hotplug_ctrl) {
            hotplug_handler_plug(hotplug_ctrl, dev, &local_err);
            if (local_err != NULL) {
                goto child_realize_fail;
            }
       }

       qatomic_store_release(&dev->realized, value);

    } else if (!value && dev->realized) {

        /*
         * Change the value so that any concurrent users are aware
         * that the device is going to be unrealized
         *
         * TODO: change .realized property to enum that states
         * each phase of the device realization/unrealization
         */

        qatomic_set(&dev->realized, value);
        /*
         * Ensure that concurrent users see this update prior to
         * any other changes done by unrealize.
         */
        smp_wmb();

        QLIST_FOREACH(bus, &dev->child_bus, sibling) {
            qbus_unrealize(bus);
        }
        if (qdev_get_vmsd(dev)) {
            vmstate_unregister(VMSTATE_IF(dev), qdev_get_vmsd(dev), dev);
        }
        if (dc->unrealize) {
            dc->unrealize(dev);
        }
        dev->pending_deleted_event = true;
        DEVICE_LISTENER_CALL(unrealize, Reverse, dev);
    }

    assert(local_err == NULL);
    return;

child_realize_fail:
    QLIST_FOREACH(bus, &dev->child_bus, sibling) {
        qbus_unrealize(bus);
    }

    if (qdev_get_vmsd(dev)) {
        vmstate_unregister(VMSTATE_IF(dev), qdev_get_vmsd(dev), dev);
    }

post_realize_fail:
    g_free(dev->canonical_path);
    dev->canonical_path = NULL;
    if (dc->unrealize) {
        dc->unrealize(dev);
    }

fail:
    error_propagate(errp, local_err);
    if (unattached_parent) {
        /*
         * Beware, this doesn't just revert
         * object_property_add_child(), it also runs bus_remove()!
         */
        object_unparent(OBJECT(dev));
        unattached_count--;
    }
}
```

可以看到，其重点逻辑就是调用类的**realize**/**unrealize**函数指针。

# 后端

在[前端](#前端)小节中介绍过，设备后端指的是Qemu如何处理来自设备前端的数据。

考虑到不同的设备数据处理有不同的特点，因此后端种类十分繁多，这里仅简单罗列一下。

| 设备类型 | 查找命令 | 设备后端 |
| :-: | :-: | :-: |
| 网络 | qemu-system-x86_64 -netdev help | socket、hubport、tap、user、l2tpv3、bridge、vhost-user、vhost-vdpa |
| 存储 |  | blockdev |
| 字符设备 | qemu-system-x86_64 -chardev help | ringbuf、mux、pipe、qemu-vdagent、null、msmouse、socket、vc、parallel、memory、udp、file、serial、pty、wctablet、stdio、testdev |
| ... | ... | ... |

# 参考

1. [Device Emulation](https://qemu-project.gitlab.io/qemu/system/device-emulation.html)
2. [Documentation/Architecture](https://wiki.qemu.org/Documentation/Architecture)
3. [QEMU 概述](https://martins3.github.io/qemu/introduction.html)
