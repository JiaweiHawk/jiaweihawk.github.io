---
title: qemu基本知识
date: 2024-04-08 22:01:00
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

这里简单介绍一些**QEMU**相关的基本知识，从而方便后续更深入的研究**QEMU**

# QOM(QEMU Object Model)

**QEMU**提供了一套面向对象编程的模型，从而实现各种具有继承关系的设备的模拟。

面向对象编程通常涵盖了**类**和**对象**这两个关键概念，其中**类**是**对象**的抽象定义，而**对象**则是**类**的具体实例。在**QOM**中，这些概念得到了实现和体现。
```
 struct OjbectProperty
    ┌────────────┐
    │            │
    └─────▲──────┘
          │          ┌──┬──────────────┬──┐
          │          │  │    class     ├──┼──────►┌──┬──────────────┬──┐
          │          │  ├──────────────┤  │       │  │    type      ├──┼────►┌──────────────┐
◄─────────┴──────────┼──┤  properties  │  │       │  ├──────────────┤  │     │              ◄─────┐
                     │  ├──────────────┤  │   ┌───┼──┤  properties  │  │     └──────────────┘     │
                     │  │    ...       │  │   │   │  ├──────────────┤  │     struct TypeImpl      │
                     │  └──────────────┘  │   │   │  │    ...       │  │                          │
                     │    parent_obj      │   │   │  └──────────────┘  │                          │
                     ├────────────────────┤   │   │    parent_class    │      ┌───────────────┐   │
                     │       ......       │   │   ├────────────────────┤      │               │   │
                     └────────────────────┘   │   │       ......       │      └───────────────┘   │
                       struct DeviceState     │   └────────────────────┘       struct TypeInfo────┘
                                              │     struct DeviceClass
                                              │
                                              │
                                              │
                                              │    struct OjbectProperty
                                              │       ┌────────────┐
                                              ├──────►│            │
                                              │       └────────────┘
                                              ▼
```

## 类

**QOM**使用**struct TypeInfo**和**Class**结构体类型共同描述一个类。

其中**struct TypeInfo**描述类的基本属性，**Class**结构体类型描述静态成员。

### struct TypeInfo

**QOM**中使用[**struct TypeInfo**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qom/object.h#L474)描述诸如类的名称、父类名称、实例大小和静态成员情况

```c
/**
 * struct TypeInfo:
 * @name: The name of the type.
 * @parent: The name of the parent type.
 * @instance_size: The size of the object (derivative of #Object).  If
 *   @instance_size is 0, then the size of the object will be the size of the
 *   parent object.
 * @instance_align: The required alignment of the object.  If @instance_align
 *   is 0, then normal malloc alignment is sufficient; if non-zero, then we
 *   must use qemu_memalign for allocation.
 * @instance_init: This function is called to initialize an object.  The parent
 *   class will have already been initialized so the type is only responsible
 *   for initializing its own members.
 * @instance_post_init: This function is called to finish initialization of
 *   an object, after all @instance_init functions were called.
 * @instance_finalize: This function is called during object destruction.  This
 *   is called before the parent @instance_finalize function has been called.
 *   An object should only free the members that are unique to its type in this
 *   function.
 * @abstract: If this field is true, then the class is considered abstract and
 *   cannot be directly instantiated.
 * @class_size: The size of the class object (derivative of #ObjectClass)
 *   for this object.  If @class_size is 0, then the size of the class will be
 *   assumed to be the size of the parent class.  This allows a type to avoid
 *   implementing an explicit class type if they are not adding additional
 *   virtual functions.
 * @class_init: This function is called after all parent class initialization
 *   has occurred to allow a class to set its default virtual method pointers.
 *   This is also the function to use to override virtual methods from a parent
 *   class.
 * @class_base_init: This function is called for all base classes after all
 *   parent class initialization has occurred, but before the class itself
 *   is initialized.  This is the function to use to undo the effects of
 *   memcpy from the parent class to the descendants.
 * @class_data: Data to pass to the @class_init,
 *   @class_base_init. This can be useful when building dynamic
 *   classes.
 * @interfaces: The list of interfaces associated with this type.  This
 *   should point to a static array that's terminated with a zero filled
 *   element.
 */
struct TypeInfo
{
    const char *name;
    const char *parent;

    size_t instance_size;
    size_t instance_align;
    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;
    size_t class_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void *class_data;

    InterfaceInfo *interfaces;
};
```

### Class结构体

**QOM**使用用户自定义的**Class**结构体描述诸如函数表、静态成员等类的静态内容，因此所有的对象只能共享一份**Class**结构体和**struct TypeInfo**数据。

考虑到类会继承父类的成员内容，因此需要在**Class**结构体中包含父类的**Class**数据来实现继承关系。同时为了能安全的实现面向对象编程中的向上转型，总是将父类的数据放在**Class**结构体的最开始，如[**struct PCIDeviceClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_device.h#L24)所示。

```c
/*
 * ┌─┬─┬────────────┬─┬─┐ 0│
 * │ │ │ObjectClass │ │ │  │
 * │ │ └────────────┘ │ │  │offset
 * │ │   DeviceClass  │ │  │
 * │ └────────────────┘ │  │
 * │   PCIDeviceClass   │  │
 * └────────────────────┘  ▼
 */
struct ObjectClass
{
    /* private: */
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};

struct DeviceClass {
    /* private: */
    ObjectClass parent_class;
    /* public: */
    ...
};

struct PCIDeviceClass {
    DeviceClass parent_class;
    ...
};
```

## 对象

**QOM**使用用户自定义的**Object**结构体描述非静态成员，也就是对象的数据，因此所有的对象都有自己的**Object**结构数据。

类似于**Class**结构体，考虑到对象同样会继承父类对象的成员内容，因此需要在**Object**结构体中包含父类的**Object**数据来实现继承，父类的数据同样应放在**Object**结构体的最开始以实现向上转型，如[**struct PCIDevice**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/pci/pci_device.h#L56)所示。

```c
/*
 * ┌─┬──┬────────┬─┬─┐ 0│
 * │ │  │ Object │ │ │  │
 * │ │  └────────┘ │ │  │offset
 * │ │ DeviceState │ │  │
 * │ └─────────────┘ │  │
 * │    PCIDevice    │  │
 * └─────────────────┘  ▼
 */
struct Object
{
    /* private: */
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};

struct DeviceState {
    /* private: */
    Object parent_obj;
    /* public: */
    ...
};

struct PCIDevice {
    DeviceState qdev;
    ...
};
```

## 初始化

### 类的初始化

根据[前面章节](#类)的介绍，**QOM**使用**struct TypeInfo**和**Class**结构体共同来描述类，类的初始化也就是这两个数据的初始化，包括如下几个步骤

- 注册类

    **QOM**使用[**type_init**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qemu/module.h#L56)宏注册类信息，如下所示

    ```c
    /*
     * #0  register_module_init (fn=0x555555a9b5a8 <pci_register_types>, type=MODULE_INIT_QOM) at ../../qemu/util/module.c:75
     * #1  0x0000555555a9b63c in do_qemu_init_pci_register_types () at ../../qemu/hw/pci/pci.c:2851
     * #2  0x00007ffff7829ebb in call_init (env=<optimized out>, argv=0x7fffffffdc58, argc=29) at ../csu/libc-start.c:145
     * #3  __libc_start_main_impl (main=0x555555e92809 <main>, argc=29, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48) at ../csu/libc-start.c:379
     * #4  0x000055555586ba15 in _start ()
     */
    #define type_init(function) module_init(function, MODULE_INIT_QOM)

    /* This should not be used directly.  Use block_init etc. instead.  */
    #define module_init(function, type)                                         \
    static void __attribute__((constructor)) do_qemu_init_ ## function(void)    \
    {                                                                           \
        register_module_init(function, type);                                   \
    }

    void register_module_init(void (*fn)(void), module_init_type type)
    {
        ModuleEntry *e;
        ModuleTypeList *l;

        e = g_malloc0(sizeof(*e));
        e->init = fn;
        e->type = type;

        l = find_type(type);

        QTAILQ_INSERT_TAIL(l, e, node);
    }

    static const TypeInfo pci_device_type_info = {
        .name = TYPE_PCI_DEVICE,
        .parent = TYPE_DEVICE,
        .instance_size = sizeof(PCIDevice),
        .abstract = true,
        .class_size = sizeof(PCIDeviceClass),
        .class_init = pci_device_class_init,
        .class_base_init = pci_device_class_base_init,
    };

    static void pci_register_types(void)
    {
        ...
        type_register_static(&pci_device_type_info);
    }

    type_init(pci_register_types)
    ```

    可以看到，**QOM**通过`__attribute((constructor))`标记让`do_qemu_init_X()`函数在`main()`函数之前运行。而`do_qemu_init_X()`函数是将用户自定义函数(这里是`pci_register_types()`函数)插入到`init_type_list[MODULE_INIT_QOM]`链表上

- 生成**struct TypeImpl**

    在`main()`中，`init_type_list[MODULE_INIT_QOM]`链表上所有的之前插入的用户自定义函数都会在[**module_call_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/module.c#L97)中执行，调用栈如下所示
    ```c
    /*
     * #0  type_register_static (info=0x555556ea5540 <pci_device_type_info>) at ../../qemu/qom/object.c:195
     * #1  0x0000555555a9b619 in pci_register_types () at ../../qemu/hw/pci/pci.c:2848
     * #2  0x00005555560b0d54 in module_call_init (type=MODULE_INIT_QOM) at ../../qemu/util/module.c:109
     * #3  0x0000555555bd3ce4 in qemu_init_subsystems () at ../../qemu/system/runstate.c:818
     * #4  0x0000555555bdb08b in qemu_init (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/vl.c:2786
     * #5  0x0000555555e9282d in main (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/main.c:47
     * #6  0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=29, argv=argv@entry=0x7fffffffdc58) at ../sysdeps/nptl/libc_start_call_main.h:58
     * #7  0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=29, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48) at ../csu/libc-start.c:392
     * #8  0x000055555586ba15 in _start ()
     */
    ```

    用户自定义函数通过[**type_register_static()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L193)生成[**struct TypeImpl**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L49)数据，并将其插入到一个全局**GHashTable**中，如下所示。随后可以通过类的名称调用[**type_table_lookup**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L99)获取**struct TypeImpl**数据，**struct TypeImpl**数据包含了**struct TypeInfo**数据和**Class**结构体数据(此时还未初始化)，也就是类的全部信息。
    ```c
    /*
     * #0  type_register_internal (info=0x555556ea5540 <pci_device_type_info>) at ../../qemu/qom/object.c:176
     * #1  0x0000555555e9df0a in type_register (info=0x555556ea5540 <pci_device_type_info>) at ../../qemu/qom/object.c:190
     * #2  0x0000555555e9df30 in type_register_static (info=0x555556ea5540 <pci_device_type_info>) at ../../qemu/qom/object.c:195
     * #3  0x0000555555a9b619 in pci_register_types () at ../../qemu/hw/pci/pci.c:2848
     * #4  0x00005555560b0d54 in module_call_init (type=MODULE_INIT_QOM) at ../../qemu/util/module.c:109
     * #5  0x0000555555bd3ce4 in qemu_init_subsystems () at ../../qemu/system/runstate.c:818
     * #6  0x0000555555bdb08b in qemu_init (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/vl.c:2786
     * #7  0x0000555555e9282d in main (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/main.c:47
     * #8  0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=29, argv=argv@entry=0x7fffffffdc58) at ../sysdeps/nptl/libc_start_call_main.h:58
     * #9  0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=29, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48) at ../csu/libc-start.c:392
     * #10 0x000055555586ba15 in _start ()
     */
    static TypeImpl *type_register_internal(const TypeInfo *info)
    {
        TypeImpl *ti;

        if (!type_name_is_valid(info->name)) {
            fprintf(stderr, "Registering '%s' with illegal type name\n", info->name);
            abort();
        }

        ti = type_new(info);

        type_table_add(ti);
        return ti;
    }

    static void type_table_add(TypeImpl *ti)
    {
        assert(!enumerating_types);
        g_hash_table_insert(type_table_get(), (void *)ti->name, ti);
    }

    static GHashTable *type_table_get(void)
    {
        static GHashTable *type_table;

        if (type_table == NULL) {
            type_table = g_hash_table_new(g_str_hash, g_str_equal);
        }

    return type_table;
    }

    struct TypeImpl
    {
        const char *name;

        size_t class_size;

        size_t instance_size;
        size_t instance_align;

        void (*class_init)(ObjectClass *klass, void *data);
        void (*class_base_init)(ObjectClass *klass, void *data);

        void *class_data;

        void (*instance_init)(Object *obj);
        void (*instance_post_init)(Object *obj);
        void (*instance_finalize)(Object *obj);

        bool abstract;

        const char *parent;
        TypeImpl *parent_type;

        ObjectClass *class;

        int num_interfaces;
        InterfaceImpl interfaces[MAX_INTERFACES];
    };
    ```

- 初始化**Class**结构体
    这里初始化类的最后一部分数据，即**Class**结构体。其往往在生成**struct TypeImpl**之后且对象初始化之前通过[**type_initialize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L337)进行，如下所示
    ```c
    /*
     * #0  pci_device_class_init (klass=0x555557108080, data=0x0) at ../../qemu/hw/pci/pci.c:2630
     * #1  0x0000555555e9e904 in type_initialize (ti=0x5555570997c0) at ../../qemu/qom/object.c:418
     * #2  0x0000555555e9e65d in type_initialize (ti=0x555557091ba0) at ../../qemu/qom/object.c:366
     * #3  0x0000555555e9e65d in type_initialize (ti=0x555557091f60) at ../../qemu/qom/object.c:366
     * #4  0x0000555555ea02b7 in object_class_foreach_tramp (key=0x5555570920e0, value=0x555557091f60, opaque=0x7fffffffd8a0) at ../../qemu/qom/object.c:1133
     * #5  0x00007ffff7b9d6b8 in g_hash_table_foreach () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
     * #6  0x0000555555ea03a7 in object_class_foreach (fn=0x555555ea0532 <object_class_get_list_tramp>, implements_type=0x555556274512 "machine", include_abstract=false, opaque=0x7fffffffd8f0) at ../../qemu/qom/object.c:1155
     * #7  0x0000555555ea05c0 in object_class_get_list (implements_type=0x555556274512 "machine", include_abstract=false) at ../../qemu/qom/object.c:1212
     * #8  0x0000555555bd8192 in select_machine (qdict=0x5555570e5ce0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/system/vl.c:1661
     * #9  0x0000555555bd935b in qemu_create_machine (qdict=0x5555570e5ce0) at ../../qemu/system/vl.c:2101
     * #10 0x0000555555bdd50f in qemu_init (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/vl.c:3664
     * #11 0x0000555555e9282d in main (argc=29, argv=0x7fffffffdc58) at ../../qemu/system/main.c:47
     * #12 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=29, argv=argv@entry=0x7fffffffdc58) at ../sysdeps/nptl/libc_start_call_main.h:58
     * #13 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=29, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48) at ../csu/libc-start.c:392
     * #14 0x000055555586ba15 in _start ()
     */
    static void type_initialize(TypeImpl *ti)
    {
        TypeImpl *parent;
        if (ti->class) {
            return;
        }
        ...
        ti->class = g_malloc0(ti->class_size);

        parent = type_get_parent(ti);
        if (parent) {
            type_initialize(parent);
            memcpy(ti->class, parent->class, parent->class_size);
            ...
        }

        ti->class->properties = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
                                                      object_property_free);
        ti->class->type = ti;

        while (parent) {
            if (parent->class_base_init) {
                parent->class_base_init(ti->class, ti->class_data);
            }
            parent = type_get_parent(parent);
        }

        if (ti->class_init) {
            ti->class_init(ti->class, ti->class_data);
        }
    }
    ```
    **type_initialize()**首先填充**struct TypeImpl**和**Class**结构体相关的字段，此时**struct TypeImpl**才完整的包含了类的所有信息。之后初始化所有父类的**Class**结构体，并依次调用所有父类的**class_base_init()**和自己的**class_init()**从而最终完成类的初始化。

### 对象初始化

根据[前面章节](#对象)的介绍，**QOM**使用**Object**结构体来描述对象，则对象的初始化也就是该数据结构的初始化。
**QOM**根据对象的类名称调用**type_table_lookup()**获取类对应的**struct TypeImpl**，然后使用[**object_initialize_with_type()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L557)来创建并初始化一个对象实例，如下所示

```c
/*
 * #0  object_init_with_type (obj=0x5555574030d0, ti=0x5555570997c0) at ../../qemu/qom/object.c:424
 * #1  0x0000555555e9e95c in object_init_with_type (obj=0x5555574030d0, ti=0x55555709c960) at ../../qemu/qom/object.c:425
 * #2  0x0000555555e9ef40 in object_initialize_with_type (obj=0x5555574030d0, size=17776, type=0x55555709c960) at ../../qemu/qom/object.c:571
 * #3  0x0000555555e9f70f in object_new_with_type (type=0x55555709c960) at ../../qemu/qom/object.c:791
 * #4  0x0000555555e9f77b in object_new (typename=0x5555573cd3b0 "i440FX") at ../../qemu/qom/object.c:806
 * #5  0x0000555555e96faa in qdev_new (name=0x5555573cd3b0 "i440FX") at ../../qemu/hw/core/qdev.c:166
 * #6  0x0000555555a9999f in pci_new_internal (devfn=0, multifunction=false, name=0x5555573cd3b0 "i440FX") at ../../qemu/hw/pci/pci.c:2168
 * #7  0x0000555555a99a40 in pci_new (devfn=0, name=0x5555573cd3b0 "i440FX") at ../../qemu/hw/pci/pci.c:2181
 * #8  0x0000555555a99afd in pci_create_simple (bus=0x555557402480, devfn=0, name=0x5555573cd3b0 "i440FX") at ../../qemu/hw/pci/pci.c:2199
 * #9  0x0000555555ab5ec0 in i440fx_pcihost_realize (dev=0x5555573cc050, errp=0x7fffffffd520) at ../../qemu/hw/pci-host/i440fx.c:274
 * #10 0x0000555555e97d8e in device_set_realized (obj=0x5555573cc050, value=true, errp=0x7fffffffd630) at ../../qemu/hw/core/qdev.c:510
 * #11 0x0000555555ea3595 in property_set_bool (obj=0x5555573cc050, v=0x5555573cd550, name=0x5555562f4071 "realized", opaque=0x5555570edd00, errp=0x7fffffffd630) at ../../qemu/qom/object.c:2358
 * #12 0x0000555555ea112b in object_property_set (obj=0x5555573cc050, name=0x5555562f4071 "realized", v=0x5555573cd550, errp=0x7fffffffd630) at ../../qemu/qom/object.c:1472
 * #13 0x0000555555ea5d64 in object_property_set_qobject (obj=0x5555573cc050, name=0x5555562f4071 "realized", value=0x5555573cd270, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/qom-qobject.c:28
 * #14 0x0000555555ea14e4 in object_property_set_bool (obj=0x5555573cc050, name=0x5555562f4071 "realized", value=true, errp=0x55555705bca0 <error_fatal>) at ../../qemu/qom/object.c:1541
 * #15 0x0000555555e974a8 in qdev_realize (dev=0x5555573cc050, bus=0x55555735df80, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:292
 * #16 0x0000555555e974e1 in qdev_realize_and_unref (dev=0x5555573cc050, bus=0x55555735df80, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/qdev.c:299
 * #17 0x00005555559658fa in sysbus_realize_and_unref (dev=0x5555573cc050, errp=0x55555705bca0 <error_fatal>) at ../../qemu/hw/core/sysbus.c:261
 * #18 0x0000555555cae1c5 in pc_init1 (machine=0x555557355400, pci_type=0x5555562a5bbb "i440FX") at ../../qemu/hw/i386/pc_piix.c:212
 * #19 0x0000555555caee7d in pc_init_v9_0 (machine=0x555557355400) at ../../qemu/hw/i386/pc_piix.c:523
 * #20 0x000055555595e63e in machine_run_board_init (machine=0x555557355400, mem_path=0x0, errp=0x7fffffffd910) at ../../qemu/hw/core/machine.c:1547
 * #21 0x0000555555bda9d6 in qemu_init_board () at ../../qemu/system/vl.c:2613
 * #22 0x0000555555bdace5 in qmp_x_exit_preconfig (errp=0x55555705bca0 <error_fatal>) at ../../qemu/system/vl.c:2705
 * #23 0x0000555555bdd6a2 in qemu_init (argc=29, argv=0x7fffffffdc48) at ../../qemu/system/vl.c:3739
 * #24 0x0000555555e9282d in main (argc=29, argv=0x7fffffffdc48) at ../../qemu/system/main.c:47
 * #25 0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=29, argv=argv@entry=0x7fffffffdc48) at ../sysdeps/nptl/libc_start_call_main.h:58
 * #26 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=29, argv=0x7fffffffdc48, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc38) at ../csu/libc-start.c:392
 * #27 0x000055555586ba15 in _start ()
 */
static void object_initialize_with_type(Object *obj, size_t size, TypeImpl *type)
{
    type_initialize(type);
    ...
    memset(obj, 0, type->instance_size);
    obj->class = type->class;
    object_ref(obj);
    object_class_property_init_all(obj);
    obj->properties = g_hash_table_new_full(g_str_hash, g_str_equal,
                                            NULL, object_property_free);
    object_init_with_type(obj, type);
    object_post_init_with_type(obj, type);
}

static void object_init_with_type(Object *obj, TypeImpl *ti)
{
    if (type_has_parent(ti)) {
        object_init_with_type(obj, type_get_parent(ti));
    }

    if (ti->instance_init) {
        ti->instance_init(obj);
    }
}

static void object_post_init_with_type(Object *obj, TypeImpl *ti)
{
    if (ti->instance_post_init) {
        ti->instance_post_init(obj);
    }

    if (type_has_parent(ti)) {
        object_post_init_with_type(obj, type_get_parent(ti));
    }
}
```
**object_initialize_with_type()**首先调用**type_initialize()**确保类被初始化，然后调用**object_init_with_type()**和**objet_post_init_with_type()**，从而递归调用对象和对象所有父类的对象初始化相关函数。

## 类型转换

**QOM**同样实现了面向对象编程中的cast概念。根据[类](#类)和[对象](#对象)章节的介绍，相关结构体在起始偏移处存放了父类的结构体，因此向上转型始终是安全的；而为了实现向下转型，**QOM**通过[**OBJECT_DECLARE_TYPE()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qom/object.h#L233)宏声明了诸多的helper函数，如下所示

```c
/**
 * OBJECT_DECLARE_TYPE:
 * @InstanceType: instance struct name
 * @ClassType: class struct name
 * @MODULE_OBJ_NAME: the object name in uppercase with underscore separators
 *
 * This macro is typically used in a header file, and will:
 *
 *   - create the typedefs for the object and class structs
 *   - register the type for use with g_autoptr
 *   - provide three standard type cast functions
 *
 * The object struct and class struct need to be declared manually.
 */
#define OBJECT_DECLARE_TYPE(InstanceType, ClassType, MODULE_OBJ_NAME) \
    typedef struct InstanceType InstanceType; \
    typedef struct ClassType ClassType; \
    ... \
    DECLARE_OBJ_CHECKERS(InstanceType, ClassType, \
                         MODULE_OBJ_NAME, TYPE_##MODULE_OBJ_NAME)

/**
 * DECLARE_OBJ_CHECKERS:
 * @InstanceType: instance struct name
 * @ClassType: class struct name
 * @OBJ_NAME: the object name in uppercase with underscore separators
 * @TYPENAME: type name
 *
 * Direct usage of this macro should be avoided, and the complete
 * OBJECT_DECLARE_TYPE macro is recommended instead.
 *
 * This macro will provide the three standard type cast functions for a
 * QOM type.
 */
#define DECLARE_OBJ_CHECKERS(InstanceType, ClassType, OBJ_NAME, TYPENAME) \
    DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    \
    DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME)

/**
 * DECLARE_INSTANCE_CHECKER:
 * @InstanceType: instance struct name
 * @OBJ_NAME: the object name in uppercase with underscore separators
 * @TYPENAME: type name
 *
 * Direct usage of this macro should be avoided, and the complete
 * OBJECT_DECLARE_TYPE macro is recommended instead.
 *
 * This macro will provide the instance type cast functions for a
 * QOM type.
 */
#define DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED InstanceType * \
    OBJ_NAME(const void *obj) \
    { return OBJECT_CHECK(InstanceType, obj, TYPENAME); }

/**
 * OBJECT_CHECK:
 * @type: The C type to use for the return value.
 * @obj: A derivative of @type to cast.
 * @name: The QOM typename of @type
 *
 * A type safe version of @object_dynamic_cast_assert.  Typically each class
 * will define a macro based on this type to perform type safe dynamic_casts to
 * this object type.
 *
 * If an invalid object is passed to this function, a run time assert will be
 * generated.
 */
#define OBJECT_CHECK(type, obj, name) \
    ((type *)object_dynamic_cast_assert(OBJECT(obj), (name), \
                                        __FILE__, __LINE__, __func__))

/**
 * DECLARE_CLASS_CHECKERS:
 * @ClassType: class struct name
 * @OBJ_NAME: the object name in uppercase with underscore separators
 * @TYPENAME: type name
 *
 * Direct usage of this macro should be avoided, and the complete
 * OBJECT_DECLARE_TYPE macro is recommended instead.
 *
 * This macro will provide the class type cast functions for a
 * QOM type.
 */
#define DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_GET_CLASS(const void *obj) \
    { return OBJECT_GET_CLASS(ClassType, obj, TYPENAME); } \
    \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_CLASS(const void *klass) \
    { return OBJECT_CLASS_CHECK(ClassType, klass, TYPENAME); }

/**
 * OBJECT_GET_CLASS:
 * @class: The C type to use for the return value.
 * @obj: The object to obtain the class for.
 * @name: The QOM typename of @obj.
 *
 * This function will return a specific class for a given object.  Its generally
 * used by each type to provide a type safe macro to get a specific class type
 * from an object.
 */
#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

/**
 * OBJECT_CLASS_CHECK:
 * @class_type: The C type to use for the return value.
 * @class: A derivative class of @class_type to cast.
 * @name: the QOM typename of @class_type.
 *
 * A type safe version of @object_class_dynamic_cast_assert.  This macro is
 * typically wrapped by each type to perform type safe casts of a class to a
 * specific class type.
 */
#define OBJECT_CLASS_CHECK(class_type, class, name) \
    ((class_type *)object_class_dynamic_cast_assert(OBJECT_CLASS(class), (name), \
                                               __FILE__, __LINE__, __func__))
```
可以看到，**QOM**提供了**OBJ_NAME()**将任何一个**struct Object**转换为**Object**结构体、**OBJ_NAME##_GET_CLASS()**从**struct Object**提取**Class**结构体和**OBJ_NAME##_CLASS**从**struct ObjectClass**转换为**Class**结构体的函数。

由于**struct Object**的**class**字段指向对应的**struct ObjectClass**，而**struct ObjectClass**的**type**字段指向真实的**struct TypeImpl**内容,基于此，**QOM**通过[**object_dynamic_cast_assert()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L921)和[**object_class_dynamic_cast_assert()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1008)，检查目标类或对象是否为这些指针的祖先从而进行安全的转换，如下所示

```c
Object *object_dynamic_cast_assert(Object *obj, const char *typename,
                                   const char *file, int line, const char *func)
{
    ...
#ifdef CONFIG_QOM_CAST_DEBUG
    int i;
    Object *inst;

    for (i = 0; obj && i < OBJECT_CLASS_CAST_CACHE; i++) {
        if (qatomic_read(&obj->class->object_cast_cache[i]) == typename) {
            goto out;
        }
    }

    inst = object_dynamic_cast(obj, typename);

    if (!inst && obj) {
        fprintf(stderr, "%s:%d:%s: Object %p is not an instance of type %s\n",
                file, line, func, obj, typename);
        abort();
    }

    assert(obj == inst);

    if (obj && obj == inst) {
        for (i = 1; i < OBJECT_CLASS_CAST_CACHE; i++) {
            qatomic_set(&obj->class->object_cast_cache[i - 1],
                       qatomic_read(&obj->class->object_cast_cache[i]));
        }
        qatomic_set(&obj->class->object_cast_cache[i - 1], typename);
    }

out:
#endif
    return obj;
}

Object *object_dynamic_cast(Object *obj, const char *typename)
{
    if (obj && object_class_dynamic_cast(object_get_class(obj), typename)) {
        return obj;
    }

    return NULL;
}

ObjectClass *object_class_dynamic_cast(ObjectClass *class,
                                       const char *typename)
{
    ObjectClass *ret = NULL;
    TypeImpl *target_type;
    TypeImpl *type;

    if (!class) {
        return NULL;
    }

    /* A simple fast path that can trigger a lot for leaf classes.  */
    type = class->type;
    if (type->name == typename) {
        return class;
    }

    target_type = type_get_by_name(typename);
    if (!target_type) {
        /* target class type unknown, so fail the cast */
        return NULL;
    }
    ...
    if (type_is_ancestor(type, target_type)) {
        ret = class;
    }

    return ret;
}

static bool type_is_ancestor(TypeImpl *type, TypeImpl *target_type)
{
    assert(target_type);

    /* Check if target_type is a direct ancestor of type */
    while (type) {
        if (type == target_type) {
            return true;
        }

        type = type_get_parent(type);
    }

    return false;
}

ObjectClass *object_class_dynamic_cast_assert(ObjectClass *class,
                                              const char *typename,
                                              const char *file, int line,
                                              const char *func)
{
    ObjectClass *ret;

    trace_object_class_dynamic_cast_assert(class ? class->type->name : "(null)",
                                           typename, file, line, func);

#ifdef CONFIG_QOM_CAST_DEBUG
    int i;

    for (i = 0; class && i < OBJECT_CLASS_CAST_CACHE; i++) {
        if (qatomic_read(&class->class_cast_cache[i]) == typename) {
            ret = class;
            goto out;
        }
    }
#else
    if (!class || !class->interfaces) {
        return class;
    }
#endif

    ret = object_class_dynamic_cast(class, typename);
    if (!ret && class) {
        fprintf(stderr, "%s:%d:%s: Object %p is not an instance of type %s\n",
                file, line, func, class, typename);
        abort();
    }

#ifdef CONFIG_QOM_CAST_DEBUG
    if (class && ret == class) {
        for (i = 1; i < OBJECT_CLASS_CAST_CACHE; i++) {
            qatomic_set(&class->class_cast_cache[i - 1],
                       qatomic_read(&class->class_cast_cache[i]));
        }
        qatomic_set(&class->class_cast_cache[i - 1], typename);
    }
out:
#endif
    return ret;
}
```

## 属性
类似于linux中的sysfs，考虑到**QOM**的每个类的**Class**结构体基类是[**struct ObjectClass**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qom/object.h#L127)，每个对象的**Object**结构体基类是[**Object**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qom/object.h#L153)，为了提供一套类和对象的公用对外接口，**QOM**为**struct ObjectClass**和**struct Object**添加了**properties**域，即属性名称到[**struct ObjectProperty**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qom/object.h#L88)的哈希表，如下所示
```c
struct ObjectProperty
{
    char *name;
    char *type;
    char *description;
    ObjectPropertyAccessor *get;
    ObjectPropertyAccessor *set;
    ObjectPropertyResolve *resolve;
    ObjectPropertyRelease *release;
    ObjectPropertyInit *init;
    void *opaque;
    QObject *defval;
};

/**
 * typedef ObjectPropertyAccessor:
 * @obj: the object that owns the property
 * @v: the visitor that contains the property data
 * @name: the name of the property
 * @opaque: the object property opaque
 * @errp: a pointer to an Error that is filled if getting/setting fails.
 *
 * Called when trying to get/set a property.
 */
typedef void (ObjectPropertyAccessor)(Object *obj,
                                      Visitor *v,
                                      const char *name,
                                      void *opaque,
                                      Error **errp);

/**
 * typedef ObjectPropertyResolve:
 * @obj: the object that owns the property
 * @opaque: the opaque registered with the property
 * @part: the name of the property
 *
 * Resolves the #Object corresponding to property @part.
 *
 * The returned object can also be used as a starting point
 * to resolve a relative path starting with "@part".
 *
 * Returns: If @path is the path that led to @obj, the function
 * returns the #Object corresponding to "@path/@part".
 * If "@path/@part" is not a valid object path, it returns #NULL.
 */
typedef Object *(ObjectPropertyResolve)(Object *obj,
                                        void *opaque,
                                        const char *part);

/**
 * typedef ObjectPropertyRelease:
 * @obj: the object that owns the property
 * @name: the name of the property
 * @opaque: the opaque registered with the property
 *
 * Called when a property is removed from a object.
 */
typedef void (ObjectPropertyRelease)(Object *obj,
                                     const char *name,
                                     void *opaque);
```
其中，`name`表示属性的名称，`type`表示属性的类型，而`opaque`指向一个属性的具体类型的结构体信息，如下图所示
```
┌────────────────┐
│                │
│                │
├────────────────┤
│  properties    ├───────────────┬──────────────────────────────────────►
├────────────────┤               │
│                │               │
│                │        ┌──────▼──────┐
└────────────────┘        │    name     │
struct ObjectClass        ├─────────────┤
                          │    type     ├─────────►"bool"
                          ├─────────────┤
                          │    ...      │
                          ├─────────────┤
                          │    opaque   ├─────────►┌──────────┐
                          └─────────────┘          │          │
                       struct ObjectProperty       └──────────┘
                                               struct BoolProperty
```

**QOM**分别使用[**object_class_property_find()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1399)、[**object_class_property_add()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1321)和[**object_property_find()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1348)、[**object_property_add()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qom/object.c#L1310)来查找和设置这些属性，如下所示
```c
ObjectProperty *object_class_property_find(ObjectClass *klass, const char *name)
{
    ObjectClass *parent_klass;

    parent_klass = object_class_get_parent(klass);
    if (parent_klass) {
        ObjectProperty *prop =
            object_class_property_find(parent_klass, name);
        if (prop) {
            return prop;
        }
    }

    return g_hash_table_lookup(klass->properties, name);
}

ObjectProperty *
object_class_property_add(ObjectClass *klass,
                          const char *name,
                          const char *type,
                          ObjectPropertyAccessor *get,
                          ObjectPropertyAccessor *set,
                          ObjectPropertyRelease *release,
                          void *opaque)
{
    ObjectProperty *prop;

    assert(!object_class_property_find(klass, name));

    prop = g_malloc0(sizeof(*prop));

    prop->name = g_strdup(name);
    prop->type = g_strdup(type);

    prop->get = get;
    prop->set = set;
    prop->release = release;
    prop->opaque = opaque;

    g_hash_table_insert(klass->properties, prop->name, prop);

    return prop;
}

ObjectProperty *object_property_find(Object *obj, const char *name)
{
    ObjectProperty *prop;
    ObjectClass *klass = object_get_class(obj);

    prop = object_class_property_find(klass, name);
    if (prop) {
        return prop;
    }

    return g_hash_table_lookup(obj->properties, name);
}

bool object_property_set(Object *obj, const char *name, Visitor *v,
                         Error **errp)
{
    ERRP_GUARD();
    ObjectProperty *prop = object_property_find_err(obj, name, errp);

    if (prop == NULL) {
        return false;
    }

    if (!prop->set) {
        error_setg(errp, "Property '%s.%s' is not writable",
                   object_get_typename(obj), name);
        return false;
    }
    prop->set(obj, v, name, prop->opaque, errp);
    return !*errp;
}

ObjectProperty *
object_property_add(Object *obj, const char *name, const char *type,
                    ObjectPropertyAccessor *get,
                    ObjectPropertyAccessor *set,
                    ObjectPropertyRelease *release,
                    void *opaque)
{
    return object_property_try_add(obj, name, type, get, set, release,
                                   opaque, &error_abort);
}

ObjectProperty *
object_property_try_add(Object *obj, const char *name, const char *type,
                        ObjectPropertyAccessor *get,
                        ObjectPropertyAccessor *set,
                        ObjectPropertyRelease *release,
                        void *opaque, Error **errp)
{
    ObjectProperty *prop;
    ...
    if (object_property_find(obj, name) != NULL) {
        error_setg(errp, "attempt to add duplicate property '%s' to object (type '%s')",
                   name, object_get_typename(obj));
        return NULL;
    }

    prop = g_malloc0(sizeof(*prop));

    prop->name = g_strdup(name);
    prop->type = g_strdup(type);

    prop->get = get;
    prop->set = set;
    prop->release = release;
    prop->opaque = opaque;

    g_hash_table_insert(obj->properties, prop->name, prop);
    return prop;
}
```

# 参数

**QEMU**允许用户通过命令行参数来自定义虚拟机的设置，如`qemu-system-x86_64 -nic user,model=virtio-net-pci`，这里介绍一下**QEMU**的参数的相关机制。

## 数据结构

**QEMU**参数的数据结构整体关系如下所示
```
     ┌────┬─────────────┐
     │name│"nic"        │
     ├────┼─────────────┤
     │head│             ├────┐
     └────┴─────────────┘    │
      struct QemuOptsList◄─┐ │
                           │ │
                           │ │
     ┌────┬─────────────┐  │ │
     │id  │             │  │ │
     ├────┼─────────────┤  │ │
     │list│             ├──┘ │
     ├────┼─────────────┤    │
     │next│             │◄───┘
     ├────┼─────────────┤
┌────┤head│             │
│    └────┴─────────────┘
│  ┌─► struct QemuOpts  ◄──────────┐
│  │                               │
│  │                               │
│  │                               │
│  │                               │
│  │ ┌────┬────────┐               │    ┌────┬────────────────┐
│  │ │name│"user"  │               │    │name│"model"         │
│  │ ├────┼────────┤               │    ├────┼────────────────┤
│  │ │str │        │               │    │str │"virtio-net-pci"│
│  │ ├────┼────────┤               │    ├────┼────────────────┤
│  └─┤opts│        │               └────┤opts│                │
│    ├────┼────────┤                    ├────┼────────────────┤
└───►│next│        ├───────────────────►│next│                │
     └────┴────────┘                    └────┴────────────────┘
      struct QemuOpt                     struct QemuOpt
```

### struct QemuOptsList

**QEMU**将所有参数分成了几个大选项，如`-nic`、`-cpu`等，每一个大选项使用结构体[**struct QemuOptsList**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qemu/option.h#L64)表示
```c
struct QemuOptsList {
    const char *name;
    const char *implied_opt_name;
    bool merge_lists;  /* Merge multiple uses of option into a single list? */
    QTAILQ_HEAD(, QemuOpts) head;
    QemuOptDesc desc[];
};

// -nic选项的样例
QemuOptsList qemu_nic_opts = {
    .name = "nic",
    .implied_opt_name = "type",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_nic_opts.head),
    .desc = {
        /*
         * no elements => accept any params
         * validation will happen later
         */
        { /* end of list */ }
    },
};
```

### struct QemuOpt

每个**struct QemuOptsList**大选项下还支持多个小选项，如`-nic`下的`user`和`model`等小选项，每个小选项由[**struct QemuOpt**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qemu/option_int.h#L32)表示
```c
struct QemuOpt {
    char *name;
    char *str;

    const QemuOptDesc *desc;
    union {
        bool boolean;
        uint64_t uint;
    } value;

    QemuOpts     *opts;
    QTAILQ_ENTRY(QemuOpt) next;
};
```
其中**name**表示小选项的字符串表示，**str**表示对应的值。需要注意的是，**struct QemuOpt**并不和**struct QemuOptsList**直接联系，这是因为**QEMU**命令行可能会指定创建两个相同参数的设备，因此会使用**struct QemuOpts**连接。

### struct QemuOpts

[**struct QemuOpts**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qemu/option_int.h#L46)用于连接**struct QemuOpt**和**struct QemuOptsList**，可以理解为一个大选项的实例
```c
struct QemuOpts {
    char *id;
    QemuOptsList *list;
    Location loc;
    QTAILQ_HEAD(, QemuOpt) head;
    QTAILQ_ENTRY(QemuOpts) next;
};
```

## 解析

**QEMU**会在[**qemu_init()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/vl.c#L2734)中解析命令行参数，并填充相关的数据结构
```c
void qemu_init(int argc, char **argv)
{
    ...
    /* first pass of option parsing */
    optind = 1;
    while (optind < argc) {
        if (argv[optind][0] != '-') {
            /* disk image */
            optind++;
        } else {
            const QEMUOption *popt;

            popt = lookup_opt(argc, argv, &optarg, &optind);
            switch (popt->index) {
            case QEMU_OPTION_nouserconfig:
                userconfig = false;
                break;
            }
        }
    }

    ...

    /* second pass of option parsing */
    optind = 1;
    for(;;) {
        if (optind >= argc)
            break;
        if (argv[optind][0] != '-') {
            loc_set_cmdline(argv, optind, 1);
            drive_add(IF_DEFAULT, 0, argv[optind++], HD_OPTS);
        } else {
            const QEMUOption *popt;

            popt = lookup_opt(argc, argv, &optarg, &optind);
            if (!(popt->arch_mask & arch_type)) {
                error_report("Option not supported for this target");
                exit(1);
            }
            switch(popt->index) {
            ...
            case QEMU_OPTION_nic:
                default_net = 0;
                net_client_parse(qemu_find_opts("nic"), optarg);
                break;
            ...
            }
        }
    }
}
```

**QEMU**首先在[**lookup_opt()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/vl.c#L1618)中解析出所属的大选项，然后再继续解析出一个大选项的实例**struct QemuOpts**。

以`-nic`大选项为例，其在[**net_client_parse()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c#L1920)中解析出**struct QemuOpts**并插入在**nic**对应的**struct QemuOptsList**中，如下所示
```c
static bool opts_do_parse(QemuOpts *opts, const char *params,
                          const char *firstname,
                          bool warn_on_flag, bool *help_wanted, Error **errp)
{
    char *option, *value;
    const char *p;
    QemuOpt *opt;

    for (p = params; *p;) {
        p = get_opt_name_value(p, firstname, warn_on_flag, help_wanted, &option, &value);
        if (help_wanted && *help_wanted) {
            g_free(option);
            g_free(value);
            return false;
        }
        firstname = NULL;

        if (!strcmp(option, "id")) {
            g_free(option);
            g_free(value);
            continue;
        }

        opt = opt_create(opts, option, value);
        g_free(option);
        if (!opt_validate(opt, errp)) {
            qemu_opt_del(opt);
            return false;
        }
    }

    return true;
}

static QemuOpts *opts_parse(QemuOptsList *list, const char *params,
                            bool permit_abbrev,
                            bool warn_on_flag, bool *help_wanted, Error **errp)
{
    const char *firstname;
    char *id = opts_parse_id(params);
    QemuOpts *opts;

    assert(!permit_abbrev || list->implied_opt_name);
    firstname = permit_abbrev ? list->implied_opt_name : NULL;

    opts = qemu_opts_create(list, id, !list->merge_lists, errp);
    g_free(id);
    if (opts == NULL) {
        return NULL;
    }

    if (!opts_do_parse(opts, params, firstname,
                       warn_on_flag, help_wanted, errp)) {
        qemu_opts_del(opts);
        return NULL;
    }

    return opts;
}

/**
 * Create a QemuOpts in @list and with options parsed from @params.
 * If @permit_abbrev, the first key=value in @params may omit key=,
 * and is treated as if key was @list->implied_opt_name.
 * Report errors with error_report_err().  This is inappropriate in
 * QMP context.  Do not use this function there!
 * Return the new QemuOpts on success, null pointer on error.
 */
QemuOpts *qemu_opts_parse_noisily(QemuOptsList *list, const char *params,
                                  bool permit_abbrev)
{
    Error *err = NULL;
    QemuOpts *opts;
    bool help_wanted = false;

    opts = opts_parse(list, params, permit_abbrev, true,
                      opts_accepts_any(list) ? NULL : &help_wanted,
                      &err);
    if (!opts) {
        assert(!!err + !!help_wanted == 1);
        if (help_wanted) {
            qemu_opts_print_help(list, true);
        } else {
            error_report_err(err);
        }
    }
    return opts;
}

void net_client_parse(QemuOptsList *opts_list, const char *optstr)
{
    if (!qemu_opts_parse_noisily(opts_list, optstr, true)) {
        exit(1);
    }
}
```

可以看到，**QEMU**在[**opts_parse()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/qemu-option.c#L881)中使用[**qemu_opts_create()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/qemu-option.c#L608)创建**struct QemuOpts**实例并插入到**struct QemuOptsList**中，然后使用[**opts_do_parse()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/util/qemu-option.c#L799)解析所有**struct QemuOpt**并插入到**struct QemuOpts**中。

至于检查参数的正确性，则推迟到初始化**nic**设备时在进行即可，如下所示
```c
/*
 * #0  visit_check_struct (v=0x5555570ea430, errp=0x5555570ea550) at ../../qemu/qapi/qapi-visit-core.c:62
 * #1  0x0000555556055353 in visit_type_Netdev (v=0x5555570ea430, name=0x0, obj=0x7fffffffda18, errp=0x55555705bca0 <error_fatal>) at qapi/qapi-visit-net.c:1327
 * #2  0x0000555555c3d0b4 in net_client_init (opts=0x5555570e7f60, is_netdev=true, errp=0x55555705bca0 <error_fatal>) at ../../qemu/net/net.c:1427
 * #3  0x0000555555c3e0f6 in net_param_nic (dummy=0x0, opts=0x5555570e7f60, errp=0x55555705bca0 <error_fatal>) at ../../qemu/net/net.c:1822
 * #4  0x00005555560b9a7c in qemu_opts_foreach (list=0x555556f485e0 <qemu_nic_opts>, func=0x555555c3dd92 <net_param_nic>, opaque=0x0, errp=0x55555705bca0 <error_fatal>) at ../../qemu/util/qemu-option.c:1135
 * #5  0x0000555555c3e2bb in net_init_clients () at ../../qemu/net/net.c:1860
 * #6  0x0000555555bd8ef8 in qemu_create_late_backends () at ../../qemu/system/vl.c:2011
 * #7  0x0000555555bdd5f7 in qemu_init (argc=15, argv=0x7fffffffde08) at ../../qemu/system/vl.c:3712
 * #8  0x0000555555e9282d in main (argc=15, argv=0x7fffffffde08) at ../../qemu/system/main.c:47
 * #9  0x00007ffff7829d90 in __libc_start_call_main (main=main@entry=0x555555e92809 <main>, argc=argc@entry=15, argv=argv@entry=0x7fffffffde08) at ../sysdeps/nptl/libc_start_call_main.h:58
 * #10 0x00007ffff7829e40 in __libc_start_main_impl (main=0x555555e92809 <main>, argc=15, argv=0x7fffffffde08, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffddf8) at ../csu/libc-start.c:392
 * #11 0x000055555586ba15 in _start ()
 */
bool visit_type_NetLegacyNicOptions_members(Visitor *v, NetLegacyNicOptions *obj, Error **errp)
{
    bool has_netdev = !!obj->netdev;
    bool has_macaddr = !!obj->macaddr;
    bool has_model = !!obj->model;
    bool has_addr = !!obj->addr;

    if (visit_optional(v, "netdev", &has_netdev)) {
        if (!visit_type_str(v, "netdev", &obj->netdev, errp)) {
            return false;
        }
    }
    if (visit_optional(v, "macaddr", &has_macaddr)) {
        if (!visit_type_str(v, "macaddr", &obj->macaddr, errp)) {
            return false;
        }
    }
    if (visit_optional(v, "model", &has_model)) {
        if (!visit_type_str(v, "model", &obj->model, errp)) {
            return false;
        }
    }
    if (visit_optional(v, "addr", &has_addr)) {
        if (!visit_type_str(v, "addr", &obj->addr, errp)) {
            return false;
        }
    }
    if (visit_optional(v, "vectors", &obj->has_vectors)) {
        if (!visit_type_uint32(v, "vectors", &obj->vectors, errp)) {
            return false;
        }
    }
    return true;
}

bool visit_type_Netdev_members(Visitor *v, Netdev *obj, Error **errp)
{
    ...
    switch (obj->type) {
    ...
    case NET_CLIENT_DRIVER_NIC:
        return visit_type_NetLegacyNicOptions_members(v, &obj->u.nic, errp);
    ...
    default:
        abort();
    }
    return true;
}

bool visit_type_Netdev(Visitor *v, const char *name,
                 Netdev **obj, Error **errp)
{
    bool ok = false;

    if (!visit_start_struct(v, name, (void **)obj, sizeof(Netdev), errp)) {
        return false;
    }
    if (!*obj) {
        /* incomplete */
        assert(visit_is_dealloc(v));
        ok = true;
        goto out_obj;
    }
    if (!visit_type_Netdev_members(v, *obj, errp)) {
        goto out_obj;
    }
    ok = visit_check_struct(v, errp);
out_obj:
    visit_end_struct(v, (void **)obj);
    if (!ok && visit_is_input(v)) {
        qapi_free_Netdev(*obj);
        *obj = NULL;
    }
    return ok;
}
```

**QEMU**在**visit_type_Netdev()**完成参数的认证，其通过**visit_type_Netdev_members()**解析**nic**大选项预设的小选项，并将**struct QemuOpts**中剩余的小选项当做非法小选项即可。其中**visit_type_Netdev()**函数是通过[**qapi-gen.py**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi-gen.py)基于[**net.json**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/net.json#L97)自动生成的函数。

# 参考

- [The QEMU Object Model (QOM)](https://qemu-project.gitlab.io/qemu/devel/qom.html)
- [QEMU 的一些基础知识及QOM(Qemu Object Model)的部分相关源码阅读](https://www.giantbranch.cn/2020/01/05/QEMU%20%E7%9A%84%E4%B8%80%E4%BA%9B%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86%E5%8F%8AQOM%28Qemu%20Object%20Model%29%E7%9A%84%E9%83%A8%E5%88%86%E7%9B%B8%E5%85%B3%E6%BA%90%E7%A0%81%E9%98%85%E8%AF%BB/)
- [QEMU 中的面向对象 : QOM](https://martins3.github.io/qemu/qom.html)
- [QEMU学习笔记——QOM(Qemu Object Model)](https://www.binss.me/blog/qemu-note-of-qemu-object-model/)
- [编写 QEMU 模拟设备](https://ctf-wiki.org/pwn/virtualization/qemu/environment/build-qemu-dev/#qemu)
- [QEMU's instance_init() vs. realize()](https://people.redhat.com/~thuth/blog/qemu/2018/09/10/instance-init-realize.html)
- [QEMU(1) - QOM](https://blog.csdn.net/lwhuq/article/details/98642184)
- [浅谈QEMU的对象系统 ](https://juejin.cn/post/6844903845550620685)
- [QOM Property](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2018/09/05/qom-property)
- [QOM exegesis and apocalypse](https://www.linux-kvm.org/images/9/90/Kvmforum14-qom.pdf)
- [QEMU参数解析](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2015/09/26/qemu-options)
