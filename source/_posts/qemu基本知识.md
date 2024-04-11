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

## 类

**QOM**使用**struct TypeInfo**和**Class**结构体类型共同描述一个类。

其中**struct TypeInfo**描述类的基本属性，**Class**结构体类型描述静态成员。

### struct TypeInfo

**QOM**中使用[**struct TypeInfo**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/qom/object.h#L412)描述诸如类的名称、父类名称、实例大小和静态成员情况

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

考虑到类会继承父类的成员内容，因此需要在**Class**结构体中包含父类的**Class**数据来实现继承关系。同时为了能安全的实现面向对象编程中的向上转型，总是将父类的数据放在**Class**结构体的最开始，如[**struct PCIDeviceClass**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/hw/pci/pci_device.h#L24)所示。

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

类似于**Class**结构体，考虑到对象同样会继承父类对象的成员内容，因此需要在**Object**结构体中包含父类的**Object**数据来实现继承，父类的数据同样应放在**Object**结构体的最开始以实现向上转型，如[**struct PCIDevice**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/hw/pci/pci_device.h#L56)所示。

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

    **QOM**使用[**type_init**](https://elixir.bootlin.com/qemu/v8.2.2/source/include/qemu/module.h#L56)宏注册类信息，如下所示

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

    在`main()`中，`init_type_list[MODULE_INIT_QOM]`链表上所有的之前插入的用户自定义函数都会在[**module_call_init()**](https://elixir.bootlin.com/qemu/v8.2.2/source/util/module.c#L97)中执行，调用栈如下所示
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

    用户自定义函数通过[**type_register_static()**](https://elixir.bootlin.com/qemu/v8.2.2/source/qom/object.c#L156)生成[**struct TypeImpl**](https://elixir.bootlin.com/qemu/v8.2.2/source/qom/object.c#L49)数据，并将其插入到一个全局**GHashTable**中，如下所示。随后可以通过类的名称调用[**type_table_lookup**](https://elixir.bootlin.com/qemu/v8.2.2/source/qom/object.c#L99)获取**struct TypeImpl**数据，**struct TypeImpl**数据包含了**struct TypeInfo**数据和**Class**结构体数据(此时还未初始化)，也就是类的全部信息。
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
    这里初始化类的最后一部分数据，即**Class**结构体。其往往在生成**struct TypeImpl**之后且对象初始化之前通过[**type_initialize()**](https://elixir.bootlin.com/qemu/v8.2.2/source/qom/object.c#L300)进行，如下所示
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

### ~~对象初始化~~

# 参考

- [The QEMU Object Model (QOM)](https://qemu-project.gitlab.io/qemu/devel/qom.html)
- [QEMU 的一些基础知识及QOM(Qemu Object Model)的部分相关源码阅读](https://www.giantbranch.cn/2020/01/05/QEMU%20%E7%9A%84%E4%B8%80%E4%BA%9B%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86%E5%8F%8AQOM%28Qemu%20Object%20Model%29%E7%9A%84%E9%83%A8%E5%88%86%E7%9B%B8%E5%85%B3%E6%BA%90%E7%A0%81%E9%98%85%E8%AF%BB/)
- [QEMU 中的面向对象 : QOM](https://martins3.github.io/qemu/qom.html)
- [QEMU学习笔记——QOM(Qemu Object Model)](https://www.binss.me/blog/qemu-note-of-qemu-object-model/)
- [编写 QEMU 模拟设备](https://ctf-wiki.org/pwn/virtualization/qemu/environment/build-qemu-dev/#qemu)
- [QEMU's instance_init() vs. realize()](https://people.redhat.com/~thuth/blog/qemu/2018/09/10/instance-init-realize.html)
- [QEMU(1) - QOM](https://blog.csdn.net/lwhuq/article/details/98642184)
- [浅谈QEMU的对象系统 ](https://juejin.cn/post/6844903845550620685)
