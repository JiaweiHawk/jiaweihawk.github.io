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

## ~~初始化~~

# 参考

- [The QEMU Object Model (QOM)](https://qemu-project.gitlab.io/qemu/devel/qom.html)
- [QEMU 的一些基础知识及QOM(Qemu Object Model)的部分相关源码阅读](https://www.giantbranch.cn/2020/01/05/QEMU%20%E7%9A%84%E4%B8%80%E4%BA%9B%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86%E5%8F%8AQOM%28Qemu%20Object%20Model%29%E7%9A%84%E9%83%A8%E5%88%86%E7%9B%B8%E5%85%B3%E6%BA%90%E7%A0%81%E9%98%85%E8%AF%BB/)
- [QEMU 中的面向对象 : QOM](https://martins3.github.io/qemu/qom.html)
- [QEMU学习笔记——QOM(Qemu Object Model)](https://www.binss.me/blog/qemu-note-of-qemu-object-model/)
- [编写 QEMU 模拟设备](https://ctf-wiki.org/pwn/virtualization/qemu/environment/build-qemu-dev/#qemu)
- [QEMU's instance_init() vs. realize()](https://people.redhat.com/~thuth/blog/qemu/2018/09/10/instance-init-realize.html)
- [QEMU(1) - QOM](https://blog.csdn.net/lwhuq/article/details/98642184)
- [浅谈QEMU的对象系统 ](https://juejin.cn/post/6844903845550620685)
