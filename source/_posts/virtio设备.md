---
title: virtio设备
date: 2026-07-27 22:03:02
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

前面{% post_link virtio简介 %}博客简单介绍了virtio的整体思想。这里以virtio-net-pci为例，详细介绍一下virtio设备相关的细节。

# 参数

一般设备往往包括两部分:
- 前端，即呈现给guest的模拟硬件，其行为必须与guest预期看到的硬件行为一致
- 后端，即使用host资源来处理来自前端的数据的对象，即guest中设备数据真正被处理的地方

前端和后端通过各自的参数进行设置，并通过id关联在一起，如下所示
```c
# 前端: guest可以看到pci接口的virtio网卡
-device virtio-net-pci,netdev=hostnet0

# 后端：host使用tap设备处理guest中virtio网卡数据
-netdev tap,id=hostnet0
```

## 框架

qemu 借助 hxtool 与 qapi-gen 等自动化代码生成框架，使开发者仅需编写一份声明式文本，即可在构建期自动生成相应的 .h/.c 文件，从而规避了大规模、强约束且极易出错的手写解析逻辑与样板代码。这里参数的解析即用到了这些框架

### hxtool

hxtool 基于 .hx 文件生成 C 头文件与文档，主要用于 qemu 命令行参数及 hmp 命令的帮助文档与说明文本的生成。

#### 构建过程

qemu 在顶层 [meson.build](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/meson.build#L3271-L3289) 中为每个 `.hx` 文件注册了一个 `custom_target`，在构建期调用 `scripts/hxtool` 将其转换为对应的 `.def` / `.h` 文件，其规则如下

```meson
hxtool = find_program('scripts/hxtool')

hxdep = []
hx_headers = [
  ['qemu-options.hx', 'qemu-options.def'],
  ['qemu-img-cmds.hx', 'qemu-img-cmds.h'],
]
if have_system
  hx_headers += [
    ['hmp-commands.hx', 'hmp-commands.h'],
    ['hmp-commands-info.hx', 'hmp-commands-info.h'],
  ]
endif
foreach d : hx_headers
  hxdep += custom_target(d[1],
                input: files(d[0]),
                output: d[1],
                capture: true,
                command: [hxtool, '-h', '@INPUT0@'])
endforeach
genh += hxdep
```

其中`scripts/hxtool` 本身只是一个几十行的 shell 脚本，本质就是一个"带开关的行过滤器"，用于将混排在一起的"宏调用"和"文档"的`.hx`分离开:

例如[qemu-options.hx](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qemu-options.hx)，其同时包含 `DEF(...)` 的宏调用 和 `SRST`/`ERST` 的文档内容

```
DEF("help", 0, QEMU_OPTION_h,
    "-h or -help     display this help and exit\n", QEMU_ARCH_ALL)
SRST
``-h``
    Display help and exit
ERST

DEF("version", 0, QEMU_OPTION_version,
    "-version        display version information and exit\n", QEMU_ARCH_ALL)
SRST
``-version``
    Display version information and exit
ERST
```

经过`hxtool -h` 过滤后可以生成只包含宏调用的 **qemu-options.def**

```c
DEF("help", 0, QEMU_OPTION_h,
"-h or -help     display this help and exit\n", QEMU_ARCH_ALL)

DEF("version", 0, QEMU_OPTION_version,
"-version        display version information and exit\n", QEMU_ARCH_ALL)
```

#### 使用方式

后续代码通过**include**这份文件，并定义 `DEF` 宏的不同实现即可完成复用：例如[qemu_options[]](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/vl.c#L922) 数组需要选项名称、参数标志、枚举值与架构掩码等信息，则如下定义即可复用

```c
typedef struct QEMUOption {
    const char *name;
    int flags;
    int index;
    uint32_t arch_mask;
} QEMUOption;

static const QEMUOption qemu_options[] = {
    { "h", 0, QEMU_OPTION_h, QEMU_ARCH_ALL },

#define DEF(option, opt_arg, opt_enum, opt_help, arch_mask)     \
    { option, opt_arg, opt_enum, arch_mask },
#define DEFHEADING(text)
#define ARCHHEADING(text, arch_mask)

#include "qemu-options.def"
    { /* end of list */ }
};
```

可见，同一份声明配合不同的宏定义，便能复用出完全不同的功能：既省去了大量样板代码，也避免了手工维护多份列表所导致的遗漏与不一致。


### qapi-gen

qapi-gen 则更为复杂：它基于 .json 格式的 Schema 文件，生成对外暴露结构化接口的 QAPI 接口及相关代码，包括相关参数对象

#### 构建过程

类似于hxtool, qemu在[qapi/meson.build](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/meson.build)中注册了一个`custom_target`,在构建期调用`scripts/qapi-gen.py`基于[qapi/qapi-schema.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-schema.json)转换为对应的 `.h`/`.c`文件，如下所示

```
// meson.build
qapi_gen = find_program('scripts/qapi-gen.py')

// qapi/meson.build
qapi_files = custom_target('shared QAPI source files',
  output: qapi_util_outputs + qapi_specific_outputs + qapi_nonmodule_outputs,
  input: [ files('qapi-schema.json') ],
  command: [ qapi_gen, '-o', 'qapi', '-b', '@INPUT0@' ],
  depend_files: [ qapi_inputs, qapi_gen_depends ])
```

其中，[scripts/qapi-gen.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi-gen.py)相当于编译器，其按照[docs/devel/qapi-code-gen.rst](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/docs/devel/qapi-code-gen.rst)中定义的schema语法规则，解析 `.json` 文件并生成对应的文件，其规则基本如下所示:

| schema规则 | 编译规则 | 生成产物 | 描述 |
| :-: | :-: | :-: | :-: |
| `{'struct'/'enum'/'union'/'alternate':*}` | [scripts/qapi/types.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/types.py)的gen*() | $(prefix)/qapi-types*.h/.c | 生成对应的C语言的数据结构 |
| `{'struct'/'enum'/'union'/'alternate':*}` | [scripts/qapi/visit.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/visit.py)的visit*() | $(prefix)/qapi-visit*.h/.c | 生成数据结构和QObject结构相互转化的visit_type*() |
| `{'command':*}` | [scripts/qapi/commands.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/commands.py)的gen*() | $(prefix)/qapi-commands*.h/.c | 生成用于qmp命令的qmp_marshal*() |
| `{'event':*}` | [scripts/qapi/events.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/events.py)的gen*() | $(prefix)/qapi-events*.h/.c | 生成用于发送event的qapi_event*() |

#### 使用方式

后续代码会通过**include**相关的生成产物，从而完成相关的数据结构/接口的调用，可以整理为如下几种方式：

##### 数据结构

这里以网卡后端所需要的数据结构**struct Netdev**(下面在详细分析)为例

###### struct Netdev

qemu会在[qapi/net.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/net.json#L725-L760)中依照相关的schema规则定义数据结构,如下所示

```c
##
# @Netdev:
#
# Captures the configuration of a network device.
#
# @id: identifier for monitor commands.
#
# @type: Specify the driver used for interpreting remaining arguments.
#
# Since: 1.2
##
{ 'union': 'Netdev',
  'base': { 'id': 'str', 'type': 'NetClientDriver' },
  'discriminator': 'type',
  'data': {
    'nic':      'NetLegacyNicOptions',
    'user':     'NetdevUserOptions',
    'tap':      'NetdevTapOptions',
    'l2tpv3':   'NetdevL2TPv3Options',
    'socket':   'NetdevSocketOptions',
    'stream':   'NetdevStreamOptions',
    'dgram':    'NetdevDgramOptions',
    'vde':      'NetdevVdeOptions',
    'bridge':   'NetdevBridgeOptions',
    'hubport':  'NetdevHubPortOptions',
    'netmap':   'NetdevNetmapOptions',
    'af-xdp':   { 'type': 'NetdevAFXDPOptions',
                  'if': 'CONFIG_AF_XDP' },
    'vhost-user': 'NetdevVhostUserOptions',
    'vhost-vdpa': 'NetdevVhostVDPAOptions',
    'vmnet-host': { 'type': 'NetdevVmnetHostOptions',
                    'if': 'CONFIG_VMNET' },
    'vmnet-shared': { 'type': 'NetdevVmnetSharedOptions',
                      'if': 'CONFIG_VMNET' },
    'vmnet-bridged': { 'type': 'NetdevVmnetBridgedOptions',
                       'if': 'CONFIG_VMNET' } } }
```

因此，在编译时，`scripts/gen-api.py`会基于该内容在`${prefix}/qapi/qapi-types-net.h`中生成相关的数据结构，如下所示

```h
struct Netdev {
    char *id;
    NetClientDriver type;
    union { /* union tag is @type */
        NetLegacyNicOptions nic;
        NetdevUserOptions user;
        NetdevTapOptions tap;
        NetdevL2TPv3Options l2tpv3;
        NetdevSocketOptions socket;
        NetdevStreamOptions stream;
        NetdevDgramOptions dgram;
        NetdevVdeOptions vde;
        NetdevBridgeOptions bridge;
        NetdevHubPortOptions hubport;
        NetdevNetmapOptions netmap;
#if defined(CONFIG_AF_XDP)
        NetdevAFXDPOptions af_xdp;
#endif /* defined(CONFIG_AF_XDP) */
        NetdevVhostUserOptions vhost_user;
        NetdevVhostVDPAOptions vhost_vdpa;
#if defined(CONFIG_VMNET)
        NetdevVmnetHostOptions vmnet_host;
#endif /* defined(CONFIG_VMNET) */
#if defined(CONFIG_VMNET)
        NetdevVmnetSharedOptions vmnet_shared;
#endif /* defined(CONFIG_VMNET) */
#if defined(CONFIG_VMNET)
        NetdevVmnetBridgedOptions vmnet_bridged;
#endif /* defined(CONFIG_VMNET) */
    } u;
};
```

从而后续qemu代码可以通过引入该头文件来使用对应的数据结构

###### visitor

在qemu中，qmp命令参数、qemu命令行参数、数据结构深拷贝与释放等，都涉及到数据结构的访问与设置，如果逐个手写，会导致过多的重复代码。

因此qemu提供了visitor机制：通过qapi-gen生成数据结构的上述所有操作的共同接口，即visit_type_Netdev()；然后根据不同的操作类型传入包含不同回调函数的visitor变量，从而实现不同的功能。

具体的，qemu所有visitor类型包含[struct visitor](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qapi/visitor-impl.h#L17-L135),如下所示

```h
/*
 * There are four classes of visitors; setting the class determines
 * how QAPI enums are visited, as well as what additional restrictions
 * can be asserted.  The values are intentionally chosen so as to
 * permit some assertions based on whether a given bit is set (that
 * is, some assertions apply to input and clone visitors, some
 * assertions apply to output and clone visitors).
 */
typedef enum VisitorType {
    VISITOR_INPUT = 1,
    VISITOR_OUTPUT = 2,
    VISITOR_CLONE = 3,
    VISITOR_DEALLOC = 4,
} VisitorType;

struct Visitor
{
    /*
     * Only input visitors may fail!
     */

    /* Must be set to visit structs */
    bool (*start_struct)(Visitor *v, const char *name, void **obj,
                         size_t size, Error **errp);

    /* Optional; intended for input visitors */
    bool (*check_struct)(Visitor *v, Error **errp);

    /* Must be set to visit structs */
    void (*end_struct)(Visitor *v, void **obj);

    /* Must be set; implementations may require @list to be non-null,
     * but must document it. */
    bool (*start_list)(Visitor *v, const char *name, GenericList **list,
                       size_t size, Error **errp);

    /* Must be set */
    GenericList *(*next_list)(Visitor *v, GenericList *tail, size_t size);

    /* Optional; intended for input visitors */
    bool (*check_list)(Visitor *v, Error **errp);

    /* Must be set */
    void (*end_list)(Visitor *v, void **list);

    /* Must be set by input and clone visitors to visit alternates */
    bool (*start_alternate)(Visitor *v, const char *name,
                            GenericAlternate **obj, size_t size,
                            Error **errp);

    /* Optional */
    void (*end_alternate)(Visitor *v, void **obj);

    /* Must be set */
    bool (*type_int64)(Visitor *v, const char *name, int64_t *obj,
                       Error **errp);

    /* Must be set */
    bool (*type_uint64)(Visitor *v, const char *name, uint64_t *obj,
                        Error **errp);

    /* Optional; fallback is type_uint64() */
    bool (*type_size)(Visitor *v, const char *name, uint64_t *obj,
                      Error **errp);

    /* Must be set */
    bool (*type_bool)(Visitor *v, const char *name, bool *obj, Error **errp);

    /* Must be set */
    bool (*type_str)(Visitor *v, const char *name, char **obj, Error **errp);

    /* Must be set to visit numbers */
    bool (*type_number)(Visitor *v, const char *name, double *obj,
                        Error **errp);

    /* Must be set to visit arbitrary QTypes */
    bool (*type_any)(Visitor *v, const char *name, QObject **obj,
                     Error **errp);

    /* Must be set to visit explicit null values.  */
    bool (*type_null)(Visitor *v, const char *name, QNull **obj,
                      Error **errp);

    /* Must be set for input visitors to visit structs, optional otherwise.
       The core takes care of the return type in the public interface. */
    void (*optional)(Visitor *v, const char *name, bool *present);

    /* Optional */
    bool (*policy_reject)(Visitor *v, const char *name,
                          unsigned special_features, Error **errp);

    /* Optional */
    bool (*policy_skip)(Visitor *v, const char *name,
                        unsigned special_features);

    /* Must be set */
    VisitorType type;

    /* Optional */
    struct CompatPolicy compat_policy;

    /* Must be set for output visitors, optional otherwise. */
    void (*complete)(Visitor *v, void *opaque);

    /* Must be set */
    void (*free)(Visitor *v);
};
```

qemu中共有8种类型的visitor变量，如下所示

| 数据结构 | 文件 | 描述 |
| :-: | :-: | :-: |
| [`struct QObjectInputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qobject-input-visitor.c#L45-L57) | `qapi/qobject-input-visitor.c` | 把一个 QObject（QDict/QList）解析成 QAPI 的 数据结构 |
| [`struct QObjectOutputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qobject-output-visitor.c#L33-L39) | `qapi/qobject-output-visitor.c` | 把一个 QAPI 的 数据结构序列化成 QObject 树 |
| [`struct StringInputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/string-input-visitor.c#L43-L56) | `qapi/string-input-visitor.c` | 把单个字符串解析成标量或扁平整型列表 |
| [`struct StringOutputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/string-output-visitor.c#L55-L69) | `qapi/string-output-visitor.c` | 把标量或整型列表反向格式化成一行可读字符串 |
| [`struct OptsVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L65-L99) | `qapi/opts-visitor.c` | 把扁平的 `QemuOpts`解析成 QAPI 结构体 |
| [`struct QapiDeallocVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-dealloc-visitor.c#L20-L23) | `qapi/qapi-dealloc-visitor.c` | 以后序遍历递归释放一个 QAPI 对象及其所有成员 |
| [`struct QapiCloneVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-clone-visitor.c#L17-L20) | `qapi/qapi-clone-visitor.c` | 对 QAPI 对象做深拷贝 |
| [`struct ForwardFieldVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-forward-visitor.c#L27-L35) | `qapi/qapi-forward-visitor.c` | 把顶层字段名翻译成另一个名字后再转发 |




##### qmp

##### event

## 前端

## 后端

# 参考
