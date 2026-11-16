---
title: virtio设备
date: 2026-07-27 22:03:02
tags: ['qemu', '虚拟化']
categories: ['虚拟化']
---

# 前言

在{% post_link virtio简介 %}中，我们简单介绍了 virtio 的整体思想。这里以 `virtio-net-pci` 为例，进一步介绍 Qemu 中 virtio 设备相关的实现细节。

# 参数

一般的设备往往由两部分组成：
- **前端**：呈现给 **guest** 的模拟硬件，其行为必须与 guest 预期的真实硬件行为保持一致
- **后端**：使用 **host** 资源处理来自前端的数据的对象，即 guest 中设备数据真正被处理的地方

前端与后端通过各自的命令行参数进行配置，并通过 `id` 关联在一起，如下所示
```bash
# 前端：guest 中看到的 PCI 接口 virtio 网卡，其后端为 hostnet0
-device virtio-net-pci,netdev=hostnet0

# 后端：host 使用 tap 设备处理 guest 中 virtio 网卡的数据
-netdev tap,id=hostnet0,ifname=tap_for_l1
```

## 框架

Qemu 借助 `hxtool` 与 `qapi-gen` 等自动化代码生成框架，让开发者仅需维护一份声明式文本，就能在构建期自动生成对应的 `.h`/`.c` 文件，从而避免手写大量强约束、极易出错的解析逻辑与样板代码。上面这些参数的解析正是建立在这两套框架之上。

### hxtool

hxtool 负责处理 `.hx` 文件，主要用于维护 qemu 命令行选项与 hmp 命令的帮助信息：一方面把 `.hx` 转换成可供 C 代码包含的 `.def`/`.h`，另一方面把其中 `SRST`/`ERST` 之间的 rST 文本交给文档框架生成说明文档。

#### 构建过程

Qemu 在顶层 [meson.build](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/meson.build#L3271-L3289) 中为每个 `.hx` 文件注册了一个 `custom_target`，在构建期调用 `scripts/hxtool` 将其转换为对应的 `.def`/`.h` 文件，其规则如下。

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

其中 [scripts/hxtool](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/hxtool) 本身只是一个二十余行的 shell 脚本，本质是一个“带开关的行过滤器”：把混排在同一份 `.hx` 中的“宏调用”与“文档”分离开。

例如 [qemu-options.hx](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qemu-options.hx)，其中既包含 `DEF(...)` 形式的宏调用，也包含 `SRST`/`ERST` 之间的文档内容。

```c
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

经过 `hxtool -h` 过滤后，即可生成只包含宏调用的 **qemu-options.def**。

```c
DEF("help", 0, QEMU_OPTION_h,
"-h or -help     display this help and exit\n", QEMU_ARCH_ALL)

DEF("version", 0, QEMU_OPTION_version,
"-version        display version information and exit\n", QEMU_ARCH_ALL)
```

#### 使用方式

后续代码只要 `#include` 这份文件，并为 `DEF` 宏提供不同的实现即可完成复用：例如 [qemu_options[]](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/vl.c#L922) 数组需要选项名称、参数标志、枚举值与架构掩码等信息，那么按如下方式定义宏即可

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

可见，同一份声明配合不同的宏定义，即可派生出用途完全不同的代码：既省去了大量样板代码，也避免了手工维护多份列表所导致的遗漏与不一致。


### qapi-gen

qapi-gen 则要复杂得多：它基于 `.json` 格式的 schema 文件，生成 QAPI 对外暴露的结构化接口及其配套代码，其中就包括各类参数对象。

#### 构建过程

与 hxtool 类似，Qemu 在 [qapi/meson.build](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/meson.build) 中也注册了一个 `custom_target`，在构建期调用 `scripts/qapi-gen.py`，以 [qapi/qapi-schema.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-schema.json) 为输入生成对应的 `.h`/`.c` 文件，如下所示。

```meson
# meson.build
qapi_gen = find_program('scripts/qapi-gen.py')

// qapi/meson.build
qapi_files = custom_target('shared QAPI source files',
  output: qapi_util_outputs + qapi_specific_outputs + qapi_nonmodule_outputs,
  input: [ files('qapi-schema.json') ],
  command: [ qapi_gen, '-o', 'qapi', '-b', '@INPUT0@' ],
  depend_files: [ qapi_inputs, qapi_gen_depends ])
```

其中，[scripts/qapi-gen.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi-gen.py) 相当于一个编译器：它按照 [docs/devel/qapi-code-gen.rst](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/docs/devel/qapi-code-gen.rst) 中定义的 schema 语法解析 `.json` 文件，再由 `scripts/qapi/` 下的各个后端生成对应文件，其规则大致如下。

| schema规则 | 编译规则 | 生成产物 | 描述 |
| :-: | :-: | :-: | :-: |
| `{'struct'/'enum'/'union'/'alternate':*}` | [scripts/qapi/types.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/types.py) 的 `gen*()` | `$(prefix)/qapi-types*.h/.c` | 生成对应的 C 语言数据结构 |
| `{'struct'/'enum'/'union'/'alternate':*}` | [scripts/qapi/visit.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/visit.py) 的 `visit*()` | `$(prefix)/qapi-visit*.h/.c` | 生成数据结构与 QObject 相互转换的 `visit_type*()` |
| `{'command':*}` | [scripts/qapi/commands.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/commands.py) 的 `gen*()` | `$(prefix)/qapi-commands*.h/.c` | 生成用于 qmp 命令的 `qmp_marshal*()` |
| `{'event':*}` | [scripts/qapi/events.py](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi/events.py) 的 `gen*()` | `$(prefix)/qapi-events*.h/.c` | 生成用于发送 event 的 `qapi_event*()` |

#### 使用方式

生成产物最终由 Qemu 代码 `#include` 并使用，按用途大致可以分为以下几类：

##### 数据结构

这里以网卡后端所需的数据结构 **struct Netdev**（后文[后端](#后端)一节会详细分析）为例。

###### struct Netdev

Qemu 在 [qapi/net.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/net.json#L725-L760) 中按 schema 规则定义该数据结构，如下所示。

```json
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

因此，在构建时 `scripts/qapi-gen.py` 会据此在 `${prefix}/qapi/qapi-types-net.h` 中生成对应的数据结构，如下所示。

```c
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

此后 Qemu 代码只要包含该头文件，就可以直接使用这些数据结构。

###### visitor

在 Qemu 中，QMP 命令参数、命令行参数、数据结构的深拷贝与释放等场景，都需要遍历并读写一个 QAPI 数据结构。若为每种结构、每种用途各写一遍，会产生大量重复代码。

为此 Qemu 提供了 visitor 机制：由 qapi-gen 为每个数据结构生成统一的遍历入口（例如 `visit_type_Netdev()`），而遍历过程中“如何读写一个字段”则由传入的 `Visitor` 中不同的回调函数决定，从而实现不同的功能。

具体地，Qemu 中所有 Visitor 都以 [struct Visitor](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/qapi/visitor-impl.h#L17-L135) 为统一接口，其各字段含义如下。

```c
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

这些回调函数会在生成的 **visit_type_Netdev()** 中按如下顺序被调用。

```c
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

bool visit_type_Netdev_members(Visitor *v, Netdev *obj, Error **errp)
{
    if (!visit_type_q_obj_Netdev_base_members(v, (q_obj_Netdev_base *)obj, errp)) {
        return false;
    }
    switch (obj->type) {
    case NET_CLIENT_DRIVER_NIC:
        return visit_type_NetLegacyNicOptions_members(v, &obj->u.nic, errp);
    case NET_CLIENT_DRIVER_USER:
        return visit_type_NetdevUserOptions_members(v, &obj->u.user, errp);
    case NET_CLIENT_DRIVER_TAP:
        return visit_type_NetdevTapOptions_members(v, &obj->u.tap, errp);
    ...
    default:
        abort();
    }
    return true;
}
```

可以看到：首先在 [**visit_start_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-visit-core.c#L44) 中调用 **start_struct** 回调，完成本次访问的初始化；接着由 **qapi-gen** 生成的 **visit_type_Netdev_members()** 调用 **type_X** 等回调，处理结构体中的各个字段；然后在 [**visit_check_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-visit-core.c#L61) 中调用 **check_struct** 回调做合法性校验；最后在 [**visit_end_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-visit-core.c#L67) 中调用 **end_struct** 回调完成清理。

Qemu 中共有 8 种 Visitor 实现，如下所示。

| 数据结构 | 文件 | 描述 |
| :-: | :-: | :-: |
| [`struct QObjectInputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qobject-input-visitor.c#L45-L57) | `qapi/qobject-input-visitor.c` | 把一个 QObject（QDict/QList）解析成 QAPI 数据结构 |
| [`struct QObjectOutputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qobject-output-visitor.c#L33-L39) | `qapi/qobject-output-visitor.c` | 把一个 QAPI 数据结构序列化成 QObject 树 |
| [`struct StringInputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/string-input-visitor.c#L43-L56) | `qapi/string-input-visitor.c` | 把单个字符串解析成标量或扁平整型列表 |
| [`struct StringOutputVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/string-output-visitor.c#L55-L69) | `qapi/string-output-visitor.c` | 把标量或整型列表反向格式化成一行可读字符串 |
| [`struct OptsVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L65-L99) | `qapi/opts-visitor.c` | 把扁平的 `QemuOpts` 解析成 QAPI 结构体 |
| [`struct QapiDeallocVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-dealloc-visitor.c#L20-L23) | `qapi/qapi-dealloc-visitor.c` | 以后序遍历递归释放一个 QAPI 对象及其所有成员 |
| [`struct QapiCloneVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-clone-visitor.c#L17-L20) | `qapi/qapi-clone-visitor.c` | 对 QAPI 对象做深拷贝 |
| [`struct ForwardFieldVisitor`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-forward-visitor.c#L27-L35) | `qapi/qapi-forward-visitor.c` | 把顶层字段名翻译成另一个名字后再转发 |

这里以解析命令行参数 `-netdev tap,id=net,ifname=tap_for_l1,script=no,downscript=no` 为例，介绍 `OptsVisitor` 如何把 `QemuOpts` 解析成 `Netdev`。整个过程的入口是 [net_client_init()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c)：它先用 [opts_visitor_new()](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L553) 创建一个装好各回调的 `Visitor`，再调用 `visit_type_Netdev()` 完成解析，如下所示。

```c
Visitor *
opts_visitor_new(const QemuOpts *opts)
{
    OptsVisitor *ov;

    assert(opts);
    ov = g_malloc0(sizeof *ov);

    ov->visitor.type = VISITOR_INPUT;

    ov->visitor.start_struct = &opts_start_struct;
    ov->visitor.check_struct = &opts_check_struct;
    ov->visitor.end_struct   = &opts_end_struct;

    ov->visitor.start_list = &opts_start_list;
    ov->visitor.next_list  = &opts_next_list;
    ov->visitor.check_list = &opts_check_list;
    ov->visitor.end_list   = &opts_end_list;

    ov->visitor.type_int64  = &opts_type_int64;
    ov->visitor.type_uint64 = &opts_type_uint64;
    ov->visitor.type_size   = &opts_type_size;
    ov->visitor.type_bool   = &opts_type_bool;
    ov->visitor.type_str    = &opts_type_str;

    /* type_number() is not filled in, but this is not the first visitor to
     * skip some mandatory methods... */

    ov->visitor.optional = &opts_optional;
    ov->visitor.free = opts_free;

    ov->opts_root = opts;

    return &ov->visitor;
}
```

**OptsVisitor**的核心思路是：先把 `QemuOpts` 中的每一个元素 `(key, val)` 收录到哈希表 [`unprocessed_opts`](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L77) 中，其键为元素的 `key`，值为同名 `key` 的所有 `val` 按出现顺序组成的 **GQueue**；解析某个字段时，再按字段名从表中取出对应的队列，取队尾元素（即同名参数最后一次出现的值生效）解析并赋值。

因此，**OptsVisitor**会首先在**start_struct**回调，即[**opts_start_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L137)中构建这张哈希表。

```c
//#0  opts_start_struct (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, size=0xd0, errp=0x555556e83800 <error_fatal>) at ../qapi/opts-visitor.c:140
//#1  0x0000555555f470a7 in visit_start_struct (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, size=0xd0, errp=0x555556e83800 <error_fatal>) at ../qapi/qapi-visit-core.c:54
//#2  0x0000555555f10e39 in visit_type_Netdev (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1315
//#3  0x0000555555b855d3 in net_client_init (opts=0x555556ef8f20, is_netdev=0x1, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1427
//#4  0x0000555555b86240 in net_init_netdev (dummy=0x0, opts=0x555556ef8f20, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1747
//#5  0x0000555555f6dccd in qemu_opts_foreach (list=0x555556d7fcc0 <qemu_netdev_opts>, func=0x555555b861d7 <net_init_netdev>, opaque=0x0, errp=0x555556e83800 <error_fatal>)
//    at ../util/qemu-option.c:1135
//#6  0x0000555555b86774 in net_init_clients () at ../net/net.c:1857
//#7  0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#8  0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968) at ../system/vl.c:3712
//#9  0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:47
//#10 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
//    stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#12 0x000055555584b661 in _start ()
static bool
opts_start_struct(Visitor *v, const char *name, void **obj,
                  size_t size, Error **errp)
{
    OptsVisitor *ov = to_ov(v);
    const QemuOpt *opt;

    if (obj) {
        *obj = g_malloc0(size);
    }
    if (ov->depth++ > 0) {
        return true;
    }

    ov->unprocessed_opts = g_hash_table_new_full(&g_str_hash, &g_str_equal,
                                                 NULL, &destroy_list);
    QTAILQ_FOREACH(opt, &ov->opts_root->head, next) {
        /* ensured by qemu-option.c::opts_do_parse() */
        assert(strcmp(opt->name, "id") != 0);

        opts_visitor_insert(ov->unprocessed_opts, opt);
    }

    if (ov->opts_root->id != NULL) {
        ov->fake_id_opt = g_malloc0(sizeof *ov->fake_id_opt);

        ov->fake_id_opt->name = g_strdup("id");
        ov->fake_id_opt->str = g_strdup(ov->opts_root->id);
        opts_visitor_insert(ov->unprocessed_opts, ov->fake_id_opt);
    }
    return true;
}
```

因此上面的 `-netdev tap,id=net,ifname=tap_for_l1,script=no,downscript=no` 会被整理成如下结构。

| 键 | 对应的 GQueue（按出现顺序入队，取值时取队尾） |
| :-: | :-: |
| type | ["tap"] |
| ifname | ["tap_for_l1"] |
| script | ["no"] |
| downscript | ["no"] |
| id | ["net"] |

随后在**visit_type_Netdev_members()**中会依次解析**struct Netdev**的各个字段，并把已解析的数据从哈希表**unprocessed_opts**中移除。以**type**字段为例。

```c
bool visit_type_Netdev_members(Visitor *v, Netdev *obj, Error **errp)
{
    if (!visit_type_q_obj_Netdev_base_members(v, (q_obj_Netdev_base *)obj, errp)) {
        return false;
    }
    switch (obj->type) {
    ...
    case NET_CLIENT_DRIVER_TAP:
        return visit_type_NetdevTapOptions_members(v, &obj->u.tap, errp);
    ...
    default:
        abort();
    }
    return true;
}

bool visit_type_q_obj_Netdev_base_members(Visitor *v, q_obj_Netdev_base *obj, Error **errp)
{
    ...
    if (!visit_type_NetClientDriver(v, "type", &obj->type, errp)) {
        return false;
    }
    return true;
}

bool visit_type_NetClientDriver(Visitor *v, const char *name,
                 NetClientDriver *obj, Error **errp)
{
    int value = *obj;
    bool ok = visit_type_enum(v, name, &value, &NetClientDriver_lookup, errp);
    *obj = value;
    return ok;
}

bool visit_type_enum(Visitor *v, const char *name, int *obj,
                     const QEnumLookup *lookup, Error **errp)
{
    ...
    switch (v->type) {
    case VISITOR_INPUT:
        return input_type_enum(v, name, obj, lookup, errp);
    ...
    default:
        abort();
    }
}

static bool input_type_enum(Visitor *v, const char *name, int *obj,
                            const QEnumLookup *lookup, Error **errp)
{
    ...
    if (!visit_type_str(v, name, &enum_str, errp)) {
        return false;
    }

    value = qapi_enum_parse(lookup, enum_str, -1, NULL);
    ...
    *obj = value;
    return true;
}

//#0  opts_type_str (v=0x55555711c890, name=0x5555561baa19 "type", obj=0x7fffffffd3e0, 
//    errp=0x555556e83800 <error_fatal>) at ../qapi/opts-visitor.c:352
//#1  0x0000555555f4814d in visit_type_str (v=0x55555711c890, name=0x5555561baa19 "type", obj=0x7fffffffd3e0, 
//    errp=0x555556e83800 <error_fatal>) at ../qapi/qapi-visit-core.c:349
//#2  0x0000555555f4846b in input_type_enum (v=0x55555711c890, name=0x5555561baa19 "type", obj=0x7fffffffd478, 
//    lookup=0x555556d148b0 <NetClientDriver_lookup>, errp=0x555556e83800 <error_fatal>)
//    at ../qapi/qapi-visit-core.c:401
//#3  0x0000555555f48640 in visit_type_enum (v=0x55555711c890, name=0x5555561baa19 "type", obj=0x7fffffffd478, 
//    lookup=0x555556d148b0 <NetClientDriver_lookup>, errp=0x555556e83800 <error_fatal>)
//    at ../qapi/qapi-visit-core.c:431
//#4  0x0000555555f10b4b in visit_type_NetClientDriver (v=0x55555711c890, name=0x5555561baa19 "type", 
//    obj=0x55555711c608, errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1238
//#5  0x0000555555f10bcc in visit_type_q_obj_Netdev_base_members (v=0x55555711c890, obj=0x55555711c600, 
//    errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1248
//#6  0x0000555555f10c14 in visit_type_Netdev_members (v=0x55555711c890, obj=0x55555711c600, 
//    errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1256
//#7  0x0000555555f10eae in visit_type_Netdev (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, 
//    errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1324
//#8  0x0000555555b855d3 in net_client_init (opts=0x555556ef8f20, is_netdev=0x1, errp=0x555556e83800 <error_fatal>)
//    at ../net/net.c:1427
//#9  0x0000555555b86240 in net_init_netdev (dummy=0x0, opts=0x555556ef8f20, errp=0x555556e83800 <error_fatal>)
//    at ../net/net.c:1747
//#10 0x0000555555f6dccd in qemu_opts_foreach (list=0x555556d7fcc0 <qemu_netdev_opts>, 
//    func=0x555555b861d7 <net_init_netdev>, opaque=0x0, errp=0x555556e83800 <error_fatal>)
//    at ../util/qemu-option.c:1135
//#11 0x0000555555b86774 in net_init_clients () at ../net/net.c:1857
//#12 0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#13 0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968) at ../system/vl.c:3712
//#14 0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:47
//#15 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, 
//    argv=argv@entry=0x7fffffffd968) at ../sysdeps/nptl/libc_start_call_main.h:58
//#16 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, 
//    init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd958)
//    at ../csu/libc-start.c:360
//#17 0x000055555584b661 in _start ()
static bool
opts_type_str(Visitor *v, const char *name, char **obj, Error **errp)
{
    OptsVisitor *ov = to_ov(v);
    const QemuOpt *opt;

    opt = lookup_scalar(ov, name, errp);
    if (!opt) {
        *obj = NULL;
        return false;
    }
    *obj = g_strdup(opt->str ? opt->str : "");
    /* Note that we consume a string even if this is called as part of
     * an enum visit that later fails because the string is not a
     * valid enum value; this is harmless because tracking what gets
     * consumed only matters to visit_end_struct() as the final error
     * check if there were no other failures during the visit.  */
    processed(ov, name);
    return true;
}
```

可以看到，解析最终落到回调函数 [**opts_type_str()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L350)：它先调用 [**lookup_scalar()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L318) 从 **unprocessed_opts** 中取出 `type` 对应的元素，把其字符串值赋给目标字段，再调用 [**processed()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L338) 把该键从 **unprocessed_opts** 中删除，既避免重复解析，也为最后的校验留下依据。其余字段的解析方式完全相同，区别仅在于调用的 **type_X** 回调不同（整型走 `opts_type_int64()`、布尔走 `opts_type_bool()` 等）

在解析完**struct Netdev**的所有字段后，接着会在**visit_check_struct()**中，即[**opts_check_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L171)检查哈希表里是否还有未被解析的键值对。若还有剩余，说明命令行传入了无法识别的参数，此时报错即可

```c
//#0  opts_check_struct (v=0x55555711c890, errp=0x555556e83800 <error_fatal>) at ../qapi/opts-visitor.c:173
//#1  0x0000555555f47157 in visit_check_struct (v=0x55555711c890, errp=0x555556e83800 <error_fatal>) at ../qapi/qapi-visit-core.c:64
//#2  0x0000555555f10ec8 in visit_type_Netdev (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1327
//#3  0x0000555555b855d3 in net_client_init (opts=0x555556ef8f20, is_netdev=0x1, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1427
//#4  0x0000555555b86240 in net_init_netdev (dummy=0x0, opts=0x555556ef8f20, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1747
//#5  0x0000555555f6dccd in qemu_opts_foreach (list=0x555556d7fcc0 <qemu_netdev_opts>, func=0x555555b861d7 <net_init_netdev>, opaque=0x0, errp=0x555556e83800 <error_fatal>)
//    at ../util/qemu-option.c:1135
//#6  0x0000555555b86774 in net_init_clients () at ../net/net.c:1857
//#7  0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#8  0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968) at ../system/vl.c:3712
//#9  0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:47
//#10 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
//    stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#12 0x000055555584b661 in _start ()
static bool
opts_check_struct(Visitor *v, Error **errp)
{
    OptsVisitor *ov = to_ov(v);
    GHashTableIter iter;
    GQueue *any;

    if (ov->depth > 1) {
        return true;
    }

    /* we should have processed all (distinct) QemuOpt instances */
    g_hash_table_iter_init(&iter, ov->unprocessed_opts);
    if (g_hash_table_iter_next(&iter, NULL, (void **)&any)) {
        const QemuOpt *first;

        first = g_queue_peek_head(any);
        error_setg(errp, QERR_INVALID_PARAMETER, first->name);
        return false;
    }
    return true;
}
```

最后，在**visit_end_struct()**中，即[**opts_end_struct()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/opts-visitor.c#L195)释放初始化阶段分配的资源即可，如下所示。

```c
//#0  opts_end_struct (v=0x55555711c890, obj=0x7fffffffd560) at ../qapi/opts-visitor.c:197
//#1  0x0000555555f471af in visit_end_struct (v=0x55555711c890, obj=0x7fffffffd560) at ../qapi/qapi-visit-core.c:70
//#2  0x0000555555f10ee1 in visit_type_Netdev (v=0x55555711c890, name=0x0, obj=0x7fffffffd560, errp=0x555556e83800 <error_fatal>) at qapi/qapi-visit-net.c:1329
//#3  0x0000555555b855d3 in net_client_init (opts=0x555556ef8f20, is_netdev=0x1, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1427
//#4  0x0000555555b86240 in net_init_netdev (dummy=0x0, opts=0x555556ef8f20, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1747
//#5  0x0000555555f6dccd in qemu_opts_foreach (list=0x555556d7fcc0 <qemu_netdev_opts>, func=0x555555b861d7 <net_init_netdev>, opaque=0x0, errp=0x555556e83800 <error_fatal>)
//    at ../util/qemu-option.c:1135
//#6  0x0000555555b86774 in net_init_clients () at ../net/net.c:1857
//#7  0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#8  0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968) at ../system/vl.c:3712
//#9  0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:47
//#10 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968) at ../sysdeps/nptl/libc_start_call_main.h:58
//#11 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
//    stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#12 0x000055555584b661 in _start ()
static void
opts_end_struct(Visitor *v, void **obj)
{
    OptsVisitor *ov = to_ov(v);

    if (--ov->depth > 0) {
        return;
    }

    g_hash_table_destroy(ov->unprocessed_opts);
    ov->unprocessed_opts = NULL;
    if (ov->fake_id_opt) {
        g_free(ov->fake_id_opt->name);
        g_free(ov->fake_id_opt->str);
        g_free(ov->fake_id_opt);
    }
    ov->fake_id_opt = NULL;
}
```

##### qmp

除了数据结构之外，qapi 的 `*.json` 中还会用 `{'command':*}` 规则定义 QMP 命令。这里仍以网卡后端为例：Qemu 在 [qapi/net.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/net.json#L56) 中定义了 `netdev_add` 命令，其参数正是上一节的 **struct Netdev**，如下所示

```json
##
# @netdev_add:
#
# Add a network backend.
#
# Additional arguments depend on the type.
#
# Since: 0.14
#
# Errors:
#     - If @type is not a valid network backend, DeviceNotFound
#
# Example:
#
#     -> { "execute": "netdev_add",
#          "arguments": { "type": "user", "id": "netdev1",
#                         "dnssearch": [ { "str": "example.org" } ] } }
#     <- { "return": {} }
##
{ 'command': 'netdev_add', 'data': 'Netdev', 'boxed': true,
  'allow-preconfig': true }
```

其中 `'data': 'Netdev'` 指定了该命令的参数类型；`'boxed': true` 表示生成的 C 函数直接接收一个装箱后的 **struct Netdev** 指针，而不是展开后的各个字段。

在构建时 `scripts/qapi/commands.py` 会据此在 `${prefix}/qapi/qapi-commands-net.c` 中生成对应的 qmp 处理框架函数 `qmp_marshal_netdev_add()`，如下所示

```c
void qmp_marshal_netdev_add(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    bool ok = false;
    Visitor *v;
    Netdev arg = {0};

    v = qobject_input_visitor_new_qmp(QOBJECT(args));
    if (!visit_start_struct(v, NULL, NULL, 0, errp)) {
        goto out;
    }
    if (visit_type_Netdev_members(v, &arg, errp)) {
        ok = visit_check_struct(v, errp);
    }
    visit_end_struct(v, NULL);
    if (!ok) {
        goto out;
    }

    if (trace_event_get_state_backends(TRACE_QMP_ENTER_NETDEV_ADD)) {
        g_autoptr(GString) req_json = qobject_to_json(QOBJECT(args));

        trace_qmp_enter_netdev_add(req_json->str);
    }

    qmp_netdev_add(&arg, &err);
    if (err) {
        trace_qmp_exit_netdev_add(error_get_pretty(err), false);
        error_propagate(errp, err);
        goto out;
    }

    trace_qmp_exit_netdev_add("{}", true);

out:
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_type_Netdev_members(v, &arg, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}
```

可以看到，它同样借助 visitor 机制完成工作：先创建 input visitor，把 QMP 请求中的 **QDict** 反序列化为 **struct Netdev**；解析成功后调用真正的处理函数 [**qmp_netdev_add()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c#L1444)。因此在 Qemu 中新增一条 QMP 命令时，只需要在 schema 中声明命令、再实现对应的 `qmp_*()` 函数即可，参数解析等框架代码全都由 qapi-gen 自动生成。

不过 marshal 函数本身并不会被自动调用，它需要先注册进 QMP 的命令表。为此 `scripts/qapi/commands.py` 会在 `${prefix}/qapi/qapi-init-commands.c` 中生成 `qmp_init_marshal()`，由它调用 [**qmp_register_command()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-registry.c#L18) 把各命令连同其选项注册到全局链表 `qmp_commands` 中，如下所示。

```c
void qmp_init_marshal(QmpCommandList *cmds)
{
    QTAILQ_INIT(cmds);

    qmp_register_command(cmds, "netdev_add",
                         qmp_marshal_netdev_add, QCO_ALLOW_PRECONFIG, 0);
    ...
}
```

此后 QMP 客户端发来的请求会由 [**monitor_qmp_dispatch()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/monitor/qmp.c#L163) 交给 [**qmp_dispatch()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-dispatch.c#L137)：它先用 [**qmp_find_command()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-registry.c#L35) 按命令名查表，再调用查到的 `cmd->fn()`，也就是前面生成的 marshal 函数，如下所示。

```c
// qapi/qmp-dispatch.c
cmd = qmp_find_command(cmds, command);
if (cmd == NULL) {
    error_set(&err, ERROR_CLASS_COMMAND_NOT_FOUND,
              "The command %s has not been found", command);
    goto out;
}
...
monitor_set_cur(qemu_coroutine_self(), cur_mon);
cmd->fn(args, &ret, &err);
monitor_set_cur(qemu_coroutine_self(), NULL);
```

至此，一条 QMP 命令的完整链路就已经清晰了：JSON 请求 → `qmp_dispatch()` 查表 → `qmp_marshal_netdev_add()` 反序列化 → `qmp_netdev_add()` 实际处理。

##### event

与 qmp 命令相对，qapi 的 `*.json` 中还会用 `{'event':*}` 规则定义由 Qemu 主动上报的事件。这里仍以网卡后端为例：Qemu 在 [qapi/net.json](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/net.json#L991) 中定义了 **NETDEV_STREAM_CONNECTED** 事件，如下所示

```json
##
# @NETDEV_STREAM_CONNECTED:
#
# Emitted when the netdev stream backend is connected
#
# @netdev-id: QEMU netdev id that is connected
#
# @addr: The destination address
#
# Since: 7.2
#
# Examples:
#
#     <- { "event": "NETDEV_STREAM_CONNECTED",
#          "data": { "netdev-id": "netdev0",
#                    "addr": { "port": "47666", "ipv6": true,
#                              "host": "::1", "type": "inet" } },
#          "timestamp": { "seconds": 1666269863, "microseconds": 311222 } }
#
#     <- { "event": "NETDEV_STREAM_CONNECTED",
#          "data": { "netdev-id": "netdev0",
#                    "addr": { "path": "/tmp/qemu0", "type": "unix" } },
#          "timestamp": { "seconds": 1666269706, "microseconds": 413651 } }
##
{ 'event': 'NETDEV_STREAM_CONNECTED',
  'data': { 'netdev-id': 'str',
            'addr': 'SocketAddress' } }
```

在构建时 `scripts/qapi/events.py` 会据此在 `${prefix}/qapi/qapi-events-net.c` 中生成对应的发送函数 `qapi_event_send_netdev_stream_connected()`，如下所示

```c
void qapi_event_send_netdev_stream_connected(const char *netdev_id, SocketAddress *addr)
{
    QDict *qmp;
    QObject *obj;
    Visitor *v;
    q_obj_NETDEV_STREAM_CONNECTED_arg param = {
        (char *)netdev_id, addr
    };

    qmp = qmp_event_build_dict("NETDEV_STREAM_CONNECTED");

    v = qobject_output_visitor_new_qmp(&obj);

    visit_start_struct(v, "NETDEV_STREAM_CONNECTED", NULL, 0, &error_abort);
    visit_type_q_obj_NETDEV_STREAM_CONNECTED_arg_members(v, &param, &error_abort);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);

    visit_complete(v, &obj);
    if (qdict_size(qobject_to(QDict, obj))) {
        qdict_put_obj(qmp, "data", obj);
    } else {
        qobject_unref(obj);
    }
    qapi_event_emit(QAPI_EVENT_NETDEV_STREAM_CONNECTED, qmp);

    visit_free(v);
    qobject_unref(qmp);
}
```

可以看到，它的数据流向与 qmp 恰好相反：先创建 output visitor，把装箱参数 **q_obj_NETDEV_STREAM_CONNECTED_arg** 序列化成 **QObject**；再用 [**qmp_event_build_dict()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-event.c#L36) 造出event的骨架 **QDict**，把序列化结果挂到它的 `data` 键上；最后调用 [**qapi_event_emit()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/monitor/monitor.c#L415) 发送。因此上报一个事件时，Qemu 代码只需要调用生成的 `qapi_event_send_*()` 函数，事件对象的组装与发送逻辑同样由 qapi-gen 自动生成。

## 数据结构

`-device virtio-net-pci,netdev=hostnet0 -netdev tap,id=hostnet0,ifname=tap_for_l1` 在 Qemu 内部对应三组数据结构：

- **前端设备**：[**struct VirtIONetPCI**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L36) 是 PCI 外壳，[**struct VirtIONet**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/virtio/virtio-net.h#L166) 承载 virtio 网卡语义
- **后端设备**：[**struct TAPState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/tap.c#L50) 把 host 上的 tap 文件描述符包装成一个网卡后端
- **公共抽象**：[**struct NetClientState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/net/net.h#L103) 描述一个网络节点，[**struct NetClientInfo**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/net/net.h#L73) 是该节点的行为函数表

前后端之间并不存在直接的成员指针：两者都只认识 `NetClientState`，先通过 `nc->peer` 找到对端节点，再通过 `nc->info` 调用对端的行为回调。这是理解后文所有代码的前提。

### 公共抽象

#### struct NetClientState

前端有 `VirtIONet`，后端有 `TAPState`，两者的类型完全不同、也不能直接互操作。qemu 的做法是把每一个参与数据收发的节点抽象为 [**struct NetClientState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/net/net.h#L103)，前端与后端各持有一个并互为 peer：

```c
struct NetClientState {
    NetClientInfo *info;
    int link_down;
    QTAILQ_ENTRY(NetClientState) next;
    NetClientState *peer;
    NetQueue *incoming_queue;
    char *model;
    char *name;
    char info_str[256];
    unsigned receive_disabled : 1;
    NetClientDestructor *destructor;
    unsigned int queue_index;
    unsigned rxfilter_notify_enabled:1;
    int vring_enable;
    int vnet_hdr_len;
    bool is_netdev;
    bool do_not_pad; /* do not pad to the minimum ethernet frame length */
    bool is_datapath;
    QTAILQ_HEAD(, NetFilterState) filters;
};
```

其中几个关键字段：

- `info`：指向 `NetClientInfo` 行为表，决定这个节点“是什么”（NIC/TAP 等）以及“能做什么”
- `peer`：指向配对的对端节点，是前后端关联的唯一桥梁

#### struct NetClientInfo

[**struct NetClientInfo**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/net/net.h#L73) 是一张行为函数表（本质是函数指针集合，作用与 C++ 的虚表类似），描述该节点的能力：

```c
typedef struct NetClientInfo {
    NetClientDriver type;
    size_t size;
    NetReceive *receive;
    NetReceive *receive_raw;
    NetReceiveIOV *receive_iov;
    NetCanReceive *can_receive;
    NetStart *start;
    NetLoad *load;
    NetStop *stop;
    NetCleanup *cleanup;
    LinkStatusChanged *link_status_changed;
    QueryRxFilter *query_rx_filter;
    NetPoll *poll;
    HasUfo *has_ufo;
    HasUso *has_uso;
    HasVnetHdr *has_vnet_hdr;
    HasVnetHdrLen *has_vnet_hdr_len;
    GetUsingVnetHdr *get_using_vnet_hdr;
    UsingVnetHdr *using_vnet_hdr;
    SetOffload *set_offload;
    GetVnetHdrLen *get_vnet_hdr_len;
    SetVnetHdrLen *set_vnet_hdr_len;
    SetVnetLE *set_vnet_le;
    SetVnetBE *set_vnet_be;
    NetAnnounce *announce;
    SetSteeringEBPF *set_steering_ebpf;
    NetCheckPeerType *check_peer_type;
} NetClientInfo;
```

其中最重要的是收包方向的两个回调 **receive**/**receive_iov**，前后端正是靠它们完成数据面的互通：guest 发包时，前端节点通过 `nc->peer` 找到后端节点，调用后端 `info->receive_iov`，把报文交给后端处理；反过来，host 侧有报文到达时，后端节点同样通过 `peer` 调用前端 `info->receive`，把报文送进 guest。

### 前端

#### struct VirtIONetPCI

virtio 前端通常由“PCI 外壳 + virtio 设备”两层拼成，`virtio-net-pci` 也不例外。它的类型信息由 [**virtio_net_pci_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L93) 描述:

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

struct VirtIONetPCI {
    VirtIOPCIProxy parent_obj;
    VirtIONet vdev;
};
```

其两个成员分工非常清晰：

- **parent_obj（struct VirtIOPCIProxy）**：virtio 传输层（transport）的 PCI 实现，把 virtio 的通用配置、通知等寄存器映射成 PCI 的 BAR，guest 中的 virtio-net-pci 驱动正是通过这些 BAR 与设备交互
- **vdev（struct VirtIONet）**：真正的 virtio 网卡设备，管理收发 vq、MAC、多队列等设备语义，数据面的收发包最终由它交给网卡后端

#### struct VirtIOPCIProxy

[**struct VirtIOPCIProxy**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/virtio/virtio-pci.h#L134) 结构如下所示

```c
struct VirtIOPCIProxy {
    PCIDevice pci_dev;
    MemoryRegion bar;
    union {
        struct {
            VirtIOPCIRegion common;
            VirtIOPCIRegion isr;
            VirtIOPCIRegion device;
            VirtIOPCIRegion notify;
            VirtIOPCIRegion notify_pio;
        };
        VirtIOPCIRegion regs[5];
    };
    VirtIOPCIRegion lm;
    MemoryRegion modern_bar;
    MemoryRegion io_bar;
    uint32_t legacy_io_bar_idx;
    uint32_t msix_bar_idx;
    uint32_t modern_io_bar_idx;
    uint32_t modern_mem_bar_idx;
    int config_cap;
    uint32_t flags;
    bool disable_modern;
    bool ignore_backend_features;
    OnOffAuto disable_legacy;
    /* Transitional device id */
    uint16_t trans_devid;
    uint32_t class_code;
    uint32_t nvectors;
    uint32_t dfselect;
    uint32_t gfselect;
    uint32_t guest_features[2];
    VirtIOPCIQueue vqs[VIRTIO_QUEUE_MAX];

    VirtIOIRQFD *vector_irqfd;
    int nvqs_with_notifiers;
    VirtioBusState bus;
};
```

它本质上是 virtio 传输层在 PCI 总线上的实现，几个关键字段：

- `pci_dev`：内嵌的 **PCIDevice**，QOM 对象树的父对象，设备以它为主体挂到 guest 的 PCI 总线上
- `modern_bar`/`io_bar`：作为 BAR 暴露给 guest 的 **MemoryRegion**，virtio modern 规范的 common、isr、device、notify 等寄存器组（即 `regs[]` 中的各 region）就映射在这里
- `vqs[]`：每个 virtqueue 在 PCI 传输层的状态，例如 guest 侧 avail/used 环的地址与通知方式
- `nvectors`/`vector_irqfd`：MSI-X 中断向量与 virtqueue 之间的映射
- `bus`：内嵌的 **VirtioBusState**。[**virtio_net_pci_realize()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/virtio/virtio-net-pci.c#L49) 正是通过 `qdev_realize(vdev, BUS(&vpci_dev->bus), ...)` 把内嵌的 `VirtIONet` 挂上这条总线，"PCI 外壳 + virtio 设备"就此组合完成

#### struct VirtIONet

而[**struct VirtIONet**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/hw/virtio/virtio-net.h#L166)结构如下所示：

```c
struct VirtIONet {
    VirtIODevice parent_obj;
    uint8_t mac[ETH_ALEN];
    uint16_t status;
    VirtIONetQueue *vqs;
    VirtQueue *ctrl_vq;
    NICState *nic;
    /* RSC Chains - temporary storage of coalesced data,
       all these data are lost in case of migration */
    QTAILQ_HEAD(, VirtioNetRscChain) rsc_chains;
    uint32_t tx_timeout;
    int32_t tx_burst;
    uint32_t has_vnet_hdr;
    size_t host_hdr_len;
    size_t guest_hdr_len;
    uint64_t host_features;
    uint32_t rsc_timeout;
    uint8_t rsc4_enabled;
    uint8_t rsc6_enabled;
    uint8_t has_ufo;
    uint32_t mergeable_rx_bufs;
    uint8_t promisc;
    uint8_t allmulti;
    uint8_t alluni;
    uint8_t nomulti;
    uint8_t nouni;
    uint8_t nobcast;
    uint8_t vhost_started;
    struct {
        uint32_t in_use;
        uint32_t first_multi;
        uint8_t multi_overflow;
        uint8_t uni_overflow;
        uint8_t *macs;
    } mac_table;
    uint32_t *vlans;
    virtio_net_conf net_conf;
    NICConf nic_conf;
    DeviceState *qdev;
    int multiqueue;
    uint16_t max_queue_pairs;
    uint16_t curr_queue_pairs;
    uint16_t max_ncs;
    size_t config_size;
    char *netclient_name;
    char *netclient_type;
    uint64_t curr_guest_offloads;
    /* used on saved state restore phase to preserve the curr_guest_offloads */
    uint64_t saved_guest_offloads;
    AnnounceTimer announce_timer;
    bool needs_vnet_hdr_swap;
    bool mtu_bypass_backend;
    /* primary failover device is hidden*/
    bool failover_primary_hidden;
    bool failover;
    DeviceListener primary_listener;
    QDict *primary_opts;
    bool primary_opts_from_json;
    NotifierWithReturn migration_state;
    VirtioNetRssData rss_data;
    struct NetRxPkt *rx_pkt;
    struct EBPFRSSContext ebpf_rss;
    uint32_t nr_ebpf_rss_fds;
    char **ebpf_rss_fds;
};
```

注意 `VirtIONet` 持有的不是单个 `NetClientState`：多队列场景下，每个收发队列各对应一个前端节点，这些节点统一聚合在 [**struct NICState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/include/net/net.h#L126) 中，由 `VirtIONet` 的 `nic` 成员持有：

```c
typedef struct NICState {
    NetClientState *ncs;
    NICConf *conf;
    MemReentrancyGuard *reentrancy_guard;
    void *opaque;
    bool peer_deleted;
} NICState;
```

每个队列前端节点的行为由 [**net_virtio_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L3418) 描述：

```c
static NetClientInfo net_virtio_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = virtio_net_can_receive,
    .receive = virtio_net_receive,
    .link_status_changed = virtio_net_set_link_status,
    .query_rx_filter = virtio_net_query_rxfilter,
    .announce = virtio_net_announce,
};
```

当 host 侧有报文到达 tap 设备时，后端最终通过 peer 调用到前端的 [**virtio_net_receive()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/net/virtio-net.c#L2691)，把报文写入 guest 预先挂到接收 vq 的缓冲中并通知guest：

```c
//#0  virtio_net_receive (nc=0x555557da3b08, buf=0x55555711d8bc "\001", size=0xc3) at ../hw/net/virtio-net.c:2694
//#1  0x0000555555b8385f in nc_sendv_compat (nc=0x555557da3b08, iov=0x7fffffffd460, iovcnt=0x1, flags=0x0) at ../net/net.c:810
//#2  0x0000555555b8398c in qemu_deliver_packet_iov (sender=0x55555711d2c0, flags=0x0, iov=0x7fffffffd460, iovcnt=0x1, opaque=0x555557da3b08) at ../net/net.c:847
//#3  0x0000555555b8734b in qemu_net_queue_deliver (queue=0x555557da3cd0, sender=0x55555711d2c0, flags=0x0, data=0x55555711d8bc "\001", size=0xc3)
//    at ../net/queue.c:164
//#4  0x0000555555b87532 in qemu_net_queue_send (queue=0x555557da3cd0, sender=0x55555711d2c0, flags=0x0, data=0x55555711d8bc "\001", size=0xc3, 
//    sent_cb=0x555555b8ca56 <tap_send_completed>) at ../net/queue.c:221
//#5  0x0000555555b835dc in qemu_send_packet_async_with_flags (sender=0x55555711d2c0, flags=0x0, buf=0x55555711d8bc "\001", size=0xc3, 
//    sent_cb=0x555555b8ca56 <tap_send_completed>) at ../net/net.c:745
//#6  0x0000555555b83622 in qemu_send_packet_async (sender=0x55555711d2c0, buf=0x55555711d8bc "\001", size=0xc3, sent_cb=0x555555b8ca56 <tap_send_completed>)
//    at ../net/net.c:752
//#7  0x0000555555b8cba9 in tap_send (opaque=0x55555711d2c0) at ../net/tap.c:212
//#8  0x0000555555f5eb47 in aio_dispatch_handler (ctx=0x555556ef5be0, node=0x55555711c100) at ../util/aio-posix.c:372
//#9  0x0000555555f5ed08 in aio_dispatch_handlers (ctx=0x555556ef5be0) at ../util/aio-posix.c:414
//#10 0x0000555555f5ed50 in aio_dispatch (ctx=0x555556ef5be0) at ../util/aio-posix.c:424
//#11 0x0000555555f7c424 in aio_ctx_dispatch (source=0x555556ef5be0, callback=0x0, user_data=0x0) at ../util/async.c:360
//#12 0x00007ffff7d8b485 in ?? () from /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#13 0x00007ffff7d8dd78 in g_main_context_dispatch () from /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#14 0x0000555555f7d9b6 in glib_pollfds_poll () at ../util/main-loop.c:287
//#15 0x0000555555f7da44 in os_host_main_loop_wait (timeout=0x1c002b74) at ../util/main-loop.c:310
//#16 0x0000555555f7db64 in main_loop_wait (nonblocking=0x0) at ../util/main-loop.c:589
//#17 0x0000555555b2e067 in qemu_main_loop () at ../system/runstate.c:783
//#18 0x0000555555d92c24 in qemu_default_main () at ../system/main.c:37
//#19 0x0000555555d92c61 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:48
//#20 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968)
//    at ../sysdeps/nptl/libc_start_call_main.h:58
//#21 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, 
//    rtld_fini=<optimized out>, stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#22 0x000055555584b661 in _start ()
```

### 后端

qemu 会用 **TAPState** 来表示 tap 后端，从而将 host 上的 tun/tap 字符设备包装成一个 **struct NetClientState** 节点。具体的，[**struct TAPState**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/tap.c#L50) 如下所示

```c
typedef struct TAPState {
    NetClientState nc;
    int fd;
    char down_script[1024];
    char down_script_arg[128];
    uint8_t buf[NET_BUFSIZE];
    bool read_poll;
    bool write_poll;
    bool using_vnet_hdr;
    bool has_ufo;
    bool has_uso;
    bool enabled;
    VHostNetState *vhost_net;
    unsigned host_vnet_hdr_len;
    Notifier exit;
} TAPState;
```

`nc` 同样是首成员，这一布局让 qemu 在只持有 `NetClientState *` 时，可以用 `DO_UPCAST(TAPState, nc, nc)`（本质是 `container_of`）反推出整个 `TAPState`。

而后端节点的行为由 `nc->info` 指向的 [**net_tap_info**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/tap.c#L389) 提供

```c
static NetClientInfo net_tap_info = {
    .type = NET_CLIENT_DRIVER_TAP,
    .size = sizeof(TAPState),
    .receive = tap_receive,
    .receive_raw = tap_receive_raw,
    .receive_iov = tap_receive_iov,
    .poll = tap_poll,
    .cleanup = tap_cleanup,
    .has_ufo = tap_has_ufo,
    .has_uso = tap_has_uso,
    .has_vnet_hdr = tap_has_vnet_hdr,
    .has_vnet_hdr_len = tap_has_vnet_hdr_len,
    .get_using_vnet_hdr = tap_get_using_vnet_hdr,
    .using_vnet_hdr = tap_using_vnet_hdr,
    .set_offload = tap_set_offload,
    .get_vnet_hdr_len = tap_get_vnet_hdr_len,
    .set_vnet_hdr_len = tap_set_vnet_hdr_len,
    .set_vnet_le = tap_set_vnet_le,
    .set_vnet_be = tap_set_vnet_be,
    .set_steering_ebpf = tap_set_steering_ebpf,
};
```

当 guest 驱动向外发包时，前端最终通过 peer 调用到后端的 [**tap_receive_iov()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/tap.c#L116)，后者经 `tap_write_packet()` 用 `writev()` 把报文写入 tap 设备的 fd，报文由此进入 host 的网络协议栈：

```c
//#0  tap_receive_iov (nc=0x55555711d2c0, iov=0x555557b6b630, iovcnt=0x1) at ../net/tap.c:119
//#1  0x0000555555b83971 in qemu_deliver_packet_iov (sender=0x555557da3b08, flags=0x0, iov=0x555557b6b630, iovcnt=0x1, opaque=0x55555711d2c0) at ../net/net.c:845
//#2  0x0000555555b873c8 in qemu_net_queue_deliver_iov (queue=0x555556efa2f0, sender=0x555557da3b08, flags=0x0, iov=0x555557b6b630, iovcnt=0x1) at ../net/queue.c:179
//#3  0x0000555555b87617 in qemu_net_queue_send_iov (queue=0x555556efa2f0, sender=0x555557da3b08, flags=0x0, iov=0x555557b6b630, iovcnt=0x1, 
//    sent_cb=0x555555ccc4e2 <virtio_net_tx_complete>) at ../net/queue.c:246
//#4  0x0000555555b83af9 in qemu_sendv_packet_async (sender=0x555557da3b08, iov=0x555557b6b630, iovcnt=0x1, sent_cb=0x555555ccc4e2 <virtio_net_tx_complete>)
//    at ../net/net.c:892
//#5  0x0000555555ccca15 in virtio_net_flush_tx (q=0x555556ef8dc0) at ../hw/net/virtio-net.c:2812
//#6  0x0000555555cccf5d in virtio_net_tx_bh (opaque=0x555556ef8dc0) at ../hw/net/virtio-net.c:2960
//#7  0x0000555555f7be7c in aio_bh_call (bh=0x555556ef8d40) at ../util/async.c:171
//#8  0x0000555555f7bfb5 in aio_bh_poll (ctx=0x555556ef9a50) at ../util/async.c:218
//#9  0x0000555555f5ed44 in aio_dispatch (ctx=0x555556ef9a50) at ../util/aio-posix.c:423
//#10 0x0000555555f7c424 in aio_ctx_dispatch (source=0x555556ef9a50, callback=0x0, user_data=0x0) at ../util/async.c:360
//#11 0x00007ffff7d8b485 in ?? () from /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#12 0x00007ffff7d8dd78 in g_main_context_dispatch () from /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#13 0x0000555555f7d9b6 in glib_pollfds_poll () at ../util/main-loop.c:287
//#14 0x0000555555f7da44 in os_host_main_loop_wait (timeout=0x0) at ../util/main-loop.c:310
//#15 0x0000555555f7db64 in main_loop_wait (nonblocking=0x0) at ../util/main-loop.c:589
//#16 0x0000555555b2e067 in qemu_main_loop () at ../system/runstate.c:783
//#17 0x0000555555d92c24 in qemu_default_main () at ../system/main.c:37
//#18 0x0000555555d92c61 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:48
//#19 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968)
//    at ../sysdeps/nptl/libc_start_call_main.h:58
//#20 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, 
//    rtld_fini=<optimized out>, stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#21 0x000055555584b661 in _start ()
```

## 启动过程

这里详细介绍一下`-device virtio-net-pci,netdev=hostnet0 -netdev tap,id=hostnet0,ifname=tap_for_l1`命令行的网卡的启动过程

### 创建后端

由于前端依赖于后端，所以后端往往先于前端构建。qemu会在[**qemu_create_late_backends()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/system/vl.c#L2005)中创建大部分设备后端，其中调用[**net_init_clients()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c#L1848)创建网卡后端，如下所示

```c
//#0  net_init_clients () at ../net/net.c:1851
//#1  0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#2  0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968)
//    at ../system/vl.c:3712
//#3  0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968)
//    at ../system/main.c:47
//#4  0x00007ffff7b62ca8 in __libc_start_call_main (
//    main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, 
//    argv=argv@entry=0x7fffffffd968)
//    at ../sysdeps/nptl/libc_start_call_main.h:58
//#5  0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, 
//    argc=0x26, argv=0x7fffffffd968, init=<optimized out>, 
//    fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd958)
//    at ../csu/libc-start.c:360
//#6  0x000055555584b661 in _start ()
void net_init_clients(void)
{
    net_change_state_entry =
        qemu_add_vm_change_state_handler(net_vm_change_state_handler, NULL);

    QTAILQ_INIT(&net_clients);

    netdev_init_modern();

    qemu_opts_foreach(qemu_find_opts("netdev"), net_init_netdev, NULL,
                      &error_fatal);

    qemu_opts_foreach(qemu_find_opts("nic"), net_param_nic, NULL,
                      &error_fatal);

    qemu_opts_foreach(qemu_find_opts("net"), net_init_client, NULL,
                      &error_fatal);
}
```

可以看到，其会调用[**net_init_netdev()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c#L1739)来处理所有**netdev**的后端选项，即`-netdev tap,id=hostnet0,ifname=tap_for_l1`,如下所示

```c
static int net_init_netdev(void *dummy, QemuOpts *opts, Error **errp)
{
    const char *type = qemu_opt_get(opts, "type");

    if (type && is_help_option(type)) {
        show_netdevs();
        exit(0);
    }
    return net_client_init(opts, true, errp);
}

static int net_client_init(QemuOpts *opts, bool is_netdev, Error **errp)
{
    ...
    Visitor *v = opts_visitor_new(opts);
    ...
    if (visit_type_Netdev(v, NULL, &object, errp)) {
        ret = net_client_init1(object, is_netdev, errp);
    }

    qapi_free_Netdev(object);

out:
    g_strfreev(substrings);
    visit_free(v);
    return ret;
}
```

其核心逻辑在[**net_client_init1()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/net.c#L1279),会根据netdev类型调用对应的初始化回调函数,如下所示

```c
static int (* const net_client_init_fun[NET_CLIENT_DRIVER__MAX])(
    const Netdev *netdev,
    const char *name,
    NetClientState *peer, Error **errp) = {
        ...
        [NET_CLIENT_DRIVER_TAP]       = net_init_tap,
        ...
};

static int net_client_init1(const Netdev *netdev, bool is_netdev, Error **errp)
{
    ...
    NetClientState *nc;
    ...
    if (net_client_init_fun[netdev->type](netdev, netdev->id, peer, errp) < 0) {
        /* FIXME drop when all init functions store an Error */
        if (errp && !*errp) {
            error_setg(errp, "Device '%s' could not be initialized",
                       NetClientDriver_str(netdev->type));
        }
        return -1;
    }
    ...
}
```
在这里即调用[**net_init_tap()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/net/tap.c#L812)

```c
int net_init_tap(const Netdev *netdev, const char *name,
                 NetClientState *peer, Error **errp)
{
    ...
    tap = &netdev->u.tap;
    queues = tap->has_queues ? tap->queues : 1;
    ...
    if (tap->ifname) {
        pstrcpy(ifname, sizeof ifname, tap->ifname);
    } else {
        ifname[0] = '\0';
    }

    for (i = 0; i < queues; i++) {
        fd = net_tap_init(tap, &vnet_hdr, i >= 1 ? "no" : script,
                          ifname, sizeof ifname, queues > 1, errp);
        if (fd == -1) {
            return -1;
        }
        ...
        net_init_tap_one(tap, peer, "tap", name, ifname,
                         i >= 1 ? "no" : script,
                         i >= 1 ? "no" : downscript,
                         vhostfdname, vnet_hdr, fd, &err);
        ...
    }
    

    return 0;
}

static int net_tap_init(const NetdevTapOptions *tap, int *vnet_hdr,
                        const char *setup_script, char *ifname,
                        size_t ifname_sz, int mq_required, Error **errp)
{
    ...
    fd = RETRY_ON_EINTR(tap_open(ifname, ifname_sz, vnet_hdr, vnet_hdr_required,
                      mq_required, errp));
    if (fd < 0) {
        return -1;
    }
    ...
    return fd;
}

static void net_init_tap_one(const NetdevTapOptions *tap, NetClientState *peer,
                             const char *model, const char *name,
                             const char *ifname, const char *script,
                             const char *downscript, const char *vhostfdname,
                             int vnet_hdr, int fd, Error **errp)
{
    ...
    TAPState *s = net_tap_fd_init(peer, model, name, fd, vnet_hdr);
    ...
}

//#0  net_tap_fd_init (peer=0x0, model=0x555556122e15 "tap", name=0x55555711cb60 "net", fd=0xb, vnet_hdr=0x1) at ../net/tap.c:417
//#1  0x0000555555b8e095 in net_init_tap_one (tap=0x55555711c610, peer=0x0, model=0x555556122e15 "tap", name=0x55555711cb60 "net", 
//    ifname=0x7fffffffd3f0 "tap_for_l1", script=0x555556efa360 "no", downscript=0x555556ef9280 "no", vhostfdname=0x0, vnet_hdr=0x1, fd=0xb, errp=0x7fffffffd478)
//    at ../net/tap.c:707
//#2  0x0000555555b8f150 in net_init_tap (netdev=0x55555711c600, name=0x55555711cb60 "net", peer=0x0, errp=0x555556e83800 <error_fatal>) at ../net/tap.c:1021
//#3  0x0000555555b85242 in net_client_init1 (netdev=0x55555711c600, is_netdev=0x1, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1320
//#4  0x0000555555b855ed in net_client_init (opts=0x555556ef8f20, is_netdev=0x1, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1428
//#5  0x0000555555b86240 in net_init_netdev (dummy=0x0, opts=0x555556ef8f20, errp=0x555556e83800 <error_fatal>) at ../net/net.c:1747
//#6  0x0000555555f6dccd in qemu_opts_foreach (list=0x555556d7fcc0 <qemu_netdev_opts>, func=0x555555b861d7 <net_init_netdev>, opaque=0x0, 
//    errp=0x555556e83800 <error_fatal>) at ../util/qemu-option.c:1135
//#7  0x0000555555b86774 in net_init_clients () at ../net/net.c:1857
//#8  0x0000555555b32fb0 in qemu_create_late_backends () at ../system/vl.c:2011
//#9  0x0000555555b37745 in qemu_init (argc=0x26, argv=0x7fffffffd968) at ../system/vl.c:3712
//#10 0x0000555555d92c58 in main (argc=0x26, argv=0x7fffffffd968) at ../system/main.c:47
//#11 0x00007ffff7b62ca8 in __libc_start_call_main (main=main@entry=0x555555d92c38 <main>, argc=argc@entry=0x26, argv=argv@entry=0x7fffffffd968)
//    at ../sysdeps/nptl/libc_start_call_main.h:58
//#12 0x00007ffff7b62d65 in __libc_start_main_impl (main=0x555555d92c38 <main>, argc=0x26, argv=0x7fffffffd968, init=<optimized out>, fini=<optimized out>, 
//    rtld_fini=<optimized out>, stack_end=0x7fffffffd958) at ../csu/libc-start.c:360
//#13 0x000055555584b661 in _start ()
static TAPState *net_tap_fd_init(NetClientState *peer,
                                 const char *model,
                                 const char *name,
                                 int fd,
                                 int vnet_hdr)
{
    NetClientState *nc;
    TAPState *s;

    nc = qemu_new_net_client(&net_tap_info, peer, model, name);

    s = DO_UPCAST(TAPState, nc, nc);

    s->fd = fd;
    s->host_vnet_hdr_len = vnet_hdr ? sizeof(struct virtio_net_hdr) : 0;
    s->using_vnet_hdr = false;
    s->has_ufo = tap_probe_has_ufo(s->fd);
    s->has_uso = tap_probe_has_uso(s->fd);
    s->enabled = true;
    tap_set_offload(&s->nc, 0, 0, 0, 0, 0, 0, 0);
    /*
     * Make sure host header length is set correctly in tap:
     * it might have been modified by another instance of qemu.
     */
    if (tap_probe_vnet_hdr_len(s->fd, s->host_vnet_hdr_len)) {
        tap_fd_set_vnet_hdr_len(s->fd, s->host_vnet_hdr_len);
    }
    tap_read_poll(s, true);
    s->vhost_net = NULL;

    s->exit.notify = tap_exit_notify;
    qemu_add_exit_notifier(&s->exit);

    return s;
}
```

# 参考
