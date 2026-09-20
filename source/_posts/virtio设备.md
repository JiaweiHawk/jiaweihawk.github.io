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
-netdev tap,id=hostnet0
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

##### event

## 前端

## 后端

# 参考
