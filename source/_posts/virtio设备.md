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

#### 复用方式

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

## 前端

## 后端

# 参考
