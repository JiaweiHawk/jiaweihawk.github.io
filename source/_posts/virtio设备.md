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

qemu 借助 hxtool 与 qapi-gen 等自动化代码生成框架，使开发者仅需编写一份声明式文本，即可在构建期自动生成相应的 C 代码，从而规避了大规模、强约束且极易出错的手写解析逻辑与样板代码。这里参数的解析即用到了这些框架

### hxtool

hxtool 基于 .hx 文件生成 C 头文件与文档，主要用于 qemu 命令行参数及 hmp 命令的帮助文档与说明文本的生成。

### qapi-gen

qapi-gen 则更为复杂：它基于 .json 格式的 Schema 文件，生成对外暴露结构化接口的 QAPI 接口及相关代码，包括相关参数对象

## 前端

## 后端

# 参考
