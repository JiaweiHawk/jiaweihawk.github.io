---
title: linux内核编译
date: 2022-05-15 15:55:13
tags: ['linux', '内核']
categories: ['内核']
---

# 前言

这篇博客分析一下Ubuntu更换内核的步骤

# 安装依赖

执行如下命令，安装编译内核所需要的依赖组件
```bash
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison
```

# 下载源码

执行如下类似命令，从相关的网站中下载版本的内核源码并解压
```bash
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.17.tar.gz && tar -zxvf linux-5.17.tar.gz
```

# 编译设置

为了使编译的内核可以在当前Ubuntu系统中完美适配，在需要以当前的内核设置，来编译新内核
执行如下命令即可以设置相同的选项
```bash
cp /boot/config-$(uname -r) .config && make oldconfig
```

执行过程中，由于存在**新特性**或**新设定**，程序会对此进行询问，默认使用回车选择推荐配置即可

# 编译内核

完成设置后，执行如下命令进行编译即可
```bash
make -j $(nproc) all
```

# 安装内核


## 模块安装

执行如下命令，将内核模块安装到指定目录中
```bash
su -c 'make -j $(nproc) INSTALL_MOD_STRIP=1 modules_install'
```

其中，**INSTALL_MOD_STRIP**选项用来去除调试信息，避免生成的镜像过大而无法正常启动


## 镜像安装

执行如下命令，安装内核镜像
```bash
su -c 'make -j $(nproc) install'
```


# 参考

> 1. https://trainingportal.linuxfoundation.org/learn/course/a-beginners-guide-to-linux-kernel-development-lfd103/building-and-installing-your-first-kernel/building-and-installing-your-first-kernel?page=1
> 2. https://linuxhint.com/compile-and-install-kernel-ubuntu/
> 3. https://groups.google.com/g/comp.os.linux.development.system/c/bjU7AfeZl5I