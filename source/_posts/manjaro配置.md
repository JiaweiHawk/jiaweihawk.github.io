---
title: manjaro配置
date: 2021-06-05 09:57:23
tags: [设置, 系统启动]
categories: 设置
description: “简单介绍manjaro的安装和配置"
---

# 前言

  从manjaro的U盘启动设置开始，介绍manjaro系统的整个安装、配置过程

# 制作启动U盘

  在这里顺便介绍一些系统启动、磁盘分区的相关基础知识，最后根据这些知识，完成启动u盘的安装

## 系统启动

  系统启动，本质上是识别并读取存储上的数据信息，并完成操作系统的加载，最后将计算机的控制权转交给操作系统。
  因此，系统启动的过程，即首先区分存储(往往是硬盘或U盘)的分区，其次执行启动分区的代码，完成系统分区中的操作系统加载，最后将计算机的控制权转交即可。。
  就目前来说，系统启动有两种常用的模式——**Legacy mode**和**UEFI mode**

### Legacy mode(BIOS/MBR)

Legacy mode，即通过MBR/BIOS进行引导的传统模式。BIOS只能识别设备，无法识别分区和文件信息。因此对应的引导的流程如下：

- 从ROM执行BIOS代码进行自检
- 读取主引导记录(MBR) ：即按照指定的设备顺序，读取设备的第一个扇区
  1. 如果其最后两个字节为**55AAH**，则读入该扇区，该扇区中包含设备的分区信息。之后将计算机控制权交给该主引导扇区的引导程序即可。
  2. 如果不相等，则继续尝试其他设备

这里借鉴[知乎前辈的图](https://zhuanlan.zhihu.com/p/26098509)，给出主引导扇区的格式

![主引导扇区格式.png](主引导扇区格式.png)

上面的图片很清晰的说明了Legacy mode下区分存储分区的方式，则当读入主引导分区并将计算机控制权交给引导程序后，可以获取分区情况，从而可以继续载入启动分区的代码，最终加载系统分区中的操作系统。这里同样借用[知乎前辈的图](https://zhuanlan.zhihu.com/p/31365115)如下所示

![Legacy mode启动过程](legacy-mode.png)

### UEFI mode(UEFI/GPT)

UEFI mode，实际上是Legacy mode的替代品。与Legacy mode不同的是，UEFI mode不仅可以识别设备，其同时可以识别ROM、分区表和文件系统。因此对应的引导流程如下：

- 运行ROM中的Pre-EFI初始化模块进行自检
- 加载位于ROM中的DXE**(Driver Execution Environment)**
  1. 枚举并加载位于各个设备ROM中的**设备驱动**，从而可以识别所有的设备信息
  2. 对**磁盘设备**，使用ROM中驱动识别磁盘上的`MBR`或`GPT`**(GUID Partition Table)**分区表，从而获取磁盘的分区信息
  3. 对于**每个**分区，使用ROM或EFI系统分区中的文件系统驱动，从而完成分区中文件系统的加载。
- 将计算机控制权交给EFI系统分区的引导程序即可

实际上`MBR`和`GPT`都从磁盘的第一个扇区开始，其中GPT分区表的格式如所示

![gpt分区表格式](gpt分区表格式.png)

可以看到，如果主板不支持UEFI，则其还是可以通过PMBR结构，实现类似于**Legacy mode**的引导；否则，其通过**Partition Table**，完成分区的识别，从而通过文件系统驱动，获取ESP分区的指定引导程序并完成引导，如下所示

![uefi-mode](uefi-mode.png)

### 总结

这里再说一下个人的理解——实际上**Legacy mode**和**UEFI mode**本质没有区别，都是加载引导程序，从而去引导操作系统的加载。其区别在于
- ROM中的BIOS无法识别设备上的分区、文件等数据。因此将引导程序放在主引导扇区的固定位置，则BIOS将**计算机的控制权转交给该引导程序**。而引导程序可以通过读取设备的**mbr**分区表，完成操作系统的加载
- ROM中的UEFI有相关的驱动，因此其可以识别分区、文件等数据。因此其通过读取设备的**gpt**分区表，完成操作系统的加载，在此之前**无须转交计算机控制权**。

## 制作manjaro启动U盘

这里我们分别构造适用于**Legacy mode**引导和适用于**UEFI mode**引导的manjaro启动u盘

### 适用于Legacy mode引导

- 首先，按照前面的分析，我们在磁盘上创建MBR分区表，实现磁盘的分区

```bash
sudo fdisk /dev/sdX

Command (m for help): o

Command (m for help): n
Partition type
   p   primary (0 primary, 0 extended, 4 free)
   e   extended (container for logical partitions)
Select (default p): p
Partition number (1-4, default 1): 
First sector (2048-15646719, default 2048): 
Last sector, +/-sectors or +/-size{K,M,G,T,P} (2048-15646719, default 15646719):

Command (m for help): a
Selected partition 1
The bootable flag on partition 1 is enabled now.

Command (m for help): w


sudo mkfs.vfat -F32 /dev/sdXn
```

- 接着，向系统分区写入相关的操作系统数据

```bash
sudo pacman -S grub

sudo mkdir -p /mnt/{iso,usb}
sudo mount -o loop manjaro-kde-21.0.5-210519-linux510.iso /mnt/iso
sudo mount /dev/sdXn /mnt/usb
sudo cp -a /mnt/iso/. /mnt/usb/
sudo umount /mnt/*
```

- 最后，将引导程序写入主引导扇区并完成其他设置即可

```bash
sudo grub-install --target=i386-pc --boot-directory=/mnt/usb/boot /dev/sdX
```

这里由于manjaro镜像中已经有相关的配置文件**boot/grub/grub.cfg**，因此不需要在配置。此时，已经完成适用于**Legacy mode**的启动u盘

### 适用于UEFI mode引导

由于**UEFI mode**会替代**Legacy mode**引导模式，因此这里同样给出适用于**UEFI mode**的引导

- 首先，我们在磁盘上创建gpt分区表，实现磁盘的分区。这里需要说明的是，**UEFI mode**引导，其会在**EFI分区(EFI system partition)**中查找引导程序，因此一定需要有**EFI分区/ESP**

```bash
sudo fdisk /dev/sdX

Command (m for help): g                        

Command (m for help): n
Partition number (1-128, default 1): 
First sector (2048-15646686, default 2048): 
Last sector, +/-sectors or +/-size{K,M,G,T,P} (2048-15646686, default 15646686): 

Command (m for help): t
Selected partition 1
Partition type or alias (type L to list all): 1
Changed type of partition 'Linux filesystem' to 'EFI System'.


Command (m for help): w

sudo mkfs.vfat -F32 /dev/sdXn
```

- 接着，向**EFI分区**中写入操作系统相关数据

```bash
sudo mkdir -p /mnt/{iso,usb}

sudo mount /dev/sdXn /mnt/usb
sudo mount -o loop manjaro-kde-21.0.5-210519-linux510.iso /mnt/iso
sudo cp -a /mnt/iso/. /mnt/usb
sudo umount /mnt/iso
```

- 最后，将引导程序写入**EFI分区**，并完成相关的配置即可

```bash
sudo grub-install --removable --no-floppy --target=x86_64-efi --boot-directory=/mnt/usb/boot --efi-directory=/mnt/usb

sudo umount /mnt/usb
```

这里由于manjaro镜像中已经有相关的配置文件**boot/grub/grub.cfg**，因此不需要在配置grub。此时，已经完成适用于**UEFI mode**的启动u盘

# 系统配置



## 换源

  在konsole中输入如下bash命令
```bash
sudo pacman-mirrors -i -c China -m rank && sudo pacman -Syy
```
  然后从弹出的框中选择一个最好的源即可

## 安装yay

  manjaro除了pacman以外，yay同样是重要的一个软件安装途径，如下进行安装和设置
```bash
sudo pacman -S yay && yay --aururl "https://aur.tuna.tsinghua.edu.cn" --save
```
  yay镜像有连接次数限制，因此有时需要恢复成原始资源网站，即
```bash
yay --aururl "https://aur.archlinux.org" --save
```

## 安装neovim

  使用neovim作为系统的文本编辑器，在终端输入如下命令
  ```bash
sudo pacman -S neovim xsel && sudo ln -sf /usr/bin/nvim /usr/bin/vi && mkdir ~/.config/nvim && /bin/bash -c 'echo "set clipboard+=unnamedplus\nlet g:python_recommended_style = 0" > ~/.config/nvim/init.vim'
  ```


## 分辨率
### 系统dpi

  点击屏幕左下角的`application launcher`，或者点击`Win`建，打开`System Settings`，选择`Display Configuration`选项，通过设置**Resolution**和**Global scale**完成系统分辨率和DPI的设置
  ![系统dpi设置](系统dpi设置.PNG)

### 字体dpi

  点击屏幕左下角的`application launcher`，或者点击`Win`建，打开`System Settings`，选择`Appearance => fonts`选项，通过设置**General**、**Fixed width**、**Small**、**Toolbar**、**Menu**和**Window title**以及**Force font DPI**，完成系统中字体DPI的设置
  ![字体dpi设置](字体dpi设置.PNG)

### 登录窗口dpi

  即manajaro登录界面的dpi，这里通过编辑sddm的设置文件——即`\etc\sddm.conf`完成，添加或修改如下项的值

```conf
[Wayland]
EnableHiDPI=true

[X11]
EnableHiDPI=true
ServerArguments=-nolisten tcp -dpi 192
```




## 安装输入法

### 下载输入法
在konsole中执行如下bash命令
```bash
sudo pacman -S fcitx5-im fcitx5-rime
```

通过 **~/.pam_environment** 配置环境变量，写入如下内容
```
GTK_IM_MODULE DEFAULT=fcitx
QT_IM_MODULE  DEFAULT=fcitx
XMODIFIERS    DEFAULT=@im=fcitx
INPUT_METHOD  DEFAULT=fcitx
SDL_IM_MODULE DEFAULT=fcitx
```
  <br>然后重启更新计算机环境


### 配置输入法

  点击右下角菜单栏的键盘托盘图标，点击`设置`，添加`rime`输入法
  ![配置输入法](配置输入法.PNG)
  首先创建**~/.local/share/fcitx5/rime/default.custom.yaml**，并输入如下内容
  ```yaml
patch:
  schema_list:
    - schema: luna_pinyin_simp
  ```
  接着创建**~/.local/share/fcitx5/rime/luna_pinyin_simp.custom.yaml**，并输入如下内容
```yaml
patch:
  switches:
    - name: ascii_mode
      reset: 1
      states: ["中文", "西文"]
    - name: full_shape
      reset: 0
      states: ["半角", "全角"]
    - name: zh_simp
      reset: 1
      states: ["繁體", "简体"]
      
  recognizer/patterns:
    reverse_lookup: "[a-z]*'?$"
    
  punctuator/half_shape:
    "," : "，"
    "." : "。"
    "<" : "《"
    ">" : ">"
    "/" : "/"
    "?" : "?"
    ";" : ";"
    ":" : ":"
    "\"" : "\""
    "\\": "、"
    "|" : "|"
    "`" : "`"
    "~" : "~"
    "!" : "!"
    "@" : "@"
    "#" : "#"
    "%" : "%"
    "$" : "$"
    "^" : "^"
    "&" : "&"
    "*" : "*"
    "(" : "("
    ")" : ")"
    "-" : "-"
    '_' : ——
    "+" : "+"
    "=" : "="
    "[" : "["
    "]" : "]"
    "{" : "{"
    "}" : "}"
```

  创建**~/.config/fcitx5/conf/classicui.conf**，并输入如下内容调整输入框的字体设置
```conf
# 按屏幕 DPI 使用
PerScreenDPI=True

# Font (设置成你喜欢的字体)
Font="Noto Sans Regular 13"
```



  然后切换至rime输入法，随便输入相关信息，并输入 `ctrl + ~`，切换至 **朙月拼音·简化字**输入法。最后，点击右下角菜单栏的键盘托盘图标，选择`deploy`重新部署rime输入法。
  然后重启更新计算机环境。
  最后点击右下角菜单栏的键盘托盘图标，点击`设置`，删除`Keyboard-English(US)`输入法即可

## 设置konsole

### 关闭yakuake
  即点击屏幕左下角的`application launcher`，或者点击`Win`建，打开`System Settings`，选择`Workspace => Startup and Shutdown => Autostart`选项，删除**yakuake**项。
  ![关闭yakuake](关闭yakuake.png)

### 设置快捷键
  即点击屏幕左下角的`application launcher`，或者点击`Win`建，打开`System Settings`，选择`Workspace => Shortcuts => Shortcuts`选项，点击 **Add Application**选项，添加`konsole`，并设置相关的快捷键即可。
  ![设置konsole快捷键](设置konsole快捷键.PNG)

### 设置字体
  打开konsole，在界面上方的`Settings => Edit Current Profile`，选择`Appearance`，在**Font**对应字段进行设置即可
  ![设置konsole字体](设置konsole字体.PNG)


## 设置护眼

  这里使用跨平台的**Stretchly**软件，进行定时的息屏休息功能

### 安装Stretchly

  首先在[链接](https://github.com/hovancik/stretchly/releases)中，下载*Stretchly-[version].pacman*文件

  在konsole中执行如下bash命令，完成软件的安装
```bash
sudo pacman -U $(ls | grep "Stretchly")
```

### 配置Stretchly

  首先，设置其为自动启动程序，即点击屏幕左下角的`application launcher`，或者点击`Win`建，打开`System Settings`，选择`Workspace => Startup and Shutdown => Autostart`选项，添加**Stretchly**项。

  ![设置stretchly自动启动](自动启动stretchly.PNG)


  接着启动*Stretchly*，完成软件的设置即可。即点击屏幕左下角的`application launcher`，或者点击`Win`建，在搜索框输入**Stretchly**，然后点击软件即可。之后按照软件的引导，完成相关的配置即可

  ![启动stretchly](启动stretchly.PNG)

## 设置python

### 安装python3

  系统已经默认安装

### 安装pip3

  系统已经默认安装

### 安装python2

在konsole中执行如下bash命令
```bash
sudo pacman -S python2
```

### 安装pip2

在konsole中执行如下bash命令
```bash
sudo pacman -S python2-pip
```

### 配置pip

在konsole中执行如下bash命令
```bash
python2 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U && python2 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

  有时python的pip会出现相关的错误信息，则执行如下命令重新安装pip
```bash
wget --no-check-certificate https://bootstrap.pypa.io/pip/$(python2 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py && python2 get-pip.py && rm -rf get-pip.py && python2 -m pip install pathlib2


wget --no-check-certificate https://bootstrap.pypa.io/pip/$(python3 -V 2>&1 | sed 's/\./ /g' | awk '{printf("%s.%s", $2, $3)}')/get-pip.py -O get-pip3.py && python3 get-pip3.py && rm -rf get-pip3.py
```
  然后再执行上述的命令即可

## 设置C/C++
在konsole中执行如下bash命令
```bash
sudo pacman -S gcc
```

## 设置Java
在konsole中执行如下bash命令
```bash
sudo pacman -S jdk11-openjdk
```

## 设置Git

### 安装git

  在终端下执行如下命令继续安装
```bash
sudo pacman -S git
```

### 初始化用户信息

在konsole中执行如下bash命令，其中相关的参数填写git的系统设置即可
```bash
git config --global user.name "hawk" && git config --global user.email 18801353760@163.com && git config --global core.editor vi
```

### 导出公、私钥

首先，如果没有相关的公、私钥，可以参考[帮助链接](https://gitee.com/help/articles/4229)，生成自己的公、私钥

这里将公、私钥进行压缩，并进行加密处理，在konsole中执行如下bash命令
```bash
git_passwd=
```

```bash
git_name=hawk && git_email=18801353760@163.com && tar -zcvf ssh.tar.gz -C ~ --exclude .ssh/known_hosts .ssh/ && K=$(echo ${git_passwd}${git_name}${git_email} | md5sum | awk '{print $1}') && iv=$(echo ${git_passwd}${git_name} | md5sum | awk '{print $1}') && openssl enc -aes-256-cbc -e -in ssh.tar.gz -out ssh.dec -K ${K} -iv ${iv}
```

### 导入公、私钥

即导入上述导出的公、私钥，这里给出我自己的加密后的[公、私钥](ssh.dec)
然后对文件首先进行解密处理，最后解压缩即可，在konsole中执行如下bash命令
```bash
git_passwd=
```

```bash
git_name=hawk && git_email=18801353760@163.com && K=$(echo ${git_passwd}${git_name}${git_email} | md5sum | awk '{print $1}') && iv=$(echo ${git_passwd}${git_name} | md5sum | awk '{print $1}') && openssl enc -aes-256-cbc -d -in ssh.dec -out ssh.tar.gz -K ${K} -iv ${iv} && tar -zxvf ssh.tar.gz -C ~/ && chmod 700 -R ~/.ssh
```




## 设置v2ray代理

这里通过安装**clash**，实现代理上网

### 下载clash代理

  在终端执行如下命令，安装**clash**软件
  ```bash
sudo pacman -S clash
```

### 设置clash代理

  clash需要**yaml**格式的config文件，从而完成设置。
  我们可以将给定的文件放置在**~/.config/clash**目录下。如果给的是一个订阅链接，则我们首先根据链接，将设置文件下载下来，然后重命名后放置在**~/.config/clash**目录下即可

  然后，我们通过如下命令，启用指定配置文件的clash
  ```bash
clash -f /path/to/config
```

  此时，我们可以登录[http://clash.razord.top/](http://clash.razord.top/)网站，进行进一步的设置，如下所示
  ![clash的网页设置](clash的网页设置.PNG)
  我们只需要将http代理端口和Socks5代理端口特别关注以下即可，然后点击菜单中的**代理**选项，进行代理即可


### 配置firefox和proxychains

大部分时候，打开**clash**，可以实现数据走系统代理
但是类似于firefox、命令行等的数据并不走系统代理，因此需要单独进行设置。

对于**firefox**来说，通过在**Network Settings**的**proxy**即可，如下所示
  ![firefox代理设置](firefox代理设置.PNG)

  其中，对应的端口是clash监听的本地http端口即可

而对于命令行来说，可以通过设置**proxychains**完成相关的代理
首先执行如下命令完成代理
```bash
sudo pacman -S proxychians
```

接着，需要修改全局代理链，将**/etc/proxychains.conf**文件的代理修改如下
```bash
[ProxyList]
socks5  127.0.0.1 8888
```

上述端口为**clash**中监听的本地socks5端口即可
之后，通过`proxychains -q [待执行命令]`，完成代理



## 设置QEMU

> **qemu**是一个广泛使用的开源计算机模拟器和虚拟机

  因此，这里使用qemu提供manjaro上的虚拟机功能

### 安装qemu

这里安装qemu相关的依赖和功能软件包
```bash
sudo pacman -S qemu ovmf bridge-utils vde2 dnsmasq ebtables openbsd-netcat
```

| 软件包 | 功能 |
| :-: | :-: |
| ovmf | UEFI支持 |
| bridge-utils | 网络桥接支持 |
| vde2 | 以太网支持 |
| dnsmasq ebtables | NAT/DHCP网络 |
| openbsd-netcat | ssh连接虚拟机支持 |

### 安装图形化前端管理

这里选择**virt-manager**作为管理KVM虚拟机的前端。而virt-manager依赖于libvirt的提供的接口，因此安装virt-manager及其依赖
```bash
sudo pacman -S virt-manager virt-viewer libvirt
```

然后启动libvirtd服务，并将网络设置为自动启动即可
```bash
sudo systemctl enable libvirtd
sudo systemctl start libvirtd

sudo virsh net-autostart default
```

### 配置win10虚拟机

#### 下载win10ISO文件

前往[ITELLYOU](https://next.itellyou.cn/)，下载官方win10的ISO镜像文件

#### 下载virtio-win驱动

为了提高虚拟机性能，虚拟机会使用virtIO技术，而windows客户机需要手动安装该驱动

首先，点击[链接](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso)下载相关驱动

#### 启动virt-manager

执行如下命令启动**virt-manager**管理程序
```bash
sudo virt-manager
```

![启动virt-manager](启动virt-manager.PNG)

#### 新建虚拟机

在**virt-manager**界面的上方菜单，点击最左侧的**创建新的虚拟机**按钮
![点击创建新的虚拟机按钮](点击创建新的虚拟机按钮.PNG)


选择从本地镜像安装，`x86_64`架构，点击右下角**Forward**下一步
![选择镜像界面](选择镜像.PNG)


点击该界面上方的**Browse**界面，选择ISO位置，界面如下所示
![管理存储池界面](管理存储池界面.PNG)


这里选择右下角第一个**Browse Local**，选择前面下载的win10的ISO镜像即可
![选择win10镜像](选择win10镜像.PNG)

该界面下方取消**自动检测系统**，直接选择windows10系统
![选择操作系统为win10](选择操作系统为win10.PNG)

点击右下角的**Forward**下一步，设置内存和CPU信息
![设置内存和CPU](设置内存和CPU.PNG)

点击右下角的**Forward**下一步，设置磁盘信息
![设置虚拟机磁盘](设置虚拟机磁盘.PNG)

点击右下角的**Forward**下一步，选择在启动前编辑选项
![在启动前编辑虚拟机](在启动前编辑虚拟机.PNG)

点击右下角的**Finish**，进入虚拟机的编辑界面，完成相关的编辑
![虚拟机编辑界面](虚拟机编辑界面.PNG)

在这里添加另一个CDROM设置，其文件是前面下载的Virtio驱动文件，如下所示
![添加Virtio驱动CDROM](添加Virtio驱动CDROM.PNG)

完成编辑后，点击右上角的**Begin Installation**，完成虚拟机的安装

这里特别说明的是，当进行到**你想将Windows安装在哪里**时，其无法显示磁盘信息，如下所示
![未加载Virtio驱动程序](未加载Virtio驱动程序.PNG)

点击左下角**加载驱动程序**，选择相关的驱动程序安装即可
![安装Virtio驱动程序](安装Virtio驱动程序.PNG)

#### 配置VirtIO guest tools

为了启用主机和虚拟机之间的剪切板共享，需要在虚拟机中安装VirtIO guest tools，点击[https://www.spice-space.org/download/binaries/spice-guest-tools/](https://www.spice-space.org/download/binaries/spice-guest-tools/)下载安装即可


# 异常处理

## Failed to start Load/Save Screen Backlight Brightness of backlight:acpi\_video0

这里实际上系统使用了两种服务保存并载入背光设置，一个为`systemd-backlight@backlight:acpi_video0`；另一个为`systemd-backlight@backlight:amdgpu_b10`。对于AMD集显来说，第一个出错，会使用第二种设置，则直接mask掉第一个服务即可，在konsole中执行如下bash命令

```bash
sudo systemctl mask systemd-backlight@backlight:acpi_video0
```
