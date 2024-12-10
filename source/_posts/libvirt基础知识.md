---
title: libvirt基础知识
date: 2024-12-04 22:00:26
tags: ['虚拟化', 'libvirt']
categories: ['虚拟化']
---

# 前言

前面{% post_link glib的事件循环 %}博客简单介绍了**libvirtd**的事件循环，这里再介绍一些**libvirt**的基本知识，方便后续继续更深入的研究**libvirt**

# libvirt架构

下图是libvirt架构的整体架构图

![libvirt架构图](libvirt架构图.png)

具体来说，整个libvirt由**virsh**命令行工具、**libvirtd**守护进程和**libvirt api**库实现三部分构成

- **virsh**命令行
其将**libvirt api**封装并以命令行的形式供用户使用，代码位于[tools/virsh.c](https://github.com/libvirt/libvirt/tree/b0a782f708ff5f1f74ff31a8650c372e9442b436/tools/virsh.c)路径
- **libvirtd**守护进程
其基于**libvirt api**以守护进程的形式管理本机虚拟化资源，并处理本机/远程**virsh**发送的**rpc**请求，其代码位于[src/remote/remote_daemon.c](https://github.com/libvirt/libvirt/blob/b0a782f708ff5f1f74ff31a8650c372e9442b436/src/remote/remote_daemon.c)路径
- **libvirt api**库及其driver实现
其将各个虚拟化组件的不同虚拟化技术抽象成统一的**api**，并以**driver**的形式调用具体的**api**实现。其中**api**定义在[src](https://github.com/libvirt/libvirt/tree/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src)路径的**driver-$driver.h**文件中，而具体的实现形式则在[src](https://github.com/libvirt/libvirt/tree/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src)的**$driver**文件夹中

# driver

根据[前面libvirt架构章节](#libvirt架构)内容，**driver**是libvirt功能的基本构建模块，这里简单介绍一下**libvirt**中的**driver**机制

## 结构体

**libvirt**使用[**virConnectDriver**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/driver.h#L74)管理每一个**driver**，如下所示
```c
typedef struct _virConnectDriver virConnectDriver;
struct _virConnectDriver {
    /* Whether driver permits a server in the URI */
    bool localOnly;
    /* Whether driver needs a server in the URI */
    bool remoteOnly;
    /* Whether driver can be used in embedded mode */
    bool embeddable;
    /*
     * NULL terminated list of supported URI schemes.
     *  - Single element { NULL } list indicates no supported schemes
     *  - NULL list indicates wildcard supporting all schemes
     */
    const char **uriSchemes;
    virHypervisorDriver *hypervisorDriver;
    virInterfaceDriver *interfaceDriver;
    virNetworkDriver *networkDriver;
    virNodeDeviceDriver *nodeDeviceDriver;
    virNWFilterDriver *nwfilterDriver;
    virSecretDriver *secretDriver;
    virStorageDriver *storageDriver;
};
```

可以看到，[**virConnectDriver**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/driver.h#L74)中包含了**driver**的**libvirt api**实现

## 注册

因为后续**libvirt**需要选择具体的**driver**实现，因此需要首先注册**driver**实现。**libvirt**使用[**virRegisterConnectDriver()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/libvirt.c#L525)来实现注册

```c
/**
 * virRegisterConnectDriver:
 * @driver: pointer to a driver block
 * @setSharedDrivers: populate shared drivers
 *
 * Register a virtualization driver, optionally filling in
 * any empty pointers for shared secondary drivers
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterConnectDriver(virConnectDriver *driver,
                         bool setSharedDrivers)
{
    VIR_DEBUG("driver=%p name=%s", driver,
              driver ? NULLSTR(driver->hypervisorDriver->name) : "(null)");

    virCheckNonNullArgReturn(driver, -1);
    if (virConnectDriverTabCount >= MAX_DRIVERS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register %1$s"),
                       driver->hypervisorDriver->name);
        return -1;
    }

    VIR_DEBUG("registering %s as driver %d",
           driver->hypervisorDriver->name, virConnectDriverTabCount);

    if (setSharedDrivers) {
        if (driver->interfaceDriver == NULL)
            driver->interfaceDriver = virSharedInterfaceDriver;
        if (driver->networkDriver == NULL)
            driver->networkDriver = virSharedNetworkDriver;
        if (driver->nodeDeviceDriver == NULL)
            driver->nodeDeviceDriver = virSharedNodeDeviceDriver;
        if (driver->nwfilterDriver == NULL)
            driver->nwfilterDriver = virSharedNWFilterDriver;
        if (driver->secretDriver == NULL)
            driver->secretDriver = virSharedSecretDriver;
        if (driver->storageDriver == NULL)
            driver->storageDriver = virSharedStorageDriver;
    }

    virConnectDriverTab[virConnectDriverTabCount] = driver;
    return virConnectDriverTabCount++;
}
```

可以看到，**libvirt**将其添加到**virConnectDriverTab**数组中。这样之后只需要遍历该数组即可完成**driver**的选择

## 选择

**libvirt**使用[**virConnectOpenInternal()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/libvirt.c#L894)来选择**driver**

```c
//#0  virConnectOpenInternal (name=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=0) at ../src/libvirt.c:897
//#1  0x00007ffff7cb3f6e in virConnectOpenAuth (name=name@entry=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=flags@entry=0) at ../src/libvirt.c:1283
//#2  0x00005555555924f0 in virshConnect (ctl=ctl@entry=0x7fffffffdb90, uri=0x0, readonly=false) at ../tools/virsh.c:127
//#3  0x00005555555927c3 in virshReconnect (ctl=ctl@entry=0x7fffffffdb90, name=name@entry=0x0, readonly=<optimized out>, readonly@entry=false, force=force@entry=false) at ../tools/virsh.c:208
//#4  0x00005555555929b4 in virshConnectionHandler (ctl=0x7fffffffdb90) at ../tools/virsh.c:309
//#5  0x00005555555e146a in vshCommandRun (ctl=ctl@entry=0x7fffffffdb90, cmd=0x555555673060) at ../tools/vsh.c:1358
//#6  0x0000555555591f70 in main (argc=argc@entry=2, argv=argv@entry=0x7fffffffdf58) at ../tools/virsh.c:889
//#7  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555591410 <main>, argc=argc@entry=2, argv=argv@entry=0x7fffffffdf58) at ../sysdeps/nptl/libc_start_call_main.h:58
//#8  0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555591410 <main>, argc=2, argv=0x7fffffffdf58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf48) at ../csu/libc-start.c:392
//#9  0x0000555555592145 in _start ()

//#0  virConnectOpenInternal (name=0x73f3b8004660 "", auth=0x0, flags=0) at ../src/libvirt.c:897
//#1  0x000073f3cbcb3f6e in virConnectOpenAuth (name=name@entry=0x73f3b8004660 "", auth=auth@entry=0x0, flags=flags@entry=0) at ../src/libvirt.c:1283
//#2  0x00005e62526a1fec in remoteOpenConn (uri=0x73f3b8004660 "", readonly=false, preserveIdentity=<optimized out>, conn=0x5e6252fc44d0) at ../src/remote/remote_daemon_dispatch.c:1821
//#3  0x00005e62526a4330 in remoteDispatchConnectOpen (server=<optimized out>, msg=<optimized out>, args=<optimized out>, rerr=0x73f3c6dff9e0, client=0x5e6252fc15a0) at ../src/remote/remote_daemon_dispatch.c:2091
//#4  remoteDispatchConnectOpenHelper (server=<optimized out>, client=0x5e6252fc15a0, msg=<optimized out>, rerr=0x73f3c6dff9e0, args=<optimized out>, ret=<optimized out>) at src/remote/remote_daemon_dispatch_stubs.h:3291
//#5  0x000073f3cbc0053c in virNetServerProgramDispatchCall (msg=0x5e6252fc3230, client=0x5e6252fc15a0, server=0x5e6252fad880, prog=0x5e6252fb7010) at ../src/rpc/virnetserverprogram.c:423
//#6  virNetServerProgramDispatch (prog=0x5e6252fb7010, server=server@entry=0x5e6252fad880, client=0x5e6252fc15a0, msg=0x5e6252fc3230) at ../src/rpc/virnetserverprogram.c:299
//#7  0x000073f3cbc06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x5e6252fad880) at ../src/rpc/virnetserver.c:135
//#8  virNetServerHandleJob (jobOpaque=0x5e6252f931f0, opaque=0x5e6252fad880) at ../src/rpc/virnetserver.c:155
//#9  0x000073f3cbb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#10 0x000073f3cbb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#11 0x000073f3cb294ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#12 0x000073f3cb326850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static virConnectPtr
virConnectOpenInternal(const char *name,
                       virConnectAuthPtr auth,
                       unsigned int flags)
{
    size_t i;
    int res;
    g_autoptr(virConnect) ret = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autofree char *uristr = NULL;
    bool embed = false;

    ret = virGetConnect();
    if (ret == NULL)
        return NULL;

    if (virConfLoadConfig(&conf, "libvirt.conf") < 0)
        return NULL;

    if (name && name[0] == '\0')
        name = NULL;
    ...
    /*
     * If no URI is passed, then check for an environment string if not
     * available probe the compiled in drivers to find a default hypervisor
     * if detectable.
     */
    if (name) {
        uristr = g_strdup(name);
    } else {
        if (virConnectGetDefaultURI(conf, &uristr) < 0)
            return NULL;

        if (uristr == NULL) {
            VIR_DEBUG("Trying to probe for default URI");
            for (i = 0; i < virConnectDriverTabCount && uristr == NULL; i++) {
                if (virConnectDriverTab[i]->hypervisorDriver->connectURIProbe) {
                    if (virConnectDriverTab[i]->hypervisorDriver->connectURIProbe(&uristr) < 0)
                        return NULL;
                    VIR_DEBUG("%s driver URI probe returned '%s'",
                              virConnectDriverTab[i]->hypervisorDriver->name,
                              NULLSTR(uristr));
                }
            }
        }
    }

    if (uristr) {
        char *alias = NULL;

        if (!(flags & VIR_CONNECT_NO_ALIASES) &&
            virURIResolveAlias(conf, uristr, &alias) < 0)
            return NULL;

        if (alias) {
            g_free(uristr);
            uristr = g_steal_pointer(&alias);
        }

        if (!(ret->uri = virURIParse(uristr)))
            return NULL;

        /* Avoid need for drivers to worry about NULLs, as
         * no one needs to distinguish "" vs NULL */
        if (ret->uri->path == NULL)
            ret->uri->path = g_strdup("");

        VIR_DEBUG("Split \"%s\" to URI components:\n"
                  "  scheme %s\n"
                  "  server %s\n"
                  "  user %s\n"
                  "  port %d\n"
                  "  path %s",
                  uristr,
                  NULLSTR(ret->uri->scheme), NULLSTR(ret->uri->server),
                  NULLSTR(ret->uri->user), ret->uri->port,
                  ret->uri->path);

        if (ret->uri->scheme == NULL) {
            virReportError(VIR_ERR_NO_CONNECT,
                           _("URI '%1$s' does not include a driver name"),
                           name);
            return NULL;
        }

        if (virConnectCheckURIMissingSlash(uristr,
                                           ret->uri) < 0) {
            return NULL;
        }

        if (STREQ(ret->uri->path, "/embed")) {
            const char *root = NULL;
            g_autofree char *regMethod = NULL;
            VIR_DEBUG("URI path requests %s driver embedded mode",
                      ret->uri->scheme);
            if (strspn(ret->uri->scheme, "abcdefghijklmnopqrstuvwxyz")  !=
                strlen(ret->uri->scheme)) {
                virReportError(VIR_ERR_NO_CONNECT,
                               _("URI scheme '%1$s' for embedded driver is not valid"),
                               ret->uri->scheme);
                return NULL;
            }

            root = virURIGetParam(ret->uri, "root");
            if (!root)
                return NULL;

            if (!g_path_is_absolute(root)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("root path must be absolute"));
                return NULL;
            }

            if (virEventRequireImpl() < 0)
                return NULL;

            regMethod = g_strdup_printf("%sRegister", ret->uri->scheme);

            if (virDriverLoadModule(ret->uri->scheme, regMethod, false) < 0)
                return NULL;

            if (virAccessManagerGetDefault() == NULL) {
                virAccessManager *acl;

                virResetLastError();

                if (!(acl = virAccessManagerNew("none")))
                    return NULL;
                virAccessManagerSetDefault(acl);
            }

            if (virStateInitialize(geteuid() == 0, true, root, false, NULL, NULL) < 0)
                return NULL;

            embed = true;
        }
    } else {
        VIR_DEBUG("no name, allowing driver auto-select");
    }

    /* Cleansing flags */
    ret->flags = flags & VIR_CONNECT_RO;

    for (i = 0; i < virConnectDriverTabCount; i++) {
        /* We're going to probe the remote driver next. So we have already
         * probed all other client-side-only driver before, but none of them
         * accepted the URI.
         * If the scheme corresponds to a known but disabled client-side-only
         * driver then report a useful error, instead of a cryptic one about
         * not being able to connect to libvirtd or not being able to find
         * certificates. */
        if (STREQ(virConnectDriverTab[i]->hypervisorDriver->name, "remote") &&
            ret->uri != NULL &&
            (
#ifndef WITH_ESX
             STRCASEEQ(ret->uri->scheme, "vpx") ||
             STRCASEEQ(ret->uri->scheme, "esx") ||
             STRCASEEQ(ret->uri->scheme, "gsx") ||
#endif
#ifndef WITH_HYPERV
             STRCASEEQ(ret->uri->scheme, "hyperv") ||
#endif
#ifndef WITH_VZ
             STRCASEEQ(ret->uri->scheme, "parallels") ||
#endif
             false)) {
            virReportErrorHelper(VIR_FROM_NONE, VIR_ERR_CONFIG_UNSUPPORTED,
                                 __FILE__, __FUNCTION__, __LINE__,
                                 _("libvirt was built without the '%1$s' driver"),
                                 ret->uri->scheme);
            return NULL;
        }

        VIR_DEBUG("trying driver %zu (%s) ...",
                  i, virConnectDriverTab[i]->hypervisorDriver->name);

        if (virConnectDriverTab[i]->localOnly && ret->uri && ret->uri->server) {
            VIR_DEBUG("Server present, skipping local only driver");
            continue;
        }

        /* Filter drivers based on declared URI schemes */
        if (virConnectDriverTab[i]->uriSchemes) {
            bool matchScheme = false;
            size_t s;
            if (!ret->uri) {
                VIR_DEBUG("No URI, skipping driver with URI whitelist");
                continue;
            }
            if (embed && !virConnectDriverTab[i]->embeddable) {
                VIR_DEBUG("Ignoring non-embeddable driver %s",
                          virConnectDriverTab[i]->hypervisorDriver->name);
                continue;
            }

            VIR_DEBUG("Checking for supported URI schemes");
            for (s = 0; virConnectDriverTab[i]->uriSchemes[s] != NULL; s++) {
                if (STREQ(ret->uri->scheme, virConnectDriverTab[i]->uriSchemes[s])) {
                    VIR_DEBUG("Matched URI scheme '%s'", ret->uri->scheme);
                    matchScheme = true;
                    break;
                }
            }
            if (!matchScheme) {
                VIR_DEBUG("No matching URI scheme");
                continue;
            }
        } else {
            if (embed) {
                VIR_DEBUG("Skipping wildcard for embedded URI");
                continue;
            } else {
                VIR_DEBUG("Matching any URI scheme for '%s'", ret->uri ? ret->uri->scheme : "");
            }
        }

        if (embed && !virConnectDriverTab[i]->embeddable) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Driver %1$s cannot be used in embedded mode"),
                           virConnectDriverTab[i]->hypervisorDriver->name);
            return NULL;
        }
        /* before starting the new connection, check if the driver only works
         * with a server, and so return an error if the server is missing */
        if (virConnectDriverTab[i]->remoteOnly && ret->uri && !ret->uri->server) {
            virReportError(VIR_ERR_INVALID_ARG, "%s", _("URI is missing the server part"));
            return NULL;
        }

        ret->driver = virConnectDriverTab[i]->hypervisorDriver;
        ret->interfaceDriver = virConnectDriverTab[i]->interfaceDriver;
        ret->networkDriver = virConnectDriverTab[i]->networkDriver;
        ret->nodeDeviceDriver = virConnectDriverTab[i]->nodeDeviceDriver;
        ret->nwfilterDriver = virConnectDriverTab[i]->nwfilterDriver;
        ret->secretDriver = virConnectDriverTab[i]->secretDriver;
        ret->storageDriver = virConnectDriverTab[i]->storageDriver;

        res = virConnectDriverTab[i]->hypervisorDriver->connectOpen(ret, auth, conf, flags);
        VIR_DEBUG("driver %zu %s returned %s",
                  i, virConnectDriverTab[i]->hypervisorDriver->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            break;
        } else {
            ret->driver = NULL;
            ret->interfaceDriver = NULL;
            ret->networkDriver = NULL;
            ret->nodeDeviceDriver = NULL;
            ret->nwfilterDriver = NULL;
            ret->secretDriver = NULL;
            ret->storageDriver = NULL;

            if (res == VIR_DRV_OPEN_ERROR)
                return NULL;
        }
    }

    if (!ret->driver) {
        /* If we reach here, then all drivers declined the connection. */
        virReportError(VIR_ERR_NO_CONNECT, "%s", NULLSTR(name));
        return NULL;
    }

    return g_steal_pointer(&ret);
}
```

可以看到，**virsh**和**libvirtd**都会调用[**virConnectOpenInternal()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/libvirt.c#L894)，根据**uri**来选择**driver**

在完成**driver**选择后，后续在调用**libvirt api**时则会使用上述选择的**driver**实现

# rpc

**virsh**和**libvirtd**使用**rpc消息**进行通信，下面简单介绍一下**libvirt**的**rpc**协议

## 命令

这里介绍一下**rpc**协议中client端和server端的命令信息

### client

即**virsh**，其使用[**vshCmdDef**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/vsh.h#L167)结构体描述**rpc**的命令。**virsh**所有的**rpc**命令被整理在[**cmdGroups**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/virsh.c#L799)
```c
/*
 * vshCmdDef - command definition
 */
struct _vshCmdDef {
    const char *name;           /* name of command, or NULL for list end */
    bool (*handler) (vshControl *, const vshCmd *);    /* command handler */
    const vshCmdOptDef *opts;   /* definition of command options */
    const vshCmdInfo *info;     /* details about command */
    unsigned int flags;         /* bitwise OR of VSH_CMD_FLAG */
    const char *alias;          /* name of the aliased command */
};

static const vshCmdGrp cmdGroups[] = {
    {VIRSH_CMD_GRP_DOM_MANAGEMENT, "domain", domManagementCmds},
    {VIRSH_CMD_GRP_DOM_MONITORING, "monitor", domMonitoringCmds},
    {VIRSH_CMD_GRP_DOM_EVENTS, "events", domEventCmds},
    {VIRSH_CMD_GRP_HOST_AND_HV, "host", hostAndHypervisorCmds},
    {VIRSH_CMD_GRP_CHECKPOINT, "checkpoint", checkpointCmds},
    {VIRSH_CMD_GRP_IFACE, "interface", ifaceCmds},
    {VIRSH_CMD_GRP_NWFILTER, "filter", nwfilterCmds},
    {VIRSH_CMD_GRP_NETWORK, "network", networkCmds},
    {VIRSH_CMD_GRP_NODEDEV, "nodedev", nodedevCmds},
    {VIRSH_CMD_GRP_SECRET, "secret", secretCmds},
    {VIRSH_CMD_GRP_SNAPSHOT, "snapshot", snapshotCmds},
    {VIRSH_CMD_GRP_BACKUP, "backup", backupCmds},
    {VIRSH_CMD_GRP_STORAGE_POOL, "pool", storagePoolCmds},
    {VIRSH_CMD_GRP_STORAGE_VOL, "volume", storageVolCmds},
    {VIRSH_CMD_GRP_VIRSH, "virsh", virshCmds},
    {NULL, NULL, NULL}
};
```

其只是**virsh**支持的**rpc**命令的定义而非实例，**virsh**使用[**vshCmd**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/vsh.h#L179)来具体描述用户要进行的一次**rpc**命令内容
```c
/*
 * vshCmd - parsed command
 */
struct _vshCmd {
    const vshCmdDef *def;       /* command definition */
    vshCmdOpt *opts;            /* list of command arguments */
    vshCmdOpt *lastopt;         /* last option of the commandline */
    vshCmd *next;               /* next command */
    bool skipChecks;            /* skip validity checks when retrieving opts */
    bool helpOptionSeen;        /* The '--help' option was seen when persing the command */
};
```

可以看到，其不仅包含了**rpc**命令的定义，同样包含用户要进行的**rpc**命令的具体参数等信息。具体的，**virsh**使用[**vshCommandStringParse()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/vsh.c#L1863)将用户输入的**rpc**调用字符串转换为[**vshCmd**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/vsh.h#L179)在进行处理

```c
/**
 * vshCommandStringParse:
 * @ctl virsh control structure
 * @cmdstr: string to parse
 * @partial: store partially parsed command here
 *
 * Parse given string @cmdstr as a command and store it under
 * @ctl->cmd. For readline completion, if @partial is not NULL on
 * the input then errors in parsing are ignored (because user is
 * still in progress of writing the command string) and partially
 * parsed command is stored at *@partial (caller has to free it
 * afterwards).
 */
bool
vshCommandStringParse(vshControl *ctl,
                      char *cmdstr,
                      vshCmd **partial)
{
    vshCommandParser parser = { 0 };

    if (cmdstr == NULL || *cmdstr == '\0')
        return false;

    parser.pos = cmdstr;
    parser.getNextArg = vshCommandStringGetArg;
    return vshCommandParse(ctl, &parser, partial);
}

static bool
vshCommandParse(vshControl *ctl,
                vshCommandParser *parser,
                vshCmd **partial)
{
    g_autoptr(vshCmd) cmds = NULL; /* linked list of all parsed commands in this session */
    vshCmd *cmds_last = NULL;
    g_autoptr(vshCmd) cmd = NULL; /* currently parsed command */
    vshCommandParserState state = VSH_CMD_PARSER_STATE_START;
    vshCmdOpt *opt = NULL;
    g_autofree char *optionvalue = NULL;
    bool report = !partial;
    bool ret = false;

    if (partial) {
        g_clear_pointer(partial, vshCommandFree);
    } else {
        g_clear_pointer(&ctl->cmd, vshCommandFree);
    }

    while (1) {
        /* previous iteration might have already gotten a value. Store it as the
         * token in this iteration */
        g_autofree char *tkdata = g_steal_pointer(&optionvalue);

        /* If we have a value already or the option to fill is a boolean we
         * don't want to fetch a new token */
        if (!(tkdata ||
              (opt && opt->def->type == VSH_OT_BOOL))) {
            vshCommandToken tk;

            tk = parser->getNextArg(ctl, parser, &tkdata, report);

            switch (tk) {
            case VSH_TK_ARG:
                /* will be handled below */
                break;

            case VSH_TK_ERROR:
                goto out;

            case VSH_TK_END:
            case VSH_TK_SUBCMD_END:
                /* The last argument name expects a value, but it's missing */
                if (opt) {
                    if (partial) {
                        /* for completion to work we need to also store the
                         * last token into the last 'opt' */
                        vshCmdOptAssign(ctl, cmd, opt, tkdata, report);
                    } else {
                        if (opt->def->type == VSH_OT_INT)
                            vshError(ctl, _("expected syntax: --%1$s <number>"),
                                 opt->def->name);
                        else
                            vshError(ctl, _("expected syntax: --%1$s <string>"),
                                 opt->def->name);

                        goto out;
                    }
                }

                /* command parsed -- allocate new struct for the command */
                if (cmd) {
                    /* if we encountered --help, replace parsed command with 'help <cmdname>' */
                    if (cmd->helpOptionSeen) {
                        vshCmd *helpcmd = vshCmdNewHelp(cmd->def->name);

                        vshCommandFree(cmd);
                        cmd = helpcmd;
                    }

                    if (!partial &&
                        vshCommandCheckOpts(ctl, cmd) < 0)
                        goto out;

                    if (!cmds)
                        cmds = cmd;
                    if (cmds_last)
                        cmds_last->next = cmd;
                    cmds_last = g_steal_pointer(&cmd);
                }


                /* everything parsed */
                if (tk == VSH_TK_END) {
                    ret = true;
                    goto out;
                }

                /* after processing the command we need to start over again to
                 * fetch another token */
                state = VSH_CMD_PARSER_STATE_START;
                continue;
            }
        }

        /* at this point we know that @tkdata is an argument */
        switch (state) {
        case VSH_CMD_PARSER_STATE_START:
            if (*tkdata == '#') {
                state = VSH_CMD_PARSER_STATE_COMMENT;
            } else {
                state = VSH_CMD_PARSER_STATE_COMMAND;

                if (!(cmd = vshCmdNew(ctl, tkdata, !partial)))
                    goto out;
            }

            break;

        case VSH_CMD_PARSER_STATE_COMMENT:
            /* continue eating tokens until end of line or end of input */
            state = VSH_CMD_PARSER_STATE_COMMENT;
            break;

        case VSH_CMD_PARSER_STATE_COMMAND: {
            /* parsing individual options for the command. There are following options:
             *   --option
             *   --option value
             *   --option=value
             *   --aliasoptionwithvalue (value is part of the alias definition)
             *   value
             *   -- (terminate accepting '--option', fill only positional args)
             */
            const char *optionname = tkdata + 2;
            char *sep;

            if (!STRPREFIX(tkdata, "--")) {
                if (vshCmdOptAssignPositional(ctl, cmd, tkdata, report) < 0)
                    goto out;
                break;
            }

            if (STREQ(tkdata, "--")) {
                state = VSH_CMD_PARSER_STATE_POSITIONAL_ONLY;
                break;
            }

            if ((sep = strchr(optionname, '='))) {
                *(sep++) = '\0';

                /* 'optionvalue' has lifetime until next iteration */
                optionvalue = g_strdup(sep);
            }

            /* lookup the option. Note that vshCmdGetOption also resolves aliases
             * and thus the value possibly contained in the alias */
            if (STREQ(optionname, "help")) {
                cmd->helpOptionSeen = true;
                g_clear_pointer(&optionvalue, g_free);
            } else if (!(opt = vshCmdGetOption(ctl, cmd, optionname, &optionvalue, report))) {
                if (STRNEQ(cmd->def->name, "help"))
                    goto out;

                /* ignore spurious arguments for 'help' command */
                g_clear_pointer(&optionvalue, g_free);
                state = VSH_CMD_PARSER_STATE_COMMAND;
            } else {
                state = VSH_CMD_PARSER_STATE_ASSIGN_OPT;
            }
        }
            break;

        case VSH_CMD_PARSER_STATE_ASSIGN_OPT:
            /* Parameter for a boolean was passed via --boolopt=val */
            if (tkdata && opt->def->type == VSH_OT_BOOL) {
                if (report)
                    vshError(ctl, _("invalid '=' after option --%1$s"),
                             opt->def->name);
                goto out;
            }

            vshCmdOptAssign(ctl, cmd, opt, tkdata, report);
            opt = NULL;
            state = VSH_CMD_PARSER_STATE_COMMAND;
            break;

        case VSH_CMD_PARSER_STATE_POSITIONAL_ONLY:
            state = VSH_CMD_PARSER_STATE_POSITIONAL_ONLY;

            if (vshCmdOptAssignPositional(ctl, cmd, tkdata, report) < 0)
                goto out;
            break;
        }
    }

 out:
    ...
    return ret;
}

static vshCmd *
vshCmdNew(vshControl *ctl,
          const char *cmdname,
          bool report)
{
    g_autoptr(vshCmd) c = g_new0(vshCmd, 1);
    const vshCmdOptDef *optdef;
    vshCmdOpt *opt;
    size_t nopts = 0;

    if (!(c->def = vshCmddefSearch(cmdname))) {
        if (report)
            vshError(ctl, _("unknown command: '%1$s'"), cmdname);

        return NULL;
    }

    /* resolve command alias */
    if (c->def->alias) {
        if (!(c->def = vshCmddefSearch(c->def->alias))) {
            /* dead code: self-test ensures that the alias exists thus no error reported here */
            return NULL;
        }
    }

    /* Find number of arguments */
    for (optdef = c->def->opts; optdef && optdef->name; optdef++)
        nopts++;

    c->opts = g_new0(vshCmdOpt, nopts + 1);
    opt = c->opts;

    /* populate links to definitions */
    for (optdef = c->def->opts; optdef && optdef->name; optdef++) {
        opt->def = optdef;
        opt++;
    }

    return g_steal_pointer(&c);
}

/* vshCmddefSearch:
 * @cmdname: name of command to find
 *
 * Looks for @cmdname in the global list of command definitions @cmdGroups and
 * returns pointer to the definition struct if the command exists.
 */
static const vshCmdDef *
vshCmddefSearch(const char *cmdname)
{
    const vshCmdGrp *g;
    const vshCmdDef *c;

    for (g = cmdGroups; g->name; g++) {
        for (c = g->commands; c->name; c++) {
            if (STREQ(c->name, cmdname))
                return c;
        }
    }

    return NULL;
}
```

可以看到，其会基于[**cmdGroups**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/virsh.c#L799)，匹配根据用户输入字符串，从而将**virsh**命令转换为[**vshCmd**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/vsh.h#L179)

### server

即**libvirtd**，其使用[**virNetServerProgramProc**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/rpc/virnetserverprogram.h#L42)结构体描述rpc的命令。所有**libvirtd**的**rpc**命令是由[**src/rpc/gendispatch.pl**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/rpc/gendispatch.pl)脚本基于[**src/remote/remote_protocol.x**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/remote/remote_protocol.x)文件自动生成的，位于**$build/src/remote/\*_dispatch_stubs.h**文件中。

```c
struct _virNetServerProgramProc {
    virNetServerProgramDispatchFunc func;
    size_t arg_len;
    xdrproc_t arg_filter;
    size_t ret_len;
    xdrproc_t ret_filter;
    bool needAuth;
    unsigned int priority;
};
```

其中具体的**rpc**命令的handler在**func**字段中，其被定义在[**src/remote/remote_daemon_dispatch.c**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/remote/remote_daemon_dispatch.c)文件中

**libvirtd**会在[**main()**](https://github.com/libvirt/libvirt/blob/be784aa5133ec5cb6fd7fd1fc82393676ba244fd/src/remote/remote_daemon.c#L780)中使用[**virNetServerProgramNew**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/rpc/virnetserverprogram.c#L61)和[**virNetServerAddProgram**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/rpc/virnetserver.c#L772)将所有的**rpc**命令插入到**srv->programs**数组中，之后在[**virNetServerDispatchNewMessage**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/rpc/virnetserver.c#L195)处理**rpc**消息时，通过遍历**srv->programs**数组找到**rpc**消息对应的**rpc**命令并进行处理

```c
static void
virNetServerDispatchNewMessage(virNetServerClient *client,
                               virNetMessage *msg,
                               void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerProgram *prog = NULL;
    unsigned int priority = 0;

    VIR_DEBUG("server=%p client=%p message=%p",
              srv, client, msg);

    VIR_WITH_OBJECT_LOCK_GUARD(srv) {
        prog = virNetServerGetProgramLocked(srv, msg);
        /* we can unlock @srv since @prog can only become invalid in case
         * of disposing @srv, but let's grab a ref first to ensure nothing
         * disposes of it before we use it. */
        virObjectRef(srv);
    }

    if (virThreadPoolGetMaxWorkers(srv->workers) > 0)  {
        virNetServerJob *job;

        job = g_new0(virNetServerJob, 1);

        job->client = virObjectRef(client);
        job->msg = msg;

        if (prog) {
            job->prog = virObjectRef(prog);
            priority = virNetServerProgramGetPriority(prog, msg->header.proc);
        }

        if (virThreadPoolSendJob(srv->workers, priority, job) < 0) {
            virObjectUnref(client);
            VIR_FREE(job);
            virObjectUnref(prog);
            goto error;
        }
    } else {
        if (virNetServerProcessMsg(srv, client, prog, msg) < 0)
            goto error;
    }

    virObjectUnref(srv);
    return;
}

/**
 * virNetServerGetProgramLocked:
 * @srv: server (must be locked by the caller)
 * @msg: message
 *
 * Searches @srv for the right program for a given message @msg.
 *
 * Returns a pointer to the server program or NULL if not found.
 */
static virNetServerProgram *
virNetServerGetProgramLocked(virNetServer *srv,
                             virNetMessage *msg)
{
    size_t i;
    for (i = 0; i < srv->nprograms; i++) {
        if (virNetServerProgramMatches(srv->programs[i], msg))
            return srv->programs[i];
    }
    return NULL;
}

int virNetServerProgramMatches(virNetServerProgram *prog,
                               virNetMessage *msg)
{
    if (prog->program == msg->header.prog &&
        prog->version == msg->header.vers)
        return 1;
    return 0;
}
```

## 通信

**rpc**的通信架构是client-server模型，是由**remote driver**实现的，这里就以最简单的**connect**命令为例进行分析

### client

即**virsh**，根据前面[rpc命令](#client)的分析，找到对应的**rpc**命令

```c
static const vshCmdGrp cmdGroups[] = {
    ...
    {VIRSH_CMD_GRP_VIRSH, "virsh", virshCmds},
    {NULL, NULL, NULL}
};
static const vshCmdDef virshCmds[] = {
    ...
    {.name = "connect",
     .handler = cmdConnect,
     .opts = opts_connect,
     .info = &info_connect,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = NULL}
};
```

可以看到，**virsh**会调用[**cmdConnect()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/virsh.c#L267)来处理该**rpc**命令

```c
//#0  virConnectOpenInternal (name=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=0) at ../src/libvirt.c:897
//#1  0x00007ffff7cb3f6e in virConnectOpenAuth (name=name@entry=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=flags@entry=0) at ../src/libvirt.c:1283
//#2  0x00005555555924f0 in virshConnect (ctl=ctl@entry=0x7fffffffdba0, uri=0x0, readonly=false) at ../tools/virsh.c:127
//#3  0x00005555555927c3 in virshReconnect (ctl=ctl@entry=0x7fffffffdba0, name=0x0, readonly=<optimized out>, readonly@entry=false, force=force@entry=true) at ../tools/virsh.c:208
//#4  0x000055555559294e in cmdConnect (ctl=0x7fffffffdba0, cmd=0x555555673060) at ../tools/virsh.c:275
//#5  0x00005555555e147f in vshCommandRun (ctl=ctl@entry=0x7fffffffdba0, cmd=0x555555673060) at ../tools/vsh.c:1359
//#6  0x0000555555591f70 in main (argc=argc@entry=2, argv=argv@entry=0x7fffffffdf68) at ../tools/virsh.c:889
//#7  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555591410 <main>, argc=argc@entry=2, argv=argv@entry=0x7fffffffdf68) at ../sysdeps/nptl/libc_start_call_main.h:58
//#8  0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555591410 <main>, argc=2, argv=0x7fffffffdf68, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf58) at ../csu/libc-start.c:392
//#9  0x0000555555592145 in _start ()
static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ro = vshCommandOptBool(cmd, "readonly");
    const char *name = NULL;

    if (vshCommandOptString(ctl, cmd, "name", &name) < 0)
        return false;

    if (virshReconnect(ctl, name, ro, true) < 0)
        return false;

    return true;
}

/*
 * virshReconnect:
 *
 * Reconnect after a disconnect from libvirtd
 *
 */
static int
virshReconnect(vshControl *ctl, const char *name, bool readonly, bool force)
{
    ...
    priv->conn = virshConnect(ctl, name ? name : ctl->connname, readonly);
    ...
    return 0;
}

/* Main Function which should be used for connecting.
 * This function properly handles keepalive settings. */
virConnectPtr
virshConnect(vshControl *ctl, const char *uri, bool readonly)
{
    ...
    do {
        virErrorPtr err;

        if ((c = virConnectOpenAuth(uri, virConnectAuthPtrDefault,
                                    readonly ? VIR_CONNECT_RO : 0)))
            break;
        ...
    } while (authfail < 5);
    ...
    return c;
}

/**
 * virConnectOpenAuth:
 * @name: (optional) URI of the hypervisor
 * @auth: Authenticate callback parameters
 * @flags: bitwise-OR of virConnectFlags
 *
 * This function should be called first to get a connection to the
 * Hypervisor. If necessary, authentication will be performed fetching
 * credentials via the callback
 *
 * See virConnectOpen for notes about environment variables which can
 * have an effect on opening drivers and freeing the connection resources
 *
 * URIs are documented at https://libvirt.org/uri.html
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * Since: 0.4.0
 */
virConnectPtr
virConnectOpenAuth(const char *name,
                   virConnectAuthPtr auth,
                   unsigned int flags)
{
    ...
    ret = virConnectOpenInternal(name, auth, flags);
    ...
    return ret;
}

static virConnectPtr
virConnectOpenInternal(const char *name,
                       virConnectAuthPtr auth,
                       unsigned int flags)
{
    ...
    
    for (i = 0; i < virConnectDriverTabCount; i++) {
        ret->driver = virConnectDriverTab[i]->hypervisorDriver;
        ret->interfaceDriver = virConnectDriverTab[i]->interfaceDriver;
        ret->networkDriver = virConnectDriverTab[i]->networkDriver;
        ret->nodeDeviceDriver = virConnectDriverTab[i]->nodeDeviceDriver;
        ret->nwfilterDriver = virConnectDriverTab[i]->nwfilterDriver;
        ret->secretDriver = virConnectDriverTab[i]->secretDriver;
        ret->storageDriver = virConnectDriverTab[i]->storageDriver;

        res = virConnectDriverTab[i]->hypervisorDriver->connectOpen(ret, auth, conf, flags);
        if (res == VIR_DRV_OPEN_SUCCESS) {
            break;
        } else {
            ret->driver = NULL;
            ret->interfaceDriver = NULL;
            ret->networkDriver = NULL;
            ret->nodeDeviceDriver = NULL;
            ret->nwfilterDriver = NULL;
            ret->secretDriver = NULL;
            ret->storageDriver = NULL;

            if (res == VIR_DRV_OPEN_ERROR)
                return NULL;
        }
    }
    ...
    return g_steal_pointer(&ret);
}
```

可以看到，最终其会调用到[**virConnectOpenInternal()**](https://github.com/libvirt/libvirt/blob/daa560858b6b6cd27d7305c8ff94c9257b96e211/src/libvirt.c#L894)进行处理，其会遍历所有**driver**对应的**connectOpen**字段，最终调用的是**remote driver**的[**remoteConnectOpen()**](https://github.com/libvirt/libvirt/blob/daa560858b6b6cd27d7305c8ff94c9257b96e211/src/remote/remote_driver.c#L1265)函数

```c
static virHypervisorDriver hypervisor_driver = {
    .name = "remote",
    .connectOpen = remoteConnectOpen, /* 0.3.0 */
    ...
}

static virConnectDriver connect_driver = {
    .hypervisorDriver = &hypervisor_driver,
    ...
};

//#0  virNetClientProgramCall (prog=prog@entry=0x55555567f410, client=client@entry=0x55555567b010, serial=serial@entry=0, proc=proc@entry=66, noutfds=noutfds@entry=0, outfds=outfds@entry=0x0, ninfds=0x0, infds=0x0, args_filter=0x7ffff767de90 <xdr_void>, args=0x0, ret_filter=0x7ffff7c3f7f0 <xdr_remote_auth_list_ret>, ret=0x7fffffffd8f0) at ../src/rpc/virnetclientprogram.c:271
//#1  0x00007ffff7c5350d in callFull (conn=<optimized out>, ret=0x7fffffffd8f0 "", ret_filter=0x7ffff7c3f7f0 <xdr_remote_auth_list_ret>, args=0x0, args_filter=0x7ffff767de90 <xdr_void>, proc_nr=66, fdoutlen=0x0, fdout=0x0, fdinlen=0, fdin=0x0, flags=flags@entry=0, priv=0x5555556785f0, priv@entry=0x42) at ../src/remote/remote_driver.c:6054
//#2  call (priv=priv@entry=0x5555556785f0, flags=flags@entry=0, proc_nr=proc_nr@entry=66, args_filter=0x7ffff767de90 <xdr_void>, args=args@entry=0x0, ret_filter=0x7ffff7c3f7f0 <xdr_remote_auth_list_ret>, ret=0x7fffffffd8f0 "", conn=<optimized out>) at ../src/remote/remote_driver.c:6076
//#3  0x00007ffff7c63f1e in remoteAuthenticate (conn=0x555555679040, auth=0x7ffff7e38920 <virConnectAuthDefault>, authtype=0x0, priv=0x5555556785f0) at ../src/remote/remote_driver.c:3193
//#4  doRemoteOpen (flags=<optimized out>, conf=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, transport=REMOTE_DRIVER_TRANSPORT_UNIX, driver_str=0x0, priv=0x5555556785f0, conn=0x555555679040) at ../src/remote/remote_driver.c:1170
//#5  remoteConnectOpen (conn=0x555555679040, auth=0x7ffff7e38920 <virConnectAuthDefault>, conf=0x0, flags=<optimized out>) at ../src/remote/remote_driver.c:1313
//#6  0x00007ffff7cb338e in virConnectOpenInternal (name=<optimized out>, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=0) at ../src/libvirt.c:1140
//#7  0x00007ffff7cb3f6e in virConnectOpenAuth (name=name@entry=0x0, auth=0x7ffff7e38920 <virConnectAuthDefault>, flags=flags@entry=0) at ../src/libvirt.c:1283
//#8  0x00005555555924f0 in virshConnect (ctl=ctl@entry=0x7fffffffdba0, uri=0x0, readonly=false) at ../tools/virsh.c:127
//#9  0x00005555555927c3 in virshReconnect (ctl=ctl@entry=0x7fffffffdba0, name=0x0, readonly=<optimized out>, readonly@entry=false, force=force@entry=true) at ../tools/virsh.c:208
//#10 0x000055555559294e in cmdConnect (ctl=0x7fffffffdba0, cmd=0x555555673060) at ../tools/virsh.c:275
//#11 0x00005555555e147f in vshCommandRun (ctl=ctl@entry=0x7fffffffdba0, cmd=0x555555673060) at ../tools/vsh.c:1359
//#12 0x0000555555591f70 in main (argc=argc@entry=2, argv=argv@entry=0x7fffffffdf68) at ../tools/virsh.c:889
//#13 0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555591410 <main>, argc=argc@entry=2, argv=argv@entry=0x7fffffffdf68) at ../sysdeps/nptl/libc_start_call_main.h:58
//#14 0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555591410 <main>, argc=2, argv=0x7fffffffdf68, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf58) at ../csu/libc-start.c:392
//#15 0x0000555555592145 in _start ()
static virDrvOpenStatus
remoteConnectOpen(virConnectPtr conn,
                  virConnectAuthPtr auth,
                  virConf *conf,
                  unsigned int flags)
{
    g_autofree struct private_data *priv = NULL;
    int ret = VIR_DRV_OPEN_ERROR;
    unsigned int rflags = 0;
    g_autofree char *driver = NULL;
    remoteDriverTransport transport;

    if (conn->uri) {
        if (remoteSplitURIScheme(conn->uri, &driver, &transport) < 0)
            return VIR_DRV_OPEN_ERROR;
    } else {
        /* No URI, then must be probing so use UNIX socket */
        transport = REMOTE_DRIVER_TRANSPORT_UNIX;
    }

    if (inside_daemon) {
        if (!conn->uri)
            return VIR_DRV_OPEN_DECLINED;

        /* Handle deferring to local drivers if we are dealing with a default
         * local URI. (Unknown local socket paths may be proxied to a remote
         * host so they are treated as remote too).
         *
         * Deferring to a local driver is needed if:
         * - the driver is registered in the current daemon
         * - if we are running monolithic libvirtd, in which case we consider
         *   even un-registered drivers as local
         */
        if (!conn->uri->server && !virURICheckUnixSocket(conn->uri)) {
            if (virHasDriverForURIScheme(driver))
                return VIR_DRV_OPEN_DECLINED;

            if (monolithic_daemon)
                return VIR_DRV_OPEN_DECLINED;
        }
    }

    if (!(priv = remoteAllocPrivateData()))
        return VIR_DRV_OPEN_ERROR;

    remoteGetURIDaemonInfo(conn->uri, transport, &rflags);
    if (flags & VIR_CONNECT_RO)
        rflags |= REMOTE_DRIVER_OPEN_RO;

    ret = doRemoteOpen(conn, priv, driver, transport, auth, conf, rflags);
    remoteDriverUnlock(priv);

    if (ret != VIR_DRV_OPEN_SUCCESS)
        conn->privateData = NULL;
    else
        conn->privateData = g_steal_pointer(&priv);

    return ret;
}

static int
doRemoteOpen(virConnectPtr conn,
             struct private_data *priv,
             const char *driver_str,
             remoteDriverTransport transport,
             virConnectAuthPtr auth G_GNUC_UNUSED,
             virConf *conf,
             unsigned int flags)
{
    ...
    if (!sockname &&
        !(sockname = remoteGetUNIXSocket(transport, mode, driver_str,
                                         flags, &daemon_path)))
        goto error;
    ...
    if (!(priv->client = virNetClientNewUNIX(sockname,
                                             daemon_path)))
        goto error;
    ...
    remote_connect_open_args args = { &name, flags };

    VIR_DEBUG("Trying to open URI '%s'", name);
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_OPEN,
             (xdrproc_t) xdr_remote_connect_open_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto error;
    ...
    return VIR_DRV_OPEN_SUCCESS;
}

static int
call(virConnectPtr conn,
     struct private_data *priv,
     unsigned int flags,
     int proc_nr,
     xdrproc_t args_filter, char *args,
     xdrproc_t ret_filter, char *ret)
{
    return callFull(conn, priv, flags,
                    NULL, 0,
                    NULL, NULL,
                    proc_nr,
                    args_filter, args,
                    ret_filter, ret);
}

/*
 * Serial a set of arguments into a method call message,
 * send that to the server and wait for reply
 */
static int
callFull(virConnectPtr conn G_GNUC_UNUSED,
         struct private_data *priv,
         unsigned int flags,
         int *fdin,
         size_t fdinlen,
         int **fdout,
         size_t *fdoutlen,
         int proc_nr,
         xdrproc_t args_filter, char *args,
         xdrproc_t ret_filter, char *ret)
{
    ...
    prog = priv->remoteProgram;

    /* Unlock, so that if we get any async events/stream data
     * while processing the RPC, we don't deadlock when our
     * callbacks for those are invoked
     */
    remoteDriverUnlock(priv);
    rv = virNetClientProgramCall(prog,
                                 client,
                                 counter,
                                 proc_nr,
                                 fdinlen, fdin,
                                 fdoutlen, fdout,
                                 args_filter, args,
                                 ret_filter, ret);
    remoteDriverLock(priv);
    priv->localUses--;

    return rv;
}

int virNetClientProgramCall(virNetClientProgram *prog,
                            virNetClient *client,
                            unsigned serial,
                            int proc,
                            size_t noutfds,
                            int *outfds,
                            size_t *ninfds,
                            int **infds,
                            xdrproc_t args_filter, void *args,
                            xdrproc_t ret_filter, void *ret)
{
    virNetMessage *msg;
    size_t i;

    if (infds)
        *infds = NULL;
    if (ninfds)
        *ninfds = 0;

    if (!(msg = virNetMessageNew(false)))
        return -1;

    msg->header.prog = prog->program;
    msg->header.vers = prog->version;
    msg->header.status = VIR_NET_OK;
    msg->header.type = noutfds ? VIR_NET_CALL_WITH_FDS : VIR_NET_CALL;
    msg->header.serial = serial;
    msg->header.proc = proc;
    msg->fds = g_new0(int, noutfds);
    msg->nfds = noutfds;
    for (i = 0; i < msg->nfds; i++)
        msg->fds[i] = -1;
    for (i = 0; i < msg->nfds; i++) {
        if ((msg->fds[i] = dup(outfds[i])) < 0) {
            virReportSystemError(errno,
                                 _("Cannot duplicate FD %1$d"),
                                 outfds[i]);
            goto error;
        }
        if (virSetInherit(msg->fds[i], false) < 0) {
            virReportSystemError(errno,
                                 _("Cannot set close-on-exec %1$d"),
                                 msg->fds[i]);
            goto error;
        }
    }

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, args_filter, args) < 0)
        goto error;

    if (virNetClientSendWithReply(client, msg) < 0)
        goto error;

    /* None of these 3 should ever happen here, because
     * virNetClientSend should have validated the reply,
     * but it doesn't hurt to check again.
     */
    if (msg->header.type != VIR_NET_REPLY &&
        msg->header.type != VIR_NET_REPLY_WITH_FDS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message type %1$d"), msg->header.type);
        goto error;
    }
    if (msg->header.proc != proc) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message proc %1$d != %2$d"),
                       msg->header.proc, proc);
        goto error;
    }
    if (msg->header.serial != serial) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message serial %1$d != %2$d"),
                       msg->header.serial, serial);
        goto error;
    }

    switch (msg->header.status) {
    case VIR_NET_OK:
        if (infds && ninfds) {
            *ninfds = msg->nfds;
            *infds = g_new0(int, *ninfds);

            for (i = 0; i < *ninfds; i++)
                (*infds)[i] = -1;
            for (i = 0; i < *ninfds; i++) {
                if (((*infds)[i] = dup(msg->fds[i])) < 0) {
                    virReportSystemError(errno,
                                         _("Cannot duplicate FD %1$d"),
                                         msg->fds[i]);
                    goto error;
                }
                if (virSetInherit((*infds)[i], false) < 0) {
                    virReportSystemError(errno,
                                         _("Cannot set close-on-exec %1$d"),
                                         (*infds)[i]);
                    goto error;
                }
            }

        }
        if (virNetMessageDecodePayload(msg, ret_filter, ret) < 0)
            goto error;
        break;

    case VIR_NET_ERROR:
        virNetClientProgramDispatchError(prog, msg);
        goto error;

    case VIR_NET_CONTINUE:
    default:
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %1$d"), msg->header.status);
        goto error;
    }

    virNetMessageFree(msg);

    return 0;
}
```

可以看到，**virsh**最终会在[**virNetClientProgramCall()**](https://github.com/libvirt/libvirt/blob/daa560858b6b6cd27d7305c8ff94c9257b96e211/src/rpc/virnetclientprogram.c#L261)中生成**rpc**消息并通过socket等信道发送

### server

即**libvirtd**，根据前面{% post_link glib的事件循环 %}博客的内容，最终**libvirtd**会调用[**virNetServerProgramDispatchCall()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/rpc/virnetserverprogram.c#L249)函数来处理**rpc**消息

```c
//#0  0x0000763d1be003a0 in virNetServerProgramDispatchCall (msg=<optimized out>, client=<optimized out>, server=<optimized out>, prog=<optimized out>) at ../src/rpc/virnetserverprogram.c:373
//#1  virNetServerProgramDispatch (prog=0x591cd6811010, server=server@entry=0x591cd6807880, client=0x591cd681b380, msg=0x591cd6821700) at ../src/rpc/virnetserverprogram.c:299
//#2  0x0000763d1be06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x591cd6807880) at ../src/rpc/virnetserver.c:135
//#3  virNetServerHandleJob (jobOpaque=0x591cd67efbd0, opaque=0x591cd6807880) at ../src/rpc/virnetserver.c:155
//#4  0x0000763d1bd3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#5  0x0000763d1bd3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#6  0x0000763d1b694ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#7  0x0000763d1b726850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming method call, with header already decoded
 *
 * This method is used to dispatch a message representing an
 * incoming method call from a client. It decodes the payload
 * to obtain method call arguments, invokes the method and
 * then sends a reply packet with the return values
 *
 * Returns 0 if the reply was sent, or -1 upon fatal error
 */
static int
virNetServerProgramDispatchCall(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg)
{
    g_autofree char *arg = NULL;
    g_autofree char *ret = NULL;
    int rv = -1;
    virNetServerProgramProc *dispatcher = NULL;
    virNetMessageError rerr = { 0 };
    size_t i;
    g_autoptr(virIdentity) identity = NULL;

    if (msg->header.status != VIR_NET_OK) {
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %1$u"),
                       msg->header.status);
        goto error;
    }

    dispatcher = virNetServerProgramGetProc(prog, msg->header.proc);

    if (!dispatcher) {
        virReportError(VIR_ERR_RPC,
                       _("unknown procedure: %1$d"),
                       msg->header.proc);
        goto error;
    }

    /* If the client is not authenticated, don't allow any RPC ops
     * which are except for authentication ones */
    if (dispatcher->needAuth &&
        !virNetServerClientIsAuthenticated(client)) {
        /* Explicitly *NOT* calling  remoteDispatchAuthError() because
           we want back-compatibility with libvirt clients which don't
           support the VIR_ERR_AUTH_FAILED error code */
        virReportError(VIR_ERR_RPC,
                       "%s", _("authentication required"));
        goto error;
    }

    arg = g_new0(char, dispatcher->arg_len);
    ret = g_new0(char, dispatcher->ret_len);

    if (virNetMessageDecodePayload(msg, dispatcher->arg_filter, arg) < 0)
        goto error;

    if (!(identity = virNetServerClientGetIdentity(client)))
        goto error;

    if (virIdentitySetCurrent(identity) < 0)
        goto error;

    /*
     * When the RPC handler is called:
     *
     *  - Server object is unlocked
     *  - Client object is unlocked
     *
     * Without locking, it is safe to use:
     *
     *   'args and 'ret'
     */
    rv = (dispatcher->func)(server, client, msg, &rerr, arg, ret);

    if (virIdentitySetCurrent(NULL) < 0)
        goto error;

    /*
     * If rv == 1, this indicates the dispatch func has
     * populated 'msg' with a list of FDs to return to
     * the caller.
     *
     * Otherwise we must clear out the FDs we got from
     * the client originally.
     *
     */
    if (rv != 1) {
        for (i = 0; i < msg->nfds; i++)
            VIR_FORCE_CLOSE(msg->fds[i]);
        VIR_FREE(msg->fds);
        msg->nfds = 0;
    }

    if (rv < 0)
        goto error;

    /* Return header. We're re-using same message object, so
     * only need to tweak type/status fields */
    /*msg->header.prog = msg->header.prog;*/
    /*msg->header.vers = msg->header.vers;*/
    /*msg->header.proc = msg->header.proc;*/
    msg->header.type = msg->nfds ? VIR_NET_REPLY_WITH_FDS : VIR_NET_REPLY;
    /*msg->header.serial = msg->header.serial;*/
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, dispatcher->ret_filter, ret) < 0)
        goto error;

    xdr_free(dispatcher->arg_filter, arg);
    xdr_free(dispatcher->ret_filter, ret);

    /* Put reply on end of tx queue to send out  */
    return virNetServerClientSendMessage(client, msg);
}
```

根据[前面rpc命令章节](#server)的内容，**libvirtd**会遍历所有**rpc**命令，找到**connect**命令对应的handler，即由脚本自动生成的**remoteDispatchConnectOpenHelper()**函数，最终调用到[**remoteDispatchConnectOpen**](https://github.com/search?q=repo%3Alibvirt%2Flibvirt%20remoteDispatchConnectOpen&type=code)，从而完成最终的**rpc**命令处理

```c
//#0  0x0000591cd5926231 in remoteDispatchConnectOpen (server=<optimized out>, msg=<optimized out>, args=<optimized out>, rerr=<optimized out>, client=<optimized out>) at ../src/remote/remote_daemon_dispatch.c:2061
//#1  remoteDispatchConnectOpenHelper (server=0x591cd6807880, client=0x591cd681b380, msg=0x591cd6821700, rerr=0x763d153ff9e0, args=0x763cf40025f0, ret=0x0) at src/remote/remote_daemon_dispatch_stubs.h:3291
//#2  0x0000763d1be0053c in virNetServerProgramDispatchCall (msg=0x591cd6821700, client=0x591cd681b380, server=0x591cd6807880, prog=0x591cd6811010) at ../src/rpc/virnetserverprogram.c:423
//#3  virNetServerProgramDispatch (prog=0x591cd6811010, server=server@entry=0x591cd6807880, client=0x591cd681b380, msg=0x591cd6821700) at ../src/rpc/virnetserverprogram.c:299
//#4  0x0000763d1be06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x591cd6807880) at ../src/rpc/virnetserver.c:135
//#5  virNetServerHandleJob (jobOpaque=0x591cd67f2590, opaque=0x591cd6807880) at ../src/rpc/virnetserver.c:155
//#6  0x0000763d1bd3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#7  0x0000763d1bd3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#8  0x0000763d1b694ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#9  0x0000763d1b726850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

static int remoteDispatchConnectOpenHelper(
    virNetServer *server,
    virNetServerClient *client,
    virNetMessage *msg,
    struct virNetMessageError *rerr,
    void *args,
    void *ret G_GNUC_UNUSED)
{
  int rv;
  virThreadJobSet("remoteDispatchConnectOpen");
  VIR_DEBUG("server=%p client=%p msg=%p rerr=%p args=%p ret=%p",
            server, client, msg, rerr, args, ret);
  rv = remoteDispatchConnectOpen(server, client, msg, rerr, args);
  virThreadJobClear(rv);
  return rv;
}
/* remoteDispatchConnectOpen body has to be implemented manually */

static int
remoteDispatchConnectOpen(virNetServer *server G_GNUC_UNUSED,
                          virNetServerClient *client,
                          virNetMessage *msg G_GNUC_UNUSED,
                          struct virNetMessageError *rerr,
                          struct remote_connect_open_args *args)
{
    const char *name;
#ifdef VIRTPROXYD
    g_autofree char *probeduri = NULL;
#endif
    unsigned int flags;
    struct daemonClientPrivate *priv = virNetServerClientGetPrivateData(client);
#ifdef MODULE_NAME
    const char *type = NULL;
#endif /* !MODULE_NAME */
    bool preserveIdentity = false;
    VIR_LOCK_GUARD lock = virLockGuardLock(&priv->lock);

    VIR_DEBUG("priv=%p conn=%p", priv, priv->conn);
    /* Already opened? */
    if (priv->conn) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection already open"));
        goto cleanup;
    }

    name = args->name ? *args->name : NULL;

    /* If this connection arrived on a readonly socket, force
     * the connection to be readonly.
     */
    flags = args->flags;
    if (virNetServerClientGetReadonly(client))
        flags |= VIR_CONNECT_RO;

    priv->readonly = flags & VIR_CONNECT_RO;

    VIR_DEBUG("Opening driver %s", name);
    if (remoteOpenConn(name,
                       priv->readonly,
                       preserveIdentity,
                       &priv->conn) < 0)
        goto cleanup;
    VIR_DEBUG("Opened %p", priv->conn);

    /*
     * For libvirtd/virtproxyd one connection handles
     * all drivers
     */
    VIR_DEBUG("Pointing secondary drivers to primary");
    priv->interfaceConn = virObjectRef(priv->conn);
    priv->networkConn = virObjectRef(priv->conn);
    priv->nodedevConn = virObjectRef(priv->conn);
    priv->nwfilterConn = virObjectRef(priv->conn);
    priv->secretConn = virObjectRef(priv->conn);
    priv->storageConn = virObjectRef(priv->conn);

    /* force update the @readonly attribute which was inherited from the
     * virNetServerService object - this is important for sockets that are RW
     * by default, but do accept RO flags, e.g. TCP
     */
    virNetServerClientSetReadonly(client, (flags & VIR_CONNECT_RO));
    return 0;
}
```

# hypervisor

这里以**qemu**作为例子分析**libvirtd**和**hypervisor**的交互，下面简单介绍一下**libvirtd**中和**qemu**相关的基础知识

## driver

**libvirtd**通过**qemu driver**实现与**qemu**的通信，这里以**virsh start $domain**为例进行分析

根据[前面rpc章节](#rpc)，**virsh**会调用[**cmdStart()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/tools/virsh-domain.c#L4031)，基于**remote driver**发送**rpc**消息

```c
static const vshCmdGrp cmdGroups[] = {
    {VIRSH_CMD_GRP_DOM_MANAGEMENT, "domain", domManagementCmds},
    ...
    {NULL, NULL, NULL}
};

const vshCmdDef domManagementCmds[] = {
    ...
    {.name = "start",
     .handler = cmdStart,
     .opts = opts_start,
     .info = &info_start,
     .flags = 0
    },
    ...
    {.name = NULL}
};

//#0  remoteDomainCreate (domain=0x55555567f500) at ../src/remote/remote_driver.c:2342
//#1  0x00007ffff7cc8baa in virDomainCreate (domain=domain@entry=0x55555567f500) at ../src/libvirt-domain.c:7079
//#2  0x00005555555b5fec in virshDomainCreateHelper (flags=0, fds=<optimized out>, nfds=<optimized out>, dom=0x55555567f500) at ../tools/virsh-domain.c:4027
//#3  cmdStart (ctl=0x7fffffffdbb0, cmd=<optimized out>) at ../tools/virsh-domain.c:4097
//#4  0x00005555555e147f in vshCommandRun (ctl=ctl@entry=0x7fffffffdbb0, cmd=0x555555673060) at ../tools/vsh.c:1359
//#5  0x0000555555591f70 in main (argc=argc@entry=3, argv=argv@entry=0x7fffffffdf78) at ../tools/virsh.c:889
//#6  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555591410 <main>, argc=argc@entry=3, argv=argv@entry=0x7fffffffdf78) at ../sysdeps/nptl/libc_start_call_main.h:58
//#7  0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555591410 <main>, argc=3, argv=0x7fffffffdf78, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf68) at ../csu/libc-start.c:392
//#8  0x0000555555592145 in _start ()
static bool
cmdStart(vshControl *ctl, const vshCmd *cmd)
{
    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME | VIRSH_BYUUID)))
        return false;
    ...
    rc = virshDomainCreateHelper(dom, nfds, fds, flags);
    ...
    return true;
}

static int
virshDomainCreateHelper(virDomainPtr dom,
                        unsigned int nfds,
                        int *fds,
                        unsigned int flags)
{
    ...
    return virDomainCreate(dom);
}

static int
remoteDomainCreate(virDomainPtr domain)
{
    remote_domain_create_args args = {0};
    remote_domain_lookup_by_uuid_args args2 = {0};
    g_auto(remote_domain_lookup_by_uuid_ret) ret2 = {0};
    struct private_data *priv = domain->conn->privateData;
    VIR_LOCK_GUARD lock = remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE,
             (xdrproc_t) xdr_remote_domain_create_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    /* Need to do a lookup figure out ID of newly started guest, because
     * bug in design of REMOTE_PROC_DOMAIN_CREATE means we aren't getting
     * it returned.
     */
    memcpy(args2.uuid, domain->uuid, VIR_UUID_BUFLEN);
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID,
             (xdrproc_t) xdr_remote_domain_lookup_by_uuid_args, (char *) &args2,
             (xdrproc_t) xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret2) == -1)
        return -1;

    domain->id = ret2.dom.id;

    return 0;
}
```

**libvirtd**收到**rpc**消息后，根据基于[**REMOTE_PROC_DOMAIN_CREATE**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/remote/remote_protocol.x#L4090)生成的**remoteProcs**项，其会调用[**virDomainCreate()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/libvirt-domain.c#L7064)进行处理

```c
//#0  virDomainCreate (domain=domain@entry=0x7db668020500) at ../src/libvirt-domain.c:7065
//#1  0x00005b5800f8f091 in remoteDispatchDomainCreate (server=0x5b5802d9d880, msg=0x5b5802d9bb20, args=0x7db6b00025b0, rerr=0x7db6c33ff9e0, client=<optimized out>) at src/remote/remote_daemon_dispatch_stubs.h:5050
//#2  remoteDispatchDomainCreateHelper (server=0x5b5802d9d880, client=<optimized out>, msg=0x5b5802d9bb20, rerr=0x7db6c33ff9e0, args=0x7db6b00025b0, ret=0x0) at src/remote/remote_daemon_dispatch_stubs.h:5029
//#3  0x00007db6cdc0053c in virNetServerProgramDispatchCall (msg=0x5b5802d9bb20, client=0x5b5802db1010, server=0x5b5802d9d880, prog=0x5b5802da7010) at ../src/rpc/virnetserverprogram.c:423
//#4  virNetServerProgramDispatch (prog=0x5b5802da7010, server=server@entry=0x5b5802d9d880, client=0x5b5802db1010, msg=0x5b5802d9bb20) at ../src/rpc/virnetserverprogram.c:299
//#5  0x00007db6cdc06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x5b5802d9d880) at ../src/rpc/virnetserver.c:135
//#6  virNetServerHandleJob (jobOpaque=0x5b5802d80540, opaque=0x5b5802d9d880) at ../src/rpc/virnetserver.c:155
//#7  0x00007db6cdb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#8  0x00007db6cdb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#9  0x00007db6cd494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#10 0x00007db6cd526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static int remoteDispatchDomainCreateHelper(
    virNetServer *server,
    virNetServerClient *client,
    virNetMessage *msg,
    struct virNetMessageError *rerr,
    void *args,
    void *ret G_GNUC_UNUSED)
{
  int rv;
  virThreadJobSet("remoteDispatchDomainCreate");
  VIR_DEBUG("server=%p client=%p msg=%p rerr=%p args=%p ret=%p",
            server, client, msg, rerr, args, ret);
  rv = remoteDispatchDomainCreate(server, client, msg, rerr, args);
  virThreadJobClear(rv);
  return rv;
}

static int remoteDispatchDomainCreate(
    virNetServer *server G_GNUC_UNUSED,
    virNetServerClient *client,
    virNetMessage *msg G_GNUC_UNUSED,
    struct virNetMessageError *rerr,
    remote_domain_create_args *args)
{
    int rv = -1;
    virDomainPtr dom = NULL;

    virConnectPtr conn = remoteGetHypervisorConn(client);
    if (!conn)
        goto cleanup;

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainCreate(dom) < 0)
        goto cleanup;

    rv = 0;
    ...
    return rv;
}

/**
 * virDomainCreate:
 * @domain: pointer to a defined domain
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.  The domain will be paused only
 * if restoring from managed state created from a paused domain.  For more
 * control, see virDomainCreateWithFlags().
 *
 * Returns 0 in case of success, -1 in case of error
 *
 * Since: 0.1.1
 */
int
virDomainCreate(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainCreate) {
        int ret;
        ret = conn->driver->domainCreate(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(domain->conn);
    return -1;
}
```

这里和**virsh**执行了相同的函数，但**libvirtd**需要和**qemu**进行交互，会使用**qemu driver**的[**qemuDomainCreate()**](https://github.com/libvirt/libvirt/blob/300362421e4b5a5820db9f458cc514b762fc30a4/src/qemu/qemu_driver.c#L6404)进行处理，最终启动qemu进程

```c
//#0  virDomainCreate (domain=domain@entry=0x7db65c0069a0) at ../src/libvirt-domain.c:7065
//#1  0x00005b5800f8f091 in remoteDispatchDomainCreate (server=0x5b5802d9d880, msg=0x5b5802db3f30, args=0x7db6bc002450, rerr=0x7db6c8fff9e0, client=<optimized out>) at src/remote/remote_daemon_dispatch_stubs.h:5050
//#2  remoteDispatchDomainCreateHelper (server=0x5b5802d9d880, client=<optimized out>, msg=0x5b5802db3f30, rerr=0x7db6c8fff9e0, args=0x7db6bc002450, ret=0x0) at src/remote/remote_daemon_dispatch_stubs.h:5029
//#3  0x00007db6cdc0053c in virNetServerProgramDispatchCall (msg=0x5b5802db3f30, client=0x5b5802db1340, server=0x5b5802d9d880, prog=0x5b5802da7010) at ../src/rpc/virnetserverprogram.c:423
//#4  virNetServerProgramDispatch (prog=0x5b5802da7010, server=server@entry=0x5b5802d9d880, client=0x5b5802db1340, msg=0x5b5802db3f30) at ../src/rpc/virnetserverprogram.c:299
//#5  0x00007db6cdc06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x5b5802d9d880) at ../src/rpc/virnetserver.c:135
//#6  virNetServerHandleJob (jobOpaque=0x5b5802d89130, opaque=0x5b5802d9d880) at ../src/rpc/virnetserver.c:155
//#7  0x00007db6cdb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#8  0x00007db6cdb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#9  0x00007db6cd494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#10 0x00007db6cd526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static int
qemuDomainCreate(virDomainPtr dom)
{
    return qemuDomainCreateWithFlags(dom, 0);
}

static int
qemuDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    virQEMUDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_BYPASS_CACHE |
                  VIR_DOMAIN_START_FORCE_BOOT |
                  VIR_DOMAIN_START_RESET_NVRAM, -1);

    if (!(vm = qemuDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (qemuProcessBeginJob(vm, VIR_DOMAIN_JOB_OPERATION_START, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto endjob;
    }

    if (qemuDomainObjStart(dom->conn, driver, vm, flags,
                           VIR_ASYNC_JOB_START) < 0)
        goto endjob;

    dom->id = vm->def->id;
    ret = 0;

 endjob:
    qemuProcessEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}
```

## qmp

**libvirtd**使用**qmp**(Qemu Machine Protocol)与**qemu**虚拟机进行交互，其中**qmp**是一种基于json的协议，下面以**virsh qemu-monitor-command $domain query-kvm**为例进行分析

### 发送

根据[前面rpc小节](#rpc)的内容，**virsh**调用[**remoteDomainQemuMonitorCommand()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/remote/remote_driver.c#L5479)发送**rpc**消息，而**libvirtd**调用[**qemuDomainQemuMonitorCommand()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_driver.c#L13457)处理**rpc**命令

```c
//#0  remoteDomainQemuMonitorCommand (domain=0x55555567f500, cmd=0x555555678090 "{\"execute\":\"query-kvm\",\"arguments\":{}}", result=0x7fffffffda28, flags=0) at ../src/remote/remote_driver.c:5481
//#1  0x00007ffff7fb1337 in virDomainQemuMonitorCommand (domain=domain@entry=0x55555567f500, cmd=cmd@entry=0x555555678090 "{\"execute\":\"query-kvm\",\"arguments\":{}}", result=result@entry=0x7fffffffda28, flags=flags@entry=0) at ../src/libvirt-qemu.c:85
//#2  0x00005555555b4d2e in cmdQemuMonitorCommand (ctl=0x7fffffffdb60, cmd=0x555555673060) at ../tools/virsh-domain.c:9767
//#3  0x00005555555e147f in vshCommandRun (ctl=ctl@entry=0x7fffffffdb60, cmd=0x555555673060) at ../tools/vsh.c:1359
//#4  0x0000555555591f70 in main (argc=argc@entry=4, argv=argv@entry=0x7fffffffdf28) at ../tools/virsh.c:889
//#5  0x00007ffff7429d90 in __libc_start_call_main (main=main@entry=0x555555591410 <main>, argc=argc@entry=4, argv=argv@entry=0x7fffffffdf28) at ../sysdeps/nptl/libc_start_call_main.h:58
//#6  0x00007ffff7429e40 in __libc_start_main_impl (main=0x555555591410 <main>, argc=4, argv=0x7fffffffdf28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf18) at ../csu/libc-start.c:392
//#7  0x0000555555592145 in _start ()
static const vshCmdGrp cmdGroups[] = {
    {VIRSH_CMD_GRP_DOM_MANAGEMENT, "domain", domManagementCmds},
    ...
    {NULL, NULL, NULL}
};

const vshCmdDef domManagementCmds[] = {
    ...
    {.name = "qemu-monitor-command",
     .handler = cmdQemuMonitorCommand,
     .opts = opts_qemu_monitor_command,
     .info = &info_qemu_monitor_command,
     .flags = 0
    },
    ...
    {.name = NULL}
};

static virConnectDriver connect_driver = {
    .hypervisorDriver = &hypervisor_driver,
    ...
};

static virHypervisorDriver hypervisor_driver = {
    .name = "remote",
    ...
    .domainQemuMonitorCommand = remoteDomainQemuMonitorCommand, /* 0.8.3 */
    ...
};

//#0  qemuDomainQemuMonitorCommand (domain=0x7dc77c006b80, cmd=0x7dc7e4033de0 "{\"execute\":\"query-kvm\",\"arguments\":{}}", result=0x7dc7e40077e0, flags=0) at ../src/qemu/qemu_driver.c:13458
//#1  0x00007dc7ef01f337 in virDomainQemuMonitorCommand (domain=domain@entry=0x7dc77c006b80, cmd=0x7dc7e4033de0 "{\"execute\":\"query-kvm\",\"arguments\":{}}", result=result@entry=0x7dc7e40077e0, flags=0) at ../src/libvirt-qemu.c:85
//#2  0x00006006ccbf1bbf in qemuDispatchDomainMonitorCommand (server=0x6006cd62e880, msg=0x6006cd62ccb0, ret=0x7dc7e40077e0, args=0x7dc7e403a330, rerr=0x7dc7ea9ff9e0, client=<optimized out>) at ../src/remote/remote_daemon_dispatch.c:4669
//#3  qemuDispatchDomainMonitorCommandHelper (server=0x6006cd62e880, client=<optimized out>, msg=0x6006cd62ccb0, rerr=0x7dc7ea9ff9e0, args=0x7dc7e403a330, ret=0x7dc7e40077e0) at src/remote/qemu_daemon_dispatch_stubs.h:195
//#4  0x00007dc7eec0053c in virNetServerProgramDispatchCall (msg=0x6006cd62ccb0, client=0x6006cd642340, server=0x6006cd62e880, prog=0x6006cd638090) at ../src/rpc/virnetserverprogram.c:423
//#5  virNetServerProgramDispatch (prog=0x6006cd638090, server=server@entry=0x6006cd62e880, client=0x6006cd642340, msg=0x6006cd62ccb0) at ../src/rpc/virnetserverprogram.c:299
//#6  0x00007dc7eec06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x6006cd62e880) at ../src/rpc/virnetserver.c:135
//#7  virNetServerHandleJob (jobOpaque=0x6006cd61a4f0, opaque=0x6006cd62e880) at ../src/rpc/virnetserver.c:155
//#8  0x00007dc7eeb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#9  0x00007dc7eeb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#10 0x00007dc7ee494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#11 0x00007dc7ee526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static virConnectDriver qemuConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "qemu", NULL },
    .embeddable = true,
    .hypervisorDriver = &qemuHypervisorDriver,
};

static virHypervisorDriver qemuHypervisorDriver = {
    .name = QEMU_DRIVER_NAME,
    ...
    .domainQemuMonitorCommand = qemuDomainQemuMonitorCommand, /* 0.8.3 */
    ...
};
```

下面详细分析一下**libvirtd**中[**qemuDomainQemuMonitorCommand()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_driver.c#L13457)的逻辑，如下所示

```c
//#0  qemuMonitorSend (mon=mon@entry=0x7dc7cc03e010, msg=msg@entry=0x7dc7ea9ff770) at ../src/qemu/qemu_monitor.c:820
//#1  0x00007dc7dbd33e6a in qemuMonitorJSONCommandWithFd (mon=0x7dc7cc03e010, cmd=0x7dc7e4000b90, scm_fd=-1, reply=0x7dc7ea9ff7e0) at ../src/qemu/qemu_monitor_json.c:285
//#2  0x00007dc7dbd3b5a0 in qemuMonitorJSONArbitraryCommand (mon=0x7dc7cc03e010, cmd_str=<optimized out>, fd=-1, reply_str=0x7dc7e40077e0) at ../src/qemu/qemu_monitor_json.c:4111
//#3  0x00007dc7dbd2b0ab in qemuMonitorArbitraryCommand (mon=<optimized out>, cmd=cmd@entry=0x7dc7e4033de0 "{\"execute\":\"query-kvm\",\"arguments\":{}}", fd=fd@entry=-1, reply=reply@entry=0x7dc7e40077e0, hmp=hmp@entry=false) at ../src/qemu/qemu_monitor.c:2870
//#4  0x00007dc7dbcd8291 in qemuDomainQemuMonitorCommandWithFiles (domain=<optimized out>, cmd=0x7dc7e4033de0 "{\"execute\":\"query-kvm\",\"arguments\":{}}", ninfds=ninfds@entry=0, infds=infds@entry=0x0, noutfds=noutfds@entry=0x0, outfds=outfds@entry=0x0, result=0x7dc7e40077e0, flags=0) at ../src/qemu/qemu_driver.c:13441
//#5  0x00007dc7dbcd83c9 in qemuDomainQemuMonitorCommand (domain=<optimized out>, cmd=<optimized out>, result=<optimized out>, flags=<optimized out>) at ../src/qemu/qemu_driver.c:13459
//#6  0x00007dc7ef01f337 in virDomainQemuMonitorCommand (domain=domain@entry=0x7dc7e4002410, cmd=0x7dc7e4033de0 "{\"execute\":\"query-kvm\",\"arguments\":{}}", result=result@entry=0x7dc7e40077e0, flags=0) at ../src/libvirt-qemu.c:85
//#7  0x00006006ccbf1bbf in qemuDispatchDomainMonitorCommand (server=0x6006cd62e880, msg=0x6006cd649910, ret=0x7dc7e40077e0, args=0x7dc7e403a330, rerr=0x7dc7ea9ff9e0, client=<optimized out>) at ../src/remote/remote_daemon_dispatch.c:4669
//#8  qemuDispatchDomainMonitorCommandHelper (server=0x6006cd62e880, client=<optimized out>, msg=0x6006cd649910, rerr=0x7dc7ea9ff9e0, args=0x7dc7e403a330, ret=0x7dc7e40077e0) at src/remote/qemu_daemon_dispatch_stubs.h:195
//#9  0x00007dc7eec0053c in virNetServerProgramDispatchCall (msg=0x6006cd649910, client=0x6006cd642230, server=0x6006cd62e880, prog=0x6006cd638090) at ../src/rpc/virnetserverprogram.c:423
//#10 virNetServerProgramDispatch (prog=0x6006cd638090, server=server@entry=0x6006cd62e880, client=0x6006cd642230, msg=0x6006cd649910) at ../src/rpc/virnetserverprogram.c:299
//#11 0x00007dc7eec06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x6006cd62e880) at ../src/rpc/virnetserver.c:135
//#12 virNetServerHandleJob (jobOpaque=0x6006cd610b20, opaque=0x6006cd62e880) at ../src/rpc/virnetserver.c:155
//#13 0x00007dc7eeb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#14 0x00007dc7eeb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#15 0x00007dc7ee494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#16 0x00007dc7ee526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static int
qemuDomainQemuMonitorCommand(virDomainPtr domain,
                             const char *cmd,
                             char **result,
                             unsigned int flags)
{
    return qemuDomainQemuMonitorCommandWithFiles(domain, cmd, 0, NULL, NULL, NULL, result, flags);
}

static int
qemuDomainQemuMonitorCommandWithFiles(virDomainPtr domain,
                                      const char *cmd,
                                      unsigned int ninfds,
                                      int *infds,
                                      unsigned int *noutfds,
                                      int **outfds,
                                      char **result,
                                      unsigned int flags)
{
    virQEMUDriver *driver = domain->conn->privateData;
    virDomainObj *vm = NULL;
    int ret = -1;
    qemuDomainObjPrivate *priv;
    bool hmp;
    int fd = -1;

    ...
    if (!(vm = qemuDomainObjFromDomain(domain)))
        goto cleanup;
    ...
    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;
    ...
    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, fd, result, hmp);
    qemuDomainObjExitMonitor(vm);

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

int
qemuMonitorArbitraryCommand(qemuMonitor *mon,
                            const char *cmd,
                            int fd,
                            char **reply,
                            bool hmp)
{
    ...
    return qemuMonitorJSONArbitraryCommand(mon, cmd, fd, reply);
}

int qemuMonitorJSONArbitraryCommand(qemuMonitor *mon,
                                    const char *cmd_str,
                                    int fd,
                                    char **reply_str)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = virJSONValueFromString(cmd_str)))
        return -1;

    if (qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        return -1;

    if (!(*reply_str = virJSONValueToString(reply, false)))
        return -1;

    return 0;
}

static int
qemuMonitorJSONCommandWithFd(qemuMonitor *mon,
                             virJSONValue *cmd,
                             int scm_fd,
                             virJSONValue **reply)
{
    int ret = -1;
    qemuMonitorMessage msg = { 0 };
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;

    *reply = NULL;

    if (virJSONValueObjectHasKey(cmd, "execute")) {
        g_autofree char *id = qemuMonitorNextCommandID(mon);

        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to append command 'id' string"));
            return -1;
        }
    }

    if (virJSONValueToBuffer(cmd, &cmdbuf, false) < 0)
        return -1;
    virBufferAddLit(&cmdbuf, "\r\n");

    msg.txLength = virBufferUse(&cmdbuf);
    msg.txBuffer = virBufferCurrentContent(&cmdbuf);
    msg.txFD = scm_fd;

    ret = qemuMonitorSend(mon, &msg);

    if (ret == 0) {
        if (!msg.rxObject) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing monitor reply object"));
            ret = -1;
        } else {
            *reply = msg.rxObject;
        }
    }

    return ret;
}

int
qemuMonitorSend(qemuMonitor *mon,
                qemuMonitorMessage *msg)
{
    int ret = -1;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s mon=%p vm=%p name=%s",
                  NULLSTR(mon->lastError.message), mon, mon->vm, mon->domainName);
        virSetError(&mon->lastError);
        return -1;
    }
    if (mon->goteof) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("End of file from qemu monitor (vm='%1$s')"), mon->domainName);
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    PROBE(QEMU_MONITOR_SEND_MSG,
          "mon=%p msg=%s fd=%d",
          mon, mon->msg->txBuffer, mon->msg->txFD);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to wait on monitor condition (vm='%1$s')"), mon->domainName);
            goto cleanup;
        }
    }

    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s mon=%p vm=%p name=%s",
                  NULLSTR(mon->lastError.message), mon, mon->vm, mon->domainName);
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}
```

整理逻辑比较清晰，**libvirtd**拼装好**qmp**的json字符串后，调用[**qemuMonitorUpdateWatch()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor.c#L416)进行异步发送，其逻辑如下所示

```c
static void
qemuMonitorUpdateWatch(qemuMonitor *mon)
{
    qemuMonitorUnregister(mon);
    if (mon->socket)
        qemuMonitorRegister(mon);
}

/**
 * qemuMonitorRegister:
 * @mon: QEMU monitor
 *
 * Registers the monitor in the event loop. The caller has to hold the
 * lock for @mon.
 */
void
qemuMonitorRegister(qemuMonitor *mon)
{
    GIOCondition cond = 0;

    if (mon->lastError.code == VIR_ERR_OK) {
        cond |= G_IO_IN;

        if ((mon->msg && mon->msg->txOffset < mon->msg->txLength) &&
            !mon->waitGreeting)
            cond |= G_IO_OUT;
    }

    mon->watch = g_socket_create_source(mon->socket,
                                        cond,
                                        NULL);

    virObjectRef(mon);
    g_source_set_callback(mon->watch,
                          (GSourceFunc)qemuMonitorIO,
                          mon,
                          (GDestroyNotify)virObjectUnref);

    g_source_attach(mon->watch,
                    mon->context);
}

//#0  qemuMonitorIO (socket=<optimized out>, cond=G_IO_OUT, opaque=0x7dc7cc03e010) at ../src/qemu/qemu_monitor.c:437
//#1  0x00007dc7ee8be49b in  () at /lib/x86_64-linux-gnu/libgio-2.0.so.0
//#2  0x00007dc7eef27c44 in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#3  0x00007dc7eef7d2b8 in  () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#4  0x00007dc7eef272b3 in g_main_loop_run () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#5  0x00007dc7eeaee2df in virEventThreadWorker (opaque=0x7dc7cc03a3f0) at ../src/util/vireventthread.c:124
//#6  0x00007dc7eef56ab1 in  () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#7  0x00007dc7ee494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#8  0x00007dc7ee526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
static gboolean
qemuMonitorIO(GSocket *socket G_GNUC_UNUSED,
              GIOCondition cond,
              gpointer opaque)
{
    qemuMonitor *mon = opaque;
    ...
    if (cond & G_IO_OUT) {
        if (qemuMonitorIOWrite(mon) < 0) {
            error = true;
            if (errno == ECONNRESET)
                hangup = true;
        }
    }
    ...
    qemuMonitorUpdateWatch(mon);
    ...
    return G_SOURCE_REMOVE;
}
```

基于{% post_link glib的事件循环 %}分析，**libvirtd**会更新**qemu monitor**的socket事件源。这样在**worker**线程的事件循环中，当该socket事件源可用时会调用[**qemuMonitorIOWrite()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor.c#L323)将**qmp**消息发送给**qemu monitor**

这里额外说明一下上面的**worker**线程，其是**libvirtd**在启动qemu虚拟机时调用[**qemuDomainObjStartWorker()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_domain.c#L1837)创建的，用以处理和虚拟机的交互，如下所示

```c
//#0  0x00007dc7eeaee439 in virEventThreadStart (name=<optimized out>, evt=<optimized out>) at ../src/util/vireventthread.c:136
//#1  virEventThreadNew (name=name@entry=0x7dc7e401a7f0 "vm-l1") at ../src/util/vireventthread.c:184
//#2  0x00007dc7dbcb1d44 in qemuDomainObjStartWorker (dom=dom@entry=0x7dc788328830) at ../src/qemu/qemu_domain.c:1845
//#3  0x00007dc7dbd57d62 in qemuProcessLaunch (conn=<optimized out>, driver=0x7dc788026000, vm=<optimized out>, asyncJob=<optimized out>, incoming=0x0, snapshot=<optimized out>, vmop=<optimized out>, flags=<optimized out>) at ../src/qemu/qemu_process.c:7916
//#4  0x00007dc7dbd5ce2a in qemuProcessStart (conn=conn@entry=0x7dc7c8005dd0, driver=driver@entry=0x7dc788026000, vm=vm@entry=0x7dc788328830, updatedCPU=updatedCPU@entry=0x0, asyncJob=asyncJob@entry=VIR_ASYNC_JOB_START, migrateFrom=migrateFrom@entry=0x0, migrateFd=-1, migratePath=0x0, snapshot=0x0, vmop=VIR_NETDEV_VPORT_PROFILE_OP_CREATE, flags=<optimized out>) at ../src/qemu/qemu_process.c:8213
//#5  0x00007dc7dbcf5372 in qemuDomainObjStart (conn=0x7dc7c8005dd0, driver=0x7dc788026000, vm=0x7dc788328830, flags=<optimized out>, asyncJob=VIR_ASYNC_JOB_START) at ../src/qemu/qemu_driver.c:6339
//#6  0x00007dc7dbcf59d5 in qemuDomainCreateWithFlags (dom=0x7dc7e4002460, flags=0) at ../src/qemu/qemu_driver.c:6388
//#7  0x00007dc7eecc8baa in virDomainCreate (domain=domain@entry=0x7dc7e4002460) at ../src/libvirt-domain.c:7079
//#8  0x00006006ccbec091 in remoteDispatchDomainCreate (server=0x6006cd62e880, msg=0x6006cd64c1e0, args=0x7dc7e4033de0, rerr=0x7dc7ea9ff9e0, client=<optimized out>) at src/remote/remote_daemon_dispatch_stubs.h:5050
//#9  remoteDispatchDomainCreateHelper (server=0x6006cd62e880, client=<optimized out>, msg=0x6006cd64c1e0, rerr=0x7dc7ea9ff9e0, args=0x7dc7e4033de0, ret=0x0) at src/remote/remote_daemon_dispatch_stubs.h:5029
//#10 0x00007dc7eec0053c in virNetServerProgramDispatchCall (msg=0x6006cd64c1e0, client=0x6006cd642010, server=0x6006cd62e880, prog=0x6006cd638010) at ../src/rpc/virnetserverprogram.c:423
//#11 virNetServerProgramDispatch (prog=0x6006cd638010, server=server@entry=0x6006cd62e880, client=0x6006cd642010, msg=0x6006cd64c1e0) at ../src/rpc/virnetserverprogram.c:299
//#12 0x00007dc7eec06538 in virNetServerProcessMsg (msg=<optimized out>, prog=<optimized out>, client=<optimized out>, srv=0x6006cd62e880) at ../src/rpc/virnetserver.c:135
//#13 virNetServerHandleJob (jobOpaque=0x6006cd616090, opaque=0x6006cd62e880) at ../src/rpc/virnetserver.c:155
//#14 0x00007dc7eeb3e9f3 in virThreadPoolWorker (opaque=<optimized out>) at ../src/util/virthreadpool.c:164
//#15 0x00007dc7eeb3dfe9 in virThreadHelper (data=<optimized out>) at ../src/util/virthread.c:256
//#16 0x00007dc7ee494ac3 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
//#17 0x00007dc7ee526850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
int
qemuDomainObjStartWorker(virDomainObj *dom)
{
    qemuDomainObjPrivate *priv = dom->privateData;

    if (!priv->eventThread) {
        g_autofree char *threadName = g_strdup_printf("vm-%s", dom->def->name);
        if (!(priv->eventThread = virEventThreadNew(threadName)))
            return -1;
    }

    return 0;
}

virEventThread *
virEventThreadNew(const char *name)
{
    g_autoptr(virEventThread) evt = VIR_EVENT_THREAD(g_object_new(VIR_TYPE_EVENT_THREAD, NULL));

    if (virEventThreadStart(evt, name) < 0)
        return NULL;

    return g_steal_pointer(&evt);
}

static int
virEventThreadStart(virEventThread *evt, const char *name)
{
    g_autoptr(GError) gerr = NULL;
    g_autofree char *thname = NULL;
    size_t maxname = virThreadMaxName();
    virEventThreadData *data;

    if (maxname)
        thname = g_strndup(name, maxname);
    else
        thname = g_strdup(name);

    if (evt->thread) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Event thread is already running"));
        return -1;
    }

    data = g_new0(virEventThreadData, 1);
    data->loop = g_main_loop_ref(evt->loop);
    data->context = g_main_context_ref(evt->context);
    g_mutex_init(&data->lock);
    g_cond_init(&data->cond);

    evt->thread = g_thread_try_new(thname,
                                   virEventThreadWorker,
                                   data,
                                   &gerr);
    if (!evt->thread) {
        virEventThreadDataFree(data);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to start event thread: %1$s"),
                       gerr->message);
        return -1;
    }

    g_mutex_lock(&data->lock);
    while (!data->running)
        g_cond_wait(&data->cond, &data->lock);
    g_mutex_unlock(&data->lock);

    return 0;
}

static void *
virEventThreadWorker(void *opaque)
{
    virEventThreadData *data = opaque;
    /*
     * Do NOT use g_autoptr on this. We need to unref it
     * before the GMainContext is unrefed
     */
    GSource *running = g_idle_source_new();

    g_source_set_callback(running, virEventThreadNotify, data, NULL);

    g_source_attach(running, data->context);

    g_main_loop_run(data->loop);

    g_source_unref(running);
    virEventThreadDataFree(data);

    return NULL;
}
```

说回正题，**libvirtd**将**qmp**消息发送到**qemu monitor**后，**qemu monitor**会处理该**qmp**消息。由于**qem**处理**qmp**消息涉及到协程等概念，这里就不赘述，简单来说就是事件循环捕获到**monitor socket**可读，则执行回调函数唤醒协程，协程执行[**monitor_qmp_dispatcher_co()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/monitor/qmp.c#L274)并最终触发[**do_qmp_dispatch_bh()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-dispatch.c#L122)的**QEMUBH**资源，从而执行基于[**scripts/qapi-gen.py**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/scripts/qapi-gen.py)脚本基于[**qapi/qapi-schema.json**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qapi-schema.json)生成的**qmp_init_marshal()**注册的[**qmp_query_kvm()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/hw/core/machine-qmp-cmds.c#L236)handler处理该**qmp**命令

```c
//#0  qmp_dispatch (cmds=0x6201acdc5a50 <qmp_commands>, request=0x7850a8007630, allow_oob=false, cur_mon=0x6201acf6ecf0) at ../qapi/qmp-dispatch.c:139
//#1  0x00006201abd3f930 in monitor_qmp_dispatch (mon=0x6201acf6ecf0, req=0x7850a8007630) at ../monitor/qmp.c:168
//#2  0x00006201abd3fe66 in monitor_qmp_dispatcher_co (data=0x0) at ../monitor/qmp.c:335
//#3  0x00006201abe32f87 in coroutine_trampoline (i0=-1393168112, i1=25089) at ../util/coroutine-ucontext.c:175
//#4  0x00007851b845a130 in __start_context () at ../sysdeps/unix/sysv/linux/x86_64/__start_context.S:90
//#5  0x00007fffe3b98b50 in  ()
//#6  0x0000000000000000 in  ()
/*
 * Runs outside of coroutine context for OOB commands, but in coroutine
 * context for everything else.
 */
QDict *coroutine_mixed_fn qmp_dispatch(const QmpCommandList *cmds, QObject *request,
                                       bool allow_oob, Monitor *cur_mon)
{
    /*
     * Actual context doesn't match the one the command needs.
     *
     * Case 1: we are in coroutine context, but command does not
     * have QCO_COROUTINE.  We need to drop out of coroutine
     * context for executing it.
     *
     * Case 2: we are outside coroutine context, but command has
     * QCO_COROUTINE.  Can't actually happen, because we get here
     * outside coroutine context only when executing a command
     * out of band, and OOB commands never have QCO_COROUTINE.
     */
    assert(!oob && qemu_in_coroutine() && !(cmd->options & QCO_COROUTINE));

    QmpDispatchBH data = {
        .cur_mon    = cur_mon,
        .cmd        = cmd,
        .args       = args,
        .ret        = &ret,
        .errp       = &err,
        .co         = qemu_coroutine_self(),
    };
    aio_bh_schedule_oneshot(iohandler_get_aio_context(), do_qmp_dispatch_bh,
                            &data);
    qemu_coroutine_yield();
    ...    
}


void qmp_init_marshal(QmpCommandList *cmds)
{
    QTAILQ_INIT(cmds);
    ...
    qmp_register_command(cmds, "query-kvm",
                         qmp_marshal_query_kvm, 0, 0);
    ...
}

//#0  qmp_query_kvm (errp=0x7fffe3b99208) at ../hw/core/machine-qmp-cmds.c:238
//#1  0x00006201abd9dba4 in qmp_marshal_query_kvm (args=0x7850a8008650, ret=0x7851b7fbbda8, errp=0x7851b7fbbda0) at qapi/qapi-commands-machine.c:584
//#2  0x00006201abe00d45 in do_qmp_dispatch_bh (opaque=0x7851b7fbbe40) at ../qapi/qmp-dispatch.c:128
//#3  0x00006201abe2e5c8 in aio_bh_call (bh=0x6201ad4d3000) at ../util/async.c:171
//#4  0x00006201abe2e6ef in aio_bh_poll (ctx=0x6201acf5f250) at ../util/async.c:218
//#5  0x00006201abe0ee59 in aio_dispatch (ctx=0x6201acf5f250) at ../util/aio-posix.c:423
//#6  0x00006201abe2eb84 in aio_ctx_dispatch (source=0x6201acf5f250, callback=0x0, user_data=0x0) at ../util/async.c:360
//#7  0x00007851b8992d3b in g_main_context_dispatch () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
//#8  0x00006201abe3020f in glib_pollfds_poll () at ../util/main-loop.c:287
//#9  0x00006201abe3029a in os_host_main_loop_wait (timeout=0) at ../util/main-loop.c:310
//#10 0x00006201abe303c6 in main_loop_wait (nonblocking=0) at ../util/main-loop.c:589
//#11 0x00006201ab932fc7 in qemu_main_loop () at ../system/runstate.c:783
//#12 0x00006201abbf4002 in qemu_default_main () at ../system/main.c:37
//#13 0x00006201abbf4043 in main (argc=64, argv=0x7fffe3b99618) at ../system/main.c:48
//#14 0x00007851b8429d90 in __libc_start_call_main (main=main@entry=0x6201abbf4016 <main>, argc=argc@entry=64, argv=argv@entry=0x7fffe3b99618) at ../sysdeps/nptl/libc_start_call_main.h:58
//#15 0x00007851b8429e40 in __libc_start_main_impl (main=0x6201abbf4016 <main>, argc=64, argv=0x7fffe3b99618, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffe3b99608) at ../csu/libc-start.c:392
//#16 0x00006201ab5ca675 in _start ()
void qmp_marshal_query_kvm(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    bool ok = false;
    Visitor *v;
    KvmInfo *retval;

    v = qobject_input_visitor_new_qmp(QOBJECT(args));
    if (!visit_start_struct(v, NULL, NULL, 0, errp)) {
        goto out;
    }
    ok = visit_check_struct(v, errp);
    visit_end_struct(v, NULL);
    if (!ok) {
        goto out;
    }

    if (trace_event_get_state_backends(TRACE_QMP_ENTER_QUERY_KVM)) {
        g_autoptr(GString) req_json = qobject_to_json(QOBJECT(args));

        trace_qmp_enter_query_kvm(req_json->str);
    }

    retval = qmp_query_kvm(&err);
    if (err) {
        trace_qmp_exit_query_kvm(error_get_pretty(err), false);
        error_propagate(errp, err);
        goto out;
    }

    qmp_marshal_output_KvmInfo(retval, ret, errp);

    if (trace_event_get_state_backends(TRACE_QMP_EXIT_QUERY_KVM)) {
        g_autoptr(GString) ret_json = qobject_to_json(*ret);

        trace_qmp_exit_query_kvm(ret_json->str, true);
    }

out:
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
    visit_end_struct(v, NULL);
    visit_free(v);
}

KvmInfo *qmp_query_kvm(Error **errp)
{
    KvmInfo *info = g_malloc0(sizeof(*info));

    info->enabled = kvm_enabled();
    info->present = accel_find("kvm");

    return info;
}
```

### 接受

**qemu**在[**do_qmp_dispatch_bh()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-dispatch.c#L122)中执行完**qmp**命令后，其会唤醒之前触发**QEMUBH**的协程逻辑[**qmp_dispatch()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/qapi/qmp-dispatch.c#L137)，并继续执行切换前的逻辑，将结果返回给**libvirtd**

```c
static void do_qmp_dispatch_bh(void *opaque)
{
    QmpDispatchBH *data = opaque;
    ...
    data->cmd->fn(data->args, data->ret, data->errp);
    monitor_set_cur(qemu_coroutine_self(), NULL);
    aio_co_wake(data->co);
}

/*
 * Runs outside of coroutine context for OOB commands, but in coroutine
 * context for everything else.
 */
QDict *coroutine_mixed_fn qmp_dispatch(const QmpCommandList *cmds, QObject *request,
                                       bool allow_oob, Monitor *cur_mon)
{
    ...
    /*
     * Actual context doesn't match the one the command needs.
     *
     * Case 1: we are in coroutine context, but command does not
     * have QCO_COROUTINE.  We need to drop out of coroutine
     * context for executing it.
     *
     * Case 2: we are outside coroutine context, but command has
     * QCO_COROUTINE.  Can't actually happen, because we get here
     * outside coroutine context only when executing a command
     * out of band, and OOB commands never have QCO_COROUTINE.
     */
    assert(!oob && qemu_in_coroutine() && !(cmd->options & QCO_COROUTINE));

    QmpDispatchBH data = {
        .cur_mon    = cur_mon,
        .cmd        = cmd,
        .args       = args,
        .ret        = &ret,
        .errp       = &err,
        .co         = qemu_coroutine_self(),
    };
    aio_bh_schedule_oneshot(iohandler_get_aio_context(), do_qmp_dispatch_bh,
                            &data);
    qemu_coroutine_yield();
    ...
    qobject_unref(args);
    ...
    rsp = qdict_new();
    qdict_put_obj(rsp, "return", ret);

out:
    if (err) {
        assert(!rsp);
        rsp = qmp_error_response(err);
    }

    assert(rsp);

    if (id) {
        qdict_put_obj(rsp, "id", qobject_ref(id));
    }

    return rsp;
}

/*
 * Runs outside of coroutine context for OOB commands, but in
 * coroutine context for everything else.
 */
static void monitor_qmp_dispatch(MonitorQMP *mon, QObject *req)
{
    QDict *rsp;
    QDict *error;

    rsp = qmp_dispatch(mon->commands, req, qmp_oob_enabled(mon),
                       &mon->common);
    ...
    monitor_qmp_respond(mon, rsp);
    qobject_unref(rsp);
}

/*
 * Emit QMP response @rsp to @mon.
 * Null @rsp can only happen for commands with QCO_NO_SUCCESS_RESP.
 * Nothing is emitted then.
 */
static void monitor_qmp_respond(MonitorQMP *mon, QDict *rsp)
{
    if (rsp) {
        qmp_send_response(mon, rsp);
    }
}

void qmp_send_response(MonitorQMP *mon, const QDict *rsp)
{
    const QObject *data = QOBJECT(rsp);
    GString *json;

    json = qobject_to_json_pretty(data, mon->pretty);
    assert(json != NULL);
    trace_monitor_qmp_respond(mon, json->str);

    g_string_append_c(json, '\n');
    monitor_puts(&mon->common, json->str);

    g_string_free(json, true);
}
```

可以看到，**qemu**会调用[**qmp_send_response()**](https://elixir.bootlin.com/qemu/v9.0.0-rc2/source/monitor/qmp.c#L132)将结果发送出去

而这会触发在[前面发送qmp消息](#发送)时更新的**qemu monitor**的socket事件源，从而调用[**qemuMonitorIO()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor.c#425)处理**qemu monitor**的返回

```c
static gboolean
qemuMonitorIO(GSocket *socket G_GNUC_UNUSED,
              GIOCondition cond,
              gpointer opaque)
{
    if (!error && cond & G_IO_IN) {
        int got = qemuMonitorIORead(mon);
        if (got < 0) {
            error = true;
            if (errno == ECONNRESET)
                hangup = true;
        } else if (got == 0) {
            mon->goteof = true;
        } else {
            /* Ignore hangup/error cond if we read some data, to
             * give time for that data to be consumed */
            cond = 0;

            if (qemuMonitorIOProcess(mon) < 0)
                error = true;
        }
    }

    qemuMonitorUpdateWatch(mon);
    return G_SOURCE_REMOVE;
}

/*
 * Called when the monitor has incoming data to read
 * Call this function while holding the monitor lock.
 *
 * Returns -1 on error, or number of bytes read
 */
static int
qemuMonitorIORead(qemuMonitor *mon)
{
    size_t avail = mon->bufferLength - mon->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (mon->bufferLength >= QEMU_MONITOR_MAX_RESPONSE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QEMU monitor reply exceeds buffer size (%1$d bytes)"),
                           QEMU_MONITOR_MAX_RESPONSE);
            return -1;
        }
        VIR_REALLOC_N(mon->buffer, mon->bufferLength + 1024);
        mon->bufferLength += 1024;
        avail += 1024;
    }

    /* Read as much as we can get into our buffer,
       until we block on EAGAIN, or hit EOF */
    while (avail > 1) {
        int got;
        got = read(mon->fd,
                   mon->buffer + mon->bufferOffset,
                   avail - 1);
        if (got < 0) {
            if (errno == EAGAIN)
                break;
            virReportSystemError(errno, "%s",
                                 _("Unable to read from monitor"));
            ret = -1;
            break;
        }
        if (got == 0)
            break;

        ret += got;
        avail -= got;
        mon->bufferOffset += got;
        mon->buffer[mon->bufferOffset] = '\0';
    }

    return ret;
}
```

可以看到，其会调用[**qemuMonitorIORead()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor.c#L370)从**qemu monitor**的socket中读取**qmp**命令的返回结果，并调用[**qemuMonitorIOProcess()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor.c#L266)进行处理

```c
/* This method processes data that has been received
 * from the monitor. Looking for async events and
 * replies/errors.
 */
static int
qemuMonitorIOProcess(qemuMonitor *mon)
{
    int len;
    qemuMonitorMessage *msg = NULL;

    /* See if there's a message & whether its ready for its reply
     * ie whether its completed writing all its data */
    if (mon->msg && mon->msg->txOffset == mon->msg->txLength)
        msg = mon->msg;


    PROBE_QUIET(QEMU_MONITOR_IO_PROCESS, "mon=%p buf=%s len=%zu",
                mon, mon->buffer, mon->bufferOffset);

    len = qemuMonitorJSONIOProcess(mon,
                                   mon->buffer, mon->bufferOffset,
                                   msg);
    if (len < 0)
        return -1;

    if (len && mon->waitGreeting)
        mon->waitGreeting = false;

    if (len < mon->bufferOffset) {
        memmove(mon->buffer, mon->buffer + len, mon->bufferOffset - len);
        mon->bufferOffset -= len;
    } else {
        VIR_FREE(mon->buffer);
        mon->bufferOffset = mon->bufferLength = 0;
    }
    /* As the monitor mutex was unlocked in qemuMonitorJSONIOProcess()
     * while dealing with qemu event, mon->msg could be changed which
     * means the above 'msg' may be invalid, thus we use 'mon->msg' here */
    if (mon->msg && mon->msg->finished)
        virCondBroadcast(&mon->notify);
    return len;
}

int qemuMonitorJSONIOProcess(qemuMonitor *mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessage *msg)
{
    int used = 0;
    /*VIR_DEBUG("Data %d bytes [%s]", len, data);*/

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            g_autofree char *line = g_strndup(data + used, got);

            used += got + strlen(LINE_ENDING);
            line[got] = '\0'; /* kill \n */
            if (qemuMonitorJSONIOProcessLine(mon, line, msg) < 0)
                return -1;
        } else {
            break;
        }
    }

    return used;
}

int
qemuMonitorJSONIOProcessLine(qemuMonitor *mon,
                             const char *line,
                             qemuMonitorMessage *msg)
{
    g_autoptr(virJSONValue) obj = NULL;

    VIR_DEBUG("Line [%s]", line);

    if (!(obj = virJSONValueFromString(line)))
        return -1;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%1$s' isn't an object"), line);
        return -1;
    }

    if (virJSONValueObjectHasKey(obj, "QMP")) {
        return 0;
    } else if (virJSONValueObjectHasKey(obj, "event")) {
        PROBE(QEMU_MONITOR_RECV_EVENT,
              "mon=%p event=%s", mon, line);
        return qemuMonitorJSONIOProcessEvent(mon, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") ||
               virJSONValueObjectHasKey(obj, "return")) {
        PROBE(QEMU_MONITOR_RECV_REPLY,
              "mon=%p reply=%s", mon, line);
        if (msg) {
            msg->rxObject = g_steal_pointer(&obj);
            msg->finished = 1;
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected JSON reply '%1$s'"), line);
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown JSON reply '%1$s'"), line);
    }

    return -1;
}

static int
qemuMonitorJSONIOProcessEvent(qemuMonitor *mon,
                              virJSONValue *obj)
{
    const char *type;
    qemuEventHandler *handler;
    virJSONValue *data;
    g_autofree char *details = NULL;
    virJSONValue *timestamp;
    long long seconds = -1;
    unsigned int micros = 0;

    VIR_DEBUG("mon=%p obj=%p", mon, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }
    ...
    qemuMonitorEmitEvent(mon, type, seconds, micros, details);

    handler = bsearch(type, eventHandlers, G_N_ELEMENTS(eventHandlers),
                      sizeof(eventHandlers[0]), qemuMonitorEventCompare);
    if (handler) {
        VIR_DEBUG("handle %s handler=%p data=%p", type,
                  handler->handler, data);
        (handler->handler)(mon, data);
    }
    return 0;
}
```

可以看到，**libvirtd**会调用[**qemuMonitorJSONIOProcessLine()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor_json.c#L185)将字符串形式的返回值解析成json格式，并根据返回结果的类型进行处理：例如event类型的返回结果则会调用[**qemuMonitorJSONIOProcessEvent()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor_json.c#L143)进行处理，其会调用[**monitorCallbacks**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_process.c#L1796)中对应的callback和[**eventHandlers**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/qemu/qemu_monitor_json.c#L94)中对应的handler进行处理。再完成处理后，最后调用[**virCondBroadcast()**](https://github.com/libvirt/libvirt/blob/c63bdd17b9f5c31a2511f173d60455b83d22c561/src/util/virthread.c#L198)唤醒发送**qmp**命令的任务，从而最终完成异步命令的处理

```c
int
qemuMonitorSend(qemuMonitor *mon,
                qemuMonitorMessage *msg)
{
    ...
    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    PROBE(QEMU_MONITOR_SEND_MSG,
          "mon=%p msg=%s fd=%d",
          mon, mon->msg->txBuffer, mon->msg->txFD);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to wait on monitor condition (vm='%1$s')"), mon->domainName);
            goto cleanup;
        }
    }

    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s mon=%p vm=%p name=%s",
                  NULLSTR(mon->lastError.message), mon, mon->vm, mon->domainName);
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}
```

## ~~事件处理~~

# 参考

1. [Daemon and Remote Access](https://libvirt.org/api.html#daemon-and-remote-access)
2. [Implementing a new API in Libvirt](https://libvirt.org/api_extension.html)
3. [libvirt RPC infrastructure](https://libvirt.org/kbase/internals/rpc.html)
4. [如何为 libvirt 新增一个 virsh 命令](https://tinylab.org/libvirt-new-cmd/)
6. [Documentation/QMP](https://wiki.qemu.org/Documentation/QMP)
7. [QEMU event handlers](https://libvirt.org/kbase/internals/qemu-event-handlers.html)
8. [Libvirt同步机制 —— 设计原理](https://blog.csdn.net/huang987246510/article/details/124180508)
9. [QEMU Driver Threading: The Rules](https://libvirt.org/kbase/internals/qemu-threads.html)
