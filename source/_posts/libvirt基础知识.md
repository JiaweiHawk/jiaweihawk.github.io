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

# ~~hypervisor~~

# 参考

1. [Daemon and Remote Access](https://libvirt.org/api.html#daemon-and-remote-access)
2. [Implementing a new API in Libvirt](https://libvirt.org/api_extension.html)
3. [libvirt RPC infrastructure](https://libvirt.org/kbase/internals/rpc.html)
4. [如何为 libvirt 新增一个 virsh 命令](https://tinylab.org/libvirt-new-cmd/)
