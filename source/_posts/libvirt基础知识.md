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

# ~~rpc~~

# ~~hypervisor~~

# 参考

1. [Daemon and Remote Access](https://libvirt.org/api.html#daemon-and-remote-access)
2. [Implementing a new API in Libvirt](https://libvirt.org/api_extension.html)
