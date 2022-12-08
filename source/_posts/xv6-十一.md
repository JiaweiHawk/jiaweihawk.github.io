---
title: xv6-十一
date: 2022-10-22 09:14:34
tags: ['手写', '内核']
categories: ['手写']
---

# 前言

这篇博客研究**xv6**的**设备驱动**机制

# Lab networking

本次[lab](https://pdos.csail.mit.edu/6.828/2020/labs/net.html)用来实现**xv6**的**E1000(Network Interfact Card)**的**设备驱动**

## 要求

> You'll use a network device called the E1000 to handle network communication. To xv6 (and the driver you write), the E1000 looks like a real piece of hardware connected to a real Ethernet local area network (LAN). In fact, the E1000 your driver will talk to is an emulation provided by qemu, connected to a LAN that is also emulated by qemu. On this emulated LAN, xv6 (the "guest") has an IP address of 10.0.2.15. Qemu also arranges for the computer running qemu to appear on the LAN with IP address 10.0.2.2. When xv6 uses the E1000 to send a packet to 10.0.2.2, qemu delivers the packet to the appropriate application on the (real) computer on which you're running qemu (the "host").
>
> Your job is to complete **e1000_transmit()** and **e1000_recv()**, both in **kernel/e1000.c**, so that the driver can transmit and receive packets. You are done when **make grade** says your solution passes all the tests.
>
> The **e1000_init()** function we provide you in **e1000.c** configures the E1000 to read packets to be transmitted from RAM, and to write received packets to RAM. This technique is called DMA, for direct memory access, referring to the fact that the E1000 hardware directly writes and reads packets to/from RAM.
>
> Because bursts of packets might arrive faster than the driver can process them, **e1000_init()** provides the E1000 with multiple buffers into which the E1000 can write packets. The E1000 requires these buffers to be described by an array of "descriptors" in RAM; each descriptor contains an address in RAM where the E1000 can write a received packet. **struct rx_desc** describes the descriptor format. The array of descriptors is called the receive ring, or receive queue. It's a circular ring in the sense that when the card or driver reaches the end of the array, it wraps back to the beginning. **e1000_init()** allocates **mbuf** packet buffers for the E1000 to DMA into, using **mbufalloc()**. There is also a transmit ring into which the driver places packets it wants the E1000 to send. **e1000_init()** configures the two rings to have size **RX_RING_SIZE** and **TX_RING_SIZE**.
>
> When the network stack in **net.c** needs to send a packet, it calls **e1000_transmit()** with an mbuf that holds the packet to be sent. Your transmit code must place a pointer to the packet data in a descriptor in the TX (transmit) ring. **struct tx_desc** describes the descriptor format. You will need to ensure that each mbuf is eventually freed, but only after the E1000 has finished transmitting the packet (the E1000 sets the **E1000_TXD_STAT_DD** bit in the descriptor to indicate this).
>
> When the E1000 receives each packet from the ethernet, it first DMAs the packet to the mbuf pointed to by the next RX (receive) ring descriptor, and then generates an interrupt. Your **e1000_recv()** code must scan the RX ring and deliver each new packet's mbuf to the network stack (in **net.c**) by calling **net_rx()**. You will then need to allocate a new mbuf and place it into the descriptor, so that when the E1000 reaches that point in the RX ring again it finds a fresh buffer into which to DMA a new packet.
>
> In addition to reading and writing the descriptor rings in RAM, your driver will need to interact with the E1000 through its memory-mapped control registers, to detect when received packets are available and to inform the E1000 that the driver has filled in some TX descriptors with packets to send. The global variable **regs** holds a pointer to the E1000's first control register; your driver can get at the other registers by indexing **regs** as an array. You'll need to use indices **E1000_RDT** and **E1000_TDT** in particular.

## 分析

## 实现

## 结果

执行如下命令，完成实验测试
```bash
make grade
```
![networking实验结果](networking实验结果.png)