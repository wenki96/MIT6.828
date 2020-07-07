
```
running JOS: (1.2s)
  Physical page allocator: OK
  Page management: OK
  Kernel page directory: OK
  Page management 2: OK
Score: 70/70
```



# Exercize 1

完成 kern/kmap.c 文件中的下面几个函数，可以使用 `check_page_free_list()和check_page_alloc()`函数检查内存分配是否成功：

```c
boot_alloc()
mem_init() (only up to the call to check_page_free_list(1))
page_init()
page_alloc()
page_free()
```



首先观察一下pmap.c中的代码，其中最重要的函数就是mem_init()了，在内核刚开始运行时就会调用这个子函数，对整个操作系统的内存管理系统进行一些初始化的设置，比如设定页表等等操作。

下面进入这个函数，首先这个函数调用 i386_detect_memory 子函数，这个子函数的功能就是检测现在系统中有多少可用的内存空间。

jos把整个物理内存空间划分成三个部分：

```
0x00000~0xA0000，这部分也叫basemem，是可用的。

0xA0000~0x100000，这部分叫做IO hole，是不可用的，主要被用来分配给外部设备了。

0x100000~0x，这部分叫做extmem，是可用的，这是最重要的内存区域。
```

这个子函数中包括三个变量，其中npages记录整个内存的页数，npages_basemem记录basemem的页数，npages_extmem记录extmem的页数。

```c
kern_pgdir = (pde_t *) boot_alloc(PGSIZE);
memset(kern_pgdir, 0, PGSIZE);
```

其中kern_pgdir是一个指针，pde_t *kern_pgdir，它是指向操作系统的页目录表的指针，操作系统之后工作在虚拟内存模式下时，就需要这个页目录表进行地址转换。我们为这个页目录表分配的内存大小空间为PGSIZE，即一个页的大小。并且首先把这部分内存清0。

------

### boot_alloc

其中boot_alloc只在JOS建立虚拟内存系统的时候使用，后续的内存分配用的是page_alloc()函数。需要注意的是这里只是将可以使用的空闲内存地址返回，并没有真正的操作物理内存。

```c
static void *
boot_alloc(uint32_t n)
{
    static char *nextfree;	// virtual address of next byte of free memory
	char *result;

	if (!nextfree) {
		extern char end[];
		nextfree = ROUNDUP((char *) end, PGSIZE);
	}
	
    //LAB 2: Your code here.
	result = nextfree;
	if(n != 0) nextfree = ROUNDUP((char *)(nextfree+n), PGSIZE);
	if((uint32_t)nextfree - KERNBASE > (npages*PGSIZE)) panic("Out of memory!\n");

	return result;
}
```

所以这条kern_pgdir = (pde_t *) boot_alloc(PGSIZE);指令就会分配一个页的内存，并且这个页就是紧跟着操作系统内核之后。

------

```c
kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;
```

这一条指令就是再为页目录表添加第一个页目录表项。通过查看memlayout.h文件，我们可以看到，UVPT的定义是一段虚拟地址的起始地址，0xef400000，从这个虚拟地址开始，存放的就是这个操作系统的页表，所以我们必须把它和页表的物理地址映射起来，PADDR(kern_pgdir)就是在计算kern_pgdir所对应的真实物理地址。

```c
// 线性地址分为如下三部分
// +--------10------+-------10-------+---------12----------+
// | Page Directory |   Page Table   | Offset within Page  |
// |      Index     |      Index     |                     |
// +----------------+----------------+---------------------+
//  \--- PDX(la) --/ \--- PTX(la) --/ \---- PGOFF(la) ----/
//  \---------- PGNUM(la) ----------/
//

// 页目录和页表的一些常量定义
#define NPDENTRIES  1024   //每个页目录的页目录项数目为1024
#define NPTENTRIES  1024   //每个页表的页表项数目也为1024

#define PGSIZE      4096   // 页大小为4096B，即4KB
#define PGSHIFT     12      // log2(PGSIZE)

#define PTSIZE      (PGSIZE*NPTENTRIES) // 一个页目录项映射内存大小，4MB
#define PTSHIFT     22      // log2(PTSIZE)

#define PTXSHIFT    12       
#define PDXSHIFT    22  

// 页号
#define PGNUM(la)   (((uintptr_t) (la)) >> PTXSHIFT)

// 页目录项索引(高10位)
#define PDX(la)     ((((uintptr_t) (la)) >> PDXSHIFT) & 0x3FF)

// 页表项索引（中间10位）
#define PTX(la)     ((((uintptr_t) (la)) >> PTXSHIFT) & 0x3FF)

// 页内偏移
#define PGOFF(la)   (((uintptr_t) (la)) & 0xFFF)

// 由索引构造线性地址
#define PGADDR(d, t, o) ((void*) ((d) << PDXSHIFT | (t) << PTXSHIFT | (o)))
```

------

### mem_init

注释掉那行panic代码，加入pages的初始化代码:

```c
// panic("mem_init: This function is not finished\n");
pages = (struct PageInfo *) boot_alloc(npages * sizeof(struct PageInfo));
memset(pages, 0, npages * sizeof(struct PageInfo));
```

------

### page_init

可以到这个函数的定义处具体查看，整个函数是由一个for循环构成，它会遍历所有内存页所对应的在npages数组中的PageInfo结构体，并且根据这个页当前的状态来修改这个结构体的状态，如果页已被占用，那么要把PageInfo结构体中的pp_ref属性置一；如果是空闲页，则要把这个页送入pages_free_list链表中。根据注释中的提示，第0页已被占用，io hole部分已被占用，还有在extmem区域还有一部分已经被占用，代码如下：

```c
void
page_init(void)
{
	size_t i;
	int num_alloc = ((uint32_t)boot_alloc(0) - KERNBASE) / PGSIZE; //Pages used in extended memory
	int num_iohole = 96; //io hole
	for (i = 0; i < npages; i++) { 
		if(i == 0) pages[i].pp_ref = 1; //Do not use page 0
		else if(i >= npages_basemem && i < npages_basemem+num_iohole+num_alloc) pages[i].pp_ref = 1;
		else{
			pages[i].pp_ref = 0;
			pages[i].pp_link = page_free_list;
			page_free_list = &pages[i];
		}
	}
}
```

------

初始化关于所有物理内存页的相关数据结构后，进入check_page_free_list(1)子函数，这个函数的功能就是检查page_free_list链表的所谓空闲页，是否真的都是合法的，空闲的。当输入参数为1时，这个函数要在检查前先进行一步额外的操作，对空闲页链表free_page_list进行修改，经过page_init，free_page_list中已经存放了所有的空闲页表，但是他们的顺序是按照页表的编号从大到小排列的。

当前操作系统所采用的页目录表entry_pgdir（不是kern_pgdir）中，并没有对大编号的页表进行映射，所以这部分页表我们还不能操作。但是小编号的页表，即从0号页表开始到1023号页表，已经映射过了，所以可以对这部分页表进行操作。那么check_page_free_list(1)要完成的就是把这部分页表对应的PageInfo结构体移动到free_page_list的前端，供操作系统现在使用。

------

### page_alloc

从空闲链表取第一个，并更新链表头指向下一个空闲位置，如果指定了alloc_flag，则将PageInfo结构对应的那4KB内存区域清零(用page2kva(page)可以得到对应页面的虚拟地址):

```c
struct PageInfo *
page_alloc(int alloc_flags)
{
	struct PageInfo *result;
	if(!page_free_list) return NULL;

	result = page_free_list;
	page_free_list = result->pp_link;
	result->pp_link = NULL;

	if(alloc_flags & ALLOC_ZERO) memset(page2kva(result), 0, PGSIZE);

	return result;
}
```

### page_free

释放对应页面，将该页面对应的PageInfo项加入page_free_list链表头部。

```c
void
page_free(struct PageInfo *pp)
{
	assert(pp->pp_ref == 0 && pp->pp_link == NULL);
	pp->pp_link = page_free_list;
	page_free_list = pp;
}
```

# Exercize 2

熟悉80386手册的第5，6章，熟悉分页和分段机制以及基于页的保护机制，见https://www.jianshu.com/p/752b7735a65b。

# Exercize 3

熟悉qemu的调试命令，使用 `CTRL+a+c` 进入monitor模式，可以输入命令 `info pg`查看页表项，使用`info mem`查看内存概要，使用 `xp /Nx paddr` 查看物理地址处的内容，与 gdb 的 `p /Nx vaddr` 可以验证对应地址的数据是否一致。

# Exercize 4

前面我们只是完成了页表管理的结构如空闲链表page_free_list和页表数组pages的初始化，现在需要加入页表管理的函数。

### pgdir_walk

根据虚拟地址va找到对应的页表项地址。如果指定了create标志，则如果物理页不存在的时候分配新的页，并设置页目录项的值为新分配页的物理地址。

```c
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
	int pde_index = PDX(va);
    int pte_index = PTX(va);
    pde_t *pde = &pgdir[pde_index];
    if (!(*pde & PTE_P)) {
        if (create) {
            struct PageInfo *page = page_alloc(ALLOC_ZERO);
            if (!page) return NULL;
            page->pp_ref++;
            *pde = page2pa(page) | PTE_P | PTE_U | PTE_W;
        } else {
            return NULL;
        }   
    }   

    pte_t *p = (pte_t *) KADDR(PTE_ADDR(*pde));
    return &p[pte_index];
}
```

### boot_map_region

映射虚拟地址va到物理地址pa，映射大小为size，所做操作就是找到对应的页表项地址，设置页表项的值为物理地址pa(pa是4KB对齐的，对应该页的首地址)。用到上一个函数pgdir_walk找虚拟地址对应的页表项地址。

这个函数主要的目的是为了设置虚拟地址UTOP之上的地址范围，这一部分的地址映射是静态的，在操作系统的运行过程中不会改变，所以这个页的PageInfo结构体中的pp_ref域的值不会发生改变。

```c
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
	int pages = PGNUM(size);
    for (int i = 0; i < pages; i++) {
        pte_t *pte = pgdir_walk(pgdir, (void *)va, 1);
        if (!pte) panic("boot_map_region panic: out of memory");
        *pte = pa | perm | PTE_P;
        va += PGSIZE, pa += PGSIZE;
    }
}
```

### page_insert

映射虚拟地址va到pp对应的物理页。如果之前该虚拟地址已经存在映射，则要先移除原来的映射。注意pp_ref++要在page_remove之前执行，不然在page_remove会导致pp_ref减到0从而page_free该页面，该页面后续会被重新分配使用而报错。

```c
int
page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
{
	pte_t *pte = pgdir_walk(pgdir, va, 1);
	if(!pte) return -E_NO_MEM;

	pp->pp_ref++; //increase first to invoid pp_ref become 0 when page_remove
	if(*pte & PTE_P) page_remove(pgdir, va);
	*pte = page2pa(pp) | perm | PTE_P;

	return 0;
}
```

### page_lookup

查找虚拟地址va对应的页表项，并返回页表项对应的PageInfo结构。

```c
struct PageInfo *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
	pte_t *pte = pgdir_walk(pgdir, va, 0);
	if(!pte || !(*pte & PTE_P)) return NULL;
	struct PageInfo *ret = pa2page(PTE_ADDR(*pte));
	if(pte_store != NULL) *pte_store = pte;
	return ret;
}
```

### page_remove

从页表中移除虚拟地址va对应的物理页映射。需要将PageInfo的引用pp_ref减1，并设置对应页表项的值为0，最后调用tlb_invalidate使tlb中该页缓存失效。

```c
void
page_remove(pde_t *pgdir, void *va)
{
	pte_t *pte;
	struct PageInfo *page = page_lookup(pgdir, va, &pte);
	if(!page || !(*pte & PTE_P)) return;
	*pte = 0;
	page_decref(page);
	tlb_invalidate(pgdir, va);
}
```

# Exercize 5

映射 UPAGES, KSTACK, KERNBASE等虚拟地址空间到物理内存。注意一点就是KSTACK映射的bootstack是在内核里面分配好的，所以它在物理内存地址要在 UPAGES 映射的物理地址pages 之前的一段区域。

```c
boot_map_region(kern_pgdir, UPAGES, PTSIZE, PADDR(pages), PTE_U);
boot_map_region(kern_pgdir, KSTACKTOP-KSTKSIZE, KSTKSIZE, PADDR(bootstack), PTE_W);
boot_map_region(kern_pgdir, KERNBASE, 0XFFFFFFFF-KERNBASE, 0, PTE_W);
```

# Questions

## Question 1

假定下面代码运行正确，那么变量x的类型应该是 uintptr_t 还是 physaddr_t?

```
	mystery_t x;
	char* value = return_a_pointer();
	*value = 10;
	x = (mystery_t) value;
```

在代码中我们操作的都是虚拟地址，因此x类型应该是 uintptr_t。

## Question 2

哪些页目录已经被填充好，它们的地址映射是怎么样的？基本就是 Exercize 5 中做的地址映射。

## Question 3

我们将用户和内核环境放在了同一个地址空间，如何保证用户程序不能读取内核的内存？

内核空间内存的页表项的perm没有设置PTE_U，需要CPL为0-2才可以访问。而用户程序的CPL为3，因为权限不够用户程序读取内核内存时会报错。

## Question 4

JOS最大可以支持多大的物理内存，为什么？

2GB，因为 UPAGES 大小最大为4MB，而每个PageInfo大小为8B，所以可以最多可以存储512K个PageInfo结构体，而每个PageInfo对应4KB内存，所以最多 512K*4K = 2G内存。

## Quesiton 5

如果我们真有这么多物理内存，用于管理内存额外消耗的内存空间有多大？

如果有2GB内存，则物理页有512K个，每个PageInfo结构占用8字节，则一共是4MB。每个物理需要对应一个页表项，每个页表项为4B，所以总的页表大小为`4B*512K=2MB`，对应为512个页表，可以全部放在一个页表目录下，页表目录大小为4K，所以共为`6MB+4K`。

如果仅从当前情况来看，需要分配的页表项的个数与目前需要映射的物理块数直接相关，当前映射了三块区域，共为`4K+8*4K+256M`，共`1+4+64K`个页表项，但由于这些区域是分隔的，而只要页表用有一项不为空就要分配整个页表，每个页表项为4字节，一个页表为4K个字节，共需要`4K+4K+64K*4=264K`个字节，所以额外消耗的内存为 `4MB + 264K + 4KB`。

## Question 6

EIP什么时候开始从低地址空间(1M多一点)的地方跳转到高地址（KERNBASE之上）运行的，为什么这一步是正常的而且是必要的？

从 kern/entry.S 中的 `jmp *%eax`语句之后就开始跳转到高地址运行了。因为在entry.S中我们的cr3加载的是entry_pgdir，它将虚拟地址 [0, 4M)和[KERNBASE, KERNBASE+4M)都映射到了物理地址 [0, 4M)，所以能保证正常运行。

而在我们新的kern_pgdir加载后，并没有映射低位的虚拟地址 [0, 4M)，所以这一步跳转是必要的。

# Challenge

*Challenge!* Extend the JOS kernel monitor with commands to:

- Display in a useful and easy-to-read format all of the physical page mappings (or lack thereof) that apply to a particular range of virtual/linear addresses in the currently active address space. For example, you might enter `'showmappings 0x3000 0x5000'` to display the physical page mappings and corresponding permission bits that apply to the pages at virtual addresses 0x3000, 0x4000, and 0x5000.
- Explicitly set, clear, or change the permissions of any mapping in the current address space.
- Dump the contents of a range of memory given either a virtual or physical address range. Be sure the dump code behaves correctly when the range extends across page boundaries!
- Do anything else that you think might be useful later for debugging the kernel. (There's a good chance it will be!)

```c
//kern/monitor.c

uint32_t xtoi(char* buf) {
	uint32_t res = 0;
	buf += 2; //0x...
	while (*buf) { 
		if (*buf >= 'a') *buf = *buf-'a'+'0'+10;//aha
		res = res*16 + *buf - '0';
		++buf;
	}
	return res;
}

void pprint(pte_t *pte) {
	cprintf("PTE_P: %x, PTE_W: %x, PTE_U: %x\n", 
		*pte&PTE_P, *pte&PTE_W, *pte&PTE_U);
}

int showmappings(int argc, char **argv, struct Trapframe *tf)
{
	if (argc == 1) {
		cprintf("Usage: showmappings 0xbegin_addr 0xend_addr\n");
		return 0;
	}
	uint32_t begin = xtoi(argv[1]), end = xtoi(argv[2]);
	cprintf("begin: %x, end: %x\n", begin, end);
	for (; begin <= end; begin += PGSIZE) {
		pte_t *pte = pgdir_walk(kern_pgdir, (void *) begin, 1);	//create
		if (!pte) panic("boot_map_region panic, out of memory");
		if (*pte & PTE_P) {
			cprintf("page %x with ", begin);
			pprint(pte);
		} else cprintf("page not exist: %x\n", begin);
	}
	return 0;
}

int setm(int argc, char **argv, struct Trapframe *tf) {
	if (argc == 1) {
		cprintf("Usage: setm 0xaddr [0|1 :clear or set] [P|W|U]\n");
		return 0;
	}
	uint32_t addr = xtoi(argv[1]);
	pte_t *pte = pgdir_walk(kern_pgdir, (void *)addr, 1);
	cprintf("%x before setm: ", addr);
	pprint(pte);
	uint32_t perm = 0;
	if (argv[3][0] == 'P') perm = PTE_P;
	if (argv[3][0] == 'W') perm = PTE_W;
	if (argv[3][0] == 'U') perm = PTE_U;
	if (argv[2][0] == '0') 	//clear
		*pte = *pte & ~perm;
	else 	//set
		*pte = *pte | perm;
	cprintf("%x after  setm: ", addr);
	pprint(pte);
	return 0;
}

int showvm(int argc, char **argv, struct Trapframe *tf) {
	if (argc == 1) {
		cprintf("Usage: showvm 0xaddr 0xn\n");
		return 0;
	}
	void** addr = (void**) xtoi(argv[1]);
	uint32_t n = xtoi(argv[2]);
	int i;
	for (i = 0; i < n; ++i)
		cprintf("VM at %x is %x\n", addr+i, addr[i]);
	return 0;
}
```

# 参考资料

- [https://www.cnblogs.com/fatsheep9146/category/769143.html](https://www.cnblogs.com/fatsheep9146/category/769143.html)
- [https://github.com/shishujuan/mit6.828-2017/blob/master/docs/lab2-exercize.md](https://github.com/shishujuan/mit6.828-2017/blob/master/docs/lab2-exercize.md)
- [https://github.com/Clann24/jos/tree/master/lab2](https://github.com/Clann24/jos/tree/master/lab2)
