```c
divzero: OK (2.0s) 
softint: OK (1.9s) 
badsegment: OK (1.9s) 
Part A score: 30/30

faultread: OK (2.1s) 
faultreadkernel: OK (1.9s) 
faultwrite: OK (1.4s) 
faultwritekernel: OK (1.6s) 
breakpoint: OK (1.9s) 
testbss: OK (1.4s) 
hello: OK (1.6s) 
buggyhello: OK (2.0s) 
    (Old jos.out.buggyhello failure log removed)
buggyhello2: OK (1.9s) 
    (Old jos.out.buggyhello2 failure log removed)
evilhello: OK (1.4s) 
    (Old jos.out.evilhello failure log removed)
Part B score: 50/50

Score: 80/80
```



# Exercize 1

进程管理结构envs对应的1024个Env结构体在物理内存中紧接着pages存储。

给NENV个Env结构体在内存中分配空间，并将 envs 结构体的物理地址映射到 从 UENV 所指向的线性地址空间，该线性地址空间允许用户访问且只读，所以页面权限被标记为PTE_U。

```c
envs = (struct Env *)boot_alloc(sizeof(struct Env) * NENV);
memset(envs, 0, sizeof(struct Env) * NENV);
 

boot_map_region(kern_pgdir, UENVS, PTSIZE, PADDR(envs), PTE_U);
```

# Exercize 2

需要完成 env_init(), env_setup_vm(), region_alloc(), load_icode(), env_create(), env_run() 这几个函数。

- 调用`env_init`函数初始化envs，将 NENV 个进程管理结构Env通过env_link串联起来，注意，env_free_list要指向第一个 Env，所以这里要用倒序的方式。在`env_init`函数中调用了`env_init_percpu`函数，加载新的全局描述符表，设置内核用到的寄存器 es, ds, ss的值为GD_KD，即内核的段选择子，DPL为0。然后通过ljmp指令`asm volatile("ljmp %0,$1f\n 1:\n" : : "i" (GD_KT));`设置CS为 GD_KT。这句汇编用到了`unnamed local labels`，含义就是跳转到 `GD_KT, 1:`这个地址处，其中的 `$1f`的意思是指跳转到后一个`1:`标签处，如果是前一个，用`$1b`，而这个后一个`1:`标签就是语句后面，所以最终效果只是设置了CS寄存器的值为GD_KT而已。
- 初始化好了envs和env_free_list后，接着调用 `ENV_CREATE(user_hello, ENV_TYPE_USER)``ENV_CREATE``kern/env.h``env_create``env_create(_binary_obj_user_hello_start, ENV_TYPE_USER)``env_alloc``load_icode`
  - env_alloc调用env_setup_vm函数分配好页目录的页表，并设置页目录项和env_pgdir字段)。
  -  `load_icode`函数则是**先设置cr3寄存器切换到该进程的页目录env_pgdir**，然后通过`region_alloc`分配每个程序段的内存并按segment将代码加载到对应内存中，加载完成后设置 env_tf->tf_eip为Elf的e_entry，即程序的初始执行位置。
- 加载完程序代码后，万事俱备，调用 `env_run(e)` 函数开始运行程序。如果当前有进程正在运行，则设置当前进程状态为`ENV_RUNNABLE`，并将需要运行的进程e的状态设置为`ENV_RUNNING`，**然后加载e的页目录表地址 env_pgdir 到cr3寄存器中**，调用 `env_pop_tf(struct Trapframe *tf)` 开始执行程序e。
- env_pop_tf其实就是将栈指针esp指向该进程的env_tf，然后将 env_tf 中存储的寄存器的值弹出到对应寄存器中，最后通过 iret 指令弹出栈中的元素分别到 EIP, CS, EFLAGS 到对应寄存器并跳转到 `CS:EIP` 存储的地址执行(当使用iret指令返回到一个不同特权级运行时，还会弹出堆栈段选择子及堆栈指针分别到SS与SP寄存器)，这样，相关寄存器都从内核设置成了用户程序对应的值，EIP存储的是程序入口地址。
- env_id的生成规则很有意思，注意一下在env_free中并没有重置env_id的值，这就是为了用来下一次使用这个env结构体时生成一个新的env_id，区分之前用过的env_id，从generation的生成方式就能明白了。

### env_init()
如在用户环境的分析中提到，env_init()主要负责初始化 `struct Env`的空闲链表，跟上一章的pages空闲链表类似，注意初始化顺序。

```c
void
env_init(void)
{
    // Set up envs array
    // LAB 3: Your code here.
	env_free_list = NULL;
	for(int i=NENV-1; i>=0; i--){
		envs[i].env_id = 0;
		envs[i].env_status = ENV_FREE;
		envs[i].env_link = env_free_list;
		env_free_list = &envs[i];
	}

    // Per-CPU part of the initialization
    env_init_percpu();
}

```

### env_setup_vm()
这个函数主要功能是分配好页目录，并设置运行进程的 env_pgdir 字段，注意，env_pgdir是虚拟地址。不要忘记将 p->pp_ref++， 因为在env_free()的时候会decref的。所有的进程在UTOP之上的页目录表(除了UVPT之外)都跟kernel是一样的，所以可以直接用memcpy将kern_pgdir的页目录表内容拷贝过来，然后单独设置UVPT这个页目录项即可。

```c
static int
env_setup_vm(struct Env *e)
{
	...
    // LAB 3: Your code here.
    e->env_pgdir = (pde_t *)page2kva(p);
	p->pp_ref++;

	for(int i=0; i<PDX(UTOP); i++) e->env_pgdir[i] = 0; //initial VA below UTOP
	for(int i=PDX(UTOP); i<NPDENTRIES; i++) e->env_pgdir[i] = kern_pgdir[i]; //above
    //memcpy(e->env_pgdir, kern_pgdir, PGSIZE); is better

	// UVPT maps the env's own page table read-only.
	// Permissions: kernel R, user R
	e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;

    return 0;
}
```

### region_alloc()
为用户程序分配和映射内存，该函数只在load_icode()中调用，需要注意边界条件。

```c
static void
region_alloc(struct Env *e, void *va, size_t len)
{
	void *start = (void *)ROUNDDOWN((uint32_t)va, PGSIZE);
	void *end = (void *)ROUNDUP((uint32_t)va+len, PGSIZE);
	for(void *i = start; i<end; i+=PGSIZE){
		struct PageInfo *p = page_alloc(0);
		if(!p) panic("region alloc failed\n");
		int r = page_insert(e->env_pgdir, p, i, PTE_W|PTE_U);
		if(r) panic("region alloc page table error\n");
    }   
}
```

### load_icode()
加载用户程序二进制代码。该函数会设置进程的tf_eip值为 elf->e_entry，并分配映射用户栈内存。注意，在调用 `region_alloc` 分配映射内存前，需要先设置cr3寄存器内容为进程的页目录物理地址，设置完成后再设回 kern_pgdir的物理地址。

```c
static void
load_icode(struct Env *e, uint8_t *binary)
{
	struct Proghdr *ph, *eph;
	struct Elf *ELFHDR = (struct Elf *)binary;

	// is this a valid ELF?
	if(ELFHDR->e_magic != ELF_MAGIC) 
		panic("load icode error : file is not elf\n");

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;

	//above is same in main.c

	lcr3(PADDR(e->env_pgdir)); //use environment's own pgdir

	for (; ph < eph; ph++)
		if (ph->p_type == ELF_PROG_LOAD) { //only load segments with ph->p_type == ELF_PROG_LOAD
			region_alloc(e, (void *)ph->p_va, ph->p_memsz);
			memset((void *)ph->p_va, 0, ph->p_memsz);
			memcpy((void *)ph->p_va, binary+ph->p_offset, ph->p_filesz);
		}

	lcr3(PADDR(kern_pgdir));
	e->env_tf.tf_eip = ELFHDR->e_entry;

	// Now map one page for the program's initial stack
	// at virtual address USTACKTOP - PGSIZE.

	// LAB 3: Your code here.
	region_alloc(e, (void *)(USTACKTOP-PGSIZE), PGSIZE);
}
```

### env_create()
首先调用env_alloc分配 struct Env结构以及页目录，然后调用load_icode加载进程代码。

```c
void
env_create(uint8_t *binary, enum EnvType type)
{
	struct Env *e;
	env_alloc(&e, 0);
	load_icode(e, binary);
	e->env_type = type;
}
```

### env_run()
在用户模式运行用户进程。

```c
void
env_run(struct Env *e)
{
	if(curenv && e->env_status == ENV_RUNNING) e->env_status = ENV_RUNNABLE;
	curenv = e;
	e->env_status = ENV_RUNNING;
	e->env_runs++;
	lcr3(PADDR(e->env_pgdir));
	env_pop_tf(&e->env_tf);
}
```

做完exercize 2后，会发现提示`triple fault`，类似下面这样报错。这是因为用户程序`user/hello.c`中调用了 cprintf输出 `hello world`，会用到系统调用指令`int 0x30`。而此时系统并没有设置好中断向量表，当CPU收到系统调用中断时，发现没有处理程序可以处理，于是会报一个`general protection`异常，这就产生了`double fault exception`，而接着CPU发现它也没法处理`general protection`异常，于是报`triple fault`。通常，遇到这种情况CPU会复位系统会不断重启，为了方便调试内核，JOS用的QEMU打过补丁，从而没有不断重启，而是用一条`triple fault`的提示消息代替。

```
6828 decimal is 15254 octal!
Physical memory: 131072K available, base = 640K, extended = 130432K
boot_alloc, nextfree:f017e000
......
EAX=00000000 EBX=00000000 ECX=0000000d EDX=eebfde88
ESI=00000000 EDI=00000000 EBP=eebfde60 ESP=eebfde54
EIP=00800add EFL=00000092 [--S-A--] CPL=3 II=0 A20=1 SMM=0 HLT=0
ES =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
CS =001b 00000000 ffffffff 00cffa00 DPL=3 CS32 [-R-]
SS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
DS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
FS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
GS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
LDT=0000 00000000 00000000 00008200 DPL=0 LDT
TR =0028 f017da20 00000067 00408900 DPL=0 TSS32-avl
GDT=     f011b320 0000002f
IDT=     f017d200 000007ff
CR0=80050033 CR2=00000000 CR3=00044000 CR4=00000000
DR0=00000000 DR1=00000000 DR2=00000000 DR3=00000000 
DR6=ffff0ff0 DR7=00000400
EFER=0000000000000000
Triple fault.  Halting for inspection via QEMU monitor.
```

为了保证代码是正确的，最好在`make qemu-gdb`后 `b env_pop_tf`设置下断点，看看用户进程是否能运行到cmpl指令，并在obj/user/hello.asm内找到中断 指令`int $0x30`的地址处设断点，确定程序可以运行到此处。

```
The target architecture is assumed to be i8086
[f000:fff0]    0xffff0: ljmp   $0xf000,$0xe05b
0x0000fff0 in ?? ()
+ symbol-file obj/kern/kernel
(gdb) b env_pop_tf
Breakpoint 1 at 0xf0103b1d: file kern/env.c, line 471.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf0103b1d <env_pop_tf>:     push   %ebp

Breakpoint 1, env_pop_tf (tf=0xf01d1000) at kern/env.c:471
471     {
(gdb) s
=> 0xf0103b2f <env_pop_tf+18>:  mov    0x8(%ebp),%esp
472             asm volatile(
(gdb) si
=> 0xf0103b32 <env_pop_tf+21>:  popa
0xf0103b32      472             asm volatile(
(gdb)
=> 0xf0103b33 <env_pop_tf+22>:  pop    %es
0xf0103b33 in env_pop_tf (tf=<error reading variable: Unknown argument list address for `tf'.>) at kern/env.c:472
472             asm volatile(
(gdb)
=> 0xf0103b34 <env_pop_tf+23>:  pop    %ds
0xf0103b34      472             asm volatile(
(gdb)
=> 0xf0103b35 <env_pop_tf+24>:  add    $0x8,%esp
0xf0103b35      472             asm volatile(
(gdb)
=> 0xf0103b38 <env_pop_tf+27>:  iret
0xf0103b38      472             asm volatile(
(gdb)
=> 0x800020:    cmp    $0xeebfe000,%esp
0x00800020 in ?? ()
(gdb) b *0x800b44
Breakpoint 2 at 0x800b44
(gdb) c
Continuing.
=> 0x800b44:    int    $0x30

Breakpoint 2, 0x00800b44 in ?? ()
```

接下来我们来分析下到目前为止为了实现地址映射，我们用掉了free_page_list中哪些内存页以及对应的内存了。

- 在lab 2中我们为映射 [UPAGES, UPAGES+4M) 分配页表，用掉空闲链表free_page_list中的一页，其在内核页目录表表项为 `0xef000000 / 4M = 956`。
- 还有本实验为映射 [UENVS, UENVS + 4M) 分配页表，用掉一页内存，其页目录项为 `0xeec00000 / 4M = 955`。
- 此外，还有内核栈 [KSTACKTOP-KSTKSIZE, KSTACKTOP) 的映射，用掉一页内存，页目录项为 `efff8000 / 4M = 959`。
- 剩下就是对 [KERNBASE, 2**32-KERNBASE)映射，用掉64页内存，对应的页目录项为 `960-1023`。
- 到目前为止，除了用户进程占用的内存外，一共用掉了 1+1+1+64=67 页内存，用户进程使用内存大小跟程序大小有关。

由于检查代码会分配和释放页面，所以这里分配的页的顺序不一定是按数字顺序来的，因为释放的页面会被加入到free_page_list头部。这个我们可以进入系统来确认下是不是真的这样：

```
env:0 pgno:68 env_pgdir_addr:f01c005c,val:f0044000 kern_pgdir_addr:f017eea8,val:f017f000
```
从打印的内容可以知道内核页目录表位于虚拟地址 0xf017f000，物理地址 0x17f000处。接下来，我们从 0xf017f000处开始查看上面提到的页目录项的值，看看是否对应。先看第955和956项，可以看到955项分配了第2页内存，而956项分配了第3页内存。957项存储的是页目录地址 0x17f005(末位的5是一些标志位)，959项则是分配了第1页内存作为页表。从960项到1024则是用于的KERNBASE之上的映射。我们也可以看到用户进程页目录表项在UTOP之上跟内核页目录表是一样的，唯一例外是 UVPT对应的目录项，指向的是各自的的页目录地址。

看页目录项的标志位低3位是7，这是因为我们在`pgdir_walk()`中将页目录的权限设置的比较大，`*pde = page2pa(page) | PTE_P | PTE_U | PTE_W;`，因为x86的MMU会检查页目录项和页表项，所以页目录权限大一点是没问题的。

而我们也可以继续深入去看每个页表项的初始化情况，如我们想看下UPAGES映射的第3页的页表项，我们知道UPAGES映射到物理内存pages值 0x180000 处，查看内存数据为0x00180005，确认没错，其中页表项标志位5表示用户可读(PTE_P|PTE_U)。譬如[KSTACKTOP-KTSIZE, KSTACKTOP)的映射，它的页目录项为0x1007，在第一页。用命令看第一页对应的页表项可以看到页表项从`1016-1023`映射了8页。

注意，有些虚拟地址是映射到同一页物理内存的，只是映射的权限不同。比如 UPAGES 在我的测试环境 0xef000000 映射的物理内存页为0x180页(0x00180005，权限5是PTE_P|PTE_U)，而我们在[KERNBASE, 2**32-KERNBASE)区间的虚拟地址 0xf0004600 也是映射到物理内存 0x180页(0x00180063，末位标识3表示PTE_P|PTE_W）。

```
## 查看页目录项
(gdb) x /16x 0xf017fee0
0xf017fee0:	0x00000000	0x00000000	0x00000000	0x00002007
0xf017fef0:	0x00003007	0x0017f005	0x00000000	0x00001007
0xf017ff00:	0x00004027	0x00005027	0x00006027	0x00007027
0xf017ff10:	0x00008027	0x00009027	0x0000a027	0x0000b027

# KSTACKTOP-PGSIZE映射的8页
(gdb) x /8x 0xf0001fe0
0xf0001fe0:	0x00112003	0x00113003	0x00114003	0x00115003
0xf0001ff0:	0x00116003	0x00117003	0x00118003	0x00119003

## 查看UPAGES对应的页表项
(gdb) x /8x 0xf0003000
0xf0003000:	0x00180005	0x00181005	0x00182005	0x00183005
0xf0003010:	0x00184005	0x00185005	0x00186005	0x00187005

## KERNBASE上与UPAGES映射的同样的物理页
(gdb) x /4x 0xf0004600
0xf0004600:	0x00180063	0x00181023	0x00182023	0x00183023
```

# Exercize 3
学习异常和中断的理论知识。https://pdos.csail.mit.edu/6.828/2018/readings/i386/c09.htm。

# Exercize 4

完成中断向量表初始化以及异常/中断处理，需要修改 `kern/trapentry.S` 和 `kern/trap.c`文件。在 `trap_init()`中使用SETGATE来初始化中断向量，在`trapentry.S`中通过 `TRAPHANDLER`和`TRAPHANDLER_NOEC`初始化中断处理函数。

```c
void
trap_init(void)
{
    extern struct Segdesc gdt[];

    // LAB 3: Your code here.
    void handler0();
    void handler1();
    void handler2();
    void handler3();
    void handler4();
    void handler5();
    void handler6();
    void handler7();
    void handler8();
    void handler10();
    void handler11();
    void handler12();
    void handler13();
    void handler14();
    void handler15();
    void handler16();
    void handler48();

    SETGATE(idt[T_DIVIDE], 0, GD_KT, handler0, 0); 
    SETGATE(idt[T_DEBUG], 0, GD_KT, handler1, 0); 
    SETGATE(idt[T_NMI], 0, GD_KT, handler2, 0); 

    // T_BRKPT DPL 3
    SETGATE(idt[T_BRKPT], 0, GD_KT, handler3, 3); 

    SETGATE(idt[T_OFLOW], 0, GD_KT, handler4, 0); 
    SETGATE(idt[T_BOUND], 0, GD_KT, handler5, 0); 
    SETGATE(idt[T_ILLOP], 0, GD_KT, handler6, 0); 
    SETGATE(idt[T_DEVICE], 0, GD_KT, handler7, 0); 
    SETGATE(idt[T_DBLFLT], 0, GD_KT, handler8, 0); 
    SETGATE(idt[T_TSS], 0, GD_KT, handler10, 0); 
    SETGATE(idt[T_SEGNP], 0, GD_KT, handler11, 0); 
    SETGATE(idt[T_STACK], 0, GD_KT, handler12, 0); 
    SETGATE(idt[T_GPFLT], 0, GD_KT, handler13, 0); 
    SETGATE(idt[T_PGFLT], 0, GD_KT, handler14, 0); 
    SETGATE(idt[T_FPERR], 0, GD_KT, handler16, 0); 

    // T_SYSCALL DPL 3
    SETGATE(idt[T_SYSCALL], 0, GD_KT, handler48, 3); 

    // Per-CPU setup 
    trap_init_percpu();
}
```

trapentry.S中添加代码如下，前面是常规操作，\_alltraps这段汇编要注意下，段寄存器ds，es在mov指令中不支持立即数，所以用到ax寄存器中转下数据。在理论分析时我们提到，由用户模式发生中断进入内核时，CPU会切换到内核栈，并压入旧的 SS, ESP, EFLAGS, CS, EIP寄存器的值。接着，执行中断处理程序。这里，会先通过 `TRAPHANDLER`压入中断向量以及错误码(如果有)，然后在_alltraps中压入旧的DS, ES寄存器以及通用寄存器的值，接着将DS, ES寄存器设置为GD_KD，并将此时 ESP寄存器的值压入到内核栈中作为trap函数的参数，然后才调用trap(tf)函数。


```c
/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(handler0, T_DIVIDE)
TRAPHANDLER_NOEC(handler1, T_DEBUG)
TRAPHANDLER_NOEC(handler2, T_NMI)
TRAPHANDLER_NOEC(handler3, T_BRKPT)
TRAPHANDLER_NOEC(handler4, T_OFLOW)
TRAPHANDLER_NOEC(handler5, T_BOUND)
TRAPHANDLER_NOEC(handler6, T_ILLOP)
TRAPHANDLER(handler7, T_DEVICE)
TRAPHANDLER_NOEC(handler8, T_DBLFLT)
TRAPHANDLER(handler10, T_TSS)
TRAPHANDLER(handler11, T_SEGNP)
TRAPHANDLER(handler12, T_STACK)
TRAPHANDLER(handler13, T_GPFLT)
TRAPHANDLER(handler14, T_PGFLT)
TRAPHANDLER_NOEC(handler16, T_FPERR)
TRAPHANDLER_NOEC(handler48, T_SYSCALL)

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
		// Build trap frame.
        pushl %ds 
        pushl %es 
        pushal //push EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI

		// Set up data segments.
        movw $GD_KD, %ax
        movw %ax, %ds 
        movw %ax, %es 

		// Call trap(tf), where tf=%esp
        pushl %esp
        call trap /*never return*/


1:jmp 1b
```

做这些处理的作用是在内核栈中构造Trapframe的结构，这样在_alltraps之后，`trap(Trapframe tf)`中参数tf指向的内核栈，而栈中内容正好是一个完整的Trapframe结构。


```
 低地址                                                       高地址
 +---------------------------------------------------------------+             
 |regs | es | ds | trapno | errno | eip | cs | eflags | esp | ss |
 +---------------------------------------------------------------+
```

完成了 Exercize 4之后，我们现在`make qemu`可以看到没有报`triple fault`了，但是由于 `user_hello`运行时用了`int 0x30`触发了中断，而我们的trap()函数并没有针对中断做处理，于是会销毁该用户进程并进入 monitor()。而用`make grade`可以看到`divzero, softint, badsegment`这几个测试通过了。

```
Incoming TRAP frame at 0xefffffbc
TRAP frame at 0xf01c0000
  edi  0x00000000
  esi  0x00000000
  ebp  0xeebfde60
  oesp 0xefffffdc
  ebx  0x00000000
  edx  0xeebfde88
  ecx  0x0000000d
  eax  0x00000000
  es   0x----0023
  ds   0x----0023
  trap 0x00000030 System call
  err  0x00000000
  eip  0x00800adf
  cs   0x----001b
  flag 0x00000092
  esp  0xeebfde54
  ss   0x----0023
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```

当然这里有很多重复代码，其中的challenge可以参考xv6的实现，其用vector.pl生成了vector.S，从而完成handler的定义。

另外这里两个问题：

### Question 1
为什么要对每个中断向量设置不同的中断处理函数，而不是放到一个函数里面统一处理？

答：不同的中断或者异常当然需要不同的中断处理函数，因为不同的异常/中断可能需要不同的处理方式，比如有些异常是代表指令有错误，则不会返回被中断的命令。而有些中断可能只是为了处理外部IO事件，此时执行完中断函数还要返回到被中断的程序中继续运行。

### Question 2
为什么`user/softint.c`程序调用的是`int $14`会报13异常(general protection fault)？

答：这是因为我们在SETGATE中对中断向量14设置的DPL为0，从而由于用户程序CPL=3，触发了13异常。如果要允许，可以设置中断向量14的DPL为3，但是我们是不希望用户程序来操作内存的。

### 关于CPL, RPL, DPL

- CPL是当前正在执行的代码所在的段的特权级，存在于CS寄存器的低两位(对CS来说，选择子的RPL=当前段的CPL)。

- RPL指的是进程对段访问的请求权限，是针对段选择子而言的，不是固定的。

- DPL则是在段描述符中存储的，规定了段的访问级别，是固定的。

为什么需要RPL呢？因为同一时刻只能有一个CPL，而低权限的用户程序去调用内核的功能来访问一个目标段时，进入内核代码段时CPL 变成了内核的CPL，如果没有RPL，那么权限检查的时候就会用CPL，而这个CPL 权限比用户程序权限高，也就可能去访问需要高权限才能访问的数据，导致安全问题。所以引入RPL，让它去代表访问权限，因此在检查CPL 的同时，也会检查RPL。一般来说如果RPL 的数字比CPL大(权限比CPL的低)，那么RPL会起决定性作用，这个权限检查是CPU硬件层面做的。

# Exercize 5-6
作业5，6是在trap_dispatch中对page fault异常和breakpoint异常进行处理。比较简单，代码如下，完成后`make grade`可以看到 `faultread、faultreadkernel、faultwrite、faultwritekernel，breakpoint` 通过测试。

```c
static void
trap_dispatch(struct Trapframe *tf)
{
    // Handle processor exceptions.
    // LAB 3: Your code here.
		case T_PGFLT:
			page_fault_handler(tf);
			break;
		
		case T_BRKPT:
			monitor(tf);
			break;
		
		default:
			// Unexpected trap: The user process or the kernel has a bug.
			print_trapframe(tf);
			if (tf->tf_cs == GD_KT)
				panic("unhandled trap in kernel");
			else {
				env_destroy(curenv);
				return;
		}
}
```

### Question 3 & 4
在上面的break point exception测试程序中，如果你在设置IDT时，对break point exception采用不同的方式进行设置，可能会产生触发不同的异常，有可能是break point exception，有可能是 general protection exception。这是为什么？你应该怎么做才能得到一个我们想要的breakpoint exception，而不是general protection exception？

答：通过实验发现出现这个现象的问题就是在设置IDT表中的breakpoint exception的表项时，如果我们把表项中的DPL字段设置为3，则会触发break point exception，如果设置为0，则会触发general protection exception。DPL字段代表的含义是段描述符优先级（Descriptor Privileged Level），如果我们想要当前执行的程序能够跳转到这个描述符所指向的程序哪里继续执行的话，有个要求，就是要求当前运行程序的CPL，RPL的最大值需要小于等于DPL，否则就会出现优先级低的代码试图去访问优先级高的代码的情况，就会触发general protection exception。

那么我们的测试程序首先运行于用户态，它的CPL为3，当异常发生时，它希望去执行 int 3指令，这是一个系统级别的指令，用户态命令的CPL一定大于 int 3 的DPL，所以就会触发general protection exception，但是如果把IDT这个表项的DPL设置为3时，就不会出现这样的现象了，这时如果再出现异常，肯定是因为我们还没有编写处理break point exception的程序所引起的，所以是break point exception。

# Exercize 7 & 8
实现系统调用的支持，需要修改`trap_dispatch()`和`kern/syscall.c`。

用户程序通过 `lib/syscall.c`触发系统调用，最终由`kern/trap.c`中的trap_dispatch()统一分发，并调用`kern/syscall.c`中的syscall()处理。其参数必须设置到寄存器中，其中系统调用号存储在%eax，其他参数依次存放到 %edx, %ecx, %ebx, %edi, 和%esi，返回值通过 %eax 来传递。

**It is only when entering the kernel from user mode**, however, that the x86 processor automatically switches stacks before pushing its old register state onto the stack and **invoking the appropriate exception handler through the IDT**. 

```c
      IDT                   trapentry.S         trap.c
   
+----------------+                        
|   &handler1    |---------> handler1:          trap (struct Trapframe *tf)
|                |             // do stuff      {
|                |             call trap          // handle the exception/interrupt
|                |             // ...           }
+----------------+
|   &handler2    |--------> handler2:
|                |            // do stuff
|                |            call trap
|                |            // ...
+----------------+
       .
       .
       .
+----------------+
|   &handlerX    |--------> handlerX:
|                |             // do stuff
|                |             call trap
|                |             // ...
+----------------+
```



**System Call Handling Routine (User)**
• User calls a function
	• cprintf -> calls sys_cputs()
• sys_cputs() at user code will call syscall() (lib/syscall.c)
	• This syscall() is at lib/syscall.c
	• Set args in the register and then
• int $0x30

**System Call Handling Routine (Kernel)**
• CPU gets software interrupt
• TRAPHANDLER_NOEC(T_SYSCALL…)
• _alltraps()
• trap()
• trap_dispatch()
	• Get registers that store arguments from struct Trapframe *tf
	• Call syscall() using those registers
		• This syscall() is at kern/syscall.c



**在捋顺逻辑的过程中有一个困惑了很久的问题，观察到 kern/syscall.c 中的 sys_cputs，它调用了 cprintf，这个调用其实就是为了完成输出的功能，但是cprintf不是要调用sys_cputs系统调用吗，这不是套娃了吗？其实并不是我们要注意，当我们程序运行到这里时，系统已经工作在内核态了，调用的是处于kernel目录下的cprintf，而在用户态调用的cprintf在lib目录下。可以得出过程是/lib/cprintf->sys_cputs->int 0x30->sys_cputs->/kern/cprintf->(monitor)。**

所以剩下的就是我们如何在 kern/syscall.c 中的 syscall() 函数中正确的调用 sys_cputs 函数了，当然 kern/syscall.c 中其他的函数也能完成这个功能。所以我们必须根据触发这个系统调用的指令到底想调用哪个系统调用来确定我们该调用哪个函数。

那么怎么知道这个指令是要调用哪个系统调用呢？答案是根据 syscall 函数中的第一个参数，syscallno，那么这个值其实要我们手动传递进去的，这个值存在哪里？通过阅读 lib/syscall.c 中的syscall内置asm可以知道它存放在 eax寄存器中。

在trap_dispatch()中加入如下代码

```c
		case T_SYSCALL:
			tf->tf_regs.reg_eax = syscall(
				tf->tf_regs.reg_eax,
				tf->tf_regs.reg_edx,
				tf->tf_regs.reg_ecx,
				tf->tf_regs.reg_ebx,
				tf->tf_regs.reg_edi,
				tf->tf_regs.reg_esi
			);
			break;
```

接着在`kern/syscall.c`中对不同类型的系统调用处理。

```c
// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5) 
{
	switch (syscallno) {
        case SYS_cputs:
            sys_cputs((const char *)a1, a2);
            return 0;

        case SYS_cgetc:
            return sys_cgetc();

        case SYS_getenvid:
            return sys_getenvid();

        case SYS_env_destroy:
            return sys_env_destroy(a1);

        default:
            return -E_INVAL;
    }
}
```
完成作业7之后，在执行`user/hello.c`的第二句cprintf报 page fault，因为还没有设置它用到的thisenv的值。在`lib/libmain.c`的libmain()如下设置即可完成作业8：

```c
thisenv = &envs[ENVX(sys_getenvid())];
```
完成作业8后，我们可以看到`user_hello`的正确输出了：

```
...
Incoming TRAP frame at 0xefffffbc
hello, world
Incoming TRAP frame at 0xefffffbc
i am environment 00001000
Incoming TRAP frame at 0xefffffbc
[00001000] exiting gracefully
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```

# Exercize 9-10
处理在内核模式下出现page fault的情况，这里比较简单处理，直接panic。

```c
void
page_fault_handler(struct Trapframe *tf)
{
    ...
    // Handle kernel-mode page faults.

    // LAB 3: Your code here.
    if ((tf->tf_cs & 3) == 0) {
        panic("kernel page fault at:%x\n", fault_va);
    }   
    ...
}
```

接下来实现`user_mem_check`防止内存访问超出范围。

```c
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
    // LAB 3: Your code here.
	void *start = ROUNDDOWN((void *)va, PGSIZE);
	void *end = ROUNDUP((void *)(va+len), PGSIZE);
	int check = perm | PTE_P;

	for(; start<end; start+=PGSIZE){
		pte_t *pte = pgdir_walk(env->env_pgdir, start, 0);
		if((int)start>=ULIM || !pte || ((*pte)&check)!=check){
			user_mem_check_addr = (uintptr_t)start >= (uintptr_t)va ? (uintptr_t)start : (uintptr_t)va;
			return -E_FAULT;
		}			
	}

    return 0;
}
```

然后在 `kern/syscall.c`的 sys_cputs()中加入检查。

```
user_mem_assert(curenv, s, len, 0);
```

此外，在`kern/kdebug.c`的debuginfo_eip()中加入检查。

```c
// Make sure this memory is valid.
// Return -1 if it is not.  Hint: Call user_mem_check.
// LAB 3: Your code here.
if (user_mem_check(curenv, usd, sizeof(struct UserStabData), PTE_U))
    return -1; 
            
// Make sure the STABS and string table memory is valid.
// LAB 3: Your code here.
if (user_mem_check(curenv, stabs, stab_end - stabs, PTE_U))
    return -1;

if (user_mem_check(curenv, stabstr, stabstr_end - stabstr, PTE_U))
    return -1;
```
这样，就完成了作业9-10。

至此，lab 3完成。

# 总结
### 进程如何继续运行？
进程从中断之后是如何保证继续运行的，这个是在`trap()`函数中实现的，在其中拷贝了内核栈上的Trapframe结构体的值到curenv的env_tf中，从而实现了进程运行状态保存。

```
void 
trap(struct Trapframe *tf) {
    ......
    if ((tf->tf_cs & 3) == 3) {
        // Trapped from user mode.
        assert(curenv);

        // Copy trap frame (which is currently on the stack)
        // into 'curenv->env_tf', so that running the environment
        // will restart at the trap point.
        curenv->env_tf = *tf;
        // The trapframe on the stack should be ignored from here on.
        tf = &curenv->env_tf;
    }  
    ......
} 
```
### 用户程序运行时寄存器切换
最后，我们再来验证下前面提到的异常/中断处理。先看下用户程序运行，我们知道用户程序是在env_pop_tf()后开始运行的，观察`user_hello`运行前后的寄存器的值。可以看到 CS,ES,DS,SS,ESP等寄存器的值都切换到了用户模式的值。

```
(gdb) b env_pop_tf
Breakpoint 1 at 0xf0103969: file kern/env.c, line 464.

(gdb) info registers
eax            0xf01c0000	-266600448
ecx            0x3d4	980
edx            0x3d5	981
ebx            0x10094	65684
esp            0xf0119fbc	0xf0119fbc
ebp            0xf0119fd8	0xf0119fd8
esi            0x10094	65684
edi            0x0	0
eip            0xf0103969	0xf0103969 <env_pop_tf>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x23	35
gs             0x23	35
...
(gdb) si
=> 0xf0103978 <env_pop_tf+15>:	iret   
0xf0103978	465		asm volatile(
(gdb) si
=> 0x800020:	cmp    $0xeebfe000,%esp   # 进入用户程序了
0x00800020 in ?? ()
(gdb) info registers
eax            0x0	0
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xeebfe000	0xeebfe000 # USTACKTOP为0xeebfe000
ebp            0x0	0x0
esi            0x0	0
edi            0x0	0
eip            0x800026	0x800026
eflags         0x46	[ PF ZF ]
cs             0x1b	27
ss             0x23	35
ds             0x23	35
es             0x23	35
fs             0x23	35
gs             0x23	35
```

### 系统调用堆栈切换和堆栈内容
接着我们继续运行，此时用户程序会触发系统调用，我们在handler48打个断点，观察下中断后的状态。此时可以看到 esp寄存器的值为 0xefffffec，这是怎么来的呢？我们知道内核栈的顶部KSTACKTOP为 0xf0000000，发生异常/中断时，CPU会压入旧的  SS, ESP, EFLAGS, CS, EIP的值到栈中，这样占用了20字节(0x14），这样正好esp为`0xf0000000-0x14=0xefffffec`。查看堆栈内容，存储的确实是用户程序的EIP，CS, EFLAGS, ESP 以及SS的值。

```
(gdb) b handler48
Breakpoint 2 at 0xf0104220: file kern/trapentry.S, line 65.
(gdb) c
Continuing.
=> 0xf0104220 <handler48>:	push   $0x0

Breakpoint 2, handler48 () at kern/trapentry.S:65
65	TRAPHANDLER_NOEC(handler48, T_SYSCALL)
(gdb) info registers
eax            0x2	2
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xefffffec	0xefffffec
ebp            0xeebfdfd0	0xeebfdfd0
esi            0x0	0
edi            0x0	0
eip            0xf0104220	0xf0104220 <handler48>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x23	35
es             0x23	35
fs             0x23	35
gs             0x23	35

(gdb) x /5x 0xefffffec
0xefffffec:	0x00800b7f	0x0000001b	0x00000086	0xeebfdfc4
0xeffffffc:	0x00000023
```

接着我们继续单步运行，观察调用`trap()`之前的内核栈的内容，如下，可以看到其中的内容正好是Trapframe的结构，即第一个4字节存储的是之前esp的值，也就是Trapframe的起始位置。后面分别是8个通用寄存器的值，然后是ds, es寄存器的值0x23，接着是trapno 0x30(系统调用中断号)，因为没有错误码，接着是0，然后是用户程序 EIP, CS, EFLAGS, ESP, SS的值，确实如我们分析一样，至此lab 3的作业完成。

```
(gdb) info registers
eax            0x10	16
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xefffffb8	0xefffffb8
ebp            0xeebfdfd0	0xeebfdfd0
esi            0x0	0
edi            0x0	0
eip            0xf0104232	0xf0104232 <_alltraps+12>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x23	35
gs             0x23	35

(gdb) si
=> 0xf0104232 <_alltraps+12>:	call   0xf010406d <trap>
_alltraps () at kern/trapentry.S:79
79		call trap /*never return*/

(gdb) x /18x 0xefffffb8
0xefffffb8:	0xefffffbc	0x00000000	0x00000000	0xeebfdfd0
0xefffffc8:	0xefffffdc	0x00000000	0x00000000	0x00000000
0xefffffd8:	0x00000002	0x00000023	0x00000023	0x00000030
0xefffffe8:	0x00000000	0x00800b7f	0x0000001b	0x00000086
0xeffffff8:	0xeebfdfc4	0x00000023
```

参考资料：

- https://github.com/shishujuan/mit6.828-2017/blob/master/docs/lab3-exercize.md
- https://www.cnblogs.com/fatsheep9146/p/5451579.html
- https://os.unexploitable.systems/l/W5L2.pdf


