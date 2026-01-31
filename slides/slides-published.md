<!--
Copyright 2026 bx Shapiro <bx.Shapiro@dartmouth.edu>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
-->
# Fun with ELF. A story in 3 acts
## (if time permits)


---
# Prologue
---
# A refresher
- remember ELF?: `readelf -W --all hello-world`
- [remember ELF relocation entries?](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html#chapter7-2)
- [and symbols](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html#scrolltoc...)
![](img/gcc-toolchain.png)

---

# The ELF metadata machine
<style scoped>pre{font-size:40%}</style>

## Relocation entry:
```
,----------------------------------------------------------------------.
|           8           |           8           |          8           |
|-----------------------|-----------------------|----------------------|
|                       |        r_info         |                      |
|        r_offset       |  ---------|---------  |       r_addend       |
|                       |      4    |    4      |   (add this signed   |
|  (address to patch)   |  ---------|---------  |   value to result)   |
|                       |    type   |  symbol   |                      |
`----------------------------------------------------------------------'
```

## Symbol table entry:
```
,---------------------------------------------------------------------------------------------------------.
|           8           |    1    |    1    |       4       |          8           |          8           |
|-----------------------|---------|---------|---------------|----------------------|----------------------|
|                       |         |         |               |                      |                      |
|        st_name        | st_info |st_other |   st_shndx    |       st_value       |        st_size       |
|                       |         |         |               |                      |                      |
| (string table offset) |  (*)    |   (*)   | (section #)** |   (symbol value)**   |    (symbol size)**   |
|                       |         |         |               |                      |                      |
`---------------------------------------------------------------------------------------------------------'
* linking info, i.e., visibility (local/global/weak)
** sometimes
```
---
# See how they dance*
<style scoped>section{font-size:100%}</style>
given:
 - `r`: a relocation entry
 - `s`: a symbol (as indexed by `r_info` symbol), optional
 - `base`: is the absolute address of where the binary was loaded into memory
   - remember: all ELF metadata address/virtual address values are offsets from this base address and **not** the offset into the file on disk, although these offsets are often the same. The mappings from file offsets to virtual addresses are defined in the section/segment headers.

if relocation type is ...
- `R_X86_64_COPY` ↦ **is like a memcpy**
  - `memcpy(base + r.r_offset, s.st_value, s.st_size)`
- `R_X86_64_64` ↦ **indirect move (+ addend)**
  - `*(base + r.r_offset) = base + s.st_value + r.r_addend`
    - applies to most symbol types
  - `*(base + r.r_offset) = s.st_value + r.r_addend`
    - if symbol has `st_shndx` value of 0xfff1
    - 0xfff1 means `SHN_ABS`, symbol should be treated as an "absolute" value and not affected by relocation
- `R_X86_64_RELATIVE` ↦ **a direct move (+ addend)**
  - `*(base + r.r_offset) = (r.r_addend + base)`

---
#  How?
- [https://github.com/bx/rtld-debugging](https://github.com/bx/rtld-debugging) to debug the runtime loader
- [Using LIEF](https://lief.re/) to edit and inject ELF metadata

---
# Our first ~~victim~~ target
<style scoped>section{font-size:100%}</style>

## Source code
```c
char *hw = "hello, world\n";
char *notused = "hello, relocs\n";
int main(int argc, char *argv[]) {
    println(hw);
    return 0;
}
```

## Runtime behavior of original binary:
```
> /hello-world
hello, world
```

## Goal: Alter printed string by manipulating ELF metadata

More specifically, the `.rela.dyn` (relocation) and `.dynsym` (symbol) tables, which are processed at load time

## How (in general)?
```
mov    0x2ec9(%rip),%rax        # 5018 <hw>
mov    %rax,%rdi                   ^.___ contains address of hw string
mov    $0x0,%eax
call   2030 <printf@plt>
```

Let's change pointer at 0x5018 to point elsewhere

---
# Act 1: hello, (fill in the blank) w/ direct move
<style scoped>section{overflow: scroll}</style>

`R_X86_64_RELATIVE` ↦ `*(base + r.r_offset) = (r.r_addend + base)`

Achieved via a single standalone relocation entry.

## Inserted relocation entry:
```
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000005018  0000000000000008 R_X86_64_RELATIVE           -----------------              0
   ^- address     -------  --------                                  ^-- no symbol   addend --^
     to patch        ^         ^-- indicates reloc type `R_X86_64_relative`
                      \_____ symbol value 0 is reserved, indicates no linked symbol
```
## Raw view of relocation entry struct
```
0000000000005018 0000000000000008 0000000000000000
  ^-- r_offset    ^---- r_type       ^--- r_addend

```

## Effective computation:
```
            .----  address of char *hw
            v
*(base + 0x5018) = 0 + base
          va*  ___.^
```

 *Section headers `readelf -W --sections hello-world` determine file offset to va mapping

## Why all the base?

When printf is called...
```
Breakpoint 1, main (argc=1, argv=0x7fffffffd6d8) at hello-world.c:9
9	    printf(hw);
```

Address moved into `%rax`:
```
(gdb) x/i $pc
=> 0x555555555148 <main+15>:	mov    0x2ec9(%rip),%rax        # 0x555555558018 <hw>
(gdb) x/gx 0x555555558018
0x555555558018 <hw>:	0x0000555555556004
```

Is our string at 0x0000555555556004?
```
(gdb) print (char *) 0x0000555555556004
$2 = 0x555555556004 "hello, world\n"
(gdb)
```
yes.

## Behavior of altered executable
```sh
> ./hello-world.direct-address-simple
 ELF%
```

## Why do we see it print `ELF`?

#### Hint: `xxd -l8 -g8 hello-world`... the addend

---
# Act 1 pt II: hello, (relocs)
<style scoped>section{overflow: scroll}</style>

`R_X86_64_RELATIVE` ↦ `*(base + r.r_offset) = (r.r_addend + base)`
(same operation as before)

## Add this relocation entry instead
```
Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000005018  0000000000000008 R_X86_64_RELATIVE                         3012
```

## Addend was previously 0. Why now 0x3012?

```shell
> xxd  -s 0x3012 ./hello-world | head -n1
00003012: 6865 6c6c 6f2c 2072 656c 6f63 730a 0000  hello, relocs...
```
(note: offset 0x3012 in this ELF happens to map to a va of 0x3012 )

## Effective computation:
```
          .----  address pointer to hw
          v
*(base + 0x5018) = 0x3012 + base
                      ^---- va of 'hello, relocs' char*
```

## Result:
```
> /hello-world.direct-address
hello, relocs
```
---
# Act 2: Indirect moves
<style scoped>section{overflow: scroll}</style>
i.e. copying a symbol's `st_value` to memory

`R_X86_64_64` ↦ *(base + r.r_offset) = s.st_value + r.r_addend`

Let's overwrite the "hello, world!" string

### Note: Altered string must be in a r/w segment
So we define it slightly differently
```c
char hw[] = {'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n', 0}; //"hello, world\n
```

## 1. Insert symbol that contains value we want to write
```
         st_shndx value must be 0xfff1=ABS -----.                       .
                                                v
00000a636f6c6572     0 NOTYPE  LOCAL  DEFAULT  ABS sym0
      ^--- bytes b`\x00\x00\ncoler`
```

## 2. Insert this relocation entry that references new symbol:
```
0000000000005018  0000000100000001 R_X86_64_64            00000a636f6c6572 sym0 + 0
   ^---- va of 'hello, world' in r/w segment      name here is arbitrary  ---^
```

## Effective computation:
```
          .----  va of char hw[]
          v
*(base + 0x5018) = 0x00000a636f6c6572
                      ^--little endian, translates to 'reloc\n\x00\x00'
```

## Resulting behavior:
```sh
> ./hello-world-rw.indirect-value
reloc
```

### Just after executable is loaded:
```
 executable's base address --.
                             v
(gdb) print (char *) 0x00007ffff7fb1000 + 0x5018
$1 = 0x7ffff7fb6020 "hello, world!\n"
```

### After relocation entries are processed:
```
(gdb) print (char *) 0x00007ffff7fb1000 + 0x5018
$2 = 0x7ffff7fb6020 <hw> "reloc\n"
```

ta-da!

---
# Act 3: COPY that
<style scoped>section{overflow: scroll}</style>

`R_X86_64_COPY` ↦ `memcpy(base + r.r_offset, s.st_value, s.st_size)`

## Relocation entry:
```
   .-- address of 'hello, world'
   v
0000000000005018  0000000100000005 R_X86_64_COPY    0000000000003004 sym0 + 0
                                                       |_______________|
                                                              |
                      value and name of referenced symbol ----
```

## Symbol:
```
   .---- address of 'hello, rellocs'
   v
0000000000003004    13 NOTYPE  LOCAL  DEFAULT  UND sym0
                     ^--- length of 'hello, relocs'
               (just long enough to clobber 'hello, world\n')
```

## Effective computation:
```
                .----  va of char hw[]
                v
memcpy(base + 0x5018, base + 0x3004, 13)
address of 'hello, relocs\n' --^      ^-- # bytes copied

```

## Runtime
```
> ./hello-world-rw.copy
hello, relocs
```

## Just after binary is loaded:
```
(gdb) print (char *) 0x00007ffff7fb1000 + 0x5020
$1 = 0x7ffff7fb6020 "hello, world!\n"
(gdb) print (char *) 0x00007ffff7fb1000 + 0x3004
$2 = 0x7ffff7fb4004 "hello, relocs\n"
```

## Value of hw string after relocation, before execution:
```
(gdb) print (char *) 0x00007ffff7fb1000 + 0x5020
$3 = 0x7ffff7fb6020 <hw> "hello, relocs\n"
```

huzzah!


---
# Grand finale: altering control flow at runtime w/ ELF metadata
<style scoped>section{overflow: scroll}</style>

## Original source code
```c
char *allowed = "/bin/ls";
int main(int argc, char *argv[]) {
    if (argc == 2) {
        if (strcmp(argv[1], allowed) == 0) {
            execl(allowed, NULL);
        } else {
            printf("The following command cannot be executed: ");
            printf(argv[1], 0);
        }
    }
    return 0;
}
```

## Goal

Let's alter the metadata so it'll execute the file at argv[1], without changing the file size


## Original behavior
```sh
> ./exec-filter /bin/bash
The following command cannot be executed: /bin/bash
> ./exec-filter /bin/ls
hello-world Makefile
```
## Desired behavior

```sh
> ./exec-filter /bin/bash
[user@local]$ # produced via execl(/bin/bash, 0) call
```


## How?
Change existing metadata to alter `printf`'s `.rela.plt` entry (processed lazily by the dynamic linker) at **runtime**

`.rela.plt` entries are processed on-demand when a library function is called for the first time


## .rela.plt relocation entry we want to patch at loadtime (by a crafted .rela.dyn entry)
Note: must be in r/w memory (which is not the default)

```
                                          name of associated symbol  --------.
                                                                             v
0000000000004000  0000000300000007 R_X86_64_JUMP_SLOT     0000000000000000 printf@GLIBC_2.2.5 + 0

                         ^----- index of associated symbol (3 -- printf)
                                we want to change this to 7 (execl)

Symbol table '.dynsym' contains 9 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
    -------------------------------------------------------------------------------
   | 3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (3) |  --- current symbol
    -------------------------------------------------------------------------------
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strcmp@GLIBC_2.2.5 (3)
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    ------------------------------------------------------------------------------
   | 7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND execl@GLIBC_2.2.5 (3) |  --- we want this symbol to be used
    ------------------------------------------------------------------------------
     8: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (3)
```
# Setup: .rela.dyn & .dynsym entries to alter:

## Original .rela.dyn entry (the before):
```
0000000000003fd8  0000000600000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_registerTMCloneTable + 0
```

## Patched value of .rela.dyn entry:
```
      .----- address of printf's .got.plt r_info field,
      |      calculated from section header
      v
0000000000000688  0000000100000001 R_X86_64_64            0000000700000007 _ITM_registerTMCloneTable + 0
```

## corresponding symbol we will alter (the before):
```
0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable

```

## Patched value of symbol:
```
 copies symbol value w/out adding in base -----.
                                                v
0000000700000007     0 NOTYPE  LOCAL  DEFAULT  ABS _ITM_registerTMCloneTable
--------
   `------- altered symbol index (symbol 7 = execl)

```

See the new symbol value 0x0000000700000007?
It will be written to the printf `.rela.plt` relocation entry's `r_info` field, changing the symbol from 6 (printf) to 7 (execl)

# Effective computation

```
           .----- address of (printf .rela.plt entry)->r_info
           v
*(base + 0x688) = 0x0000000700000007
                   -------- --------
                      |        |_______ same as previous relocaiton type,  R_X86_64_GLOB_DAT
                      |___ .symbol #7
```

# It's go time
```
> gdb ./exec-filter.patch-printf-sneaky /usr/bin/bash
```

## `.rela.plt` after being loaded:
```
Elf64_Rela in .rela.plt at 7ffff7fba680 (offset 680)
$1 = address=0x4000 symbol-name='printf' symbol-index=4 type=R_X86_64_JUMP_SLOT
$2 = address=0x4008 symbol-name='strcmp' symbol-index=5 type=R_X86_64_JUMP_SLOT
$3 = address=0x4010 symbol-name='execl' symbol-index=7 type=R_X86_64_JUMP_SLOT
```

## And after `.rela.dyn` entries are processed:
```
Elf64_Rela in .rela.plt at 7ffff7fba680 (offset 680)
$10 = address=0x4000 symbol-name='execl' symbol-index=7 type=R_X86_64_JUMP_SLOT
$11 = address=0x4008 symbol-name='strcmp' symbol-index=5 type=R_X86_64_JUMP_SLOT
$12 = address=0x4010 symbol-name='execl' symbol-index=7 type=R_X86_64_JUMP_SLOT
```

## What the debugger reports when it tries to call printf
```
(gdb) x/i $pc
=> 0x7ffff7fbb1d6 <main+125>:	call   0x7ffff7fbb030 <printf@plt>
(gdb) c
process 53 is executing new program: /usr/bin/bash
```

/usr/bin/bash (which was passed is as argv[1]) is executed instead of printed

(applause)

---
# Epilogue

## Resources
- [https://github.com/bx/rtld-debugging](https://github.com/bx/rtld-debugging) to debug the runtime loader
- [LIEF](https://lief.re/) to edit and inject ELF metadata

## introducing the leaner and meaner relr
- [proposal](https://groups.google.com/g/generic-abi/c/bX460iggiKg)
- a quick peak: `readelf -W --relocs libzstd.so`
