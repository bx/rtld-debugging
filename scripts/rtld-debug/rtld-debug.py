#!/usr/bin/env python3
from pathlib import Path
import gdb
import struct
from gdb.printing import PrettyPrinter, register_pretty_printer
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_TYPE, ENUM_ST_INFO_BIND, ENUM_ST_VISIBILITY, ENUM_ST_SHNDX
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
import re


st_info_type_rev = {
    v: k for k, v in ENUM_ST_INFO_TYPE.items()
}
st_info_bind_rev = {
    v:k for k, v in ENUM_ST_INFO_BIND.items()
}
st_other_vis_rev = {
    v:k for k, v in ENUM_ST_VISIBILITY.items()
}
st_shndx_rev = {
    v:k for k, v in ENUM_ST_SHNDX.items()
}


class ObjLoadBreak(gdb.Breakpoint):
    def __init__(self, et, objpath):
        fn = "_dl_map_object_from_fd"
        print(f"inserting loading breakpont at {fn} for {objpath}")
        self.__objpath = objpath.strip()
        self.__et = et
        super().__init__(fn, gdb.BP_BREAKPOINT, internal=False, temporary=True)

    def stop(self):
        target = gdb.parse_and_eval("name").string()
        print(f"loading {target}")
        if target == self.__objpath:
            return True
        return False


class ObjRelocBreak(gdb.Breakpoint):
    def __init__(self, et, objpath):
        fn = "_dl_relocate_object"
        print(f"inserting relocation breakpont at {fn} for {objpath}")
        self.__objpath = objpath.strip()
        self.__et = et
        super().__init__(fn, gdb.BP_BREAKPOINT, internal=False, temporary=True)

    def stop(self):
        startaddr = int(gdb.parse_and_eval("l->l_map_start"))
        for m in self.__et.iter_mappings():
            if m["start"] == startaddr and m["file"] == self.__objpath:
                print(f"starting relocation of {self.__objpath}")
                return True
        return False



class EntryBreak(gdb.Breakpoint):
    def __init__(self, et, entrysym="_start"):
        self.__et = et
        super().__init__(entrysym, gdb.BP_BREAKPOINT, internal=True, temporary=True)

    def stop(self):
        self.__et.__entry_hit = True
        return False


class ELFTable(gdb.Command):
    """ prints out current contents of memory-mapped elf metadata tables """
    def __init__(self):

        gdb.execute("set python print-stack full")
        gdb.events.executable_changed.connect(self._on_exec_changed)
        # gdb.events.new_objfile.connect(self._on_new_objfile)

        self.__executable = None
        self.__exec_fp = None
        self.__elffile = None
        self.__entry_hit = False
        self.__base_addr = None
        self.__eb = None
        self.__exec_pinned = False
        self._on_exec_changed(gdb.current_progspace(), False)

        super().__init__("elf", gdb.COMMAND_USER)

    @property
    def elffile(self):
        return self.__elffile

    def file_offset_to_section_header(self, offset, addr=True):
        if not self.elffile:
            return
        for sec in self.elffile.iter_sections():
            shoff = sec.header["sh_offset"] if not addr else sec.header["sh_addr"]
            if shoff <= offset and offset < shoff + sec.header["sh_size"]:
                return sec


    def file_offset_to_segment_mapping(self, offset, elf=None, addr=True):
        true_base = None
        matches = []
        for m in self.lookup_mappings(elf):

            if true_base is None and m["offset"] == 0:
                true_base = m["start"]
            m["base"] = true_base
            # if addr:
            #     if true_base is not None and m["start"] <= (true_base + offset) < m["end"]:
            #         matches.append(m)
            # else:
            if m["offset"] <= offset and offset < m["offset"] + m["size"]:
                matches.append(m)

        return matches


    def file_offset_to_va(self, offset, addr=True):
        ms = self.file_offset_to_segment_mapping(offset, addr=addr)
        sec = self.file_offset_to_section_header(offset, addr)

        if ms and sec:
            # always assume actual location is in highest mapping
            m = ms[-1]

            if addr:
                #print(f"offset: {offset:x}, mstart: {m['start']:x}, moffset {m['offset']:x}, shaddr: {sec.header['sh_addr']:x}")
                return (offset - (sec.header["sh_addr"] - sec.header["sh_offset"]))  + (m["start"] - m["offset"]) # + (offset - m["offset"]) # + (sec.header["sh_addr"] - sec.header["sh_offset"])
            else:
                return m["start"] + (offset - m["offset"])
        # #

        # if m and sec:
        #     # first calculate base address of full image
        #     return (m["start"] - m["offset"]) + sec.header["st_addr"]
        #     return (sec_addr - m["offset"]) + m["start"] + offset
        #     #return offset + m["start"] - m["offset"]


    def va_to_section_header(self, va):

        # find encapulating mapping
        for m in self.lookup_mappings():
            if m["start"] <= va and va < m["end"]:
                # found it
                # calculate offset from start of segment
                offset = va - m["start"]
                # now calculate offset in file
                fileoffset = offset + m["offset"]
                # now find containing section
                return self.file_offset_to_section_header(fileoffset)

    def iter_mappings(self):
        mappings = []
        regexp = r"(?P<start>0x[0-9a-fA-F]{16})\s+(?P<end>0x[0-9a-fA-F]{16})\s+(?P<size>0x[0-9a-fA-F]{1,16})\s+(?P<offset>0x[0-9a-fA-F]{1,16})\s+(?P<perms>[-rwx]{3})p(\s+(?P<elf>[\s\S]+))?"
        try:
            res = gdb.execute("info proc mappings", to_string=True)
        except gdb.error:
            return mappings
        for line in res.splitlines():
            res = re.match(regexp, line)
            if res:
                mappings.append({k: int(res.group(k),16) for k in  ("start", "end", "size", "offset")})
                mappings[-1]["perms"] = res.group("perms")
                mappings[-1]["file"] = res.group("elf").strip() if "elf" in res.groupdict() else None

        return mappings

    def lookup_mappings(self, elf=None):
        mappings = []
        elf = elf if elf else self.__executable
        #regexp = r"(?P<start>0x[0-9a-fA-F]{16})\s+(?P<end>0x[0-9a-fA-F]{16})\s+(?P<size>0x[0-9a-fA-F]{1,16})\s+(?P<offset>0x[0-9a-fA-F]{1,16})\s+(?P<perms>[-rwx]{3})p\s+(?P<exec>%s)\s*$" % elf
        for m in self.iter_mappings():
            #print("look", elf, m)
            if m.get("file") == elf:
                mappings.append(m)
        return mappings

    def lookup_base_addr(self, elf=None):
        mappings = self.lookup_mappings(elf)
        for m in mappings:
            if m["offset"] == 0:
                return m["start"]

    def _try_setup_executable(self, filename, pin=False):
        if not filename or (not pin and self.__exec_pinned):
            return
        execfp = open(filename, "rb")
        elffile = ELFFile(execfp)
        if elffile.header["e_type"] not in ("ET_EXEC", "ET_DYN") or elffile.header["e_entry"] == 0:
            execfp.close()
            return

        if self.__exec_fp:
            self.__exec_fp.close()

        self.__exec_pinned = pin
        print("setting executable as", filename)
        self.__executable = filename
        self.__exec_fp = execfp
        self.__elffile = elffile
        self.__entry_hit = False
        self.__base_addr = None
        if self.__eb is not None:
            self.__eb.disable()

        entryva = self.file_offset_to_va(elffile.header["e_entry"])
        if entryva:
            self.__eb = EntryBreak(self, f"*0x{entryva:x}")

    def _on_new_objfile(self, objfileevent):
        objfile = objfileevent.new_objfile

        if objfile.is_file:
            if self.__exec_pinned and self.__elffile and not self.__eb and self.__executable == objfile.filename:
                entryva = self.file_offset_to_va(self.__elffile.header["e_entry"])
                self.__eb = EntryBreak(self, f"*0x{entryva:x}")
            else:
                self._try_setup_executable(objfile.filename)

    def _on_exec_changed(self, progspace, reloaded):
        if reloaded:
            self._try_setup_executable(self.__executable)
        else:
            self._try_setup_executable(progspace.executable_filename)


    def get_table_offset_and_size(self, secname, typ, sectioncls):
        sec = self.__elffile.get_section_by_name(secname)
        if sec and sec.header["sh_addr"] > 0 and isinstance(sec, sectioncls):
            if not isinstance(typ, str):
                typname = typ(sec)
            else:
                typname = typ
            r = gdb.lookup_type(typname)
            if r:
                tablesz = sec.header["sh_size"]
                num_entries = int(tablesz / r.sizeof)
                return sec.header["sh_addr"], num_entries, typname, r.sizeof
        return None, None, None, None


    def print_table(self, secs, typ, sectioncls):
        if not self.__elffile or not self.__base_addr:
            return
        for secname in secs:
            offset, num_entries, typname, entrysz = self.get_table_offset_and_size(secname, typ, sectioncls)
            if not num_entries:
                continue

            print(typname, "in", secname, f"at {self.__base_addr+offset:x} (offset {offset:x})")

            for i in range(num_entries):
                va = offset + self.__base_addr + (entrysz * i)
                gdb.execute(f"print *(({typname} *) 0x{va:x})")
            print()

    def invoke(self, args, from_tty):

        if self.__base_addr is None:
            self.__base_addr = self.lookup_base_addr()
        _as = args.split()
        if _as:
            arg = _as[0].strip()
            args = _as[1:]
        else:
            arg, args = "", []
        if arg == "rel":
            self.print_table(
                (".rela.plt", ".rela.dyn"),
                lambda sec: "Elf64_Rela" if sec.is_RELA() else "Elf64_Rel",
                RelocationSection
            )
        elif arg == "sym":
            self.print_table(
                (".dynsym", ".symtab"), "Elf64_Sym", SymbolTableSection
            )
        elif arg == "init" and args:
            filename = Path(args[0]).resolve()
            if filename.exists():
                self._try_setup_executable(str(filename), True)
            else:
                print("Executable does not exist: ", filename)
        elif arg == "break-reloc":
            obj = args[0] if args else self.__executable
            if not obj:
                print("cannot insert relocation breakpoint, target unknown")
                return
            ObjRelocBreak(self, obj)
        elif arg == "break-load":
            obj = args[0] if args else None
            if not obj:
                print("cannot insert object loading breakpoint, target unknown")
                return
            ObjLoadBreak(self, obj)
        elif arg == "section-offset":
            secs = args
            for secname in secs:
                sec = self.__elffile.get_section_by_name(secname)
                if not sec:
                    print(f"section {secname} not found in ELF")
                    continue
                offset = sec.header["sh_addr"]
                if not offset:
                    print(f"section {secname} is not memory-mapped")
                    continue
                va = self.file_offset_to_va(offset)
                if not va:
                    print(f"could not look up address for section {secname} at relative offset {offset:x}")
                    continue
                seg = self.file_offset_to_segment_mapping(offset)
                print(offset, seg)
                perms = seg[-1].get('perms') if seg else ""
                perms = "" if not perms else f" has permissions: {perms}"
                print(f"section {secname} at 0x{va:x}{perms}")


        else:
            print(f"unknown command: {arg}")

class ELFMetadataPrinterLocator(PrettyPrinter):
    def __init__(self, et):
        self.et = et
        super().__init__("elf-pretty-printers", [])

    def __call__(self, val):
        typename = gdb.types.get_basic_type(val.type).tag
        if typename is None:
            typename = val.type.name
        if typename in ["Elf64_Xword", "Elf64_Sxword", "Elf64_Addr", "Elf64_Off"]:
            return Hex64PrettyPrinter(val)
        elif typename in ["Elf64_Word", "Elf64_Sword"]:
            return Hex32PrettyPrinter(val)
        elif typename in ["Elf64_Half", "Elf64_Section", "Elf64_Versym"]:
            return Hex16PrettyPrinter(val)
        elif typename in ["Elf64_Rel", "Elf64_Rela"]:
            return RelPrinter(val, et)
        elif typename in ["Elf64_Sym"]:
            return SymPrinter(val, et)


class _PPrinter():
    def __init__(self, val):
        self._val = val


class SymPrinter(_PPrinter):
    """ pretty print relocation entry"""
    def __init__(self, val, et, string_table=None):
        self.__et = et
        self.__string_table = None
        super().__init__(val)

    def symbol_string(self):
        offset = int(str(self._val['st_name']), 0)
        s = f"name-offset={offset} "

        elffile =  self.__et.elffile
        if not elffile:
            return s
        addr = self._val.address
        if addr is None:
            return s

        sec = self.__et.va_to_section_header(int(str(addr), 0))
        if sec is None:
            return s

        linked = elffile.get_section(sec.header["sh_link"])

        if not linked:
            return s

        stringtable_va = self.__et.file_offset_to_va(linked.header["sh_offset"])
        if not stringtable_va:
            return s
        strva = stringtable_va + offset

        symname = gdb.parse_and_eval(f"(char *) 0x{strva:x}")
        return f"symbol-name='{symname.string()}' "

    def to_string(self):
        s = self.symbol_string()

        st_info = struct.unpack("B", self._val['st_info'].bytes)[0]
        typ = st_info & 0xf
        bind = st_info >> 4

        s += f"type={st_info_type_rev.get(typ, '<unknown>')} "
        s += f"bind={st_info_bind_rev.get(bind, '<unknown>')} "

        stother_val = struct.unpack("B", self._val['st_other'].bytes)[0]

        v = st_other_vis_rev.get(stother_val & 0x5, '<unknown>')

        s += f"visibility={v} "
        local = (stother_val >> 5) & (~0x3)
        s += f"local={local} "

        shndx = int(str(self._val['st_shndx']), 0)
        s += f"shndx={st_shndx_rev.get(shndx, shndx)} "
        s += f"value={self._val['st_value']} "
        s += f"size={self._val['st_size']}"

        return s


class RelPrinter(_PPrinter):
    """ pretty print relocation entry"""
    def __init__(self, val, et):
        self.__et = et
        super().__init__(val)

    def symbol_string(self):
        elffile =  self.__et.elffile
        r_info = int(str(self._val['r_info']), 0)
        symnum = r_info >> 32
        symstr = f"symbol-index={symnum} "
        addr = self._val.address
        if addr is None or elffile is None or symnum == 0:
            return symstr

        sec = self.__et.va_to_section_header(int(str(addr), 0))
        if sec is None:
            return symstr
        styp = gdb.lookup_type("Elf64_Sym")
        symsize = styp.sizeof
        linked = elffile.get_section(sec.header["sh_link"])
        linked_offset = linked.header["sh_offset"]
        symbol_table_va = self.__et.file_offset_to_va(linked_offset)
        if not symbol_table_va:
            return symstr
        # find and parse symbol in memory
        symval = gdb.parse_and_eval(f"*((Elf64_Sym *) 0x{symbol_table_va + (symnum * symsize):x})")
        if not symval:
            return symstr
        nameidx = int(str(symval["st_name"]), 0)
        # now look up string table in memory

        strtab = elffile.get_section(linked.header["sh_link"])
        strtabva = self.__et.file_offset_to_va(strtab["sh_offset"])
        if not strtabva:
            return symstr
        strva = strtabva + nameidx
        symname = gdb.parse_and_eval(f"(char *) 0x{strva:x}")
        return f"symbol-name='{symname.string()}' " + symstr

    def to_string(self):
        s = f"address={self._val['r_offset']} "
        r_info = int(str(self._val['r_info']), 0)

        s += self.symbol_string()

        typ = r_info & 0xffffffff
        elffile =  self.__et.elffile
        if elffile:
            typestr = describe_reloc_type(typ, elffile)
        else:
            typestr = f"0x{typ:x}"
        s += f"type={typestr}"
        if hasattr(self._val, "r_addend"):
            addend = self._val['r_addend']
            if addend:
                s += f"addend=+{addend}"
        return s


class Hex64PrettyPrinter(_PPrinter):
    """pretty print value as hex"""
    FMT = struct.Struct("<Q")

    def to_string(self):
        #bytes object containing the bytes that make up this Value’s complete
        #value in little endian order

        return f"0x{self.FMT.unpack(self._val.bytes)[0]:x}"


class FileOffsetPrettyPrinter(_PPrinter):
    """pretty print file offset"""
    FMT = struct.Struct("<Q")

    def to_string(self):
        #bytes object containing the bytes that make up this Value’s complete
        #value in little endian order
        return f"+({self.FMT.unpack(self._val.bytes)[0]})"


class Hex32PrettyPrinter(Hex64PrettyPrinter):
    """pretty print value as hex"""
    FMT = struct.Struct("<L")


class Hex16PrettyPrinter(Hex64PrettyPrinter):
    """pretty print value as hex"""
    FMT = struct.Struct("<H")


class Hex8PrettyPrinter(Hex64PrettyPrinter):
    """pretty print value as hex"""
    FMT = struct.Struct("<B")


et = ELFTable()
register_pretty_printer(None, ELFMetadataPrinterLocator(et), replace=True)
structs = Path(__file__).parent / Path("structs.o")
# load object file that contains elf structure definitions
gdb.execute(f"add-symbol-file {structs} 0")
