#!/usr/bin/env python3

import gdb
import subprocess

class LoadExecutableSymbols(gdb.Breakpoint):
    def __init__(self, spec="_dl_start_user", *args, **kwargs):
        super().__init__(spec, *args, **kwargs)

    def stop(self):
        self.enabled = False
        run_args = gdb.parameter("args")
        binname = None
        startaddr = None
        if len(run_args) > 2:
            binname = run_args.split()[2]

        if binname:
            mappings = gdb.execute("info proc mappings", to_string=True)

            for m in mappings.split("\n"):
                if m.strip().endswith(f" {binname}"):
                    # first column is start address
                    startaddr = m.split()[0]
                    break
        # load symbols from ELF executable
        if startaddr:
            gdb.execute(f"add-symbol-file {binname} -o {startaddr}")
            gdb.execute("break main")
            # now lookup address of plt
            pltstart = None
            p = subprocess.run(["objdump", "-w", "--section=.plt", "-h", binname],
                               capture_output=True, text=True)
            for line in p.stdout.split("\n"):
                parts = line.split()
                if len(parts) > 3:
                    if parts[1] == ".plt":
                        pltstart = int(parts[3], 16)
                        break
            if pltstart is not None:
                startint = int(startaddr, 16) + pltstart
                gdb.execute(f"break *0x{startint:x}")

        else:
            print(f"Could not locate binary {binname} in memory map in order to load symbols")
            print("Try using `info proc mappings` to lookup the base address of the executable")
            print(f"and then load the symbols using: `add-symbol-file {binname} -o <start address>`")
            return True


        return False

LoadExecutableSymbols()
