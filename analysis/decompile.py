import r2pipe
import sys

def decompile_binary(binary):
    r2 = r2pipe.open(binary)
    r2.cmd("aaa")
    fcts = r2.cmdj("aflj")
    if not fcts:
        print("No functions found or analysis failed :<")
        r2.quit()
        return

    o = f"{binary}de.c"
    with open(o, 'w') as f:
        for fct in fcts:
            name = fct.get("name", "unknown")
            addr = fct.get("addr", 0)
            f.write(f"/* Function {name} at 0x{addr:x} */\n")
            r2.cmd(f"s 0x{addr:x}")
            decompiled = r2.cmd("pdg")
            f.write(decompiled if decompiled else "/* Failed to decompiled function */\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decompile.py <binary>")
        sys.exit(1)
    decompile_binary(sys.argv[1])
