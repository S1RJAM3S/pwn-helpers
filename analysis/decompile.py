import r2pipe
import sys

def decompile_binary(binary):
    r = r2pipe.open(binary)
    r.cmd("aaa")
    fcts = r.cmdj("aflj")
    if not fcts:
        print("No functions found or analysis failed :<")
        return

    o = f"{binary}de.c"
    with open(o, 'w') as f:
        for fct in fcts:
            name = fct.get("name", "unknown")
            addr = fct.get("addr", 0)
            f.write(f"/* Function {name} at 0x{addr:x} */\n")
            r.cmd(f"s 0x{addr:x}")
            decompiled = r.cmd("pdg")
            f.write(decompiled if decompiled else "/* Failed to decompiled function */\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decompile.py <binary>")
        sys.exit(1)
    decompile_binary(sys.argv[1])
