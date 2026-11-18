import r2pipe
import json
import sys

def offset(binary):
    r2 = r2pipe.open(binary)
    r2.cmd("aaa")

    # Get architecture
    info = r2.cmdj("ij") or {}
    ptr_size = 8 if info.get("bin", {}).get("bits", 64) else 4

    # Get functions
    fcts = r2.cmdj("aflj")
    if not fcts:
        print("No functions found or analysis failed :<")
        r2.quit()
        return

    [print(f"{idx}   {fct.get("name", "unknown"):<40} {hex(fct.get("addr", 0)):<20}") for idx, fct in enumerate(fcts)]
    try:
        selected = fcts[int(input("Enter the index of the function to analyze: "))]
    except:
        print("Invalid :<")
        r2.quit()
        return

    fname = selected.get("name")
    faddr = selected.get("addr")

    # Seek to function and run frame analysis
    r2.cmd(f"s {faddr}")
    r2.cmd("af")
    
    # Get local vars for this function -> Stack vars
    fvars = r2.cmdj("afvj")
    if not fvars:
        print("No variables found or analysis failed :<")
        r2.quit()
        return

    # TODO: Add stack vars -> Choose buffer -> Find padding to RET
