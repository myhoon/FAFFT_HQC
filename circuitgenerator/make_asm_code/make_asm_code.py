import re
import math
import sys

# Global variables: available r registers, current allocation status, and the list of generated assembly instructions
available_r = ['r{}'.format(i) for i in range(12)]
reg_alloc = {}  # key: x index, value: allocated r register name
asm = []        # List to store generated assembly instructions

def next_usage(x, curr_index, ops):
    """Returns the index of the next operation where x is used, or math.inf if not used again."""
    for i in range(curr_index + 1, len(ops)):
        dest, src = ops[i]
        if dest == x or src == x:
            return i
    return math.inf

def allocate_register(x, curr_index, ops, forbidden=[]):
    """Allocates an r register for x or spills another if all are used (excluding forbidden)."""
    global available_r, reg_alloc, asm

    if x in reg_alloc:
        return reg_alloc[x]
    if available_r:
        r = available_r.pop(0)
        asm.append(f"vmov {r}, s{x}    @ load x[{x}] from s{x}")
        reg_alloc[x] = r
        return r
    candidates = []
    for x_i, r_reg in reg_alloc.items():
        if x_i in forbidden:
            continue
        usage = next_usage(x_i, curr_index, ops)
        candidates.append((x_i, r_reg, usage))
    if not candidates:
        raise Exception("No registers to spill outside of operands for current operation.")
    spill_x, r_spill, usage = max(candidates, key=lambda item: item[2])
    asm.append(f"vmov s{spill_x}, {r_spill}    @ spill x[{spill_x}] from {r_spill}")
    available_r.append(r_spill)
    del reg_alloc[spill_x]
    r = available_r.pop(0)
    asm.append(f"vmov {r}, s{x}    @ load x[{x}] from s{x}")
    reg_alloc[x] = r
    return r

def process_xor(dest, src, curr_index, ops):
    """Generates vmov/eor instructions for x[dest] = x[dest] ^ x[src]."""
    forbidden = [dest, src]
    r_dest = allocate_register(dest, curr_index, ops, forbidden)
    r_src  = allocate_register(src, curr_index, ops, forbidden)
    asm.append(f"eor {r_dest}, {r_dest}, {r_src}    @ x[{dest}] = x[{dest}] ^ x[{src}]")

def generate_asm(xor_ops):
    """Generates assembly instructions for a list of XOR operations."""
    global available_r, reg_alloc, asm
    available_r = ['r{}'.format(i) for i in range(12)]
    reg_alloc = {}
    asm = []
    for i, (dest, src) in enumerate(xor_ops):
        process_xor(dest, src, i, xor_ops)
    return asm

def final_store(store_ops):
    """Generates final STR or VSTR instructions for storing values into y[]."""
    global asm, reg_alloc
    store_lines = []
    for y_idx, x_idx in store_ops:
        offset = y_idx * 4
        if x_idx in reg_alloc:
            store_lines.append((y_idx, f"str  {reg_alloc[x_idx]}, [r14, #{offset}]    @ y[{y_idx}] = x[{x_idx}] from {reg_alloc[x_idx]}"))
        else:
            store_lines.append((y_idx, f"vstr.32  s{x_idx}, [r14, #{offset}]    @ y[{y_idx}] = x[{x_idx}] from s{x_idx}"))
    store_lines.sort(key=lambda t: t[0])
    for _, line in store_lines:
        asm.append(line)

def parse_input(input_str):
    """Parses input text and returns XOR and store operation tuples."""
    xor_ops = []
    store_ops = []
    lines = input_str.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('@'):
            continue
        m = re.match(r"x\[(\d+)\]\s*=\s*x\[(\d+)\]\s*\^\s*x\[(\d+)\];", line)
        if m:
            dest = int(m.group(1))
            src = int(m.group(3))
            xor_ops.append((dest, src))
            continue
        m = re.match(r"y\[(\d+)\]\s*=\s*x\[(\d+)\];", line)
        if m:
            y_idx = int(m.group(1))
            x_idx = int(m.group(2))
            store_ops.append((y_idx, x_idx))
            continue
        print("Unrecognized line:", line)
    return xor_ops, store_ops

def wrap_function(func_name, body_asm):
    """Wraps the body assembly instructions into a complete function."""
    wrapped = []
    wrapped.append(".syntax unified")
    wrapped.append(".cpu cortex-m4")
    wrapped.append(".fpu fpv4-sp-d16")
    wrapped.append(f".global {func_name}")
    wrapped.append(f".type {func_name}, %function")
    wrapped.append(".align 2")
    wrapped.append(f"{func_name}:")
    wrapped.append("push { r0-r12, r14 }")
    wrapped.append("vpush {d8-d15}")
    wrapped.append("mov  r14, r0")
    wrapped.append("mov  r12, r1")
    for i in range(32):
        offset = i * 4
        wrapped.append(f"vldr.32 s{i}, [r12, #{offset}]")
    wrapped.extend(body_asm)
    wrapped.append("vpop { d8-d15 }")
    wrapped.append("pop { r0-r12, r14 }")
    wrapped.append("bx lr")
    wrapped.append(f".size   {func_name}, .-{func_name}")
    return wrapped

if __name__ == '__main__':
    if len(sys.argv) > 2:
        filename = sys.argv[1]
        func_name = sys.argv[2]
    elif len(sys.argv) > 1:
        filename = sys.argv[1]
        func_name = "generated_function"
    else:
        filename = "input.txt"
        func_name = "generated_function"
    with open(filename, "r", encoding="utf-8") as f:
        input_code = f.read()
    xor_ops, store_ops = parse_input(input_code)
    generate_asm(xor_ops)
    if store_ops:
        final_store(store_ops)
    else:
        for i in range(32):
            asm.append(f"vstr.32  s{i}, [r14, #{i*4}]    @ y[{i}] = x[{i}] from s{i}")
    final_body = asm[:]
    wrapped_code = wrap_function(func_name, final_body)
    output_filename = f"{func_name}.s"
    with open(output_filename, "w", encoding="utf-8") as out:
        out.write("\n".join(wrapped_code))
        
# Usage example: python3 make_asm_code_txt.py v28.txt gft_mul_v28