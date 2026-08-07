#!/usr/bin/env python3
"""Generate the Win64 MASM backend from the checked-in qhasm/GAS output.

The instruction bodies stay mechanically identical.  This generator changes
the assembly spelling and adds a Microsoft x64 ABI prologue/epilogue around
each leaf routine.  Run it from this directory after changing a .s source.
"""

from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "edwards25519_win64.asm"

DATA_SOURCES = ["consts.s", "consts4x.s"]
CODE_SOURCES = [
    "fe25519_freeze.s",
    "fe25519_mul.s",
    "fe25519_nsquare.s",
    "fe25519_square.s",
    "ge25519_add_p1p1.s",
    "ge25519_dbl_p1p1.s",
    "ge25519_lookup.s",
    "ge25519_lookup_niels.s",
    "ge25519_nielsadd2.s",
    "ge25519_p1p1_to_p2.s",
    "ge25519_p1p1_to_p3.s",
    "ge4x_add_p1p1.s",
    "ge4x_double_p1p1.s",
    "ge4x_lookup.s",
    "ge4x_lookup_niels.s",
    "ge4x_niels_add_p1p1.s",
    "gfe4x_add.s",
    "gfe4x_mul.s",
    "gfe4x_square.s",
    "gfe4x_sub.s",
]

GPR_NONVOLATILE = ["rdi", "rsi", "rbx", "rbp", "r12", "r13", "r14", "r15"]
SUFFIXED_OPS = {
    "addq": "add",
    "imulq": "imul",
    "leaq": "lea",
    "movq": "mov",
    "movsbq": "movsx",
    "movzbq": "movzx",
    "mulq": "mul",
    "subq": "sub",
}


def hex_masm(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        digits = match.group(1).upper()
        return "0" + digits + "h"

    return re.sub(r"0x([0-9A-Fa-f]+)", replace, value)


def split_operands(text: str) -> list[str]:
    return [part.strip() for part in text.split(",")]


def memory_operand(operand: str) -> str:
    match = re.fullmatch(r"([^()]*)\(([a-z0-9]+)\)", operand)
    if not match:
        return operand
    displacement, base = match.groups()
    if base == "rip":
        return f"[{displacement}]"
    if not displacement or displacement == "0":
        return f"[{base}]"
    if displacement.startswith("-"):
        return f"[{base}{displacement}]"
    return f"[{base}+{displacement}]"


def operand_masm(operand: str, mnemonic: str) -> str:
    operand = operand.replace("%", "").replace("$", "")
    operand = memory_operand(operand)
    operand = hex_masm(operand)
    if mnemonic == "movsx" and operand.startswith("["):
        operand = "BYTE PTR " + operand
    elif mnemonic == "movzx" and operand.startswith("["):
        operand = "BYTE PTR " + operand
    elif mnemonic == "mul" and operand.startswith("["):
        operand = "QWORD PTR " + operand
    elif mnemonic == "vbroadcastsd" and operand.startswith("["):
        operand = "QWORD PTR " + operand
    elif mnemonic.startswith("v") and operand.startswith("["):
        operand = "YMMWORD PTR " + operand
    return operand


def instruction_masm(line: str, local_prefix: str) -> str:
    label_match = re.fullmatch(r"([._A-Za-z][._A-Za-z0-9]*):", line)
    if label_match:
        label = label_match.group(1)
        if label.startswith("."):
            label = local_prefix + label[1:]
        return label + ":"

    parts = line.split(None, 1)
    mnemonic = SUFFIXED_OPS.get(parts[0], parts[0])
    operands = split_operands(parts[1]) if len(parts) == 2 else []
    operands = [
        (local_prefix + op[1:]) if op.startswith(".") else op for op in operands
    ]
    operands = [operand_masm(op, mnemonic) for op in reversed(operands)]
    return "    " + mnemonic + (" " + ", ".join(operands) if operands else "")


def actual_lines(source: Path) -> list[str]:
    result = []
    for raw in source.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or (line.startswith(".") and not line.endswith(":")):
            continue
        result.append(line)
    return result


def data_block() -> tuple[list[str], set[str]]:
    output = [".const", "ALIGN 16"]
    labels: set[str] = set()
    for filename in DATA_SOURCES:
        for raw in (HERE / filename).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):\s+\.(quad|double)\s+(.+)", line)
            if not match:
                continue
            label, kind, values_text = match.groups()
            labels.add(label)
            values = split_operands(values_text)
            if kind == "double":
                values = [
                    "0%016Xh" % struct.unpack("<Q", struct.pack("<d", float(value)))[0]
                    for value in values
                ]
            else:
                values = [hex_masm(value) for value in values]
            output.append(f"{label} DQ " + ", ".join(values))
    return output, labels


def function_name(source: Path) -> str:
    globals_ = re.findall(r"^\.(?:globl|global)\s+([A-Za-z_][A-Za-z0-9_]*)", source.read_text(encoding="utf-8"), re.M)
    public = [name for name in globals_ if not name.startswith("_")]
    if len(public) != 1:
        raise RuntimeError(f"expected one undecorated public symbol in {source.name}: {public}")
    return public[0]


def stack_bytes(lines: list[str], source: Path) -> int:
    for index in range(len(lines) - 3):
        if lines[index:index + 2] == ["mov %rsp,%r11", "and $31,%r11"]:
            match = re.fullmatch(r"add \$([0-9]+),%r11", lines[index + 2])
            if not match or lines[index + 3] != "sub %r11,%rsp":
                raise RuntimeError(f"unrecognized qhasm entry in {source.name}")
            del lines[index:index + 4]
            return int(match.group(1))
    raise RuntimeError(f"qhasm entry not found in {source.name}")


def function_block(source: Path) -> list[str]:
    name = function_name(source)
    lines = actual_lines(source)
    while lines and lines[0].endswith(":"):
        lines.pop(0)
    body_stack = stack_bytes(lines, source)
    if not lines or lines[-1] != "ret":
        raise RuntimeError(f"unrecognized qhasm exit in {source.name}: {lines[-3:]}")
    lines.pop()
    try:
        exit_adjust = len(lines) - 1 - lines[::-1].index("add %r11,%rsp")
    except ValueError as error:
        raise RuntimeError(f"qhasm stack restore not found in {source.name}") from error
    del lines[exit_adjust]

    text = "\n".join(lines)
    saved_gprs = [reg for reg in GPR_NONVOLATILE if f"%{reg}" in text]
    # rdi/rsi hold the first two System-V arguments even if a particular body
    # happens not to mention one of them after qhasm optimization.
    for reg in ("rdi", "rsi"):
        if reg not in saved_gprs:
            saved_gprs.insert(0 if reg == "rdi" else 1, reg)
    saved_xmms = sorted({
        int(index) for index in re.findall(r"%[xy]mm(\d+)", text) if int(index) >= 6
    })

    before_alloc_mod16 = (8 - 8 * len(saved_gprs)) % 16
    total_stack = body_stack + 16 * len(saved_xmms)
    total_stack += (before_alloc_mod16 - total_stack) % 16
    xmm_base = body_stack

    out = ["", "ALIGN 16", f"PUBLIC {name}", f"{name} PROC FRAME"]
    for reg in saved_gprs:
        out.extend([f"    push {reg}", f"    .pushreg {reg}"])
    if total_stack:
        out.extend([f"    sub rsp, {total_stack}", f"    .allocstack {total_stack}"])
    for offset_index, xmm in enumerate(saved_xmms):
        offset = xmm_base + 16 * offset_index
        out.extend([
            f"    vmovdqu XMMWORD PTR [rsp+{offset}], xmm{xmm}",
            f"    .savexmm128 xmm{xmm}, {offset}",
        ])
    out.extend([
        "    .endprolog",
        "    mov rdi, rcx",
        "    mov rsi, rdx",
        "    mov rdx, r8",
    ])

    local_prefix = "L_" + name + "_"
    for line in lines:
        translated = instruction_masm(line, local_prefix)
        # The qhasm lookup buffers are only guaranteed 16-byte aligned by the
        # Win64 ABI frame.  Unaligned loads are equivalent on this cold path.
        if "[" in translated:
            translated = translated.replace("vmovapd", "vmovupd")
        out.append(translated)

    if saved_xmms:
        out.append("    vzeroupper")
    for offset_index, xmm in reversed(list(enumerate(saved_xmms))):
        offset = xmm_base + 16 * offset_index
        out.append(f"    vmovdqu xmm{xmm}, XMMWORD PTR [rsp+{offset}]")
    if total_stack:
        out.append(f"    add rsp, {total_stack}")
    for reg in reversed(saved_gprs):
        out.append(f"    pop {reg}")
    out.extend(["    ret", f"{name} ENDP"])
    return out


def main() -> None:
    data, local_data = data_block()
    rip_symbols: set[str] = set()
    for filename in CODE_SOURCES:
        text = (HERE / filename).read_text(encoding="utf-8")
        rip_symbols.update(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\(%rip\)", text))
    externs = sorted(rip_symbols - local_data)

    output = [
        "; Generated by generate_win64_asm.py. Do not edit by hand.",
        "; Public-domain qhasm instruction bodies, adapted to Microsoft x64.",
        "OPTION CASEMAP:NONE",
        "OPTION DOTNAME",
        "",
    ]
    output.extend(f"EXTERN {symbol}:BYTE" for symbol in externs)
    output.extend(["", *data, "", ".code"])
    for filename in CODE_SOURCES:
        output.extend(function_block(HERE / filename))
    output.extend(["", "END", ""])
    OUTPUT.write_text("\n".join(output), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
