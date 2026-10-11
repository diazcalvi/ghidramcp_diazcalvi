"""Differential test for PC 0x864fb0 against a read-only exact-hash EXE."""
import argparse
import ctypes
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EFLAGS, UC_X86_REG_ESI, UC_X86_REG_ESP

ROOT = Path(__file__).resolve().parent
EXPECTED = "f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a"
FUNCTION = 0x864FB0
BASE_GETTER = 0x866D20
BASE_GLOBAL = 0x1132068
STACK = 0x2000000
RETURN = STACK + 0x100


def compile_library(output):
    source = ROOT / "pes6_team_info_address.c"
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler:
        subprocess.run(
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-shared", "-fPIC", str(source), "-o", str(output)],
            check=True,
        )
        return

    vs_root = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio"
    candidates = list(vs_root.glob("*/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"))
    candidates += list(vs_root.glob("*/Community/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"))
    cl = next((p for p in candidates if p.is_file()), None)
    if cl:
        vcvars = cl.parents[6] / "Auxiliary" / "Build" / "vcvars64.bat"
        if not vcvars.is_file():
            raise RuntimeError(f"Found cl.exe but not vcvars64.bat: {vcvars}")
        batch = output.parent / "build.cmd"
        batch.write_text(
            "\r\n".join([
                f'@call "{vcvars}" >nul',
                "@if errorlevel 1 exit /b %errorlevel%",
                f'@"{cl}" /nologo /O2 /W4 /WX /LD "{source}" /link /OUT:"{output}"',
                "",
            ]),
            encoding="ascii",
        )
        subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=output.parent, check=True)
        return

    raise RuntimeError("No existing GCC, Clang, or Visual Studio C compiler is available")


def va_to_offset(info, va):
    section = next(
        item for item in info["sections"]
        if int(item["address"], 16) <= va < int(item["address"], 16) + item["file_size"]
    )
    return section["file_offset"] + va - int(section["address"], 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="read-only exact-hash PES6 PC executable")
    args = parser.parse_args()
    raw = args.binary.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == EXPECTED, (digest, EXPECTED)

    import sys
    sys.path.insert(0, str(ROOT.parent))
    from inspect_pe import inspect
    pe = inspect(args.binary)
    function_offset = va_to_offset(pe, FUNCTION)
    getter_offset = va_to_offset(pe, BASE_GETTER)

    temp_root = os.environ.get("PES6_PORT_TEMP")
    if temp_root is None and os.name == "nt":
        temp_root = r"C:\Users\Owner\AppData\Local\Temp"
    with tempfile.TemporaryDirectory(prefix="pes6-team-info-address-", dir=temp_root) as temp:
        library_path = Path(temp) / ("pes6_team_info_address.dll" if os.name == "nt" else "libpes6_team_info_address.so")
        compile_library(library_path)
        library = ctypes.CDLL(str(library_path))
        function = library.pes6_pc_team_info_address
        function.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        function.restype = ctypes.c_uint32

        machine = Uc(UC_ARCH_X86, UC_MODE_32)
        for address in (0x864000, 0x865000, 0x866000, 0x1132000):
            machine.mem_map(address, 4096)
        machine.mem_map(STACK - 0x1000, 0x2000)
        machine.mem_write(FUNCTION, raw[function_offset:function_offset + 0x33])
        machine.mem_write(BASE_GETTER, raw[getter_offset:getter_offset + 6])

        rng = random.Random(FUNCTION)
        cases = 0
        for low in range(0x10000):
            team_id = (rng.getrandbits(16) << 16) | low
            base = rng.getrandbits(32)
            if low % 7 == 0:
                base = 0
            machine.mem_write(BASE_GLOBAL, struct.pack("<I", base))
            machine.mem_write(STACK, struct.pack("<I", RETURN))
            machine.reg_write(UC_X86_REG_ESP, STACK)
            machine.reg_write(UC_X86_REG_EAX, team_id)
            machine.reg_write(UC_X86_REG_ESI, rng.getrandbits(32))
            initial_esi = machine.reg_read(UC_X86_REG_ESI)
            machine.reg_write(UC_X86_REG_EFLAGS, 2)
            machine.emu_start(FUNCTION, RETURN, count=64)
            assert machine.reg_read(UC_X86_REG_ESP) == STACK + 4
            assert machine.reg_read(UC_X86_REG_ESI) == initial_esi
            assert struct.unpack("<I", bytes(machine.mem_read(BASE_GLOBAL, 4)))[0] == base
            assert struct.unpack("<I", bytes(machine.mem_read(STACK, 4)))[0] == RETURN
            original = machine.reg_read(UC_X86_REG_EAX)
            translated = function(team_id, base)
            assert translated == original, (hex(team_id), hex(base), hex(translated), hex(original))
            cases += 1

        if os.name == "nt":
            free_library = ctypes.windll.kernel32.FreeLibrary
            free_library.argtypes = [ctypes.c_void_p]
            free_library.restype = ctypes.c_int
            assert free_library(library._handle)

    result = {
        "reference_sha256": digest,
        "reference_function": hex(FUNCTION),
        "base_global": hex(BASE_GLOBAL),
        "cases": cases,
        "passed": True,
        "seed": hex(FUNCTION),
        "coverage": ["all 65536 low-word IDs", "randomized ignored upper words",
                     "randomized 32-bit table bases including null", "range and stride arithmetic",
                     "callee-saved ESI", "stack and global unchanged", "return value"],
        "limitation": "The semantic identity of the records at this base remains unresolved.",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
