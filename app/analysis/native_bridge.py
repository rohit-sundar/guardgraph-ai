"""
JNI / native library bridge resolution.

Resolves System.loadLibrary(String) / Runtime.loadLibrary(String) call
targets via the shared static-resolution engine, locates the matching
lib*.so inside the APK (checking non-standard locations like assets/, not
just lib/<abi>/ — disguised .so placement under assets/ is an evasion
pattern this project's own corpus already surfaced), and reads its ELF
dynamic symbol table via pyelftools to correlate against the DEX's
`native`-flagged method declarations.

A file matching the library name is not guaranteed to be a real ELF at
all — a decoy/encrypted payload with a `.so` extension exists in this
project's own malware corpus (confirmed: an 8KB "lib9.so" under assets/
whose first four bytes are not \\x7fELF). Anything that doesn't parse as
ELF is reported as such, not silently skipped.

Explicitly NOT implemented: mapping WHICH native method belongs to WHICH
loaded library. That requires resolving JNI_OnLoad's RegisterNatives calls
inside the .so itself — real native disassembly, out of scope here — so
native-flagged DEX methods are reported app-wide, not split per library.

Also reads the .dynsym table's UNDEFINED (imported) symbols — the libc/
OpenSSL functions this library calls out to — as a cheap substitute for
real disassembly. This says "this native code can open sockets" without
knowing what it does with them; deliberately a capability signal, not
behavior analysis.
"""
import io
from dataclasses import dataclass, field

import networkx as nx

from app.analysis.static_resolution import resolve_invocations

LOAD_LIBRARY_APIS = (
    "Ljava/lang/System;->loadLibrary",
    "Ljava/lang/Runtime;->loadLibrary",
)

# Curated, not exhaustive — imported libc/OpenSSL symbols whose mere presence
# is a meaningful capability signal even without knowing how they're used.
# Grouped for readability in describe(); the grouping itself isn't used for
# scoring, only the flat set of matched names.
RISKY_IMPORTS = {
    "network": {"connect", "socket", "send", "sendto", "recv", "recvfrom", "getaddrinfo"},
    "process/exec": {"system", "fork", "execve", "execl", "popen", "dlopen"},
    "crypto": {
        "EVP_EncryptUpdate", "EVP_DecryptUpdate", "EVP_CipherInit",
        "AES_encrypt", "AES_decrypt", "MD5_Update", "SHA1_Update",
    },
}
_RISKY_IMPORT_NAMES = frozenset(name for group in RISKY_IMPORTS.values() for name in group)


@dataclass
class NativeBridgeFinding:
    library_name: str
    resolved_so_path: str | None = None
    is_valid_elf: bool | None = None  # None = no matching .so found in the APK at all
    dynsym_count: int = 0
    java_prefixed_symbols: list = field(default_factory=list)
    declared_native_methods: list = field(default_factory=list)
    risky_imports: list = field(default_factory=list)

    def describe(self) -> str:
        if self.resolved_so_path is None:
            return f'System.loadLibrary("{self.library_name}") — no matching lib*.so found in the APK'
        if self.is_valid_elf is False:
            return (
                f'System.loadLibrary("{self.library_name}") -> {self.resolved_so_path} — '
                f'NOT a valid ELF (possible decoy/encrypted payload disguised as a native library)'
            )
        parts = [
            f'System.loadLibrary("{self.library_name}") -> {self.resolved_so_path}',
            f'{self.dynsym_count} dynamic symbols',
        ]
        if self.java_prefixed_symbols:
            parts.append(f'JNI exports: {", ".join(self.java_prefixed_symbols[:6])}')
        if self.declared_native_methods:
            parts.append(
                f'{len(self.declared_native_methods)} native-flagged DEX methods declared app-wide '
                f'(no Java_-symbol export found — likely registered via JNI_OnLoad/RegisterNatives)'
                if not self.java_prefixed_symbols else
                f'{len(self.declared_native_methods)} native-flagged DEX methods declared app-wide'
            )
        if self.risky_imports:
            parts.append(f'imports: {", ".join(self.risky_imports)}')
        return " — ".join(parts)


def _find_library_file(apk_obj, library_name: str) -> str | None:
    if apk_obj is None:
        return None
    candidates = {f"lib{library_name}.so", f"{library_name}.so"}
    try:
        all_files = list(apk_obj.get_files())
    except Exception:
        return None
    for f in all_files:
        if f.rsplit("/", 1)[-1] in candidates:
            return f
    return None


def _parse_elf_dynsym(raw: bytes) -> tuple[bool, int, list[str], list[str]]:
    if raw[:4] != b"\x7fELF":
        return False, 0, [], []
    try:
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(raw))
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            return True, 0, [], []
        names = []
        risky_imports = set()
        for s in dynsym.iter_symbols():
            if not s.name:
                continue
            names.append(s.name)
            # Undefined (SHN_UNDEF) = imported from elsewhere at load time, not
            # implemented in this library — an import, not an export.
            if s.entry.st_shndx == "SHN_UNDEF" and s.name in _RISKY_IMPORT_NAMES:
                risky_imports.add(s.name)
        java_syms = sorted(n for n in names if n.startswith("Java_"))
        return True, len(names), java_syms, sorted(risky_imports)
    except Exception:
        return False, 0, [], []


def _declared_native_methods(analysis_obj) -> list[str]:
    if analysis_obj is None:
        return []
    names = []
    try:
        for m in analysis_obj.get_methods():
            em = m.get_method()
            flags = (em.get_access_flags_string() or "").lower()
            if "native" in flags:
                names.append(str(em).split(" [access_flags", 1)[0])
    except Exception:
        pass
    return names


def resolve_native_bridges(
    cfgs: dict[str, nx.DiGraph], apk_obj=None, analysis_obj=None
) -> list[NativeBridgeFinding]:
    """
    Resolves System/Runtime.loadLibrary(name) call targets, matches them
    against .so files packaged in the APK, and reads dynamic symbols where
    the matched file is a genuine ELF.
    """
    findings: list[NativeBridgeFinding] = []
    seen_libraries: set[str] = set()
    declared_native: list[str] | None = None

    for event in resolve_invocations(cfgs):
        if not any(api in event.target_api for api in LOAD_LIBRARY_APIS):
            continue
        arg0 = event.arg(0)
        if not (arg0 and arg0[0] == "literal"):
            continue
        library_name = arg0[1]
        if library_name in seen_libraries:
            continue
        seen_libraries.add(library_name)

        so_path = _find_library_file(apk_obj, library_name)
        finding = NativeBridgeFinding(library_name=library_name, resolved_so_path=so_path)
        if so_path is not None:
            try:
                raw = apk_obj.get_file(so_path)
            except Exception:
                raw = b""
            is_elf, count, java_syms, risky_imports = _parse_elf_dynsym(raw)
            finding.is_valid_elf = is_elf
            finding.dynsym_count = count
            finding.java_prefixed_symbols = java_syms
            finding.risky_imports = risky_imports
            if is_elf:
                if declared_native is None:
                    declared_native = _declared_native_methods(analysis_obj)
                finding.declared_native_methods = declared_native
        findings.append(finding)

    return findings
