"""
Tests for the 4 remaining reverse-engineering features built on the shared
static_resolution engine: crypto config recovery, DCL tracing, WebView JS
bridge mapping, and native library bridge resolution.
"""
import io
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import networkx as nx

from app.analysis.cfg import enrich_acfg
from app.analysis.crypto_recovery import recover_crypto_configs
from app.analysis.dcl_tracing import trace_dcl_targets
from app.analysis.native_bridge import resolve_native_bridges
from app.analysis.webview_bridge import map_webview_bridges


class _FakeInstruction:
    def __init__(self, name: str, output: str):
        self._name, self._output = name, output

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output


class _FakeBlock:
    def __init__(self, instructions, start=0, end=1):
        self._instructions, self.start, self.end = instructions, start, end
        self.childs = []

    def get_instructions(self):
        return self._instructions


class _FakeBlocks:
    def __init__(self, blocks):
        self._blocks = blocks

    def get(self):
        return self._blocks


class _FakeMethod:
    def __init__(self, blocks_instructions: dict):
        self._blocks = _FakeBlocks([
            _FakeBlock(instrs, start=int(node_id), end=int(node_id) + 1)
            for node_id, instrs in blocks_instructions.items()
        ])

    def get_basic_blocks(self):
        return self._blocks


def _build_graph(node_instructions: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    for node_id in node_instructions:
        g.add_node(node_id)
    enrich_acfg(g, _FakeMethod(node_instructions))
    return g


# ── crypto recovery ──────────────────────────────────────────────────────────

def test_cipher_transformation_resolves_and_flags_ecb():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v0, "AES/ECB/PKCS5Padding"'),
            _FakeInstruction("invoke-static", "v0, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
        ],
    })
    findings = recover_crypto_configs({"Lcom/test/Fake;->m()V": g})

    assert len(findings) == 1
    assert findings[0].transformation == "AES/ECB/PKCS5Padding"
    assert any("ECB" in f for f in findings[0].weak_flags)


def test_secret_key_spec_resolves_algorithm_and_flags_key_present():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v2, "AES"'),
            _FakeInstruction("new-instance", "v0, Ljavax/crypto/spec/SecretKeySpec;"),
            _FakeInstruction("invoke-direct", "v0, v1, v2, Ljavax/crypto/spec/SecretKeySpec;-><init>([B Ljava/lang/String;)V"),
        ],
    })
    findings = recover_crypto_configs({"Lcom/test/Fake;->m()V": g})

    assert findings[0].algorithm == "AES"
    assert findings[0].key_material_present is True


# ── DCL tracing ───────────────────────────────────────────────────────────────

def test_dex_class_loader_path_resolves_and_matches_payload_asset():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v1, "config.json"'),
            _FakeInstruction("new-instance", "v0, Ldalvik/system/DexClassLoader;"),
            _FakeInstruction("invoke-direct", "v0, v1, v2, v3, v4, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V"),
        ],
    })
    findings = trace_dcl_targets({"Lcom/test/Fake;->m()V": g}, payload_assets=["assets/config.json"])

    assert findings[0].resolved_path == "config.json"
    assert findings[0].matches_known_asset is True


# ── WebView JS bridge mapping ────────────────────────────────────────────────

class _FakeMethodAnalysis:
    def __init__(self, name, flags):
        self._name, self._flags = name, flags

    def get_name(self):
        return self._name

    def get_access_flags_string(self):
        return self._flags


class _FakeClassMethodWrapper:
    def __init__(self, em):
        self._em = em

    def get_method(self):
        return self._em


class _FakeClassAnalysis:
    def __init__(self, methods):
        self._methods = methods

    def get_methods(self):
        return [_FakeClassMethodWrapper(m) for m in self._methods]


class _FakeAnalysisObj:
    def __init__(self, classes: dict):
        self._classes = classes

    def get_class_analysis(self, descriptor):
        return self._classes.get(descriptor)


def test_addjavascriptinterface_resolves_name_and_lists_public_methods():
    g = _build_graph({
        "0": [
            _FakeInstruction("new-instance", "v1, Lcom/evil/JsBridge;"),
            _FakeInstruction("const-string", 'v2, "Android"'),
            _FakeInstruction("invoke-virtual", "v0, v1, v2, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"),
        ],
    })
    fake_analysis = _FakeAnalysisObj({
        "Lcom/evil/JsBridge;": _FakeClassAnalysis([
            _FakeMethodAnalysis("<init>", "public constructor"),
            _FakeMethodAnalysis("readSms", "public"),
            _FakeMethodAnalysis("helper", "private"),
        ])
    })
    findings = map_webview_bridges({"Lcom/test/Fake;->m()V": g}, analysis_obj=fake_analysis)

    assert findings[0].interface_name == "Android"
    assert findings[0].exposed_class == "Lcom/evil/JsBridge;"
    assert findings[0].exposed_methods == ["readSms"]


# ── native bridge resolution ─────────────────────────────────────────────────

class _FakeApkObj:
    def __init__(self, files: dict):
        self._files = files

    def get_files(self):
        return list(self._files.keys())

    def get_file(self, name):
        return self._files[name]


def _minimal_elf_with_dynsym() -> bytes:
    """Not a full valid ELF — just enough to prove the magic-byte gate works."""
    return b"\x7fELF" + b"\x00" * 60


def _real_elf_with_dynsym(defined: list[str], undefined: list[str]) -> bytes:
    """
    A genuine, minimal, parseable 64-bit little-endian ELF with a real section
    header table and a real .dynsym/.dynstr pair — unlike
    `_minimal_elf_with_dynsym()` above (magic bytes only), this exercises
    pyelftools' actual section-walking path, which is what
    `_parse_elf_dynsym`'s import/export split depends on.

    `defined` symbols get a non-zero, non-special st_shndx (an ordinary
    section index — the value itself doesn't matter to the parser, only that
    it isn't SHN_UNDEF). `undefined` symbols get st_shndx=0 (SHN_UNDEF),
    which pyelftools decodes back to the string "SHN_UNDEF" — confirmed live
    against a real pyelftools install before writing this fixture.
    """
    def sym(name_off: int, shndx: int) -> bytes:
        STB_GLOBAL, STT_FUNC = 1, 2
        info = (STB_GLOBAL << 4) | STT_FUNC
        return struct.pack("<IBBHQQ", name_off, info, 0, shndx, 0, 0)

    dynstr = b"\x00"
    offsets = []
    for name in defined + undefined:
        offsets.append(len(dynstr))
        dynstr += name.encode() + b"\x00"

    dynsym = sym(0, 0)  # mandatory null symbol at index 0
    for name, off in zip(defined, offsets):
        dynsym += sym(off, shndx=1)
    for name, off in zip(undefined, offsets[len(defined):]):
        dynsym += sym(off, shndx=0)

    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    off_dynsym_name, off_dynstr_name, off_shstrtab_name = 1, 9, 17

    ehsize = 64
    dynsym_off = ehsize
    dynstr_off = dynsym_off + len(dynsym)
    shstrtab_off = dynstr_off + len(dynstr)
    shoff = shstrtab_off + len(shstrtab)

    def shdr(name, type_, link, entsize, offset, size) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, type_, 0, 0, offset, size, link, 1, 8, entsize)

    SHT_NULL, SHT_DYNSYM, SHT_STRTAB = 0, 11, 3
    sh_null = shdr(0, SHT_NULL, 0, 0, 0, 0)
    sh_dynsym = shdr(off_dynsym_name, SHT_DYNSYM, 2, 24, dynsym_off, len(dynsym))
    sh_dynstr = shdr(off_dynstr_name, SHT_STRTAB, 0, 0, dynstr_off, len(dynstr))
    sh_shstrtab = shdr(off_shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab))

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3, 0x3E, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 4, 3,
    )
    return ehdr + dynsym + dynstr + shstrtab + sh_null + sh_dynsym + sh_dynstr + sh_shstrtab


def test_load_library_with_non_elf_payload_is_flagged_not_valid():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v0, "native9"'),
            _FakeInstruction("invoke-static", "v0, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
        ],
    })
    apk_obj = _FakeApkObj({"assets/libnative9.so": b"NOT_AN_ELF_PAYLOAD"})
    findings = resolve_native_bridges({"Lcom/test/Fake;->m()V": g}, apk_obj=apk_obj, analysis_obj=None)

    assert findings[0].library_name == "native9"
    assert findings[0].resolved_so_path == "assets/libnative9.so"
    assert findings[0].is_valid_elf is False


def test_load_library_with_no_matching_so_reports_not_found():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v0, "missing"'),
            _FakeInstruction("invoke-static", "v0, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
        ],
    })
    apk_obj = _FakeApkObj({})
    findings = resolve_native_bridges({"Lcom/test/Fake;->m()V": g}, apk_obj=apk_obj, analysis_obj=None)

    assert findings[0].resolved_so_path is None
    assert findings[0].is_valid_elf is None


def test_native_library_flags_risky_imports_and_ignores_unlisted_ones():
    """
    Cheap substitute for real .so disassembly (see native_bridge.py's module
    docstring): a `connect` import is a real network-capability signal even
    without disassembling what the library does with it. `some_helper` isn't
    on the curated allowlist and must not show up as a "risky" finding.
    """
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v0, "native9"'),
            _FakeInstruction("invoke-static", "v0, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
        ],
    })
    raw = _real_elf_with_dynsym(
        defined=["Java_com_test_Foo_bar"],
        undefined=["connect", "some_helper"],
    )
    apk_obj = _FakeApkObj({"assets/libnative9.so": raw})
    findings = resolve_native_bridges({"Lcom/test/Fake;->m()V": g}, apk_obj=apk_obj, analysis_obj=None)

    assert findings[0].is_valid_elf is True
    assert findings[0].java_prefixed_symbols == ["Java_com_test_Foo_bar"]
    assert findings[0].risky_imports == ["connect"]
    assert "imports: connect" in findings[0].describe()


def test_native_library_with_no_risky_imports_omits_imports_note():
    g = _build_graph({
        "0": [
            _FakeInstruction("const-string", 'v0, "native9"'),
            _FakeInstruction("invoke-static", "v0, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"),
        ],
    })
    raw = _real_elf_with_dynsym(defined=["Java_com_test_Foo_bar"], undefined=["some_helper"])
    apk_obj = _FakeApkObj({"assets/libnative9.so": raw})
    findings = resolve_native_bridges({"Lcom/test/Fake;->m()V": g}, apk_obj=apk_obj, analysis_obj=None)

    assert findings[0].risky_imports == []
    assert "imports:" not in findings[0].describe()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
