"""
Crypto configuration recovery — resolves the algorithm/transformation
STRING arguments to Cipher.getInstance / SecretKeySpec / IvParameterSpec
via the shared static-resolution engine, and flags weak configurations
(ECB mode, DES/RC4/MD5, or a transformation with no explicit mode, which
the JCA provider defaults to ECB).

Explicitly NOT implemented: extracting the actual key/IV BYTE material.
Real-world key bytes are almost always loaded via a `fill-array-data`
pseudo-instruction whose payload table this codebase's CFG layer doesn't
parse (cfg.py's instruction stream only sees the array-data offset, e.g.
"v1, +0000016h" — not the bytes). Decoding that wrong would silently report
a FAKE key, which is worse than admitting "key material present, not
statically decoded" — so that's what this reports instead.
"""
from dataclasses import dataclass, field

import networkx as nx

from app.analysis.static_resolution import resolve_invocations, short_api

CIPHER_GET_INSTANCE = "Ljavax/crypto/Cipher;->getInstance"
SECRET_KEY_SPEC_INIT = "Ljavax/crypto/spec/SecretKeySpec;-><init>"
IV_PARAM_SPEC_INIT = "Ljavax/crypto/spec/IvParameterSpec;-><init>"

_WEAK_MODE_MARKERS = ("ECB",)
_WEAK_ALGO_MARKERS = ("DES", "RC4", "RC2", "MD5")


@dataclass
class CryptoFinding:
    method_sig: str
    node_id: str
    api: str
    transformation: str | None = None
    algorithm: str | None = None
    key_material_present: bool = False
    iv_material_present: bool = False
    weak_flags: list = field(default_factory=list)

    def describe(self) -> str:
        parts = [short_api(self.api)]
        if self.transformation:
            parts.append(f'transformation="{self.transformation}"')
        if self.algorithm:
            parts.append(f'algorithm="{self.algorithm}"')
        if self.key_material_present:
            parts.append("key bytes present [not statically decoded]")
        if self.iv_material_present:
            parts.append("IV bytes present [not statically decoded]")
        if self.weak_flags:
            parts.append("WEAK: " + ", ".join(self.weak_flags))
        return " — ".join(parts)


def _weak_flags_for(transformation: str | None, algorithm: str | None) -> list[str]:
    flags = []
    haystack = " ".join(x for x in (transformation, algorithm) if x).upper()
    if any(m in haystack for m in _WEAK_MODE_MARKERS):
        flags.append("ECB mode (no IV, pattern leakage)")
    for m in _WEAK_ALGO_MARKERS:
        if m in haystack:
            flags.append(f"weak/legacy algorithm ({m})")
    if transformation and "/" not in transformation:
        flags.append("no explicit mode/padding in transformation — provider default is ECB")
    return flags


def recover_crypto_configs(cfgs: dict[str, nx.DiGraph]) -> list[CryptoFinding]:
    """Resolves Cipher/SecretKeySpec/IvParameterSpec configuration from already-decoded literals."""
    findings: list[CryptoFinding] = []
    for event in resolve_invocations(cfgs):
        target = event.target_api
        if CIPHER_GET_INSTANCE in target:
            arg0 = event.arg(0)
            transformation = arg0[1] if arg0 and arg0[0] == "literal" else None
            findings.append(CryptoFinding(
                event.method_sig, event.node_id, CIPHER_GET_INSTANCE,
                transformation=transformation,
                weak_flags=_weak_flags_for(transformation, None),
            ))
        elif SECRET_KEY_SPEC_INIT in target:
            # SecretKeySpec(byte[] key, String algorithm) — this=arg0, key=arg1, algorithm=arg2.
            arg2 = event.arg(2)
            algorithm = arg2[1] if arg2 and arg2[0] == "literal" else None
            findings.append(CryptoFinding(
                event.method_sig, event.node_id, SECRET_KEY_SPEC_INIT,
                algorithm=algorithm, key_material_present=True,
                weak_flags=_weak_flags_for(None, algorithm),
            ))
        elif IV_PARAM_SPEC_INIT in target:
            findings.append(CryptoFinding(
                event.method_sig, event.node_id, IV_PARAM_SPEC_INIT,
                iv_material_present=True,
            ))
    return findings
