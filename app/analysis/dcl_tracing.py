"""
Dynamic code loading (DCL) tracing — resolves the dexPath/buffer-source
argument to DexClassLoader / InMemoryDexClassLoader / PathClassLoader
constructors via the shared static-resolution engine, and cross-references
the resolved path against the asset inventory apk_static.py already
extracted (payload_assets: files flagged as DEX/ZIP-magic payloads hiding
under a disguised extension), so a resolved loader target that matches a
known suspicious asset is called out explicitly rather than left as two
separate, uncorrelated facts.
"""
from dataclasses import dataclass, field

import networkx as nx

from app.analysis.static_resolution import resolve_invocations, short_api

DCL_CONSTRUCTORS = {
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ldalvik/system/InMemoryDexClassLoader;-><init>",
    "Ldalvik/system/PathClassLoader;-><init>",
}


@dataclass
class DclFinding:
    method_sig: str
    node_id: str
    api: str
    resolved_path: str | None = None
    matches_known_asset: bool = False

    def describe(self) -> str:
        api_short = short_api(self.api)
        if self.resolved_path:
            tag = " [matches a flagged payload asset]" if self.matches_known_asset else ""
            return f'{api_short}("{self.resolved_path}"){tag}'
        return f"{api_short}(<path not statically resolved>)"


def trace_dcl_targets(cfgs: dict[str, nx.DiGraph], payload_assets: list[str] | None = None) -> list[DclFinding]:
    """
    Resolves DexClassLoader-family constructor arguments back to literal
    paths where the chain is unambiguous. `payload_assets` should be
    ingestion.payload_assets — filenames flagged elsewhere as disguised
    DEX/ZIP payloads — so a resolved path that names one of them is marked.
    """
    payload_names = {a.rsplit("/", 1)[-1] for a in (payload_assets or [])}
    findings: list[DclFinding] = []

    for event in resolve_invocations(cfgs):
        target = event.target_api
        matched_api = next((api for api in DCL_CONSTRUCTORS if api in target), None)
        if matched_api is None:
            continue
        # DexClassLoader(String dexPath, ...) / PathClassLoader(String dexPath, ...) —
        # this=arg0, dexPath=arg1. InMemoryDexClassLoader takes a ByteBuffer, not a
        # path string, so its arg1 will simply never resolve to a literal here.
        arg1 = event.arg(1)
        resolved_path = arg1[1] if arg1 and arg1[0] == "literal" else None
        matches = bool(resolved_path) and resolved_path.rsplit("/", 1)[-1] in payload_names
        findings.append(DclFinding(
            event.method_sig, event.node_id, matched_api,
            resolved_path=resolved_path, matches_known_asset=matches,
        ))

    return findings
