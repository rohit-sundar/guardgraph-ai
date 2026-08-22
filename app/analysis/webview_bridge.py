"""
WebView JavascriptInterface exposure mapping — resolves
addJavascriptInterface(Object, String) calls via the shared static-
resolution engine: the bridge NAME (the String arg) resolves through the
same register-literal tracking used everywhere else here; the exposed
OBJECT's class resolves when it was built via a traceable `new-instance`
(the same "class" kind the engine already tracks for reflection targets).

Once the exposed class is known, its methods are read from the Androguard
Analysis object and reported as the capability surface reachable from
untrusted web content. This deliberately does NOT filter by the
@JavascriptInterface annotation: Androguard 4.1.2's annotation parsing is
inconsistent across DEX versions, and silently dropping methods because
annotation parsing failed would UNDER-report a real attack surface — the
wrong direction to fail closed in for this specific case. So every public
method of the exposed class is listed, explicitly labeled as not
annotation-filtered, rather than a possibly-incomplete filtered list
presented as if it were complete.
"""
from dataclasses import dataclass, field

import networkx as nx

from app.analysis.static_resolution import resolve_invocations

ADD_JS_INTERFACE = "Landroid/webkit/WebView;->addJavascriptInterface"


@dataclass
class WebViewBridgeFinding:
    method_sig: str
    node_id: str
    interface_name: str | None = None
    exposed_class: str | None = None
    exposed_methods: list = field(default_factory=list)

    def describe(self) -> str:
        name = f'"{self.interface_name}"' if self.interface_name else "<name not resolved>"
        cls = self.exposed_class or "<exposed object's class not resolved>"
        base = f"addJavascriptInterface({cls}, {name})"
        if self.exposed_methods:
            shown = ", ".join(self.exposed_methods[:8])
            more = f" (+{len(self.exposed_methods) - 8} more)" if len(self.exposed_methods) > 8 else ""
            base += f" — public surface exposed to web content: {shown}{more} [not annotation-filtered]"
        return base


def _public_methods(analysis_obj, class_descriptor: str) -> list[str]:
    if analysis_obj is None:
        return []
    try:
        class_analysis = analysis_obj.get_class_analysis(class_descriptor)
    except Exception:
        return []
    if class_analysis is None:
        return []
    names: list[str] = []
    try:
        for m in class_analysis.get_methods():
            em = m.get_method()
            flags = (em.get_access_flags_string() or "").lower()
            if "public" in flags and not em.get_name().startswith("<"):
                names.append(em.get_name())
    except Exception:
        return names
    return sorted(set(names))


def map_webview_bridges(cfgs: dict[str, nx.DiGraph], analysis_obj=None) -> list[WebViewBridgeFinding]:
    """
    Resolves addJavascriptInterface(Object, String) call sites. `analysis_obj`
    is Androguard's Analysis object (already available from ingestion) — used
    only to look up the exposed class's declared methods; the call-site
    resolution itself works off `cfgs` alone.
    """
    findings: list[WebViewBridgeFinding] = []
    for event in resolve_invocations(cfgs):
        if ADD_JS_INTERFACE not in event.target_api:
            continue
        # WebView;->addJavascriptInterface(Object object, String name) —
        # this=arg0 (the WebView), object=arg1, name=arg2.
        arg1, arg2 = event.arg(1), event.arg(2)
        exposed_class = arg1[1] if arg1 and arg1[0] == "class" else None
        interface_name = arg2[1] if arg2 and arg2[0] == "literal" else None
        exposed_methods = _public_methods(analysis_obj, exposed_class) if exposed_class else []
        findings.append(WebViewBridgeFinding(
            event.method_sig, event.node_id,
            interface_name=interface_name,
            exposed_class=exposed_class,
            exposed_methods=exposed_methods,
        ))
    return findings
