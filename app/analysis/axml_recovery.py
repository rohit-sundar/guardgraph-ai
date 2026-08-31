"""
AndroidManifest.xml recovery for manifests built to break the parser (Phase 1).

A corrupted manifest is not a broken file — it is a working file plus damage
aimed at everything except the Android runtime. The platform's own AXML reader
is lenient in three specific ways that androguard is not, and each one has been
weaponised in the Bank of India evaluation set:

  1. **A scrambled ZIP entry header.** Sample 1's manifest declares compression
     method `55217` and a compressed size of 4089 bytes over 11684 bytes of
     stored AXML. Handled upstream of this module by `apk_container`, which is
     why recovery here starts from bytes rather than from a filename.

  2. **An AXML chunk size that disagrees with the buffer.** Androguard rejects
     the file outright ("Declared filesize does not match real size"). The
     platform reads the chunks it finds. `_normalise_axml_header` rewrites the
     declared size to the real one before parsing.

  3. **Empty attribute names.** Sample 1 carries elements whose name index
     resolves to the empty string, which walks straight into an `IndexError` in
     androguard's `AXMLPrinter._fix_name` — a crash, not a parse failure, so the
     whole APK object is lost over one malformed attribute.
     `install_axml_tolerance` substitutes a placeholder for exactly that case.

When the element tree still cannot be built — sample 4's manifest carries dummy
data between chunk headers and leaves androguard's element stack unbalanced, so
its document root comes back `None`, and its event parser spins rather than
terminating — the string pool is still intact and still holds the permission
names, component class names and intent actions. `recover_from_string_pool`
reads those directly. It is a strictly weaker result and says so: the pool
records *that* a string is present, never which element referenced it, so
recovered components come back unclassified rather than guessed into
activities/services/receivers.

Nothing here is speculative decoding. Every field is a string the manifest
itself contains; the uncertainty is only ever about which element owned it.
"""
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from app.analysis.apk_container import ApkContainer

MANIFEST_NAME = "AndroidManifest.xml"

# AXML chunk type 0x0003 (RES_XML_TYPE), 8-byte header, then a u32 total size.
_AXML_MAGIC = b"\x03\x00\x08\x00"

# Placeholder androguard is given in place of an empty attribute name, so its
# `name[0]` check has something to look at. Deliberately not a valid XML name
# character sequence anyone would write, so it cannot collide with a real one.
EMPTY_NAME_PLACEHOLDER = "_axml_empty_name_"

_RE_PERMISSION = re.compile(
    r"^[a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*\.permission\.[A-Z][A-Z0-9_]*$"
)
_RE_ACTION = re.compile(
    r"^[a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*\.(?:action|category)\.[A-Za-z][A-Za-z0-9_]*$"
)
# Class-like: dotted, and at least one segment starts with a capital.
_RE_CLASS_NAME = re.compile(
    r"^[a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_$]+)+$"
)

# Intent-filter actions that are bare framework class names rather than
# `*.action.*` — the VPN and accessibility entry points both look like this, and
# both are exactly what this set of samples uses.
_BARE_FRAMEWORK_ACTIONS = frozenset({
    "android.net.VpnService",
    "android.accessibilityservice.AccessibilityService",
    "android.service.notification.NotificationListenerService",
    "android.app.action.DEVICE_ADMIN_ENABLED",
})

# Suffixes the build tools append to the application id verbatim. Finding one of
# these in the string pool hands back the package name exactly, with no guessing
# — `com.tomo.tozy.naki.androidx-startup` can only have come from
# `com.tomo.tozy.naki`. Ordered most to least reliable.
_GENERATED_PACKAGE_SUFFIXES = (
    ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
    ".androidx-startup",
    ".permission.C2D_MESSAGE",
    ".fileprovider",
    ".provider",
)

_tolerance_installed = False


def install_axml_tolerance() -> None:
    """
    Teach androguard's AXML printer to survive an empty attribute name.

    Idempotent, and scoped to one failure: a name that is the empty string gets
    a placeholder, and every other name takes the original code path untouched.
    A well-formed manifest parses byte-identically before and after this call —
    the patch can only turn a crash into a parse.

    Done as a patch rather than a fork because the crash is inside androguard's
    constructor, with no hook, callback or subclass point between the caller and
    the `IndexError`.
    """
    global _tolerance_installed
    if _tolerance_installed:
        return

    try:
        from androguard.core import axml as _axml

        original = _axml.AXMLPrinter._fix_name

        def _fix_name_tolerant(self, prefix, name):  # type: ignore[no-untyped-def]
            if not name:
                return prefix, EMPTY_NAME_PLACEHOLDER
            return original(self, prefix, name)

        _axml.AXMLPrinter._fix_name = _fix_name_tolerant
        _tolerance_installed = True
        logger.debug("AXML empty-attribute-name tolerance installed.")
    except Exception as e:  # pragma: no cover - androguard internals moved
        logger.warning(
            f"Could not install AXML tolerance ({e}) — manifests using the "
            "empty-attribute-name trick will still crash the parser."
        )


def _normalise_axml_header(data: bytes) -> bytes:
    """
    Rewrite the AXML chunk's declared total size to the buffer's real length.

    Androguard refuses to parse when the two disagree in either direction, and
    the disagreement is the whole trick: the platform reads chunks until it runs
    out, so the declared total is never load-bearing at runtime.

    Returns the input unchanged when it is not AXML or already consistent.
    """
    if len(data) < 8 or data[:4] != _AXML_MAGIC:
        return data
    declared = struct.unpack("<I", data[4:8])[0]
    if declared == len(data):
        return data
    logger.debug(
        f"AXML declares {declared} bytes over a {len(data)}-byte buffer — "
        "normalising the header to the real length."
    )
    return data[:4] + struct.pack("<I", len(data)) + data[8:]


@dataclass
class RecoveredManifest:
    """
    What a fallback pass got back, and how much to trust it.

    `source` is the honest part of this object:

      * `"tree"` — the element tree parsed. Everything is attributed to the
        element that declared it, so the classified component lists are real.
      * `"string_pool"` — only the pool survived. `components` holds class names
        with no way to tell an activity from a service, and the classified lists
        stay empty rather than being filled by guess.
    """

    source: str
    package: Optional[str] = None
    app_label: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    intent_actions: list[str] = field(default_factory=list)
    # Unclassified component class names — populated only on the string-pool path.
    components: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def component_count(self) -> int:
        if self.source == "tree":
            return len(self.activities) + len(self.services) + len(self.receivers)
        return len(self.components)

    @property
    def is_empty(self) -> bool:
        return not (self.package or self.permissions or self.component_count)


def _manifest_bytes(container: ApkContainer) -> Optional[bytes]:
    """
    The manifest the platform would load, preferring whichever copy actually
    parses when the archive ships more than one.

    Duplicate entry names are one of the tricks in this set, and which copy a
    tool sees depends on whether it indexes by name or iterates — so try them
    all and take the first that carries the AXML magic.
    """
    candidates = container.read_all(MANIFEST_NAME)
    for _entry, data in candidates:
        if data[:4] == _AXML_MAGIC:
            return data
    return candidates[0][1] if candidates else None


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def recover_from_tree(data: bytes) -> Optional[RecoveredManifest]:
    """Parse the AXML into an element tree and read the manifest properly."""
    install_axml_tolerance()
    try:
        from androguard.core.axml import AXMLPrinter

        printer = AXMLPrinter(_normalise_axml_header(data))
        root = printer.get_xml_obj()
    except Exception as e:
        logger.debug(f"AXML tree parse failed: {e}")
        return None

    if root is None:
        return None

    ns = "{http://schemas.android.com/apk/res/android}"

    def attr(el, name: str) -> Optional[str]:
        # Manifests in this set drop the android: prefix on some attributes,
        # which is legal enough for aapt and reads as a bare name here.
        return _text(el.get(f"{ns}{name}")) or _text(el.get(name))

    out = RecoveredManifest(source="tree")
    out.package = _text(root.get("package"))

    for el in root.iter():
        tag = str(el.tag)
        if tag.endswith("uses-permission") or tag.endswith("uses-permission-sdk-23"):
            name = attr(el, "name")
            if name and name not in out.permissions:
                out.permissions.append(name)
        elif tag.endswith("activity") or tag.endswith("activity-alias"):
            name = attr(el, "name")
            if name:
                out.activities.append(name)
        elif tag.endswith("service"):
            name = attr(el, "name")
            if name:
                out.services.append(name)
        elif tag.endswith("receiver"):
            name = attr(el, "name")
            if name:
                out.receivers.append(name)
        elif tag.endswith("action") or tag.endswith("category"):
            name = attr(el, "name")
            if name and name not in out.intent_actions:
                out.intent_actions.append(name)
        elif tag.endswith("application"):
            label = attr(el, "label")
            # A resource reference (@7F0D001C) is not a name; leave it to the
            # normal resource-resolving path rather than reporting the id.
            if label and not label.startswith("@"):
                out.app_label = label

    out.note = "manifest recovered by tolerant AXML parse"
    return None if out.is_empty else out


def _package_from_pool(strings: list[str]) -> Optional[str]:
    """
    Recover the application id from build-tool-generated strings.

    These suffixes are appended to the application id verbatim by aapt2 and by
    the androidx libraries, so stripping one back off is a derivation, not a
    guess. Checked longest-suffix-first so `.permission.C2D_MESSAGE` cannot be
    mistaken for `.provider` on a package that ends in the word "provider".
    """
    for suffix in _GENERATED_PACKAGE_SUFFIXES:
        for s in strings:
            if s.endswith(suffix) and len(s) > len(suffix):
                candidate = s[: -len(suffix)]
                if _RE_CLASS_NAME.match(candidate) or "." in candidate:
                    return candidate
    return None


def recover_from_string_pool(data: bytes) -> Optional[RecoveredManifest]:
    """
    Read the manifest's string pool when the element tree cannot be built.

    Uses `AXMLParser` only for its string-pool decoding and deliberately never
    drives its event loop: sample 4's manifest makes that loop return its error
    sentinel indefinitely rather than terminating, so iterating it is a hang, not
    a parse failure.
    """
    try:
        from androguard.core.axml import AXMLParser

        parser = AXMLParser(_normalise_axml_header(data))
        pool = parser.sb
        strings = [str(pool.getString(i)) for i in range(len(pool))]
    except Exception as e:
        logger.debug(f"AXML string-pool read failed: {e}")
        return None

    if not strings:
        return None

    out = RecoveredManifest(source="string_pool")
    out.package = _package_from_pool(strings)

    for s in strings:
        if not s or len(s) > 256:
            continue
        if _RE_PERMISSION.match(s):
            if s not in out.permissions:
                out.permissions.append(s)
        elif s in _BARE_FRAMEWORK_ACTIONS or _RE_ACTION.match(s):
            if s not in out.intent_actions:
                out.intent_actions.append(s)
        elif _RE_CLASS_NAME.match(s) and any(
            seg[:1].isupper() for seg in s.split(".")[1:]
        ):
            if s not in out.components:
                out.components.append(s)

    out.note = (
        "manifest element tree unrecoverable — permissions, intent actions and "
        "component names read from the AXML string pool; components could not be "
        "attributed to activity/service/receiver"
    )
    return None if out.is_empty else out


def recover_manifest(container: ApkContainer) -> Optional[RecoveredManifest]:
    """
    Best available reading of a manifest the normal path could not use.

    Tries the element tree first and falls back to the string pool, so a caller
    always gets the strongest result the file supports — or None when the
    manifest is genuinely unreadable, which stays a reported gap rather than an
    empty answer.
    """
    data = _manifest_bytes(container)
    if not data:
        logger.debug("No AndroidManifest.xml entry could be read from the container.")
        return None

    recovered = recover_from_tree(data)
    if recovered is not None:
        logger.info(
            f"Manifest recovered via tolerant AXML parse: "
            f"package={recovered.package}, {len(recovered.permissions)} permissions, "
            f"{recovered.component_count} components."
        )
        return recovered

    recovered = recover_from_string_pool(data)
    if recovered is not None:
        logger.info(
            f"Manifest recovered via string pool: package={recovered.package}, "
            f"{len(recovered.permissions)} permissions, "
            f"{recovered.component_count} unclassified components."
        )
    return recovered
