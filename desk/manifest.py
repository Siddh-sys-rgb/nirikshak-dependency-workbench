"""Parse a deliberately small, non-executing subset of requirements.txt."""
import re

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


class InputError(ValueError):
    pass


MAX_BYTES = 32768
MAX_LINES = 150
MAX_PACKAGES = 30
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,99})\s*==\s*([^\s;#]{1,80})$")


def parse_manifest(text):
    if not isinstance(text, str) or not text.strip():
        raise InputError("Paste a non-empty requirements manifest.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise InputError("Manifest exceeds 32 KiB.")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise InputError("Manifest exceeds 150 lines.")
    packages, unsupported, seen = [], [], {}
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        match = PIN.fullmatch(line)
        reason = "Only one exact package==version pin per line is supported."
        if match and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", match.group(1)):
            name, version = match.groups()
            try:
                parsed = Version(version)
            except InvalidVersion:
                reason = "The version is not a valid PEP 440 version."
            else:
                if parsed.local is not None:
                    reason = "Local build versions are not supported by this workbench."
                else:
                    name = canonicalize_name(name)
                    version = str(parsed)
                    if name in seen:
                        reason = ("Duplicate package pin." if seen[name] == version else
                                  "Conflicting versions for the same package.")
                        if seen[name] != version:
                            next(p for p in packages if p["name"] == name)["ambiguous"] = True
                    else:
                        packages.append({"name": name, "version": version, "line": number})
                        seen[name] = version
                        continue
        unsupported.append({"line": number, "text": raw[:250], "reason": reason})
    if len(packages) > MAX_PACKAGES:
        raise InputError("A scan supports at most 30 distinct package pins.")
    if not packages and not unsupported:
        raise InputError("The manifest contains only comments or blank lines.")
    # Never infer environment markers, resolve extras, read nested files, fetch
    # package URLs, run pip or shell commands, or import submitted packages.
    return {"packages": packages, "unsupported": unsupported,
            "line_count": len(lines), "complete_manifest": not unsupported}
