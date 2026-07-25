"""
Cisco IOS running-config parser.

This is the deterministic layer. It reads a raw running-config and produces a
structured view of the device: global settings, interfaces, line blocks, ACLs,
SNMP communities, and so on.

Nothing in this module makes a judgement about whether a setting is good or bad.
That is the job of rules.py. Keeping parsing and judgement separate is what lets
the rule set grow without the parser becoming a tangle of special cases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Interface:
    """A single interface stanza."""

    name: str
    lines: list[str] = field(default_factory=list)

    @property
    def is_shutdown(self) -> bool:
        return any(ln.strip() == "shutdown" for ln in self.lines)

    @property
    def has_description(self) -> bool:
        return any(ln.strip().startswith("description ") for ln in self.lines)

    @property
    def ip_address(self) -> str | None:
        for ln in self.lines:
            m = re.match(r"\s*ip address (\S+) (\S+)", ln)
            if m:
                return f"{m.group(1)} {m.group(2)}"
        return None

    @property
    def is_layer3(self) -> bool:
        return self.ip_address is not None

    def has_line(self, pattern: str) -> bool:
        """True if any line in this stanza matches the regex pattern."""
        return any(re.search(pattern, ln) for ln in self.lines)


@dataclass
class LineBlock:
    """A `line con 0` / `line vty 0 4` style stanza."""

    name: str
    lines: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """Returns 'console', 'vty', 'aux', or 'other'."""
        n = self.name.lower()
        if "con" in n:
            return "console"
        if "vty" in n:
            return "vty"
        if "aux" in n:
            return "aux"
        return "other"

    @property
    def transport_input(self) -> list[str]:
        for ln in self.lines:
            m = re.match(r"\s*transport input (.+)", ln)
            if m:
                return m.group(1).split()
        return []

    @property
    def exec_timeout(self) -> tuple[int, int] | None:
        """Returns (minutes, seconds) or None if not configured."""
        for ln in self.lines:
            m = re.match(r"\s*exec-timeout (\d+) (\d+)", ln)
            if m:
                return (int(m.group(1)), int(m.group(2)))
        return None

    @property
    def access_class(self) -> str | None:
        for ln in self.lines:
            m = re.match(r"\s*access-class (\S+) in", ln)
            if m:
                return m.group(1)
        return None

    def has_line(self, pattern: str) -> bool:
        return any(re.search(pattern, ln) for ln in self.lines)


@dataclass
class SnmpCommunity:
    """An SNMP community string with its access level."""

    string: str
    access: str  # RO or RW
    acl: str | None = None
    raw: str = ""


@dataclass
class ParsedConfig:
    """The structured result of parsing a running-config."""

    hostname: str = "unknown"
    raw: str = ""
    global_lines: list[str] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    line_blocks: list[LineBlock] = field(default_factory=list)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    acl_names: set[str] = field(default_factory=set)
    banners: dict[str, str] = field(default_factory=dict)

    # ---- lookup helpers used heavily by the rule set -------------------

    def has_global(self, pattern: str) -> bool:
        """True if any global line matches the regex pattern."""
        return any(re.search(pattern, ln) for ln in self.global_lines)

    def find_global(self, pattern: str) -> list[str]:
        """All global lines matching the regex pattern."""
        return [ln for ln in self.global_lines if re.search(pattern, ln)]

    def first_global(self, pattern: str) -> str | None:
        matches = self.find_global(pattern)
        return matches[0] if matches else None

    def vty_blocks(self) -> list[LineBlock]:
        return [b for b in self.line_blocks if b.kind == "vty"]

    def console_blocks(self) -> list[LineBlock]:
        return [b for b in self.line_blocks if b.kind == "console"]

    def aux_blocks(self) -> list[LineBlock]:
        return [b for b in self.line_blocks if b.kind == "aux"]

    def summary(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "total_lines": len(self.raw.splitlines()),
            "interfaces": len(self.interfaces),
            "interfaces_shutdown": sum(1 for i in self.interfaces if i.is_shutdown),
            "line_blocks": len(self.line_blocks),
            "snmp_communities": len(self.snmp_communities),
            "acls": len(self.acl_names),
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Lines that open a stanza whose children are indented beneath it.
_STANZA_STARTERS = ("interface ", "line ", "router ", "ip access-list ",
                    "class-map ", "policy-map ", "crypto ", "vrf ")


def _is_stanza_child(line: str) -> bool:
    """A child line is indented and is not blank or a comment."""
    return line.startswith((" ", "\t")) and line.strip() != "" and not line.strip().startswith("!")


def parse_config(text: str) -> ParsedConfig:
    """Parse a Cisco IOS running-config into a ParsedConfig.

    The parser is intentionally forgiving: real configs contain vendor quirks,
    truncated output, and comment noise. Anything it cannot classify falls
    through to global_lines rather than raising.
    """
    cfg = ParsedConfig(raw=text)

    lines = text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip blanks and bare comment markers
        if stripped == "" or stripped == "!":
            i += 1
            continue

        # --- banner blocks: delimiter-terminated, must be handled first ---
        banner_match = re.match(r"banner (\w+) (\S)", stripped)
        if banner_match:
            btype, delim = banner_match.group(1), banner_match.group(2)
            body: list[str] = []
            # Banner text may start on the same line after the delimiter
            rest = stripped[banner_match.end():]
            if delim in rest:
                cfg.banners[btype] = rest.split(delim)[0].strip()
                i += 1
                continue
            body.append(rest)
            i += 1
            while i < n and delim not in lines[i]:
                body.append(lines[i])
                i += 1
            if i < n:
                body.append(lines[i].split(delim)[0])
                i += 1
            cfg.banners[btype] = "\n".join(body).strip()
            continue

        # --- hostname ---
        m = re.match(r"hostname (\S+)", stripped)
        if m:
            cfg.hostname = m.group(1)
            cfg.global_lines.append(stripped)
            i += 1
            continue

        # --- interface stanza ---
        m = re.match(r"interface (\S+)", stripped)
        if m:
            iface = Interface(name=m.group(1))
            i += 1
            while i < n and _is_stanza_child(lines[i]):
                iface.lines.append(lines[i])
                i += 1
            cfg.interfaces.append(iface)
            continue

        # --- line stanza (con / vty / aux) ---
        m = re.match(r"line (.+)", stripped)
        if m:
            blk = LineBlock(name=m.group(1).strip())
            i += 1
            while i < n and _is_stanza_child(lines[i]):
                blk.lines.append(lines[i])
                i += 1
            cfg.line_blocks.append(blk)
            continue

        # --- named ACL stanza ---
        m = re.match(r"ip access-list \w+ (\S+)", stripped)
        if m:
            cfg.acl_names.add(m.group(1))
            cfg.global_lines.append(stripped)
            i += 1
            while i < n and _is_stanza_child(lines[i]):
                cfg.global_lines.append(lines[i].strip())
                i += 1
            continue

        # --- numbered ACL (single line form) ---
        m = re.match(r"access-list (\d+) ", stripped)
        if m:
            cfg.acl_names.add(m.group(1))
            cfg.global_lines.append(stripped)
            i += 1
            continue

        # --- SNMP community ---
        m = re.match(r"snmp-server community (\S+)(?:\s+(RO|RW))?(?:\s+(\S+))?", stripped)
        if m:
            cfg.snmp_communities.append(
                SnmpCommunity(
                    string=m.group(1),
                    access=(m.group(2) or "RO").upper(),
                    acl=m.group(3),
                    raw=stripped,
                )
            )
            cfg.global_lines.append(stripped)
            i += 1
            continue

        # --- other stanza starters: keep the header, absorb children ---
        if stripped.startswith(_STANZA_STARTERS):
            cfg.global_lines.append(stripped)
            i += 1
            while i < n and _is_stanza_child(lines[i]):
                cfg.global_lines.append(lines[i].strip())
                i += 1
            continue

        # --- plain global line ---
        cfg.global_lines.append(stripped)
        i += 1

    return cfg
