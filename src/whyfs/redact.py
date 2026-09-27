"""Command-line secret redaction: the reference implementation of the whyfs policy.

Two passes, identical on every platform (the native collectors, whyfs-collect.c and
whyfs-collect-win.c, implement the same rules and are tested against this module with the
shared vectors in tests/redaction_vectors.json):

1. argv pass (Linux argv, `whyfs trace`): an argument equal to a sensitive name, or a
   ``-name``/``--name`` switch as defined below, hides the next argument; a ``key=value``
   argument with a sensitive key hides the value.  A shell script argument (after -c, -lc,
   /c, /k, -Command) is not argv: it goes to the text pass alone.
2. text pass (redact_text): scans command *text* -- every Linux argument, and the whole raw
   Windows command line (cmd.exe and PowerShell parse their own line) -- for secrets that
   argv tokenization cannot isolate, e.g. a shell wrapper ``sh -c '... --password x'`` or ``cmd /c ""tool" --token x API_KEY=y"``.  Forms:

     --name VALUE   -name VALUE   /name VALUE    name is sensitive, or ends in -/_/. + sensitive
     KEY=VALUE      --KEY=VALUE   /KEY:VALUE   -KEY:VALUE              KEY contains a sensitive name
     $KEY = VALUE   $env:KEY=VALUE                                     (PowerShell)
     NAME: [Bearer|Basic|Token|Digest] VALUE    NAME as for --name     (HTTP header text)

   A form starts only at a word boundary (start, whitespace, a quote, ; & | ( or `).
   VALUE is one shell word: unquoted characters and quoted "..." / '...' segments, ended by
   whitespace, an unquoted ; & |, or a quote that closes an outer quoting (one followed by
   whitespace or the end).  A wholly
   quoted value keeps its quotes ("<redacted>") so the command still reads correctly.

Matching is ASCII case-insensitive; every other character is data.  Nothing outside a
matched value changes.
"""
from __future__ import annotations

import shlex

SENSITIVE = ("password", "passwd", "token", "secret", "api-key", "apikey", "api_key", "access-key",
             "access_key", "private-key", "private_key", "credential", "authorization")
MARK = "<redacted>"
_WS = " \t\n\r\v\f"
_QUOTES = "\"'"
_BOUNDARY = _WS + _QUOTES + ";&|(`"
_KEYCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
_SEPS = ";&|"  # unquoted, these end a shell word (sh, cmd.exe, PowerShell)
_SCHEMES = ("bearer", "basic", "token", "digest")


def _lower(s: str) -> str:  # ASCII only, like the C collectors
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def key_is_sensitive(key: str) -> bool:
    k = _lower(key)
    return any(s in k for s in SENSITIVE)


def switch_is_sensitive(name: str) -> bool:
    n = _lower(name)
    return any(n == s or (n.endswith(s) and n[-len(s) - 1] in "-_.") for s in SENSITIVE)


def _value_end(t: str, j: int) -> int:
    n, k = len(t), j
    while k < n and t[k] not in _WS and t[k] not in _SEPS:
        c = t[k]
        if c in _QUOTES:
            if k > j and (k + 1 == n or t[k + 1] in _WS or t[k + 1] in _SEPS):
                return k  # closes an outer quoting
            close = t.find(c, k + 1)
            if close < 0:
                return n if k == j else k
            k = close + 1
        else:
            k += 1
    return k


def _skip_ws(t: str, k: int) -> int:
    while k < len(t) and t[k] in _WS:
        k += 1
    return k


def _match(t: str, i: int):
    """(value_start, value_end) of a secret whose form starts at i, else None."""
    n, p, dollar, prefix = len(t), i, False, 0
    if t[p] == "$":
        dollar, p = True, p + 1
        if _lower(t[p:p + 4]) == "env:":
            p += 4
    elif t.startswith("--", p):
        prefix = 2
    elif t[p] in "-/":
        prefix = 1
    ks = p + prefix
    ke = ks
    while ke < n and t[ke] in _KEYCH:
        ke += 1
    if ke == ks:
        return None
    key = t[ks:ke]
    sep = t[ke] if ke < n else ""
    if sep == "=":
        return (ke + 1, _value_end(t, ke + 1)) if key_is_sensitive(key) else None
    if dollar:
        q = _skip_ws(t, ke)
        if q < n and t[q] == "=" and key_is_sensitive(key):
            vs = _skip_ws(t, q + 1)
            return vs, _value_end(t, vs)
        return None
    if sep == ":":
        if prefix:
            return (ke + 1, _value_end(t, ke + 1)) if key_is_sensitive(key) else None
        if ke + 1 < n and t[ke + 1] in _WS and switch_is_sensitive(key):  # header text
            vs = _skip_ws(t, ke + 1)
            ve = _value_end(t, vs)
            if _lower(t[vs:ve]) in _SCHEMES:  # keep the scheme visible, hide the credential
                vs = _skip_ws(t, ve)
                ve = _value_end(t, vs)
            return vs, ve
        return None
    if prefix and (sep == "" or sep in _WS) and switch_is_sensitive(key):
        vs = _skip_ws(t, ke)
        return (vs, _value_end(t, vs)) if vs < n else None
    return None


def redact_text(t: str) -> str:
    out, i, n, lit = [], 0, len(t), 0
    while i < n:
        if i == 0 or t[i - 1] in _BOUNDARY:
            m = _match(t, i)
            if m and m[1] > m[0]:
                vs, ve = m
                v = t[vs:ve]
                whole = len(v) >= 2 and v[0] in _QUOTES and v[-1] == v[0] and t.find(v[0], vs + 1) == ve - 1
                out.append(t[lit:vs])
                out.append(v[0] + MARK + v[0] if whole else MARK)
                i = lit = ve
                continue
        i += 1
    out.append(t[lit:])
    return "".join(out)


def _is_switch(a: str) -> bool:
    """-name / --name whose name is sensitive (redact.switch_is_sensitive), e.g. --auth-token."""
    name = a[2:] if a.startswith("--") else a[1:] if a.startswith("-") else ""
    return bool(name) and all(c in _KEYCH for c in name) and switch_is_sensitive(name)


def _is_script_flag(a: str) -> bool:
    """The next argument is a shell script: sh/bash -c (and -lc, -ec, ...), cmd /c /k, PowerShell -Command."""
    low = _lower(a)
    if low in ("/c", "/k", "-command", "--command"):
        return True
    return 2 <= len(low) <= 5 and low[0] == "-" and low[-1] == "c" and all("a" <= c <= "z" for c in low[1:])


def redact_argv(argv: list[str]) -> str:
    """The displayed (shell-quoted) form of argv with secrets replaced.

    argv pass per argument, except that a shell script argument (after -c, -lc, /c, /k,
    -Command) is command text; the command-text pass covers every argument not already
    redacted by the argv pass.  The joined string is
    whyfs's own shell quoting, so it is not rescanned: its '"'"' escapes are not the
    program's syntax.
    """
    out: list[str] = []
    secret_next = False
    for i, a in enumerate(argv):
        low = a.lower()  # str.lower, as graduated (the Linux collector emulates it exactly)
        if secret_next:
            out.append(MARK)
            secret_next = False
            continue
        if i and _is_script_flag(argv[i - 1]):  # a shell script is command text
            out.append(redact_text(a))
            continue
        if any(low == "--" + s or low == s for s in SENSITIVE) or _is_switch(a):
            out.append(a)
            secret_next = True
            continue
        if "=" in a and any(s in low.split("=", 1)[0] for s in SENSITIVE):
            out.append(a.split("=", 1)[0] + "=" + MARK)
        else:
            out.append(redact_text(a))
    return shlex.join(out)
