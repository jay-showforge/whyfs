"""JSON for the CLI fast path without importing the `json` package.

`import json` pulls in `re`, `enum`, `functools` and `collections`: about 10 ms of a `whyfs why`
or `whyfs label` process whose whole budget is 100 ms.  The parser here is CPython's own C
scanner (`_json.make_scanner`, the one `json.loads` uses); the formatter reproduces
`json.dumps(obj, indent=..., default=str)` exactly (tests/test_discovery.py checks both against
`json`).  Anything unusual falls back to the `json` package.
"""
from __future__ import annotations

try:
    from _json import encode_basestring_ascii as _enc_str
    from _json import make_scanner as _make_scanner
except ImportError:  # not CPython: use the real thing
    _make_scanner = None

_CONSTANTS = {"-Infinity": float("-inf"), "Infinity": float("inf"), "NaN": float("nan")}


class _Context:  # the attributes c_make_scanner reads from a JSONDecoder
    strict = True
    object_hook = None
    object_pairs_hook = None
    parse_float = float
    parse_int = int
    parse_constant = staticmethod(_CONSTANTS.__getitem__)
    memo: dict = {}


_scan = _make_scanner(_Context()) if _make_scanner else None
_WS = " \t\n\r"


def loads(s: str | bytes):
    if isinstance(s, (bytes, bytearray)):
        s = s.decode("utf-8")
    t = s.strip(_WS)
    if _scan is not None and t:
        try:
            obj, end = _scan(t, 0)
            if end == len(t):
                return obj
        except StopIteration:
            pass
    import json  # malformed or unusual: the real parser, and its error message
    return json.loads(s)


def _float(o: float) -> str:
    if o != o:
        return "NaN"
    if o == float("inf"):
        return "Infinity"
    if o == float("-inf"):
        return "-Infinity"
    return float.__repr__(o)


def _key(k) -> str:
    if isinstance(k, str):
        return k
    if k is True:
        return "true"
    if k is False:
        return "false"
    if k is None:
        return "null"
    if isinstance(k, int):
        return int.__repr__(k)
    if isinstance(k, float):
        return _float(k)
    raise TypeError(f"keys must be str, int, float, bool or None, not {k.__class__.__name__}")


def _enc(o, indent: str | None, level: int, out: list) -> None:
    if isinstance(o, str):
        out.append(_enc_str(o))
    elif o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, int):
        out.append(int.__repr__(o))
    elif isinstance(o, float):
        out.append(_float(o))
    elif isinstance(o, (list, tuple)):
        if not o:
            out.append("[]")
            return
        if indent is None:
            out.append("[")
            for i, v in enumerate(o):
                if i:
                    out.append(",")
                _enc(v, None, 0, out)
            out.append("]")
            return
        inner = "\n" + indent * (level + 1)
        out.append("[")
        for i, v in enumerate(o):
            out.append(("," if i else "") + inner)
            _enc(v, indent, level + 1, out)
        out.append("\n" + indent * level + "]")
    elif isinstance(o, dict):
        if not o:
            out.append("{}")
            return
        inner = None if indent is None else "\n" + indent * (level + 1)
        out.append("{")
        for i, (k, v) in enumerate(o.items()):
            if inner is None:
                out.append(("," if i else "") + _enc_str(_key(k)) + ":")
                _enc(v, None, 0, out)
            else:
                out.append(("," if i else "") + inner + _enc_str(_key(k)) + ": ")
                _enc(v, indent, level + 1, out)
        out.append("}" if inner is None else "\n" + indent * level + "}")
    else:
        _enc(str(o), indent, level, out)  # default=str


def dumps(obj, indent: int | None = None) -> str:
    """json.dumps(obj, indent=indent, default=str), or with separators (",", ":") when indent is None."""
    if _make_scanner is None:
        import json
        return json.dumps(obj, indent=indent, default=str, separators=None if indent is not None else (",", ":"))
    out: list = []
    _enc(obj, None if indent is None else " " * indent, 0, out)
    return "".join(out)
