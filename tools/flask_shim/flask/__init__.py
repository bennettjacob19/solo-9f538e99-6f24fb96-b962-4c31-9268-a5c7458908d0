"""仅供本地无 Flask 环境验证使用的最小 Flask 兼容垫片。

实现 proxy/app.py 实际用到的子集：路由（含 URL 参数）、request、jsonify、
redirect、render_template（Jinja2 子集：{{ }}、{% if/elif/else/endif %}、
{% for x in y %}、过滤器 join/upper/lower/safe）、flash 会话 cookie、
url_for、abort、Response。Docker 镜像内仍通过 requirements.txt 安装真正的 Flask。
"""

import hashlib
import hmac
import http.cookies
import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------------- 极简 Jinja2 子集渲染器（基于 token 块） ----------------
class _SafeStr(str):
    pass


class _AttrDict(dict):
    """Jinja 风格：r.id 等价于 r['id']，嵌套 dict/list 自动包装。"""

    def __getattr__(self, name):
        try:
            return _wrap(self[name])
        except KeyError as exc:
            raise AttributeError(name) from exc


def _wrap(obj):
    if isinstance(obj, dict) and not isinstance(obj, _AttrDict):
        return _AttrDict({k: _wrap(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return [_wrap(v) for v in obj]
    return obj


def _to_html(x):
    if isinstance(x, _SafeStr):
        return str(x)
    if x is None:
        return ""
    s = str(x)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


def _parse_filter_calls(protected):
    """拆分 value | f | g(args)，返回嵌套调用代码。"""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(protected):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append(protected[start:i].strip())
            start = i + 1
    parts.append(protected[start:].strip())
    code = parts[0]
    for call in parts[1:]:
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*)\))?\s*$", call, re.S)
        if not m or m.group(1) not in FILTERS:
            raise ValueError(f"不支持的过滤器: {call}")
        fname, fargs = m.group(1), m.group(2)
        code = f"__flt['{fname}']({code}" + (f", {fargs.strip()}" if fargs else "") + ")"
    return code


FILTERS = {
    "join": lambda v, sep="": sep.join(str(x) for x in v),
    "upper": lambda v: str(v).upper(),
    "lower": lambda v: str(v).lower(),
    "safe": lambda v: _SafeStr(str(v)),
}


def _compile_expr(expr, ctx, filters):
    expr = expr.strip()
    strings = {}

    def repl(m):
        key = f"__s{len(strings)}__"
        strings[key] = m.group(0)
        return key

    protected = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", repl, expr)
    code = _parse_filter_calls(protected)
    for key, val in strings.items():
        code = code.replace(key, val)
    safe_globals = {"__builtins__": {}, **ctx, "__flt": filters,
                    "len": len, "str": str, "min": min, "max": max,
                    "True": True, "False": False, "None": None,
                    "true": True, "false": False, "none": None,
                    "isinstance": isinstance, "round": round, "int": int}
    return eval(code, safe_globals)


def render_jinja(template_text, context):
    filters = FILTERS
    raw_tokens = re.split(r"(\{%.*?%\}|\{\{.*?\}\})", template_text)
    prog = []
    for tok in raw_tokens:
        if not tok:
            continue
        if tok.startswith("{%"):
            inner = tok[2:-2].strip()
            bits = inner.split(None, 1)
            prog.append(("tag", bits[0], bits[1].strip() if len(bits) > 1 else ""))
        elif tok.startswith("{{"):
            prog.append(("expr", tok[2:-2].strip(), ""))
        else:
            prog.append(("text", tok, ""))

    def emit(instructions, ctx):
        buf, i = [], 0
        while i < len(instructions):
            kind, a, b = instructions[i]
            if kind == "text":
                buf.append(a)
            elif kind == "expr":
                buf.append(_to_html(_compile_expr(a, ctx, filters)))
            elif kind == "tag" and a == "if":
                depth, j = 1, i + 1
                branches, cur, conds = [], [], [b]
                while j < len(instructions):
                    k2, a2, b2 = instructions[j]
                    if k2 == "tag" and a2 == "if":
                        depth += 1
                        cur.append(instructions[j])
                    elif k2 == "tag" and a2 == "endif":
                        depth -= 1
                        if depth == 0:
                            break
                        cur.append(instructions[j])
                    elif k2 == "tag" and a2 in ("elif", "else") and depth == 1:
                        branches.append((conds[-1], cur))
                        cur = []
                        conds.append(None if a2 == "else" else b2)
                    else:
                        cur.append(instructions[j])
                    j += 1
                branches.append((conds[-1], cur))
                for cond, body in branches:
                    if cond is None or _compile_expr(cond, ctx, filters):
                        buf.append(emit(body, ctx))
                        break
                i = j
            elif kind == "tag" and a == "with":
                depth, j, body = 1, i + 1, []
                while j < len(instructions):
                    k2, a2, _b2 = instructions[j]
                    if k2 == "tag" and a2 == "with":
                        depth += 1
                    elif k2 == "tag" and a2 == "endwith":
                        depth -= 1
                        if depth == 0:
                            break
                    body.append(instructions[j])
                    j += 1
                lctx = dict(ctx)
                for assign in b.split(","):
                    if "=" in assign:
                        name, expr = assign.split("=", 1)
                        lctx[name.strip()] = _compile_expr(expr, ctx, filters)
                buf.append(emit(body, lctx))
                i = j
            elif kind == "tag" and a == "for":
                depth, j, body = 1, i + 1, []
                while j < len(instructions):
                    k2, a2, _b2 = instructions[j]
                    if k2 == "tag" and a2 == "for":
                        depth += 1
                    elif k2 == "tag" and a2 == "endfor":
                        depth -= 1
                        if depth == 0:
                            break
                    body.append(instructions[j])
                    j += 1
                fm = re.match(r"(.+?)\s+in\s+(.+)", b)
                varspec = [v.strip() for v in fm.group(1).split(",")]
                iterable = list(_compile_expr(fm.group(2), ctx, filters) or [])
                for index, val in enumerate(iterable):
                    lctx = dict(ctx)
                    if len(varspec) == 1:
                        lctx[varspec[0]] = val
                    else:
                        for k, v in zip(varspec, val):
                            lctx[k] = v
                    lctx["loop"] = {"index": index + 1, "first": index == 0,
                                    "last": index == len(iterable) - 1}
                    buf.append(emit(body, lctx))
                i = j
            i += 1
        return "".join(buf)

    return emit(prog, {k: _wrap(v) for k, v in context.items()})


# ---------------- 请求/响应 ----------------
class Request:
    def __init__(self, method, path, query, form, cookies, headers):
        self.method = method
        self.path = path
        self.args = query
        self.form = form
        self.cookies = cookies
        self.headers = headers


class Response(Exception):
    def __init__(self, body, status=200, headers=None, mimetype="text/html"):
        super().__init__(status)
        if isinstance(body, str):
            body = body.encode()
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.headers.setdefault("Content-Type", f"{mimetype}; charset=utf-8")


def abort(code):
    raise Response(f"<h1>{code}</h1>", status=code)


def jsonify(obj):
    return Response(json.dumps(obj, ensure_ascii=False), mimetype="application/json")


def redirect(location, code=302):
    return Response(b"", status=code, headers={"Location": location})


# ---------------- Flask 垫片主体 ----------------
class _FlaskApp:
    def __init__(self, name):
        self.name = name
        self.routes = []          # (regex, methods, func, param_names, sig)
        self.secret_key = None
        self.template_folder = "templates"
        # 以调用方（应用模块）所在目录为根：templates/ 与 app 同级
        frame = sys._getframe(1)
        self.root_path = os.path.dirname(os.path.abspath(
            frame.f_globals.get("__file__", os.getcwd())))

    def _add(self, rule, methods, func):
        param_names = re.findall(r"<(?:[^:>:]+:)?([^>]+)>", rule)
        sig = dict(re.findall(r"<(?:([^:>:]+):)?([^>]+)>", rule))
        pattern = "^" + re.sub(r"<(?:[^:>:]+:)?[^>]+>", r"([^/]+)", rule) + "$"
        func._rule = rule
        func._sig = sig
        self.routes.append((re.compile(pattern), methods, func, param_names, sig))

    def route(self, rule, **kwargs):
        methods = kwargs.get("methods", ["GET"])

        def deco(func):
            self._add(rule, methods, func)
            return func
        return deco

    def get(self, rule):
        return self.route(rule, methods=["GET"])

    def post(self, rule):
        return self.route(rule, methods=["POST"])

    def run(self, host="127.0.0.1", port=8080, threaded=True, **kwargs):
        httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        print(f"[shim-flask] listening on {host}:{port}", flush=True)
        httpd.serve_forever()


_current_app = [None]
_current_flash_cookie = [[]]
_request_stack = [None]


def _take_flashes(with_categories):
    items = list(_current_flash_cookie[0])
    _current_flash_cookie[0] = []
    return items if with_categories else [m for _, m in items]


def render_template(name, **ctx):
    app = _current_app[0]
    path = os.path.join(app.root_path, app.template_folder, name)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    ctx["get_flashed_messages"] = lambda with_categories=False: _take_flashes(with_categories)
    ctx["url_for"] = lambda endpoint, **kw: _url_for(app, endpoint, kw)
    return Response(render_jinja(text, ctx))


def flash(message, category="message"):
    _current_flash_cookie[0].append((category, message))


def _url_for(app, endpoint, kw):
    for _regex, _m, func, _p, _s in app.routes:
        if func.__name__ == endpoint:
            url = func._rule
            for k, v in kw.items():
                url = re.sub(rf"<(?:[^:>:]+:)?{k}>", str(v), url)
            return url
    return "/"


def url_for(endpoint, **kw):
    return _url_for(_current_app[0], endpoint, kw)


class _ReqProxy:
    def __getattr__(self, name):
        return getattr(_request_stack[0], name)


request = _ReqProxy()


def _read_flashes(app, cookies):
    payload, sig = cookies.get("flashes"), cookies.get("flashes_sig")
    if not payload or not sig:
        return []
    try:
        raw = urllib.parse.unquote(payload)
        expect = hmac.new((app.secret_key or b"x"), raw.encode(),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return []
        return [tuple(x) for x in json.loads(raw)]
    except Exception:
        return []


def _make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _serve(self):
            parsed = urllib.parse.urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            form = {k: v[0] for k, v in
                    urllib.parse.parse_qs(raw.decode()).items()}
            query = {k: v[0] for k, v in
                     urllib.parse.parse_qs(parsed.query).items()}
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            cookies = {k: m.value for k, m in cookie.items()}
            _current_app[0] = app
            _current_flash_cookie[0] = _read_flashes(app, cookies)
            _request_stack[0] = Request(self.command, parsed.path, query, form,
                                        cookies, self.headers)
            try:
                resp = None
                for regex, methods, func, params, sig in app.routes:
                    m = regex.match(parsed.path)
                    if not m:
                        continue
                    if self.command not in methods:
                        resp = Response(b"method not allowed", 405)
                        break
                    kwargs = dict(zip(params, m.groups()))
                    for k in list(kwargs):
                        if sig.get(k) == "int":
                            kwargs[k] = int(kwargs[k])
                    out = func(**kwargs)
                    resp = out if isinstance(out, Response) else Response(out)
                    break
                if resp is None:
                    resp = Response("<h1>404 Not Found</h1>", 404)
            except Response as r:
                resp = r
            self._write(app, resp)

        do_GET = _serve
        do_POST = _serve

        def _write(self, app, resp):
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            flashes = _current_flash_cookie[0]
            if flashes:
                payload = json.dumps(flashes, ensure_ascii=False)
                sig = hmac.new((app.secret_key or b"x"), payload.encode(),
                               hashlib.sha256).hexdigest()
                c = http.cookies.SimpleCookie()
                c["flashes"] = urllib.parse.quote(payload)
                c["flashes_sig"] = sig
                for morsel in c.values():
                    morsel["path"] = "/"
                    self.send_header("Set-Cookie", morsel.OutputString())
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

    return Handler


Flask = _FlaskApp
