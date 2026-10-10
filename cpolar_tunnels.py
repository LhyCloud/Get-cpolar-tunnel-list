#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
cpolar_tunnels.py —— 自动获取 cpolar 隧道列表，并在终端里选一条直接打开

特点
----
  * 账号不写在脚本里：统一存在脚本同级的单文件 cpolar_config.json
    （邮箱 + 密码 + 登录 Cookie + 限速状态都在这一个文件里）；首次运行会提示输入并保存。
  * 运行后直接显示隧道列表，↑/↓ 选中，回车打开：
        https 隧道 → 默认浏览器打开 https 地址
        本机 3389 的 TCP 隧道 → mstsc 远程桌面打开
        其它 TCP 隧道 → 复制地址到剪贴板（没有通用打开方式）
  * 仅用 Python 标准库，无需 pip 安装任何东西。

原理
----
cpolar 控制台没有可用的 JSON 接口（/api/tunnels 返回 404），隧道列表只存在于需要登录的
https://dashboard.cpolar.com/status 页面。脚本先复用 Cookie 直接取该页；Cookie 失效时才
GET /login 取 csrf_token 再 POST 登录，之后解析 “在线隧道” 表格。

防封号
------
  * Cookie 持久化，正常运行时 0 次登录请求；
  * --min-interval（默认 20 秒）：间隔不足直接拒绝发请求（按 r 刷新也受此约束）；
  * 登录失败默认退避 600 秒，且每次运行最多登录 1 次，绝不自动重试。

用法
----
    python cpolar_tunnels.py                     # 抓取 + 交互式选择
    python cpolar_tunnels.py --set-account       # 重新输入并保存账号密码
    python cpolar_tunnels.py --json              # 只输出 JSON（脚本调用）
    python cpolar_tunnels.py --json -o t.json    # JSON 存文件
    python cpolar_tunnels.py --no-menu           # 只打印表格，不进入选择界面
    python cpolar_tunnels.py --dump-html p.html  # 保存原始页面，页面改版时排查

退出码：0 成功 / 2 登录失败 / 3 未解析到隧道 / 4 被本地限速拦下 / 5 网络错误
"""

from __future__ import print_function

import argparse
import getpass
import io
import json
import os
import re
import ssl
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from urllib import error, parse, request

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
BASE_URL = "https://dashboard.cpolar.com"
LOGIN_URL = BASE_URL + "/login"
STATUS_URL = BASE_URL + "/status"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

CONFIG_NAME = "cpolar_config.json"


def app_dir():
    """配置文件的存放目录。

    打包成单文件 exe（PyInstaller --onefile）后 __file__ 指向临时解包目录，进程退出即删除，
    所以必须用 exe 自身所在目录；直接运行 .py 时用脚本所在目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


SCRIPT_DIR = app_dir()
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, CONFIG_NAME)

EXIT_OK = 0
EXIT_LOGIN_FAILED = 2
EXIT_NO_TUNNEL = 3
EXIT_RATE_LIMITED = 4
EXIT_NETWORK_ERROR = 5

ANY_URL_RE = re.compile(r"^(?:https?|tcp|tls|ftp)://", re.I)
CPOLAR_URL_RE = re.compile(r"^https?://[^/]*cpolar\.(?:top|cn|io|com|net)\b", re.I)
URL_TEXT_RE = re.compile(r"^(?:https?|tcp|tls|ftp)://[^\s]+$", re.I)
ERROR_MARK_RE = re.compile(r"alert-error|alert-danger|captcha|验证码|用户名或密码|密码错误", re.I)

COL_NAME = ("隧道名称", "名称", "name", "tunnel")
COL_URL = ("URL", "url", "公网地址", "地址")
COL_REGION = ("地区", "region")
COL_LOCAL = ("本地地址", "local")

ANSI_RESET = "\x1b[0m"
ANSI_REVERSE = "\x1b[7m"
ANSI_DIM = "\x1b[2m"
ANSI_HOME_CLEAR = "\x1b[H\x1b[2J"


def log(msg, quiet=False):
    if not quiet:
        sys.stderr.write("[cpolar] %s\n" % msg)
        sys.stderr.flush()


def force_utf8_output():
    """Windows 控制台默认 GBK，中文会乱码；这里统一成 UTF-8。"""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def enable_ansi():
    """Windows 10+ 打开控制台的 VT 转义支持，返回是否可用 ANSI。"""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            return False
        return True
    except Exception:
        return False


def dedupe(seq):
    out = []
    for item in seq:
        if item and item not in out:
            out.append(item)
    return out


def url_sort_key(url):
    order = {"https": 0, "http": 1}
    scheme = url.split("://", 1)[0].lower()
    return (order.get(scheme, 2), url)


def local_port(local_addr):
    m = re.search(r":(\d+)\s*$", (local_addr or "").strip())
    return m.group(1) if m else ""


def tcp_host_port(url):
    body = url.split("://", 1)[-1]
    return body.split("/", 1)[0]


# --------------------------------------------------------------------------
# 配置文件：邮箱 + 密码 + Cookie + 状态，全在一个外部文件里
# --------------------------------------------------------------------------
def cookie_to_dict(cookie):
    return {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": bool(cookie.secure),
        "expires": cookie.expires,
        "domain_specified": bool(cookie.domain_specified),
        "domain_initial_dot": bool(cookie.domain_initial_dot),
        "path_specified": bool(cookie.path_specified),
        "version": cookie.version,
        "port": cookie.port,
        "comment": cookie.comment,
        "discard": bool(cookie.discard),
    }


def dict_to_cookie(item):
    return Cookie(
        version=item.get("version", 0),
        name=item["name"],
        value=item.get("value", ""),
        port=item.get("port"),
        port_specified=False,
        domain=item.get("domain", ""),
        domain_specified=item.get("domain_specified", True),
        domain_initial_dot=item.get("domain_initial_dot", False),
        path=item.get("path", "/"),
        path_specified=item.get("path_specified", True),
        secure=item.get("secure", False),
        expires=item.get("expires"),
        discard=item.get("discard", False),
        comment=item.get("comment"),
        comment_url=None,
        rest={},
        rfc2109=False,
    )


class Config(object):
    """单文件外部存储：<脚本目录>/cpolar_config.json"""

    def __init__(self, path):
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        if self.path and os.path.exists(self.path):
            try:
                with io.open(self.path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh) or {}
            except Exception as exc:
                sys.stderr.write("[cpolar] 配置文件解析失败（按空配置处理）：%s\n" % exc)
                self.data = {}
        return self.data

    def save(self):
        if not self.path:
            return False
        try:
            directory = os.path.dirname(self.path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            tmp = self.path + ".tmp"
            with io.open(tmp, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(self.data, ensure_ascii=False, indent=2))
            os.replace(tmp, self.path)
            return True
        except Exception as exc:
            sys.stderr.write("[cpolar] 配置写入失败：%s\n" % exc)
            return False

    # -- 字段访问 ---------------------------------------------------------
    @property
    def email(self):
        return self.data.get("email") or ""

    @property
    def password(self):
        return self.data.get("password") or ""

    def set_account(self, email, password):
        self.data["email"] = email
        if password:
            self.data["password"] = password

    def load_jar(self):
        jar = CookieJar()
        for item in self.data.get("cookies") or []:
            try:
                jar.set_cookie(dict_to_cookie(item))
            except Exception:
                continue
        return jar

    def save_jar(self, jar):
        self.data["cookies"] = [cookie_to_dict(c) for c in jar]

    def state_get(self, key, default=None):
        return (self.data.get("state") or {}).get(key, default)

    def state_set(self, key, value):
        self.data.setdefault("state", {})[key] = value


def prompt_account(config_path):
    """交互式输入账号密码并保存到配置文件。"""
    sys.stderr.write("[cpolar] 首次使用，请输入 cpolar 账号（会保存到 %s）\n" % config_path)
    email = ""
    while not email:
        email = (input("cpolar 邮箱: ") or "").strip()
    password = ""
    while not password:
        password = getpass.getpass("cpolar 密码（不回显）: ").strip()
    return email, password


# --------------------------------------------------------------------------
# 极简 HTML 表格解析（标准库实现，不依赖 bs4 / lxml）
# --------------------------------------------------------------------------
class TableCollector(HTMLParser):
    SKIP_TAGS = ("script", "style")

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.tables = []
        self._stack = []
        self._cell = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip += 1
            return
        attrd = dict(attrs)
        if tag == "table":
            self._stack.append({"attrs": attrd, "rows": [], "row": None})
        elif tag == "tr" and self._stack:
            table = self._stack[-1]
            if table["row"] is not None:
                table["rows"].append(table["row"])
            table["row"] = []
        elif tag in ("td", "th") and self._stack:
            table = self._stack[-1]
            if table["row"] is None:
                table["row"] = []
            self._cell = {"text": [], "links": [], "is_header": tag == "th"}
            table["row"].append(self._cell)
        elif tag == "a" and self._cell is not None:
            href = attrd.get("href")
            if href:
                self._cell["links"].append(href)
        elif tag in ("br", "p", "div") and self._cell is not None:
            self._cell["text"].append(" ")

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS:
            if self._skip:
                self._skip -= 1
            return
        if tag == "table" and self._stack:
            table = self._stack.pop()
            if table["row"]:
                table["rows"].append(table["row"])
            self.tables.append(table)
        elif tag == "tr" and self._stack:
            table = self._stack[-1]
            if table["row"] is not None:
                table["rows"].append(table["row"])
                table["row"] = None
        elif tag in ("td", "th"):
            self._cell = None

    def handle_data(self, data):
        if self._skip or self._cell is None:
            return
        if data.strip():
            self._cell["text"].append(data.strip())

    @staticmethod
    def cell_text(cell):
        return re.sub(r"\s+", " ", " ".join(cell["text"])).strip()

    def rows_as_dicts(self, table):
        out = []
        for row in table["rows"]:
            if not row:
                continue
            out.append({
                "cells": [self.cell_text(c) for c in row],
                "links": [c["links"] for c in row],
                "header": all(c["is_header"] for c in row),
            })
        return out


def pick(columns, keys):
    for key in keys:
        for head, value in columns.items():
            if head and key.lower() in head.lower() and value:
                return value
    return ""


def row_urls(cells, links):
    """取一行的公网地址：优先可用 href；href 被模板转义（#ZgotmplZ）时退回单元格文本。"""
    urls = []
    for idx, cell_links in enumerate(links):
        text = cells[idx] if idx < len(cells) else ""
        usable = [h for h in cell_links if ANY_URL_RE.match(h)]
        urls.extend(usable)
        if cell_links and not usable and URL_TEXT_RE.match(text):
            urls.append(text)
    if not urls:
        for text in cells:
            if URL_TEXT_RE.match(text):
                urls.append(text)
    return dedupe(urls)


def parse_tunnels(html):
    collector = TableCollector()
    collector.feed(html)

    best = None
    best_score = -1
    for table in collector.tables:
        rows = collector.rows_as_dicts(table)
        score = 0
        for row in rows:
            for links in row["links"]:
                for href in links:
                    if CPOLAR_URL_RE.match(href):
                        score += 3
            for text in row["cells"]:
                if CPOLAR_URL_RE.match(text):
                    score += 3
        if score > best_score:
            best_score = score
            best = rows

    debug = {"tables": len(collector.tables), "best_score": best_score}
    if not best or best_score <= 0:
        return [], debug

    headers = best[0]["cells"] if best[0]["header"] else None
    body = best[1:] if headers else best
    if headers:
        debug["headers"] = headers

    merged = []
    index = {}
    for row in body:
        cells = row["cells"]
        columns = dict(zip(headers, cells)) if headers and len(headers) == len(cells) else {}

        name = pick(columns, COL_NAME) or (cells[0] if cells else "")
        if not name:
            continue
        urls = row_urls(cells, row["links"])
        if not urls and not columns:
            continue

        if name in index:
            tunnel = merged[index[name]]
        else:
            tunnel = {
                "name": name,
                "public_urls": [],
                "region": pick(columns, COL_REGION),
                "local_addr": pick(columns, COL_LOCAL),
                "created_at": columns.get("创建时间", ""),
                "entries": [],
            }
            index[name] = len(merged)
            merged.append(tunnel)

        tunnel["public_urls"] = dedupe(tunnel["public_urls"] + urls)
        if not tunnel["region"]:
            tunnel["region"] = pick(columns, COL_REGION)
        if not tunnel["local_addr"]:
            tunnel["local_addr"] = pick(columns, COL_LOCAL)
        tunnel["entries"].append(columns or {"cells": cells, "urls": urls})

    for tunnel in merged:
        tunnel["public_urls"].sort(key=url_sort_key)

    debug["rows"] = sum(len(t["entries"]) for t in merged)
    debug["tunnels"] = len(merged)
    return merged, debug


# --------------------------------------------------------------------------
# 客户端
# --------------------------------------------------------------------------
class RateLimited(Exception):
    pass


class CpolarClient(object):
    def __init__(self, config, timeout=25, insecure=False,
                 min_interval=20.0, login_backoff=600.0, verbosity=1):
        self.config = config
        self.timeout = timeout
        self.verbosity = verbosity
        self.min_interval = min_interval
        self.login_backoff = login_backoff

        self.jar = config.load_jar()
        handlers = [request.HTTPCookieProcessor(self.jar)]
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        handlers.append(request.HTTPSHandler(context=context))
        self.opener = request.build_opener(*handlers)

    # -- 限速 / 退避 --------------------------------------------------------
    def guard_rate(self, force=False):
        if force or self.min_interval <= 0:
            return True
        gap = time.time() - (self.config.state_get("last_request_ts", 0) or 0)
        if gap < self.min_interval:
            log("距上次请求仅 %.1f 秒（下限 %d 秒），为保护账号拒绝发请求；"
                "确需立即执行请加 --force" % (gap, int(self.min_interval)))
            return False
        return True

    def guard_login_backoff(self):
        last_fail = self.config.state_get("last_login_fail_ts", 0) or 0
        if last_fail:
            gap = time.time() - last_fail
            if gap < self.login_backoff:
                log("上次登录失败距今 %.0f 秒，退避期内不再尝试登录（还需 %.0f 秒）"
                    % (gap, self.login_backoff - gap))
                return False
        return True

    # -- HTTP --------------------------------------------------------------
    def fetch(self, url, data=None, referer=None, method=None):
        body = parse.urlencode(data).encode("utf-8") if data is not None else None
        req = request.Request(url, data=body, method=method)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
        req.add_header("Referer", referer or BASE_URL + "/")
        if body is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("Origin", BASE_URL)

        self.config.state_set("last_request_ts", time.time())
        self.save_config()
        if self.verbosity >= 2:
            log("%s %s" % ("POST" if body is not None else "GET", url))

        try:
            resp = self.opener.open(req, timeout=self.timeout)
        except error.HTTPError as exc:
            raw = exc.read()
            charset = exc.headers.get_content_charset() or "utf-8"
            return exc.geturl(), exc.code, raw.decode(charset, "replace")
        with resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.geturl(), getattr(resp, "status", resp.code), raw.decode(charset, "replace")

    def save_config(self):
        self.config.save_jar(self.jar)
        self.config.save()

    # -- 登录 --------------------------------------------------------------
    @staticmethod
    def looks_logged_in(html):
        return bool(re.search(r"在线隧道|table-sm", html, re.I)) and not ERROR_MARK_RE.search(html)

    @staticmethod
    def error_message(html):
        m = re.search(r"""<div[^>]*class=["'][^"']*alert[^"']*["'][^>]*>(.*?)</div>""",
                      html, re.I | re.S)
        if m:
            return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1))).strip()[:200]
        if re.search(r"captcha|验证码", html, re.I):
            return "页面要求验证码，请手动登录控制台确认"
        return None

    def login(self):
        if not self.guard_login_backoff():
            return False
        email, password = self.config.email, self.config.password
        if not email or not password:
            log("配置文件里没有账号密码，请用 --set-account 保存，"
                "或设置环境变量 CPOLAR_EMAIL / CPOLAR_PASSWORD")
            return False

        log("登录态不可用，执行登录（每次运行最多登录 1 次）")
        _, _, page = self.fetch(LOGIN_URL)

        csrf = None
        m = re.search(r"""name=["']csrf_token["'][^>]*value=["']([^"']+)""", page, re.I)
        if not m:
            m = re.search(r"""value=["']([^"']+)["'][^>]*name=["']csrf_token["']""", page, re.I)
        if m:
            csrf = m.group(1)

        action = "/login"
        m = re.search(r"""<form[^>]*action=["']([^"']+)""", page, re.I)
        if m:
            action = m.group(1)

        payload = {"login": email, "password": password}
        if csrf:
            payload["csrf_token"] = csrf
        final_url, _, body = self.fetch(parse.urljoin(BASE_URL, action),
                                        data=payload, referer=LOGIN_URL, method="POST")

        if "/login" in final_url:
            log("登录失败：%s" % (self.error_message(body) or "账号密码不正确"))
            self.config.state_set("last_login_fail_ts", time.time())
            self.save_config()
            return False

        self.config.state_set("last_login_ok_ts", time.time())
        self.config.data["state"].pop("last_login_fail_ts", None)
        self.save_config()
        log("登录成功")
        return True

    # -- 取隧道列表 ---------------------------------------------------------
    def fetch_tunnels(self, force=False):
        if not self.guard_rate(force):
            raise RateLimited()

        had_cookie = len(self.jar) > 0
        final_url, _, page = self.fetch(STATUS_URL, referer=BASE_URL + "/")

        if "/login" in final_url or not self.looks_logged_in(page):
            if had_cookie:
                log("缓存的登录态已失效")
            if not self.login():
                return None, page
            final_url, _, page = self.fetch(STATUS_URL, referer=BASE_URL + "/")
            if "/login" in final_url:
                log("登录后仍被跳转到登录页，放弃本次请求")
                return None, page

        self.save_config()
        return parse_tunnels(page)[0], page


# --------------------------------------------------------------------------
# 打开方式
# --------------------------------------------------------------------------
def copy_to_clipboard(text):
    try:
        if os.name == "nt":
            proc = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            proc.communicate(text.encode("utf-8"))
            return proc.returncode == 0
        for cmd in (["pbcopy"], ["xclip", "-selection", "clipboard"], ["xsel", "-ib"]):
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                proc.communicate(text.encode("utf-8"))
                if proc.returncode == 0:
                    return True
            except OSError:
                continue
    except Exception:
        pass
    return False


def pick_target(tunnel, prefer=None):
    """决定回车要打开什么：(kind, url)。kind ∈ browser / rdp / clipboard。"""
    urls = tunnel.get("public_urls") or []
    https = [u for u in urls if u.lower().startswith("https://")]
    http = [u for u in urls if u.lower().startswith("http://")]
    tcp = [u for u in urls if u.lower().startswith(("tcp://", "tls://"))]
    port = local_port(tunnel.get("local_addr", ""))

    if prefer == "http":
        if http:
            return "browser", http[0]
        if https:
            return "browser", https[0]
        return None, None

    # 本机 3389 的 TCP 隧道 → 远程桌面
    if port == "3389" and tcp:
        return "rdp", tcp[0]
    if https:
        return "browser", https[0]
    if http:
        return "browser", http[0]
    if tcp:
        return "clipboard", tcp[0]
    return None, None


def open_target(kind, url, dry_run=False):
    if kind == "browser":
        if dry_run:
            return "[dry-run] 用默认浏览器打开 %s" % url
        try:
            if not webbrowser.open(url, new=2):
                return "无法启动浏览器，地址：%s" % url
        except Exception as exc:
            return "打开浏览器失败：%s（地址：%s）" % (exc, url)
        return "已用默认浏览器打开 %s" % url

    if kind == "rdp":
        address = tcp_host_port(url)
        if dry_run:
            return "[dry-run] 启动远程桌面：mstsc /v:%s" % address
        try:
            subprocess.Popen(["mstsc", "/v:" + address])
        except Exception as exc:
            return "启动 mstsc 失败：%s（地址：%s）" % (exc, address)
        return "已启动远程桌面 mstsc /v:%s" % address

    if kind == "clipboard":
        if dry_run:
            return "[dry-run] 复制到剪贴板：%s" % url
        return ("已复制到剪贴板：%s" % url) if copy_to_clipboard(url) else ("地址：%s" % url)

    return "该隧道没有可用于打开的地址"


# --------------------------------------------------------------------------
# 按键读取
# --------------------------------------------------------------------------
ARROW_MAP = {b"H": "up", b"P": "down", b"K": "left", b"M": "right"}


class ConsoleKeys(object):
    """真实控制台按键（Windows 用 msvcrt，其它平台用 termios 原始模式）。"""

    def read(self):
        if os.name == "nt":
            return self._read_windows()
        return self._read_posix()

    @staticmethod
    def _read_windows():
        import msvcrt
        ch = msvcrt.getch()
        while ch in (b"\x00", b"\xe0"):
            ch = msvcrt.getch()
            if ch in ARROW_MAP:
                return ARROW_MAP[ch]
        if ch in (b"\r", b"\n"):
            return "enter"
        if ch == b"\x1b":
            return "esc"
        if ch == b"\x03":
            return "ctrl-c"
        try:
            return ch.decode("utf-8").lower()
        except Exception:
            return "other"

    @staticmethod
    def _read_posix():
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1)
            if ch == b"\x1b":
                nxt = os.read(fd, 1)
                if nxt == b"[":
                    return {b"A": "up", b"B": "down", b"C": "right", b"D": "left"}.get(
                        os.read(fd, 1), "other")
                return "esc"
            if ch in (b"\r", b"\n"):
                return "enter"
            if ch == b"\x03":
                return "ctrl-c"
            return ch.decode("utf-8", "replace").lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


class ScriptedKeys(object):
    """--keys 指定的按键序列，用于自动测试（不依赖真实终端）。"""

    ALIASES = {"up": "up", "k": "up", "down": "down", "j": "down", "enter": "enter",
               "return": "enter", "q": "q", "quit": "q", "esc": "esc", "h": "h",
               "c": "c", "r": "r", "o": "o"}

    def __init__(self, keys, echo=True):
        self.keys = list(keys)
        self.echo = echo

    def read(self):
        if not self.keys:
            return "q"
        key = self.keys.pop(0)
        if self.echo:
            sys.stdout.write("按键: %s\n" % key)
            sys.stdout.flush()
        return key


def parse_keys(text):
    if not text:
        return []
    parts = re.split(r"[,\s]+", text.strip())
    return [ScriptedKeys.ALIASES.get(p.lower(), p.lower()) for p in parts if p]


# --------------------------------------------------------------------------
# 交互式菜单
# --------------------------------------------------------------------------
class TunnelMenu(object):
    HINTS = ("↑/↓ 选择   Enter 打开（https 优先 / 本机 3389 走远程桌面）   "
             "h 用 http 打开   c 复制地址   o 打印地址   r 刷新   q 退出")

    def __init__(self, client, tunnels, email, fetched_at, args, ansi=True, keys=None):
        self.client = client
        self.tunnels = tunnels
        self.email = email
        self.fetched_at = fetched_at
        self.args = args
        self.ansi = ansi
        self.keys = keys or ConsoleKeys()
        self.index = 0
        self.message = ""
        self.dirty = True

    # -- 渲染 --------------------------------------------------------------
    def row_text(self, tunnel):
        name = tunnel["name"]
        region = tunnel.get("region") or "-"
        local = tunnel.get("local_addr") or "-"
        urls = tunnel.get("public_urls") or []
        if not urls:
            primary = "(无公网地址)"
        else:
            urls_sorted = sorted(urls, key=url_sort_key)
            primary = urls_sorted[0]
        return name, region, local, primary, urls

    def render(self):
        name_w = max([len(t["name"]) for t in self.tunnels] + [8])
        region_w = max([len(t.get("region") or "-") for t in self.tunnels] + [4])
        local_w = max([len(t.get("local_addr") or "-") for t in self.tunnels] + [8])

        lines = []
        lines.append("cpolar 隧道列表  账号: %s  抓取时间: %s  共 %d 条"
                     % (self.email, self.fetched_at, len(self.tunnels)))
        lines.append("-" * 90)
        if not self.tunnels:
            lines.append("（没有解析到隧道：账号下可能暂无隧道，或页面结构有变化）")
        for idx, tunnel in enumerate(self.tunnels):
            name, region, local, primary, urls = self.row_text(tunnel)
            marker = "▸ " if idx == self.index else "  "
            line = "%s%-*s  %-*s  %-*s  %s" % (marker, name_w, name,
                                               region_w, region, local_w, local, primary)
            if self.ansi and idx == self.index:
                line = ANSI_REVERSE + line + ANSI_RESET
            lines.append(line)
            for extra in urls[1:]:
                lines.append("  %-*s  %-*s  %-*s  %s"
                             % (name_w, "", region_w, "", local_w, "", extra))
        lines.append("-" * 90)
        if self.message:
            lines.append(self.message)
        hints = self.HINTS
        if self.ansi:
            hints = ANSI_DIM + hints + ANSI_RESET
        lines.append(hints)
        return "\n".join(lines)

    def draw(self):
        text = self.render()
        if self.ansi:
            sys.stdout.write(ANSI_HOME_CLEAR + text + "\n")
        else:
            if not self.dirty:
                sys.stdout.write("\n")
            sys.stdout.write(text + "\n")
        sys.stdout.flush()
        self.dirty = False

    # -- 交互 --------------------------------------------------------------
    def move(self, delta):
        if not self.tunnels:
            return
        self.index = (self.index + delta) % len(self.tunnels)
        self.message = ""

    def open_selected(self, prefer=None):
        if not self.tunnels:
            return
        tunnel = self.tunnels[self.index]
        kind, url = pick_target(tunnel, prefer=prefer)
        if not kind:
            self.message = "隧道 %s 没有可打开的地址" % tunnel["name"]
            return
        self.message = "%s  →  %s" % (tunnel["name"], open_target(kind, url, self.args.dry_run))

    def refresh(self):
        try:
            tunnels, _ = self.client.fetch_tunnels(force=self.args.force)
        except RateLimited:
            self.message = "刷新被本地限速拦下（--min-interval），稍等再按 r"
            return
        except error.URLError as exc:
            self.message = "刷新失败：%s" % exc
            return
        if tunnels is None:
            self.message = "刷新失败：登录态不可用"
            return
        self.tunnels = tunnels
        self.index = min(self.index, max(0, len(tunnels) - 1))
        self.fetched_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        self.message = "已刷新：%s 条隧道" % len(tunnels)

    def handle(self, key):
        if key in ("up", "k"):
            self.move(-1)
        elif key in ("down", "j"):
            self.move(1)
        elif key == "enter":
            self.open_selected()
        elif key == "h":
            self.open_selected(prefer="http")
        elif key == "c":
            if self.tunnels:
                tunnel = self.tunnels[self.index]
                kind, url = pick_target(tunnel)
                if url and not self.args.dry_run and copy_to_clipboard(url):
                    self.message = "已复制地址：%s" % url
                elif url:
                    self.message = "地址：%s" % url
                else:
                    self.message = "隧道 %s 没有地址" % tunnel["name"]
        elif key == "o":
            if self.tunnels:
                self.message = " | ".join(self.tunnels[self.index].get("public_urls") or ["(无)"])
        elif key == "r":
            self.refresh()
        elif key in ("q", "esc", "ctrl-c"):
            return "quit"
        return None

    def run(self):
        while True:
            self.draw()
            try:
                key = self.keys.read()
            except KeyboardInterrupt:
                return
            except Exception as exc:  # 没有真实控制台时优雅退化
                log("无法读取按键（%s），改为直接打印列表" % exc)
                print_menu_static(self)
                return
            if self.handle(key) == "quit":
                return


def print_table(tunnels, fetched_at=None, email=None):
    if not tunnels:
        print("（没有解析到隧道：账号下可能暂无隧道，或页面结构有变化）")
        return
    if email:
        print("cpolar 隧道列表  账号: %s  抓取时间: %s  共 %d 条"
              % (email, fetched_at or "-", len(tunnels)))
    name_w = max([len(t["name"]) for t in tunnels] + [8])
    region_w = max([len(t.get("region") or "-") for t in tunnels] + [4])
    local_w = max([len(t.get("local_addr") or "-") for t in tunnels] + [8])
    header = "%-*s  %-*s  %-*s  %s" % (name_w, "隧道名称", region_w, "地区",
                                       local_w, "本地地址", "公网地址")
    print(header)
    print("-" * len(header))
    for tunnel in tunnels:
        urls = tunnel["public_urls"] or ["(未解析到地址)"]
        print("%-*s  %-*s  %-*s  %s" % (name_w, tunnel["name"],
                                        region_w, tunnel.get("region") or "-",
                                        local_w, tunnel.get("local_addr") or "-",
                                        urls[0]))
        for extra in urls[1:]:
            print("%-*s  %-*s  %-*s  %s" % (name_w, "", region_w, "", local_w, "", extra))


def print_menu_static(menu):
    print(menu.render())


# --------------------------------------------------------------------------
# 主程序
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="获取 cpolar 隧道列表并交互式打开（单文件，账号存在外部配置文件中）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=DEFAULT_CONFIG,
                   help="账号/Cookie 存储文件，默认 %s" % DEFAULT_CONFIG)
    p.add_argument("--email", default=os.environ.get("CPOLAR_EMAIL"),
                   help="临时指定邮箱（优先于配置文件，可用环境变量 CPOLAR_EMAIL）")
    p.add_argument("--password", default=os.environ.get("CPOLAR_PASSWORD"),
                   help="临时指定密码（优先于配置文件，可用环境变量 CPOLAR_PASSWORD）")
    p.add_argument("--set-account", action="store_true",
                   help="重新输入账号密码并保存到配置文件")
    p.add_argument("--json", action="store_true", help="以 JSON 输出，不进入选择界面")
    p.add_argument("-o", "--output", help="把结果（JSON）写入指定文件")
    p.add_argument("--no-menu", action="store_true", help="只打印表格，不进入选择界面")
    p.add_argument("--dump-html", help="保存 /status 原始页面，便于排查解析问题")
    p.add_argument("--keys", help="自动测试用：逗号分隔的按键序列，如 up,up,enter,q")
    p.add_argument("--dry-run", action="store_true", help="只显示将执行的动作，不真的打开")
    p.add_argument("--timeout", type=float, default=25.0, help="单次请求超时秒数（默认 25）")
    p.add_argument("--min-interval", type=float, default=20.0,
                   help="两次网络请求的最小间隔秒数（默认 20，0 表示不限制）")
    p.add_argument("--login-backoff", type=float, default=600.0,
                   help="登录失败后的退避秒数（默认 600）")
    p.add_argument("--force", action="store_true", help="忽略最小请求间隔限制")
    p.add_argument("--insecure", action="store_true", help="不校验 HTTPS 证书")
    p.add_argument("-v", "--verbose", action="count", default=0, help="输出更多调试信息")
    p.add_argument("-q", "--quiet", action="store_true", help="静默模式，只输出结果")
    return p


def ensure_account(config, args, force_prompt=False):
    """账号优先级：命令行/环境变量 > 配置文件 > 交互输入并保存。"""
    email = (args.email or "").strip()
    password = (args.password or "").strip()
    changed = False

    if email:
        config.data["email"] = email
        changed = True
    if password:
        config.data["password"] = password
        changed = True

    if force_prompt or not config.email or not config.password:
        try:
            email, password = prompt_account(config.path)
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\n[cpolar] 已取消输入\n")
            return False
        config.set_account(email, password)
        changed = True
        sys.stderr.write("[cpolar] 账号已保存到 %s\n" % config.path)

    if changed:
        config.save()
    return True


def main(argv=None):
    force_utf8_output()
    args = build_parser().parse_args(argv)
    verbosity = 0 if args.quiet else (2 if args.verbose else 1)

    config = Config(args.config)
    if not ensure_account(config, args, force_prompt=args.set_account):
        return EXIT_LOGIN_FAILED

    client = CpolarClient(config, timeout=args.timeout, insecure=args.insecure,
                          min_interval=args.min_interval, login_backoff=args.login_backoff,
                          verbosity=verbosity)

    try:
        tunnels, page = client.fetch_tunnels(force=args.force)
    except RateLimited:
        return EXIT_RATE_LIMITED
    except error.URLError as exc:
        log("网络错误：%s" % exc)
        return EXIT_NETWORK_ERROR
    except Exception as exc:
        log("请求异常：%s: %s" % (type(exc).__name__, exc))
        return EXIT_NETWORK_ERROR

    if tunnels is None:
        return EXIT_LOGIN_FAILED

    if args.dump_html and page:
        with io.open(args.dump_html, "w", encoding="utf-8") as fh:
            fh.write(page)
        log("已保存原始页面到 %s" % args.dump_html)

    fetched_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    payload = {
        "email": config.email,
        "source": STATUS_URL,
        "fetched_at": datetime.now().astimezone().isoformat(),
        "count": len(tunnels),
        "tunnels": tunnels,
    }

    if args.output:
        with io.open(args.output, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, indent=2))
        log("结果已写入 %s" % args.output)

    if args.json:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        return EXIT_OK if tunnels else EXIT_NO_TUNNEL

    scripted = parse_keys(args.keys) if args.keys else None
    interactive = bool(scripted) or (not args.no_menu and sys.stdout.isatty())

    if not interactive:
        print_table(tunnels, fetched_at=fetched_at, email=config.email)
        return EXIT_OK if tunnels else EXIT_NO_TUNNEL

    ansi = enable_ansi() and not scripted
    menu = TunnelMenu(client, tunnels, config.email, fetched_at, args,
                      ansi=ansi, keys=ScriptedKeys(scripted) if scripted else None)
    menu.run()
    return EXIT_OK if tunnels else EXIT_NO_TUNNEL


if __name__ == "__main__":
    sys.exit(main())
