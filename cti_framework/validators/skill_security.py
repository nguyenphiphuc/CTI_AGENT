"""
Skill Security Policy Gate — Cổng kiểm tra tĩnh (Static AST Analysis) cho Skill tự sinh.

Mục tiêu: chặn MÃ NGUY HIỂM trước khi file Python được ghi xuống đĩa hoặc được
Hunter Agent nạp vào bộ nhớ (importlib). Đây là lớp phòng thủ BỔ SUNG cho hộp cát
subprocess 5 giây — hộp cát chỉ cô lập được về thời gian, còn chính sách thực thi
phải được kiểm tra bằng phân tích AST.

Nguyên tắc thiết kế:
- DENY-BY-DEFAULT (allowlist): chỉ cho phép import các module nằm trong ALLOWED_MODULES.
- Chặn gọi hàm thực thi lệnh / dynamic code: eval, exec, compile, __import__ ...
- Chặn mọi API thao tác hệ thống nguy hiểm của os (system, popen, remove, chmod ...).
- Chặn mở tệp ở chế độ ghi (w/a/x/+); skill chỉ được QUÉT/ĐỌC, không được GHI.
- Chặn thao tác socket chủ động kết nối/gửi dữ liệu (skill giám sát, không tấn công).
- Chặn truy cập thuộc tính dunder (gây lọt ngoài encapsulation: __globals__, __subclasses__ ...).

Trả về dict JSON-serializable để lưu thẳng vào skill_verification_runs.test_output.
"""

import ast
from typing import Dict, List, Any

# --- Whitelist module: skill phòng thủ CẦN những module này để quét/đọc ---
ALLOWED_MODULES = {
    # nền tảng
    "os", "sys", "re", "json", "math", "time", "datetime", "typing", "logging",
    "enum", "dataclasses", "abc", "collections", "itertools", "functools",
    "textwrap", "string", "struct", "unicodedata", "statistics", "random",
    # xử lý / tra cứu an toàn
    "hashlib", "base64", "binascii", "ipaddress", "socket", "pathlib", "glob",
    "fnmatch", "mimetypes", "csv", "io", "contextlib", "traceback", "warnings",
    "urllib",            # CHỈ urllib.parse được dùng (xem FORBIDDEN_SUBMODULES)
    # package nội bộ của framework
    "skills",
}

# Sub-module bị cấm dù parent nằm trong whitelist
FORBIDDEN_SUBMODULES = {
    "urllib.request", "urllib.error", "urllib.robotparser", "urllib.parse.request",
}

# --- Module tuyệt đối bị cấm (thông báo lỗi rõ ràng hơn) ---
FORBIDDEN_MODULES = {
    "subprocess", "multiprocessing", "ctypes", "shutil", "pickle", "marshal",
    "importlib", "requests", "http", "http.client", "ftplib", "smtplib",
    "telnetlib", "paramiko", "sqlite3", "threading", "signal", "pty", "webbrowser",
    "httpx", "aiohttp", "docker", "winreg", "msvcrt", "posix", "resource",
}

# --- Tên hàm động code / thực thi ---
DANGEROUS_NAMES = {
    "eval", "exec", "compile", "__import__", "globals", "locals",
    "breakpoint", "setattr", "delattr", "getattr", "vars",
}

# --- API nguy hiểm của os ---
DANGEROUS_OS_ATTRS = {
    "system", "popen", "popen2", "popen3", "popen4",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "startfile", "fork", "forkpty", "kill", "killpg", "abort", "_exit",
    "chmod", "fchmod", "chown", "lchown", "fchown",
    "remove", "removedirs", "rmdir", "unlink", "rename", "renameat", "replace",
    "truncate", "ftruncate", "utime", "utimes", "futimes", "link", "symlink",
    "mknod", "mkfifo", "chroot", "setuid", "setgid", "seteuid", "setegid",
    "environ",           # không cho skill đọc biến môi trường (không cần cho việc quét)
    "pipe", "munmap",
}

# --- Thao tác socket chủ động (skill chỉ được GIÁM SÁT, không được kết nối/gửi) ---
DANGEROUS_SOCKET_ATTRS = {
    "connect", "connect_ex", "bind", "listen", "accept",
    "send", "sendall", "sendto", "sendmsg", "sendfile",
}

# --- sys: không cho can thiệp module runtime ---
DANGEROUS_SYS_ATTRS = {"modules", "settrace", "setprofile", "setrecursionlimit"}

# --- Thuộc tính dunder được phép (phần còn lại đều bị cấm) ---
SAFE_DUNDER_ATTRS = {"__init__", "__call__", "__name__", "__version__", "__doc__"}

# --- Chế độ file được phép mở: chỉ đọc ---
_WRITE_CHARS = ("w", "a", "x", "+")


def _allowed_import(module_name: str) -> bool:
    """Kiểm tra allowlist cho import (hỗ trợ import a.b)."""
    top = (module_name or "").split(".")[0]
    if top in FORBIDDEN_MODULES or module_name in FORBIDDEN_MODULES:
        return False
    if module_name in FORBIDDEN_SUBMODULES:
        return False
    return top in ALLOWED_MODULES


def _check_open_mode(node: ast.Call) -> Dict[str, Any]:
    """Kiểm tra mode của open(): chỉ chấp nhận mode đọc thuần (không w/a/x/+)."""
    mode = None
    # open(path, "r")  hoặc open(path, mode="r")
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    if mode is None:
        return {"ok": False, "detail": "open() với mode không xác định (không được phép)"}
    if not isinstance(mode, str):
        return {"ok": False, "detail": f"open() mode không hợp lệ: {mode!r}"}
    if any(ch in mode for ch in _WRITE_CHARS):
        return {"ok": False, "detail": f"open() ở chế độ ghi '{mode}' bị cấm — skill chỉ được đọc"}
    if not set(mode) <= set("rbt"):
        return {"ok": False, "detail": f"open() mode không hợp lệ: '{mode}'"}
    return {"ok": True, "detail": ""}


def scan_skill_code(code: str) -> Dict[str, Any]:
    """
    Quét mã nguồn Skill bằng AST theo chính sách an toàn.

    Returns:
        {
          "passed": bool,
          "violations": [{"line": int, "rule": str, "message": str}, ...],
          "summary": str
        }
    """
    violations: List[Dict[str, Any]] = []

    def add(line: int, rule: str, message: str) -> None:
        violations.append({"line": line, "rule": rule, "message": message})

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {
            "passed": False,
            "violations": [{"line": e.lineno or 0, "rule": "syntax_error",
                            "message": f"SyntaxError: {e.msg}"}],
            "summary": "Mã nguồn không phân tích được (lỗi cú pháp).",
        }

    # --- Bước 1: dựng bản đồ bí danh import (import os as o -> o == os) ---
    alias_map: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                alias_map[alias.asname or alias.name] = top
                alias_map[alias.asname or top] = top
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    alias_map[alias.asname] = (node.module or "").split(".")[0]

    for node in ast.walk(tree):
        # --- 1. Import policy ---
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _allowed_import(alias.name):
                    add(node.lineno, "forbidden_import",
                        f"Import module bị cấm: '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(a.name == "*" for a in node.names):
                add(node.lineno, "star_import",
                    f"import * từ '{mod}' bị cấm (không xác định được tên gọi)")
            elif not _allowed_import(mod):
                add(node.lineno, "forbidden_import",
                    f"Import module bị cấm: '{mod}'")

        # --- 2. Gọi hàm theo TÊN (eval/exec/compile/open) ---
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in DANGEROUS_NAMES:
                    add(node.lineno, "dangerous_call",
                        f"Gọi hàm '{func.id}()' bị cấm (thực thi mã động)")
                elif func.id == "open":
                    res = _check_open_mode(node)
                    if not res["ok"]:
                        add(node.lineno, "write_access", res["detail"])

        # --- 3. Tham chiếu / gọi qua THUỘC TÍNH (os.system, s.connect, __globals__ ...) ---
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            base = node.value.id if isinstance(node.value, ast.Name) else None
            mod = alias_map.get(base, base) if base else None

            if attr.startswith("__") and attr.endswith("__") and attr not in SAFE_DUNDER_ATTRS:
                add(node.lineno, "dunder_access",
                    f"Truy cập thuộc tính '{attr}' bị cấm (lọt ngoài đóng gói đối tượng)")
            elif mod == "os" and attr in DANGEROUS_OS_ATTRS:
                add(node.lineno, "dangerous_os_api",
                    f"os.{attr} bị cấm (thao tác hệ thống nguy hiểm)")
            elif mod == "sys" and attr in DANGEROUS_SYS_ATTRS:
                add(node.lineno, "runtime_tamper",
                    f"sys.{attr} bị cấm (can thiệp runtime Python)")
            elif attr in DANGEROUS_SOCKET_ATTRS:
                # Áp dụng cho mọi biến: s.connect(...) dù s là socket tạm thời
                add(node.lineno, "active_network",
                    f"'{attr}()' bị cấm — skill giám sát, không được kết nối/gửi dữ liệu")

    # --- Tổng hợp ---
    seen = set()
    deduped = []
    for v in violations:
        key = (v["line"], v["rule"], v["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    passed = not deduped
    summary = (
        "AST policy scan PASSED: không phát hiện vi phạm chính sách an toàn."
        if passed else
        f"AST policy scan FAILED: {len(deduped)} vi phạm — " +
        "; ".join(sorted({v['rule'] for v in deduped}))
    )
    return {"passed": passed, "violations": deduped, "summary": summary}


def format_violations(result: Dict[str, Any]) -> str:
    """Chuyển kết quả scan thành chuỗi ngắn gọn để lưu vào test_output."""
    if result.get("passed"):
        return result.get("summary", "AST policy scan PASSED.")
    lines = [f"[line {v['line']}] {v['rule']}: {v['message']}"
             for v in result.get("violations", [])[:20]]
    return result.get("summary", "") + "\n" + "\n".join(lines)