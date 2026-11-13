"""CI diagnostic (macOS): can the owner map a live loopback client socket to its PID, and how fast? Prints only."""

import socket
import subprocess
import sys
import time

server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
listen_port = server.getsockname()[1]
client = subprocess.Popen(
    [sys.executable, "-c", f"import socket,sys;s=socket.create_connection(('127.0.0.1',{listen_port}));sys.stdin.read()"],
    stdin=subprocess.PIPE,
)
conn, (_, client_port) = server.accept()
print(f"client pid={client.pid} 127.0.0.1:{client_port}->127.0.0.1:{listen_port}", flush=True)
for args in (
    ["lsof", "-nP", "-F", "pn", f"-iTCP@127.0.0.1:{client_port}"],
    ["lsof", "-nP", "-F", "pn", f"-iTCP:{client_port}"],
    ["lsof", "-nP", "-a", "-F", "pn", f"-iTCP:{client_port}", "-p", str(client.pid)],
):
    t0 = time.monotonic()
    proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)
    print(f"--- {' '.join(args)} rc={proc.returncode} {time.monotonic() - t0:.3f}s", flush=True)
    print(proc.stdout.strip() or "<no stdout>", proc.stderr.strip() or "<no stderr>", sep="\n", flush=True)
sys.path.insert(0, ".")
import ctypes  # noqa: E402

from tests.support import inc2_native_owner as own  # noqa: E402

t0 = time.monotonic()
pid = own._libproc_client_pid(client_port, listen_port)
print(f"--- libproc lookup -> {pid} (expected {client.pid}) {time.monotonic() - t0:.4f}s", flush=True)
t0 = time.monotonic()
print(f"--- _lookup_loopback_client_pid -> {own._lookup_loopback_client_pid(client_port, listen_port)} "
      f"{time.monotonic() - t0:.4f}s", flush=True)
lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
fds = (ctypes.c_int32 * 512)()
used = lib.proc_pidinfo(client.pid, own._PROC_PIDLISTFDS, 0, fds, ctypes.sizeof(fds))
for i in range(0, max(0, used) // 4 - 1, 2):
    if fds[i + 1] == own._PROX_FDTYPE_SOCKET:
        info = ctypes.create_string_buffer(2048)
        n = lib.proc_pidfdinfo(client.pid, fds[i], own._PROC_PIDFDSOCKETINFO, info, ctypes.sizeof(info))
        print(f"fd {fds[i]} n={n} parsed={own._parse_socket_fdinfo(info.raw[:n]) if n > 0 else None}", flush=True)
        print("hex[176:340]=" + info.raw[176:340].hex(), flush=True)
client.stdin.close()  # type: ignore[union-attr]
client.wait(timeout=10)
conn.close()
server.close()
