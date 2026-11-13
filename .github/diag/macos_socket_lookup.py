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
client.stdin.close()  # type: ignore[union-attr]
client.wait(timeout=10)
conn.close()
server.close()
