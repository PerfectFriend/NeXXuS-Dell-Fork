#!/usr/bin/env python3
"""E2E IOU (ADR-0009): iou_issue -> iou_redeem -> iou_list -> iou_balance, replay отклоняется."""
import socket, base64, os, json, struct, sys

HOST, PORT = "127.0.0.1", int(os.environ.get("E2E_API_PORT", "4010"))

def ws_connect():
    s = socket.create_connection((HOST, PORT), timeout=30)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: Upgrade\r\n"
               f"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(4096)
    assert b"101" in resp.split(b"\r\n")[0]
    return s

def send_text(s, text):
    p = text.encode(); mask = os.urandom(4); n = len(p)
    h = bytearray([0x81])
    if n < 126: h.append(0x80 | n)
    elif n < 65536: h.append(0x80 | 126); h += struct.pack(">H", n)
    else: h.append(0x80 | 127); h += struct.pack(">Q", n)
    h += mask
    s.sendall(bytes(h) + bytes(b ^ mask[i % 4] for i, b in enumerate(p)))

def recv_text(s):
    h = s.recv(2); ln = h[1] & 0x7F
    if ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
    elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
    d = b""
    while len(d) < ln: d += s.recv(ln - len(d))
    return d.decode()

def call(method, params=None, token=None):
    s = ws_connect()
    if token is not None:
        send_text(s, json.dumps({"jsonrpc": "2.0", "method": "auth", "params": {"token": token}, "id": 0}))
        json.loads(recv_text(s))
    send_text(s, json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}))
    return json.loads(recv_text(s))

ok = []
def check(name, cond, extra=""):
    assert cond, f"FAIL {name} {extra}"
    ok.append(name)
    print(f"  ✅ {name}")

tokf = os.environ.get("E2E_TOKEN_FILE", os.path.expanduser("~/.nexxus/api.token"))
token = open(tokf).read().strip()

# узнаём наш node_id
st = call("node_status", token=token)["result"]
my_id = st.get("node_id") or st.get("id")
check("node_status: node_id получен", isinstance(my_id, str) and len(my_id) == 64, str(st)[:200])

# 1. issue: мы — debtor, creditor = мы же (self-IOU для e2e)
r = call("iou_issue", {"creditor": my_id, "amount_micro": 7_000_000, "epoch": 1}, token=token)
check("iou_issue ok", "result" in r, str(r)[:300])
iou_json = r["result"]["iou"]
pk = r["result"]["debtor_pubkey"]
check("iou_issue: debtor == наш node_id", r["result"]["debtor"] == my_id)

# 2. redeem того же IOU — ок первый раз
r = call("iou_redeem", {"iou": iou_json, "debtor_pubkey": pk}, token=token)
check("iou_redeem ok", r.get("result", {}).get("ok") is True, str(r)[:300])

# 3. replay — отклонён
r = call("iou_redeem", {"iou": iou_json, "debtor_pubkey": pk}, token=token)
check("iou_redeem replay → error", bool(r.get("error")), str(r)[:300])

# 4. tampered amount — отклонён
bad = json.loads(iou_json); bad["amount_micro"] = str(int(bad["amount_micro"]) + 1)
r = call("iou_redeem", {"iou": json.dumps(bad), "debtor_pubkey": pk}, token=token)
check("iou_redeem tampered → error", bool(r.get("error")), str(r)[:300])

# 5. чужой pubkey — отклонён
r = call("iou_redeem", {"iou": iou_json, "debtor_pubkey": "ab" * 32}, token=token)
check("iou_redeem wrong pubkey → error", bool(r.get("error")), str(r)[:300])

# 6. list содержит наш IOU
r = call("iou_list", token=token)["result"]
check("iou_list: 1 запись", len(r["ious"]) == 1 and r["ious"][0] == iou_json, str(r)[:300])

# 7. balance = 7_000_000
r = call("iou_balance", {"creditor": my_id}, token=token)["result"]
check("iou_balance == 7000000", r["owed_micro"] == 7_000_000, str(r)[:200])

# 8. journal на диске: файл есть, валидный JSON в строке
data = os.path.expanduser("~/.hermes/cache/scratch/e2e-iou")
jp = os.path.join(data, "iou.log")
check("iou.log существует", os.path.exists(jp))
line = open(jp).read().strip().splitlines()[-1]
check("iou.log строка парсится", json.loads(line)["kind"] == "nexxus-iou/v1")
mode = oct(os.stat(jp).st_mode & 0o777)
check("iou.log mode 0600", mode == "0o600", mode)

print(f"\nIOU E2E: {len(ok)}/{len(ok)} passed")
sys.exit(0)
