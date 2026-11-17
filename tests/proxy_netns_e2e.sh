#!/bin/sh
set -eu
# Только одноразовый контейнер с --network none: изменяет его сетевые интерфейсы.
[ "${AWGR_PROXY_TEST_ISOLATED:-}" = 1 ] && [ -f /.dockerenv ] || {
    echo "Run only in the isolated test container" >&2
    exit 1
}
[ -z "$(ip -o addr show scope global)" ] || {
    echo "The container must have no global addresses" >&2
    exit 1
}
ip netns add exit
ip link add awgr1 type veth peer name peer1
ip link set peer1 netns exit
ip link add alt0 type veth peer name alt1
ip link set alt1 netns exit
ip addr add 8.8.5.1/24 dev alt0
ip link set alt0 up
ip netns exec exit ip addr add 8.8.5.2/24 dev alt1
ip netns exec exit ip link set alt1 up
ip addr add 8.8.4.1/24 dev awgr1
ip link set awgr1 up
ip netns exec exit ip addr add 8.8.4.2/24 dev peer1
ip netns exec exit ip link set lo up
ip netns exec exit ip link set peer1 up
ip rule add fwmark 0x2001 table 2001 priority 20001
ip route add default dev awgr1 table 2001
ip netns exec exit python3 -u -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("8.8.4.2",8443));s.listen();c,_=s.accept();c.sendall(c.recv(10));c.close();s.close()' &
server=$!
python3 - <<'PY'
import time
from app import proxy_bridge
try:
    proxy_bridge.connect(1,'awgr1',0x2001,'8.8.4.2',8443,('8.8.4.2',))
except OSError:
    print('server-owned public address: rejected')
else:
    raise SystemExit('server-owned address was accepted')
for _ in range(30):
    try:
        s=proxy_bridge.connect(1,'awgr1',0x2001,'8.8.4.2',8443)
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('failed to connect through exit')
s.setblocking(True)
s.sendall(b'test')
assert s.recv(4)==b'test'
s.close()
print('isolated exit and descriptor passing: OK')
PY
wait "$server"
# Полная цепочка: TLS -> авторизация -> worker через nsenter -> интерфейс выхода.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout "$tmpdir/key" -out "$tmpdir/cert" >/dev/null 2>&1
ip netns exec exit python3 -u -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("8.8.4.2",8443));s.listen();c,_=s.accept();c.sendall(c.recv(10));c.close();s.close()' &
server=$!
CERT_DIR="$tmpdir" python3 - <<'PY4'
import base64, os, socket, ssl, threading, time
from app import proxy_auth, proxy_bridge, proxy_listener
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ['CERT_DIR']+'/cert',os.environ['CERT_DIR']+'/key')
rec=proxy_auth.password_record('local-test-password')
usage=[0,0]
def account(uid,direction,count):
    usage[direction]+=count
    return True
srv=proxy_listener.create(('127.0.0.1',0),lambda:ctx,lambda:{'username':'test','password':rec,'upstream':'u1'},lambda h,p:proxy_bridge.connect(1,'awgr1',0x2001,h,p),account)
threading.Thread(target=srv.serve_forever,daemon=True).start()
try:
    cctx=ssl._create_unverified_context()
    with cctx.wrap_socket(socket.create_connection(srv.server_address),server_hostname='localhost') as c:
        c.settimeout(10)
        auth=base64.b64encode(b'test:local-test-password')
        c.sendall(b'CONNECT 8.8.4.2:8443 HTTP/1.1\r\nProxy-Authorization: Basic '+auth+b'\r\n\r\n')
        response=b''
        while not response.endswith(b'\r\n\r\n'):
            part=c.recv(1)
            if not part: raise RuntimeError('proxy closed')
            response+=part
        assert b'200 Connection Established' in response, response
        c.sendall(b'hello')
        assert c.recv(5)==b'hello'
        for _ in range(100):
            if usage==[5,5]: break
            time.sleep(.01)
        assert usage==[5,5], usage
    print('TLS proxy and selected exit: OK; traffic accounted')
finally:
    srv.close_active(); srv.shutdown(); srv.server_close()
PY4
wait "$server"
# Очередь на интерфейсе выхода должна ограничить и исходящий сокет прокси.
python3 -c 'from app.shaping import cap_tree; print("\n".join(c for c in cap_tree("awgr1", 0.256) if "fq_codel" not in c))' | tc -batch -
ip netns exec exit python3 -u -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("8.8.4.2",8443));s.listen();c,_=s.accept();n=0;exec("while n < 262144:\n d=c.recv(65536)\n if not d: break\n n+=len(d)");c.sendall(b"ok");c.close();s.close()' &
server=$!
python3 - <<'PY3'
import time
from app import proxy_bridge
for _ in range(30):
    try:
        s=proxy_bridge.connect(1,'awgr1',0x2001,'8.8.4.2',8443)
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('failed to connect for rate test')
s.setblocking(True)
s.settimeout(20)
start=time.monotonic()
s.sendall(b'x' * 262144)
assert s.recv(2)==b'ok'
elapsed=time.monotonic()-start
s.close()
if elapsed < 3:
    raise SystemExit('exit speed limit was not applied')
print('exit speed limit applied:', round(elapsed, 2), 'seconds')
PY3
wait "$server"
tc qdisc del dev awgr1 root
if ip link add ifbtest type ifb 2>/dev/null; then
  ip link set ifbtest up
  tc qdisc add dev awgr1 handle ffff: ingress
  tc filter add dev awgr1 parent ffff: protocol all prio 1 matchall action mirred egress redirect dev ifbtest
  python3 -c 'from app.shaping import cap_tree; print("\n".join(c for c in cap_tree("ifbtest", 0.256) if "fq_codel" not in c))' | tc -batch -
  ip netns exec exit python3 -u -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("8.8.4.2",8443));s.listen();c,_=s.accept();c.sendall(b"x"*262144);c.close();s.close()' &
  server=$!
  python3 - <<'PY5'
import time
from app import proxy_bridge
for _ in range(30):
    try:
        s=proxy_bridge.connect(1,'awgr1',0x2001,'8.8.4.2',8443)
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('failed to connect for download rate test')
s.setblocking(True)
s.settimeout(20)
start=time.monotonic()
received=0
while received < 262144:
    part=s.recv(65536)
    if not part: raise SystemExit('connection closed early')
    received+=len(part)
elapsed=time.monotonic()-start
s.close()
if elapsed < 3:
    raise SystemExit('exit download speed limit was not applied')
print('exit download speed limit applied:',round(elapsed,2),'seconds')
PY5
  wait "$server"
  tc qdisc del dev awgr1 ingress
  ip link del ifbtest
else
  echo "IFB unavailable: download limit not tested"
fi
ip link set awgr1 down
ip route add 8.8.4.2/32 via 8.8.5.2 dev alt0
ip netns exec exit ip addr del 8.8.4.2/24 dev peer1
ip netns exec exit ip addr add 8.8.4.2/32 dev alt1
ip netns exec exit python3 -u -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",8443));s.listen();exec("while True:\n c,_=s.accept()\n c.sendall(b\"direct\")\n c.close()")' &
server=$!
python3 - <<'PY2'
import socket,time
for _ in range(30):
    try:
        with socket.create_connection(("8.8.4.2",8443),timeout=1) as s:
            assert s.recv(6)==b"direct"
        print("fallback route is reachable directly")
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit("fallback route not working")
PY2
python3 - <<'PY'
from app import proxy_bridge
try:
    proxy_bridge.connect(1,'awgr1',0x2001,'8.8.4.2',8443)
except OSError:
    print('down exit: rejected')
else:
    raise SystemExit('unexpected connection through down exit')
PY

kill "$server" 2>/dev/null || true
