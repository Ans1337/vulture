"""Sinkhole: DNS + HTTP + TLS-SNI + raw TCP listeners that log and answer back."""
import asyncio, json, socket, struct, time

MY_IP = socket.gethostbyname(socket.gethostname())
TCP_PORTS = [21, 22, 25, 1337, 3000, 4444, 5555, 6667, 8000, 8888, 9001]
HTTP_PORTS = [80, 8080]
TLS_PORTS = [443, 8443]


def log(kind, **d):
    print(json.dumps({"ts": time.time(), "kind": kind, **d}), flush=True)


class DNS(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        try:
            tid, flags, qd = struct.unpack(">HHH", data[:6])
            i, labels = 12, []
            while data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode(errors="replace"))
                i += data[i] + 1
            qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
            q = data[12:i + 5]
            name = ".".join(labels)
            log("dns", name=name, qtype=qtype, src=addr[0])
            if qtype == 1:  # A -> us
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(MY_IP)
                resp = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + ans
            else:  # no AAAA etc., forces IPv4 to us
                resp = struct.pack(">HHHHHH", tid, 0x8180, 1, 0, 0, 0) + q
            self.t.sendto(resp, addr)
        except Exception as e:
            log("dns_error", error=str(e))


async def http(reader, writer, port):
    peer = writer.get_extra_info("peername")[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode(errors="replace").split("\r\n")
        method, path, _ = (lines[0].split(" ") + ["", ""])[:3]
        headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
        n = min(int(headers.get("content-length", 0) or 0), 65536)
        body = await asyncio.wait_for(reader.readexactly(n), 10) if n else b""
        log("http", port=port, src=peer, method=method, host=headers.get("host"), path=path[:500],
            headers={k: v[:200] for k, v in headers.items()}, body=body.decode(errors="replace")[:8000])
        payload = b"// ok\n"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(payload)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + payload)
        await writer.drain()
    except Exception as e:
        log("http_error", port=port, src=peer, error=type(e).__name__)
    finally:
        writer.close()


def sni(data):
    try:
        i = 43
        i += 1 + data[i]
        i += 2 + struct.unpack(">H", data[i:i + 2])[0]
        i += 1 + data[i]
        end = i + 2 + struct.unpack(">H", data[i:i + 2])[0]
        i += 2
        while i < end:
            et, el = struct.unpack(">HH", data[i:i + 4])
            if et == 0:
                return data[i + 9:i + 4 + el].decode(errors="replace")
            i += 4 + el
    except Exception:
        return None


async def tls(reader, writer, port):
    peer = writer.get_extra_info("peername")[0]
    try:
        data = await asyncio.wait_for(reader.read(4096), 10)
        log("tls", port=port, src=peer, sni=sni(data), bytes=len(data))
    except Exception:
        pass
    writer.close()


async def raw(reader, writer, port):
    peer = writer.get_extra_info("peername")[0]
    try:
        data = await asyncio.wait_for(reader.read(8192), 10)
        log("tcp", port=port, src=peer, data=data.decode(errors="replace")[:4000])
    except Exception:
        log("tcp", port=port, src=peer, data="")
    writer.close()


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(DNS, local_addr=("0.0.0.0", 53))
    for p in HTTP_PORTS:
        await asyncio.start_server(lambda r, w, p=p: http(r, w, p), "0.0.0.0", p)
    for p in TLS_PORTS:
        await asyncio.start_server(lambda r, w, p=p: tls(r, w, p), "0.0.0.0", p)
    for p in TCP_PORTS:
        await asyncio.start_server(lambda r, w, p=p: raw(r, w, p), "0.0.0.0", p)
    log("ready", ip=MY_IP)
    await asyncio.Event().wait()


asyncio.run(main())
