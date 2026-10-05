#!/usr/bin/env python3
"""Minimal fake TN5250 server for offline testing of tn5250-screen.nse.

It performs the server side of the RFC 1205 negotiation (the same sequence a
real IBM i sends), then replays a captured 5250 sign-on record framed with
IAC EOR. This lets the NSE script be exercised end-to-end with no network
access to a real host.

Usage:
    ./fake_tn5250_server.py [--port N] [--record FILE] [--once]

Defaults: port 2323, record ./signon_capture.bin.
"""
import argparse
import os
import socketserver

# Telnet bytes
IAC, DONT, DO, WONT, WILL, SB, SE, EOR = (
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF0, 0xEF)
OPT_BINARY, OPT_EOR, OPT_TTYPE, OPT_NEWENV = 0x00, 0x19, 0x18, 0x27

HERE = os.path.dirname(os.path.abspath(__file__))


def double_iac(data: bytes) -> bytes:
    return data.replace(b"\xff", b"\xff\xff")


class Handler(socketserver.BaseRequestHandler):
    record = b""

    def recv_until_quiet(self, first_timeout=2.0):
        """Read whatever the client sends; we don't strictly parse it."""
        self.request.settimeout(first_timeout)
        try:
            return self.request.recv(4096)
        except OSError:
            return b""

    def handle(self):
        c = self.request
        # 1. Offer NEW-ENVIRON and TERMINAL-TYPE.
        c.sendall(bytes([IAC, DO, OPT_NEWENV, IAC, DO, OPT_TTYPE]))
        self.recv_until_quiet()
        # 2. Ask for the terminal type.
        c.sendall(bytes([IAC, SB, OPT_TTYPE, 0x01, IAC, SE]))  # SEND
        self.recv_until_quiet()
        # 3. Negotiate EOR and BINARY both directions.
        c.sendall(bytes([IAC, DO, OPT_EOR, IAC, WILL, OPT_EOR,
                         IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY]))
        self.recv_until_quiet()
        # 4. Send the captured 5250 record, framed with IAC EOR.
        c.sendall(double_iac(self.record) + bytes([IAC, EOR]))
        # 5. Keep the socket open briefly so the client can read everything.
        self.recv_until_quiet(first_timeout=3.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2323)
    ap.add_argument("--record", default=os.path.join(HERE, "signon_capture.bin"))
    ap.add_argument("--once", action="store_true",
                    help="serve a single connection then exit")
    args = ap.parse_args()

    with open(args.record, "rb") as f:
        Handler.record = f.read()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", args.port), Handler) as srv:
        print(f"fake tn5250 server on 127.0.0.1:{args.port} "
              f"({len(Handler.record)} byte record)", flush=True)
        if args.once:
            srv.handle_request()
        else:
            srv.serve_forever()


if __name__ == "__main__":
    main()
