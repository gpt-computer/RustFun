#!/usr/bin/env python3
"""A conforming RustFun executable handler.

The `executable` runtime contract is deliberately small: read framed `InvocationRequest`
messages on stdin, write framed `InvocationResponse` messages on stdout. This handler is the
reference implementation used by the conformance suite.

Frame layout:

    +--------+------+-------+--------------+-------------------+
    | "RFN1" | ver  | codec | u32 length   | body (JSON/msgpack)|
    +--------+------+-------+--------------+-------------------+

Responses are always JSON (codec 1), which every RustFun runtime understands.
"""

import base64
import json
import os
import struct
import sys

MAGIC = b"RFN1"
CODEC_JSON = 1
VERSION = 1


def read_exactly(size):
    data = b""
    while len(data) < size:
        chunk = sys.stdin.buffer.read(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_frame():
    header = read_exactly(10)
    if header is None or header[:4] != MAGIC:
        return None
    length = struct.unpack(">I", header[6:10])[0]
    return read_exactly(length) if length else b""


def write_frame(response):
    body = json.dumps(response).encode("utf-8")
    header = bytearray(10)
    header[0:4] = MAGIC
    header[4] = VERSION
    header[5] = CODEC_JSON
    struct.pack_into(">I", header, 6, len(body))
    sys.stdout.buffer.write(bytes(header) + body)
    sys.stdout.buffer.flush()


def main():
    while True:
        body = read_frame()
        if body is None:
            return
        started = __import__("time").time()
        request = json.loads(body.decode("utf-8"))
        payload = base64.b64decode(request.get("payload") or "")
        try:
            event = json.loads(payload.decode("utf-8")) if payload else {}
        except ValueError:
            event = {"raw": payload.decode("utf-8", "replace")}
        try:
            result = {
                "ok": True,
                "echo": event,
                "lang": "executable",
                "pid": os.getpid(),
                "count": STATE["count"] + 1,
            }
            STATE["count"] += 1
            response = {
                "protocol_version": VERSION,
                "invocation_id": request.get("invocation_id"),
                "function_id": request.get("function_id"),
                "status": "success",
                "payload": base64.b64encode(json.dumps(result).encode("utf-8")).decode("ascii"),
                "error": None,
                "logs": [],
                "duration_ms": 0,
                "metrics": None,
            }
        except Exception as error:  # noqa: BLE001 - reported to the platform
            response = {
                "protocol_version": VERSION,
                "invocation_id": request.get("invocation_id"),
                "function_id": request.get("function_id"),
                "status": "function_error",
                "payload": "",
                "error": {"code": "RUSTFUN_FUNCTION_ERROR", "message": str(error), "detail": None},
                "logs": [],
                "duration_ms": 0,
                "metrics": None,
            }
        write_frame(response)
        del started


STATE = {"count": 0}

if __name__ == "__main__":
    main()
