//! Bootstrap scripts for interpreted runtimes.
//!
//! The scripts are the *only* runtime-specific code that runs inside a function instance. They
//! speak the RustFun frame protocol on stdin/stdout and translate a frame into a handler call.
//!
//! Keeping them here (rather than in a template repository) means the protocol has exactly one
//! implementation per language and it is versioned with the platform.

/// Node.js bootstrap.
///
/// Supports CommonJS (`module.exports`) and ES modules (dynamic `import()`), synchronous and
/// async handlers, and both `handler(event)` and `(event, context)` signatures.
pub const NODE_BOOTSTRAP: &str = r##"// rustfun node bootstrap (generated; do not edit)
'use strict';
const MAGIC = Buffer.from('RFN1', 'ascii');
const CODEC_JSON = 1;

function createReader(stream) {
  // A single buffered reader is shared by every frame read: `stream.read()` returns whatever is
  // available, so leftovers must be kept for the next call and the stream must stay in paused
  // mode so nothing is dropped between frames.
  let buffer = Buffer.alloc(0);

  const pull = () =>
    new Promise((resolve, reject) => {
      const onReadable = () => {
        const chunk = stream.read();
        // A null read simply means "not ready yet": wait for the next `readable` event.
        if (chunk !== null) {
          cleanup();
          resolve(chunk);
        }
      };
      const onEnd = () => {
        cleanup();
        reject(new Error('stdin closed mid-frame'));
      };
      const onError = (error) => {
        cleanup();
        reject(error);
      };
      const cleanup = () => {
        stream.off('readable', onReadable);
        stream.off('end', onEnd);
        stream.off('error', onError);
      };
      stream.on('readable', onReadable);
      stream.on('end', onEnd);
      stream.on('error', onError);
      onReadable();
    });

  return async function read(size) {
    while (buffer.length < size) {
      buffer = Buffer.concat([buffer, await pull()]);
    }
    const out = buffer.subarray(0, size);
    buffer = buffer.subarray(size);
    return out;
  };
}

async function readFrame(read) {
  const header = await read(10);
  if (!header.subarray(0, 4).equals(MAGIC)) throw new Error('bad frame magic');
  const codec = header[5];
  const length = header.readUInt32BE(6);
  const body = length > 0 ? await read(length) : Buffer.alloc(0);
  return { codec, body };
}

function writeFrame(status, payload, error, invocationId, functionId, durationMs, logs) {
  const response = {
    protocol_version: 1,
    invocation_id: invocationId,
    function_id: functionId,
    status: status,
    payload: payload ? Buffer.from(payload).toString('base64') : '',
    error: error || null,
    logs: logs || [],
    duration_ms: durationMs,
    metrics: null,
  };
  const body = Buffer.from(JSON.stringify(response), 'utf8');
  const header = Buffer.alloc(10);
  MAGIC.copy(header, 0);
  header[4] = 1;
  header[5] = CODEC_JSON;
  header.writeUInt32BE(body.length, 6);
  process.stdout.write(Buffer.concat([header, body]));
}

async function resolveHandler(modulePath, exportName) {
  const candidates = [modulePath, modulePath + '.js', modulePath + '.mjs', modulePath + '.cjs', modulePath + '.json'];
  let lastError = null;
  for (const candidate of candidates) {
    try {
      const mod = require(candidate.startsWith('.') ? candidate : './' + candidate);
      return mod && mod[exportName] !== undefined ? mod[exportName] : mod;
    } catch (error) {
      if (error && error.code === 'ERR_REQUIRE_ESM') {
        const imported = await import(candidate.startsWith('.') ? candidate : './' + candidate);
        const value = imported && imported[exportName] !== undefined ? imported[exportName] : (imported.default || imported);
        if (value !== undefined) return value;
      } else if (error && error.code !== 'MODULE_NOT_FOUND') {
        lastError = error;
      }
    }
  }
  try {
    const imported = await import(modulePath.startsWith('.') ? modulePath : './' + modulePath);
    const value = imported && imported[exportName] !== undefined ? imported[exportName] : (imported.default || imported);
    if (value !== undefined) return value;
  } catch (error) {
    lastError = error;
  }
  throw new Error('cannot resolve handler ' + modulePath + '#' + exportName + (lastError ? ': ' + lastError.message : ''));
}

async function main() {
  const modulePath = process.env.RUSTFUN_HANDLER_MODULE;
  const exportName = process.env.RUSTFUN_HANDLER_EXPORT;
  // stderr is captured by the platform (it owns the child's pipes); the protocol channel stays
  // untouched, and `logs` is reserved for handler-emitted protocol logs.
  const logs = [];
  const read = createReader(process.stdin);
  while (true) {
    let frame;
    try {
      frame = await readFrame(read);
    } catch (error) {
      return;
    }
    const started = Date.now();
    let request;
    try {
      request = JSON.parse(frame.body.toString('utf8'));
    } catch (error) {
      writeFrame('platform_error', null, { code: 'RUSTFUN_PROTOCOL_ERROR', message: String(error && error.message) }, 'unknown', 'unknown', 0, logs);
      continue;
    }
    let event = {};
    try {
      const text = Buffer.from(request.payload || '', 'base64').toString('utf8');
      event = text.length ? JSON.parse(text) : {};
    } catch (error) {
      event = { raw: Buffer.from(request.payload || '', 'base64').toString('utf8') };
    }
    const context = {
      invocationId: request.invocation_id,
      requestId: request.request_id,
      functionId: request.function_id,
      functionName: request.function_name,
      metadata: request.metadata || {},
      environment: process.env,
      deadlineMs: request.deadline_ms || 0,
    };
    try {
      const handler = await resolveHandler(modulePath, exportName);
      if (typeof handler !== 'function') throw new Error('handler ' + modulePath + '#' + exportName + ' is not a function');
      const result = await handler(event, context);
      const payload = typeof result === 'undefined' ? '' : (typeof result === 'string' ? result : JSON.stringify(result));
      writeFrame('success', payload, null, request.invocation_id, request.function_id, Date.now() - started, logs);
    } catch (error) {
      const detail = error && error.stack ? String(error.stack) : null;
      writeFrame('function_error', null, { code: 'RUSTFUN_FUNCTION_ERROR', message: String((error && error.message) || error), detail }, request.invocation_id, request.function_id, Date.now() - started, logs);
    }
  }
}

main().catch((error) => {
  process.stderr.write('rustfun bootstrap failed: ' + (error && error.stack ? error.stack : error) + '\n');
  process.exit(70);
});
"##;

/// Python bootstrap.
///
/// Supports `module:function` handlers, sync and async handlers, and module-level
/// `handler`/`main` conventions.
pub const PYTHON_BOOTSTRAP: &str = r###"#!/usr/bin/env python3
"""rustfun python bootstrap (generated; do not edit)."""
import asyncio
import base64
import importlib
import importlib.util
import json
import os
import struct
import sys
import time
import traceback

MAGIC = b"RFN1"
CODEC_JSON = 1


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
    codec = header[5]
    length = struct.unpack(">I", header[6:10])[0]
    body = read_exactly(length) if length else b""
    if body is None:
        return None
    return codec, body


def write_frame(status, payload, error, invocation_id, function_id, duration_ms, logs):
    response = {
        "protocol_version": 1,
        "invocation_id": invocation_id,
        "function_id": function_id,
        "status": status,
        "payload": base64.b64encode(payload.encode("utf-8")).decode("ascii") if payload else "",
        "error": error,
        "logs": logs,
        "duration_ms": duration_ms,
        "metrics": None,
    }
    body = json.dumps(response).encode("utf-8")
    header = bytearray(10)
    header[0:4] = MAGIC
    header[4] = 1
    header[5] = CODEC_JSON
    struct.pack_into(">I", header, 6, len(body))
    sys.stdout.buffer.write(bytes(header) + body)
    sys.stdout.buffer.flush()


def load_module(module_path):
    if module_path.endswith(".py"):
        directory = os.path.dirname(os.path.abspath(module_path)) or "."
        if directory not in sys.path:
            sys.path.insert(0, directory)
        name = os.path.splitext(os.path.basename(module_path))[0]
        spec = importlib.util.spec_from_file_location(name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot load " + module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    if module_path.startswith("."):
        return importlib.import_module(module_path, package=os.getcwd())
    return importlib.import_module(module_path)


def resolve_handler(module_path, export_name):
    module = load_module(module_path)
    value = getattr(module, export_name, None)
    if value is None:
        for fallback in ("handler", "main"):
            if hasattr(module, fallback):
                value = getattr(module, fallback)
                break
    if value is None:
        raise AttributeError("no attribute '%s' in %s" % (export_name, module_path))
    return value


def run_handler(handler, event, context):
    result = handler(event, context)
    if asyncio.iscoroutine(result):
        return asyncio.get_event_loop().run_until_complete(result)
    return result


def main():
    module_path = os.environ.get("RUSTFUN_HANDLER_MODULE", "")
    export_name = os.environ.get("RUSTFUN_HANDLER_EXPORT", "handler")
    logs = []
    while True:
        frame = read_frame()
        if frame is None:
            return
        _codec, body = frame
        started = time.time()
        try:
            request = json.loads(body.decode("utf-8"))
        except Exception as error:  # noqa: BLE001 - reported to the platform
            write_frame(
                "platform_error",
                None,
                {"code": "RUSTFUN_PROTOCOL_ERROR", "message": str(error)},
                "unknown",
                "unknown",
                0,
                logs,
            )
            continue
        try:
            raw = base64.b64decode(request.get("payload") or "")
            event = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:  # noqa: BLE001 - non-JSON payloads are passed through
            event = {"raw": raw.decode("utf-8", "replace")}
        context = {
            "invocationId": request.get("invocation_id"),
            "requestId": request.get("request_id"),
            "functionId": request.get("function_id"),
            "functionName": request.get("function_name"),
            "metadata": request.get("metadata") or {},
            "environment": dict(os.environ),
            "deadlineMs": request.get("deadline_ms") or 0,
        }
        try:
            handler = resolve_handler(module_path, export_name)
            if not callable(handler):
                raise TypeError("handler %s#%s is not callable" % (module_path, export_name))
            result = run_handler(handler, event, context)
            if result is None:
                payload = ""
            elif isinstance(result, (bytes, bytearray)):
                payload = result.decode("utf-8", "replace")
            elif isinstance(result, str):
                payload = result
            else:
                payload = json.dumps(result)
            write_frame(
                "success",
                payload,
                None,
                request.get("invocation_id"),
                request.get("function_id"),
                int((time.time() - started) * 1000),
                logs,
            )
        except BaseException as error:  # noqa: BLE001 - every failure is reported to the platform
            write_frame(
                "function_error",
                None,
                {
                    "code": "RUSTFUN_FUNCTION_ERROR",
                    "message": str(error),
                    "detail": traceback.format_exc(),
                },
                request.get("invocation_id"),
                request.get("function_id"),
                int((time.time() - started) * 1000),
                logs,
            )


if __name__ == "__main__":
    main()
"###;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_bootstrap_speaks_the_frame_protocol() {
        assert!(NODE_BOOTSTRAP.contains("RFN1"));
        assert!(NODE_BOOTSTRAP.contains("function_id"));
        assert!(NODE_BOOTSTRAP.contains("resolveHandler"));
        assert!(NODE_BOOTSTRAP.contains("function_error"));
        // The bootstrap is written as JavaScript: it must not start with a `#` comment.
        assert!(NODE_BOOTSTRAP.starts_with("//"));
        assert!(NODE_BOOTSTRAP.contains("createReader"));
    }

    #[test]
    fn python_bootstrap_speaks_the_frame_protocol() {
        assert!(PYTHON_BOOTSTRAP.contains("RFN1"));
        assert!(PYTHON_BOOTSTRAP.contains("resolve_handler"));
        assert!(PYTHON_BOOTSTRAP.contains("function_error"));
        assert!(PYTHON_BOOTSTRAP.contains("asyncio.iscoroutine"));
        // A raw string literal keeps the script byte-exact: escapes must not appear.
        assert!(PYTHON_BOOTSTRAP.starts_with("#!/usr/bin/env python3\n"));
        assert!(!PYTHON_BOOTSTRAP.contains("\\\"\"\"rustfun"));
    }

    #[test]
    fn bootstraps_do_not_contain_nul_bytes() {
        assert!(!NODE_BOOTSTRAP.contains('\0'));
        assert!(!PYTHON_BOOTSTRAP.contains('\0'));
    }
}
