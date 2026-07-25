"""Trace the offline sc2 RSA signer used by Prospero Publishing Tools 2.79.

This is an analysis helper, not part of the package-building runtime.  It starts
prospero-pub-cmd with child-process gating, hooks RSA_sign in the spawned
sc2.exe, and prints the RSA BIGNUM fields in big-endian hexadecimal.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time
import ctypes


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "artifacts" / "frida"))
import frida  # type: ignore  # installed into the analysis-only artifacts directory


def extract_pkcs1_message(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("0002"):
        return None
    try:
        encoded = bytes.fromhex(value)
    except ValueError:
        return None
    separator = encoded.find(b"\0", 2)
    if separator < 10:
        return None
    return encoded[separator + 1 :].hex()


AGENT_TEMPLATE = r"""
const module = Process.mainModule;
const rsaSign = module.base.add(__RVA__);
const seen = {};
const rsaOps = [
    { name: "public-encrypt", address: module.base.add(0x75940) },
    { name: "private-encrypt", address: module.base.add(0x75950) },
    { name: "private-decrypt", address: module.base.add(0x75960) },
    { name: "public-decrypt", address: module.base.add(0x75970) },
];

function hex(bytes) {
    return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
}

function readBn(rsa, name, offset) {
    const bn = rsa.add(offset).readPointer();
    if (bn.isNull())
        return { name, value: null };
    const limbs = bn.readPointer();
    const top = bn.add(Process.pointerSize).readS32();
    if (top < 0 || top > 512)
        return { name, error: "invalid top=" + top, pointer: bn.toString() };
    const little = new Uint8Array(limbs.readByteArray(top * Process.pointerSize));
    const big = Uint8Array.from(little).reverse();
    let first = 0;
    while (first + 1 < big.length && big[first] === 0)
        ++first;
    return {
        name,
        pointer: bn.toString(),
        top,
        value: hex(big.slice(first)),
    };
}

Interceptor.attach(rsaSign, {
    onEnter(args) {
        const rsa = args[5];
        try {
            const fields = [
                readBn(rsa, "n", 32),
                readBn(rsa, "e", 40),
                readBn(rsa, "d", 48),
                readBn(rsa, "p", 56),
                readBn(rsa, "q", 64),
                readBn(rsa, "dmp1", 72),
                readBn(rsa, "dmq1", 80),
                readBn(rsa, "iqmp", 88),
            ];
            const fingerprint = fields[0].value || rsa.toString();
            if (seen[fingerprint])
                return;
            seen[fingerprint] = true;
            send({
                event: "rsa",
                module: module.path,
                rsa: rsa.toString(),
                type: args[0].toUInt32(),
                digestLength: args[2].toUInt32(),
                flags: rsa.add(100).readU32(),
                fields,
            });
        } catch (error) {
            send({ event: "error", message: String(error), rsa: rsa.toString() });
        }
    }
});

for (const op of rsaOps) {
    Interceptor.attach(op.address, {
        onEnter(args) {
            this.length = args[0].toInt32();
            this.input = args[1];
            this.output = args[2];
            this.rsa = args[3];
            this.padding = args[4].toInt32();
            this.valid = this.length >= 0 && this.length <= 4096 && !this.rsa.isNull();
            if (!this.valid)
                return;
            try {
                this.n = readBn(this.rsa, "n", 32);
                this.e = readBn(this.rsa, "e", 40);
                this.inputHex = hex(this.input.readByteArray(this.length));
            } catch (error) {
                this.valid = false;
                send({ event: "rsa-op-error", operation: op.name, message: String(error) });
            }
        },
        onLeave(retval) {
            if (!this.valid)
                return;
            try {
                const result = retval.toInt32();
                send({
                    event: "rsa-op",
                    pid: Process.id,
                    operation: op.name,
                    inputLength: this.length,
                    padding: this.padding,
                    result,
                    input: this.inputHex,
                    output: result > 0 && result <= 4096
                        ? hex(this.output.readByteArray(result))
                        : null,
                    n: this.n,
                    e: this.e,
                });
            } catch (error) {
                send({ event: "rsa-op-error", operation: op.name, message: String(error) });
            }
        }
    });
}

send({ event: "ready", module: module.path, base: module.base.toString(),
       rsaSign: rsaSign.toString() });
"""

WINDOWS_CHILD_AGENT = r"""
function hookCreateProcess(name, readString) {
    const address = Module.getGlobalExportByName(name);
    Interceptor.attach(address, {
        onEnter(args) {
            this.isSc2 = false;
            this.processInfo = args[9];
            try {
                const application = args[0].isNull() ? "" : readString(args[0]);
                const commandLine = args[1].isNull() ? "" : readString(args[1]);
                const combined = (application + " " + commandLine).toLowerCase();
                if (combined.indexOf("sc2.exe") === -1)
                    return;
                this.isSc2 = true;
                this.application = application;
                this.commandLine = commandLine;
                args[5] = ptr(args[5].toUInt32() | 0x4); // CREATE_SUSPENDED
            } catch (error) {
                send({ event: "child-error", api: name, message: String(error) });
            }
        },
        onLeave(retval) {
            if (!this.isSc2 || retval.toInt32() === 0)
                return;
            try {
                const pi = this.processInfo;
                send({
                    event: "child",
                    api: name,
                    application: this.application,
                    commandLine: this.commandLine,
                    pid: pi.add(Process.pointerSize * 2).readU32(),
                    tid: pi.add(Process.pointerSize * 2 + 4).readU32()
                });
            } catch (error) {
                send({ event: "child-error", api: name, message: String(error) });
            }
        }
    });
}

hookCreateProcess("CreateProcessW", p => p.readUtf16String());
hookCreateProcess("CreateProcessA", p => p.readCString());
send({ event: "create-process-hooks-ready" });
"""


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: trace-sc2-rsa.py <prospero-pub-cmd.exe> <project.gp5> <output.pkg>")
        return 2

    publisher = str(Path(sys.argv[1]).resolve())
    project = Path(sys.argv[2]).resolve()
    output = str(Path(sys.argv[3]).resolve())
    device = frida.get_local_device()
    finished = threading.Event()
    captured: list[dict] = []
    child_sessions: list[frida.core.Session] = []
    capture_directory = ROOT / ".analysis" / "sc2-capture"
    capture_directory.mkdir(parents=True, exist_ok=True)
    event_log = capture_directory / f"trace-{int(time.time())}.jsonl"
    event_log_lock = threading.Lock()

    def resume_thread(tid: int) -> None:
        if os.name != "nt":
            raise RuntimeError("CreateProcessW tracing is only available on Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenThread.restype = ctypes.c_void_p
        kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        kernel32.ResumeThread.restype = ctypes.c_uint32
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenThread(0x0002, 0, tid)  # THREAD_SUSPEND_RESUME
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            result = kernel32.ResumeThread(handle)
            if result == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel32.CloseHandle(handle)

    def copy_sc2_file(command_line: str, option: str, pid: int) -> None:
        match = re.search(rf'{re.escape(option)}\s+"([^"]+)"', command_line)
        if match is None:
            return
        source = Path(match.group(1))
        if not source.is_file():
            return
        operation_match = re.search(r"--(estimate|build|fixup)\b", command_line)
        operation = operation_match.group(1) if operation_match else "other"
        suffix = "input" if option == "--input" else "output"
        destination = capture_directory / f"{pid}-{operation}-{suffix}{source.suffix}"
        shutil.copy2(source, destination)
        print(json.dumps({
            "event": "captured-file",
            "source": str(source),
            "destination": str(destination),
        }, indent=2))

    def attach_sc2(pid: int, tid: int, command_line: str) -> None:
        try:
            copy_sc2_file(command_line, "--input", pid)
            session = device.attach(pid)
            child_sessions.append(session)
            script = session.create_script(AGENT_TEMPLATE.replace("__RVA__", "0x76490"))
            script.on("message", on_message)
            script.load()
            session.on(
                "detached",
                lambda reason, crash=None:
                    copy_sc2_file(command_line, "--output", pid),
            )
            resume_thread(tid)
        except Exception as error:
            print(f"child hook failed for pid={pid}: {error}", file=sys.stderr)
            try:
                resume_thread(tid)
            except Exception:
                pass

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message["payload"]
            if payload.get("event") == "rsa-op":
                print(json.dumps({
                    "event": "rsa-op",
                    "pid": payload.get("pid"),
                    "operation": payload.get("operation"),
                    "inputLength": payload.get("inputLength"),
                    "padding": payload.get("padding"),
                    "result": payload.get("result"),
                    "message": extract_pkcs1_message(payload.get("input")),
                }))
            else:
                print(json.dumps(payload, indent=2))
            with event_log_lock:
                with event_log.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
            if payload.get("event") == "child":
                # Frida delivers messages on its own dispatcher thread. Attaching a
                # second session synchronously from that callback deadlocks on
                # Windows, leaving the CreateProcessW child suspended.
                threading.Thread(
                    target=attach_sc2,
                    args=(
                        int(payload["pid"]),
                        int(payload["tid"]),
                        str(payload.get("commandLine", "")),
                    ),
                    daemon=True,
                ).start()
            if payload.get("event") in {"rsa", "rsa-op"}:
                captured.append(payload)
        else:
            print(json.dumps(message, indent=2))

    pid = device.spawn(
        [publisher, "img_create", str(project), output],
        cwd=str(project.parent),
    )
    parent = device.attach(pid)
    parent_script = parent.create_script(WINDOWS_CHILD_AGENT)
    parent_script.on("message", on_message)
    parent_script.load()
    def on_parent_detached(reason, crash=None):
        print(json.dumps({"event": "parent-detached", "reason": reason, "crash": str(crash)}))
        finished.set()

    parent.on("detached", on_parent_detached)
    device.resume(pid)

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if finished.wait(0.1):
            break
        if not any(process.pid == pid for process in device.enumerate_processes()):
            break

    try:
        parent.detach()
    except Exception:
        pass
    for session in child_sessions:
        try:
            session.detach()
        except Exception:
            pass
    return 0 if captured else 1


if __name__ == "__main__":
    raise SystemExit(main())
