"""Start the verified CPU model for one benchmark, then stop only that process."""
import argparse
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SHA256 = "b2d794fa7587aba29f654d717ff9b73e31caeabf50a7766692903008bbe0855d"
MODEL_SHA256 = "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031"


def owns_listener(port, pid):
    """Bind the endpoint to our Popen process through Windows' TCP owner table."""
    if os.name != "nt":
        raise RuntimeError("This prepared CPU launcher requires Windows")
    import ctypes
    from ctypes import wintypes
    table_size = wintypes.DWORD(0)
    get_table = ctypes.windll.iphlpapi.GetExtendedTcpTable
    get_table.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                         wintypes.ULONG, ctypes.c_int, wintypes.ULONG)
    get_table.restype = wintypes.DWORD
    code = get_table(None, ctypes.byref(table_size), False, 2, 3, 0)
    if code != 122:  # ERROR_INSUFFICIENT_BUFFER
        raise RuntimeError("Cannot inspect local listener ownership")
    table = ctypes.create_string_buffer(table_size.value)
    if get_table(table, ctypes.byref(table_size), False, 2, 3, 0) != 0:
        raise RuntimeError("Cannot inspect local listener ownership")
    count = wintypes.DWORD.from_buffer(table).value
    row_type = wintypes.DWORD * 6
    for index in range(count):
        row = row_type.from_buffer(table, 4 + index * 24)
        if socket.ntohs(row[2] & 65535) == port and row[1] == int.from_bytes(socket.inet_aton("127.0.0.1"), "little"):
            return row[5] == pid
    return False


def digest(path):
    with path.open("rb") as stream:
        return sha256_file(stream)


def sha256_file(stream):
    checksum = sha256()
    for chunk in iter(lambda: stream.read(1048576), b""):
        checksum.update(chunk)
    return checksum.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Run the prepared Qwen CPU model against one AgentDojo case")
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--managed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.managed and sys.stdin.buffer.readline(5) != b"RUN\n":
        raise RuntimeError("Managed launcher was not released")
    sys.path.insert(0, str(ROOT))
    from app.assurance_progress import publish, read as read_progress
    progress_id = os.environ.get("ARISEC_ASSURANCE_RUN_ID")
    publish(progress_id, "preparing_model")
    if not 10 <= args.seconds <= 600:
        parser.error("Use 10–600 seconds")
    folder = ROOT / ".venv" / "assurance-model"
    provenance = json.loads((folder / "provenance.json").read_text(encoding="utf-8-sig"))
    filename = provenance["model_file"]
    if filename != "Qwen3-0.6B-Q8_0.gguf":
        parser.error("Unexpected local model")
    model = folder / filename
    archive = folder / "llama-b12651-bin-win-cpu-x64.zip"
    if (provenance["model_sha256"] != MODEL_SHA256 or provenance["runtime_sha256"] != RUNTIME_SHA256
            or digest(model) != MODEL_SHA256 or digest(archive) != RUNTIME_SHA256):
        parser.error("Prepared model/runtime checksum does not match")
    # Compare extracted executable and DLLs to the verified archive before launch.
    import zipfile
    runtime = folder / "runtime"
    with zipfile.ZipFile(archive) as zipped:
        for entry in zipped.infolist():
            if entry.is_dir():
                continue
            target = (runtime / entry.filename).resolve()
            if not target.is_relative_to(runtime.resolve()):
                parser.error("Invalid runtime archive path")
            with zipped.open(entry) as stream:
                if not target.is_file() or digest(target) != sha256_file(stream):
                    parser.error("Extracted runtime file does not match verified archive")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    alias = "arisec-qwen3-0.6b-" + uuid4().hex[:12]
    endpoint = f"http://127.0.0.1:{port}/v1"
    log_folder = ROOT / ".arisec-private" / "assurance-model"
    log_folder.mkdir(parents=True, exist_ok=True)
    print("Starting verified local Qwen CPU model; simulated benchmark tools only.", flush=True)
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"}}
    with (log_folder / (alias + ".server.log")).open("wb") as log:
        process = subprocess.Popen([str(runtime / "llama-server.exe"), "-m", str(model),
                                    "--host", "127.0.0.1", "--port", str(port), "--alias", alias,
                                    "--ctx-size", "8192", "--threads", "4", "--parallel", "1",
                                    "--reasoning-budget", "0", "--jinja"],
                                   stdout=log, stderr=subprocess.STDOUT, env=environment,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError("Local model server exited; inspect the private server log")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    response.read(4096)
                    if response.status == 200:
                        break
                except OSError:
                    pass
                finally:
                    connection.close()
                time.sleep(.5)
            else:
                raise RuntimeError("Local model did not become ready")
            if process.poll() is not None or not owns_listener(port, process.pid):
                raise RuntimeError("The model endpoint is not owned by the process started for this run")
            publish(progress_id, "model_ready")
            result = subprocess.run([sys.executable, str(ROOT / "tools/run_agentdojo.py"),
                                     "--endpoint", endpoint, "--model", alias,
                                     "--seconds", str(args.seconds), "--focused"], capture_output=True, text=True,
                                    timeout=args.seconds + 30)
            last_progress = read_progress(progress_id) if progress_id else None
            last_progress = last_progress or {}
            publish(progress_id, "finishing", completed=last_progress.get("completed", ()),
                    requests=last_progress.get("requests", 0), tools=last_progress.get("tools", 0))
            print(result.stdout, end="", flush=True)
            metadata = json.loads(result.stdout)
            summary_path = Path(metadata["summary"]).resolve()
            if not summary_path.is_relative_to((ROOT / ".arisec-private" / "assurance").resolve()):
                raise RuntimeError("Unexpected result path")
            (summary_path.parent / "local-model-provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
            return result.returncode
        finally:
            # Popen handle is the server started above, not a PID from discovery.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            print("Stopped the local model server started for this benchmark.", flush=True)


if __name__ == "__main__":
    sys.exit(main())
