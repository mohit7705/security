from __future__ import annotations

import os
import math
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit


class ResourceLimitExceeded(RuntimeError):
    """Raised when a configured scan-wide resource budget is exhausted."""


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool = False
    output_truncated: bool = False
    cancelled: bool = False
    inactivity_timed_out: bool = False
    callback_error: str = ""


class ResourceGovernor:
    """Thread-safe scan-wide limits for requests and external processes."""

    def __init__(self, limits: dict[str, Any] | None = None) -> None:
        cfg = limits or {}
        self.max_requests = self._positive_int(cfg.get("max_total_requests", 10000), "max_total_requests")
        self.max_processes = self._positive_int(cfg.get("max_external_processes", 20), "max_external_processes")
        self.max_response_bytes = self._positive_int(cfg.get("max_response_bytes", 5 * 1024 * 1024), "max_response_bytes")
        self.max_process_output_bytes = self._positive_int(cfg.get("max_process_output_bytes", 2 * 1024 * 1024), "max_process_output_bytes")
        self.max_scan_duration_sec = self._positive_float(cfg.get("max_scan_duration_sec", 4 * 3600), "max_scan_duration_sec")
        self.requests_per_host_per_sec = self._positive_float(cfg.get("requests_per_host_per_sec", 5), "requests_per_host_per_sec")
        self.max_concurrent_requests = self._positive_int(cfg.get("max_concurrent_requests", 10), "max_concurrent_requests")
        self.max_concurrent_processes = self._positive_int(cfg.get("max_concurrent_processes", 3), "max_concurrent_processes")
        self._started = time.monotonic()
        self._request_count = 0
        self._process_count = 0
        self._lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._host_last_request: dict[str, float] = {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._request_slots = threading.BoundedSemaphore(self.max_concurrent_requests)
        self._process_slots = threading.BoundedSemaphore(self.max_concurrent_processes)

    @staticmethod
    def _positive_int(value: Any, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"limits.{name} must be a positive integer")
        return value

    @staticmethod
    def _positive_float(value: Any, name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value <= 0:
            raise ValueError(f"limits.{name} must be a positive number")
        return float(value)

    @property
    def elapsed_sec(self) -> float:
        return time.monotonic() - self._started

    @property
    def requests_used(self) -> int:
        with self._lock:
            return self._request_count

    def cancel(self) -> None:
        """Signal running subprocesses and future work to stop."""
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def remaining_sec(self, requested_timeout: float | None = None) -> float:
        if self._cancel_event.is_set():
            raise ResourceLimitExceeded("Scan cancellation requested")
        remaining = self.max_scan_duration_sec - self.elapsed_sec
        if remaining <= 0:
            raise ResourceLimitExceeded("Maximum scan duration exceeded")
        return min(remaining, requested_timeout) if requested_timeout is not None else remaining

    def acquire_request(self, url: str, timeout: float | None = None) -> None:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        if not host:
            raise ValueError("A valid URL host is required for request budgeting")
        deadline = time.monotonic() + self.remaining_sec(timeout)
        if not self._request_slots.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise ResourceLimitExceeded("Timed out waiting for an HTTP concurrency slot")
        try:
            with self._lock:
                if self._request_count >= self.max_requests:
                    raise ResourceLimitExceeded("Maximum total HTTP request count exceeded")
                host_lock = self._host_locks.setdefault(host, threading.Lock())
                self._request_count += 1
            if not host_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                raise ResourceLimitExceeded("Timed out waiting for per-host rate limiter")
            try:
                interval = 1.0 / self.requests_per_host_per_sec
                wait = max(0.0, self._host_last_request.get(host, 0.0) + interval - time.monotonic())
                if time.monotonic() + wait > deadline:
                    raise ResourceLimitExceeded("Per-host rate limit exceeds remaining request deadline")
                if wait:
                    time.sleep(wait)
                self._host_last_request[host] = time.monotonic()
            finally:
                host_lock.release()
        except Exception:
            self._request_slots.release()
            raise

    def release_request(self) -> None:
        self._request_slots.release()

    def run_process(
        self,
        command: Sequence[str],
        *,
        timeout_sec: float,
        cwd: str | os.PathLike[str] | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        inactivity_timeout_sec: float | None = None,
        stdout_line_callback: Callable[[str], None] | None = None,
    ) -> ProcessResult:
        """Run an argument-array subprocess with bounded output and cancellation.

        Output is capped across stdout and stderr combined. Optional stdout
        callbacks receive complete decoded lines as they arrive, allowing
        scanners to persist sanitized partial results before process exit.
        """
        if not command or any(not isinstance(part, str) or "\\x00" in part for part in command):
            raise ValueError("command must be a non-empty sequence of NUL-free strings")
        if isinstance(timeout_sec, bool) or not isinstance(timeout_sec, (int, float)) or not math.isfinite(float(timeout_sec)) or timeout_sec <= 0:
            raise ValueError("timeout_sec must be a finite positive number")
        if inactivity_timeout_sec is not None and (
            isinstance(inactivity_timeout_sec, bool)
            or not isinstance(inactivity_timeout_sec, (int, float))
            or not math.isfinite(float(inactivity_timeout_sec))
            or inactivity_timeout_sec <= 0
        ):
            raise ValueError("inactivity_timeout_sec must be a finite positive number")

        timeout = self.remaining_sec(float(timeout_sec))
        if not self._process_slots.acquire(timeout=timeout):
            raise ResourceLimitExceeded("Timed out waiting for an external-process slot")
        with self._lock:
            if self._process_count >= self.max_processes:
                self._process_slots.release()
                raise ResourceLimitExceeded("Maximum external process count exceeded")
            self._process_count += 1

        started = time.monotonic()
        proc: subprocess.Popen[bytes] | None = None
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        output_lock = threading.Lock()
        state_lock = threading.Lock()
        total_output_bytes = 0
        last_output_at = started
        overflow = threading.Event()
        callback_failed = threading.Event()
        callback_error = ""
        stdout_line_buffer = bytearray()

        def drain(pipe, target: bytearray, *, is_stdout: bool) -> None:
            nonlocal total_output_bytes, last_output_at, callback_error
            try:
                while True:
                    chunk = pipe.read1(65536) if hasattr(pipe, 'read1') else pipe.read(65536)
                    if not chunk:
                        break
                    with output_lock:
                        remaining = self.max_process_output_bytes - total_output_bytes
                        accepted = chunk[:max(0, remaining)]
                        if accepted:
                            target.extend(accepted)
                            total_output_bytes += len(accepted)
                        if len(chunk) > max(0, remaining):
                            overflow.set()
                        last_output_at = time.monotonic()

                    if is_stdout and stdout_line_callback is not None:
                        stdout_line_buffer.extend(accepted)
                        while b"\n" in stdout_line_buffer:
                            raw_line, _, remainder = stdout_line_buffer.partition(b"\n")
                            stdout_line_buffer[:] = remainder
                            try:
                                stdout_line_callback(raw_line.decode("utf-8", errors="replace"))
                            except Exception as exc:
                                with state_lock:
                                    callback_error = type(exc).__name__
                                callback_failed.set()
                                return
                        if len(stdout_line_buffer) > self.max_process_output_bytes:
                            overflow.set()
                            return
            finally:
                if is_stdout and stdout_line_callback is not None and stdout_line_buffer and not callback_failed.is_set():
                    try:
                        stdout_line_callback(stdout_line_buffer.decode("utf-8", errors="replace"))
                    except Exception as exc:
                        with state_lock:
                            callback_error = type(exc).__name__
                        callback_failed.set()
                pipe.close()

        try:
            proc = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
            out_thread = threading.Thread(target=drain, args=(proc.stdout, stdout_buf), kwargs={"is_stdout": True}, daemon=True)
            err_thread = threading.Thread(target=drain, args=(proc.stderr, stderr_buf), kwargs={"is_stdout": False}, daemon=True)
            out_thread.start()
            err_thread.start()

            writer_thread = None
            if input_text is not None and proc.stdin is not None:
                def write_stdin() -> None:
                    try:
                        proc.stdin.write(input_text.encode("utf-8"))
                        proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass
                    finally:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass
                writer_thread = threading.Thread(target=write_stdin, daemon=True)
                writer_thread.start()

            deadline = started + timeout
            timed_out = False
            inactivity_timed_out = False
            cancelled = False
            while proc.poll() is None:
                if self._cancel_event.is_set():
                    cancelled = True
                    self._terminate_process_tree(proc)
                    break
                if overflow.is_set() or callback_failed.is_set():
                    self._terminate_process_tree(proc)
                    break
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    self._terminate_process_tree(proc)
                    break
                if inactivity_timeout_sec is not None:
                    with output_lock:
                        idle_for = now - last_output_at
                    if idle_for >= float(inactivity_timeout_sec):
                        inactivity_timed_out = True
                        self._terminate_process_tree(proc)
                        break
                time.sleep(0.05)

            proc.wait()
            out_thread.join(timeout=2)
            err_thread.join(timeout=2)
            if writer_thread is not None:
                writer_thread.join(timeout=1)
            truncated = overflow.is_set()
            actual_returncode = int(proc.returncode or 0)
            if timed_out:
                result_code = 124
            elif truncated:
                result_code = 125
            elif inactivity_timed_out:
                result_code = 126
            elif cancelled:
                result_code = 130
            elif callback_failed.is_set():
                result_code = 127
            else:
                result_code = actual_returncode
            return ProcessResult(
                command=tuple(command),
                returncode=result_code,
                stdout=bytes(stdout_buf).decode("utf-8", errors="replace"),
                stderr=bytes(stderr_buf).decode("utf-8", errors="replace"),
                duration_sec=time.monotonic() - started,
                timed_out=timed_out,
                output_truncated=truncated,
                cancelled=cancelled,
                inactivity_timed_out=inactivity_timed_out,
                callback_error=callback_error,
            )
        finally:
            if proc is not None and proc.poll() is None:
                self._terminate_process_tree(proc)
            self._process_slots.release()

    @staticmethod
    def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
