"""Native Windows job containment; workers must wait for stdin before spawning."""
import ctypes
from ctypes import wintypes
import time

_kernel = ctypes.WinDLL("kernel32", use_last_error=True)

class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]

class _IOCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IOCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in (
        "TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [
        (name, wintypes.DWORD) for name in (
            "TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses")]

for _name, _args, _result in (
    ("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
    ("SetInformationJobObject", [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
    ("AssignProcessToJobObject", [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
    ("TerminateJobObject", [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
    ("QueryInformationJobObject", [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
    ("CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
):
    _fn = getattr(_kernel, _name)
    _fn.argtypes = _args
    _fn.restype = _result

def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result

class WindowsJob:
    def __init__(self):
        self.handle = _check(_kernel.CreateJobObjectW(None, None))
        try:
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            _check(_kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        except BaseException:
            self.close()
            raise

    def assign(self, process):
        _check(_kernel.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))))

    def terminate_and_wait(self, timeout=5):
        _check(_kernel.TerminateJobObject(self.handle, 1))
        deadline = time.monotonic() + timeout
        while True:
            accounting = _Accounting()
            _check(_kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None))
            if accounting.ActiveProcesses == 0:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("Windows job cleanup timed out")
            time.sleep(min(.01, max(0, deadline - time.monotonic())))

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            _check(_kernel.CloseHandle(handle))
