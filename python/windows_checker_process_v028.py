"""Exact retained-HANDLE metrics and cleanup for trusted checker processes.

Not an execution sandbox. Job assignment happens immediately after Popen,
not atomically at CreateProcess. Memory metrics cover the direct launcher,
not Node or other descendants. The job owns descendant cleanup only.
"""
import ctypes
from ctypes import wintypes
import os
import subprocess


class OwnedCheckerJob:
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),
                        ('flags',wintypes.DWORD),('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),
                        ('active_limit',wintypes.DWORD),('affinity',ctypes.c_size_t),
                        ('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class Io(ctypes.Structure):
            _fields_ = [(name,ctypes.c_ulonglong) for name in ('read','write','other','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic',Basic),('io',Io),('process_memory',ctypes.c_size_t),
                        ('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype=wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype=wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype=wintypes.BOOL
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE];self.kernel.CloseHandle.restype=wintypes.BOOL
        self.handle=self.kernel.CreateJobObjectW(None,None)
        if not self.handle:raise ctypes.WinError(ctypes.get_last_error())
        limits=Extended();limits.basic.flags=0x2000
        if not self.kernel.SetInformationJobObject(self.handle,9,ctypes.byref(limits),ctypes.sizeof(limits)):
            error=ctypes.get_last_error();self.close();raise ctypes.WinError(error)

    def attach(self,process):
        if not self.kernel.AssignProcessToJobObject(self.handle,int(process._handle)):
            raise ValueError('checker_owned_job_assignment_failed')

    def close(self):
        if self.handle:self.kernel.CloseHandle(self.handle);self.handle=None


def process_usage(process):
    """Query this exact owned process HANDLE; counters survive process exit."""
    class Counters(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('faults',wintypes.DWORD)] + [
            (name,ctypes.c_size_t) for name in ('peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetProcessId.argtypes=[wintypes.HANDLE];kernel.GetProcessId.restype=wintypes.DWORD
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
    kernel.GetProcessTimes.restype=wintypes.BOOL
    kernel.K32GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    kernel.K32GetProcessMemoryInfo.restype=wintypes.BOOL
    handle=int(process._handle)
    if kernel.GetProcessId(handle)!=process.pid:raise ValueError('checker_process_handle_pid_mismatch')
    created,exited,system,user=[wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(system),ctypes.byref(user)):
        raise ctypes.WinError(ctypes.get_last_error())
    counters=Counters();counters.cb=ctypes.sizeof(counters)
    if not kernel.K32GetProcessMemoryInfo(handle,ctypes.byref(counters),counters.cb) or counters.peak_ws<=0:
        raise ValueError('checker_peak_working_set_unavailable')
    def ticks(value):return value.dwLowDateTime+(value.dwHighDateTime<<32)
    if ticks(created)<=0:raise ValueError('checker_creation_time_unavailable')
    return {'peak_child_rss_kib':counters.peak_ws/1024.0,'delta_peak_rss_kib':None,
            'delta_peak_rss_status':'NOT_RUN_NO_SAME_CHILD_STARTUP_BASELINE',
            'process_pid':process.pid,'process_creation_time_100ns':ticks(created),
            'child_cpu_user_s':ticks(user)/10000000.0,'child_cpu_system_s':ticks(system)/10000000.0,
            'resource_measurement_origin':'windows_owned_Popen_HANDLE_peak_working_set',
            'resource_measurement_scope':'direct checker launcher only; descendants not measured',
            'descendant_memory_measured':False,'os_sandbox_proven':False}


def run_trusted_checker(command,root,environment,timeout=20):
    if os.name!='nt':raise ValueError('native_windows_process_api_required')
    if os.environ.get('SystemRoot'):environment=dict(environment,SystemRoot=os.environ['SystemRoot'])
    job=OwnedCheckerJob();process=None
    try:
        process=subprocess.Popen(command,cwd=str(root),env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        job.attach(process)
        try:stdout,stderr=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # This Popen owns a retained native HANDLE; never look up a PID
            # globally. Its assigned job closes in finally, including children.
            process.kill();job.close();process.communicate(timeout=3)
            raise ValueError('external_checker_failed_to_run')
        metrics=process_usage(process)
        return subprocess.CompletedProcess(command,process.returncode,stdout,stderr),metrics
    finally:
        if process is not None and process.poll() is None:
            process.kill();job.close();process.communicate(timeout=3)
        job.close()
