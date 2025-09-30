#!/usr/bin/env python3
"""
DLL Injector - A pure Python3 DLL injection tool for Windows
Usage: python injector.py -f <filename.dll> --pid <pid> or --process-name <process_name>
"""

import argparse
import ctypes
import ctypes.wintypes as wintypes
import psutil
import sys
import time
import logging
from typing import Optional

# Windows constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x4
MEM_RELEASE = 0x8000

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DLLInjector:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)

        # Define function signatures
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE

        self.kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID

        self.kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL

        self.kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
        self.kernel32.GetModuleHandleA.restype = wintypes.HMODULE

        self.kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        self.kernel32.GetProcAddress.restype = wintypes.LPVOID

        self.kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE

        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD

        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

        self.kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
        self.kernel32.VirtualFreeEx.restype = wintypes.BOOL

    def get_process_by_pid(self, pid: int) -> Optional[psutil.Process]:
        """Get process by PID"""
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None

    def get_process_by_name(self, name: str) -> Optional[psutil.Process]:
        """Get process by name"""
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == name.lower():
                return proc
        return None

    def wait_for_process(self, name: str, timeout: int = 300) -> Optional[psutil.Process]:
        """Wait for process to appear, checking every second"""
        logger.info(f"Waiting for process '{name}' to start...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            proc = self.get_process_by_name(name)
            if proc:
                logger.info(f"Found process '{name}' with PID {proc.pid}")
                return proc

            logger.info(f"Process '{name}' not found, waiting...")
            time.sleep(1)

        logger.error(f"Timeout waiting for process '{name}'")
        return None

    def inject_dll(self, process: psutil.Process, dll_path: str) -> bool:
        """Inject DLL into the target process"""
        pid = process.pid
        logger.info(f"Starting DLL injection into process {pid} ({process.name()})")

        # Convert DLL path to bytes
        dll_path_bytes = dll_path.encode('utf-8')
        dll_path_length = len(dll_path_bytes) + 1

        # Open process with all access
        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            logger.error(f"Failed to open process {pid}. Error: {ctypes.get_last_error()}")
            return False

        try:
            # Allocate memory in target process
            remote_memory = self.kernel32.VirtualAllocEx(
                h_process, None, dll_path_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )

            if not remote_memory:
                logger.error(f"Failed to allocate memory in process {pid}. Error: {ctypes.get_last_error()}")
                return False

            logger.info(f"Allocated memory at address: 0x{remote_memory:08X}")

            # Write DLL path to allocated memory
            bytes_written = ctypes.c_size_t(0)
            success = self.kernel32.WriteProcessMemory(
                h_process, remote_memory, dll_path_bytes, dll_path_length, ctypes.byref(bytes_written)
            )

            if not success:
                logger.error(f"Failed to write DLL path to process memory. Error: {ctypes.get_last_error()}")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            logger.info(f"Written {bytes_written.value} bytes to process memory")

            # Get LoadLibraryA address
            h_kernel32 = self.kernel32.GetModuleHandleA(b'kernel32.dll')
            if not h_kernel32:
                logger.error("Failed to get kernel32.dll handle")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            load_library_addr = self.kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')
            if not load_library_addr:
                logger.error("Failed to get LoadLibraryA address")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            logger.info(f"LoadLibraryA address: 0x{load_library_addr:08X}")

            # Create remote thread to load DLL
            thread_id = wintypes.DWORD(0)
            h_thread = self.kernel32.CreateRemoteThread(
                h_process, None, 0, load_library_addr, remote_memory, 0, ctypes.byref(thread_id)
            )

            if not h_thread:
                logger.error(f"Failed to create remote thread. Error: {ctypes.get_last_error()}")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            logger.info(f"Created remote thread with ID: {thread_id.value}")

            # Wait for thread to complete
            wait_result = self.kernel32.WaitForSingleObject(h_thread, 5000)  # 5 second timeout

            if wait_result == 0:  # WAIT_OBJECT_0
                logger.info("DLL injection completed successfully!")
            else:
                logger.warning(f"WaitForSingleObject returned: {wait_result}")

            # Clean up
            self.kernel32.CloseHandle(h_thread)

        finally:
            # Always close process handle
            self.kernel32.CloseHandle(h_process)

        return True

def main():
    parser = argparse.ArgumentParser(description='DLL Injector for Windows')
    parser.add_argument('-f', '--file', required=True, help='Path to DLL file to inject')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pid', type=int, help='Process ID to inject into')
    group.add_argument('--process-name', help='Process name to inject into (will wait if not found)')

    args = parser.parse_args()

    # Validate DLL file exists
    dll_path = args.file
    try:
        with open(dll_path, 'rb'):
            pass
    except FileNotFoundError:
        logger.error(f"DLL file not found: {dll_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error accessing DLL file: {e}")
        sys.exit(1)

    logger.info(f"Target DLL: {dll_path}")

    injector = DLLInjector()

    # Get target process
    target_process = None

    if args.pid:
        logger.info(f"Looking for process with PID: {args.pid}")
        target_process = injector.get_process_by_pid(args.pid)
        if not target_process:
            logger.error(f"Process with PID {args.pid} not found")
            sys.exit(1)
    else:
        process_name = args.process_name
        logger.info(f"Looking for process: {process_name}")
        target_process = injector.get_process_by_name(process_name)

        if not target_process:
            logger.info(f"Process '{process_name}' not found, waiting...")
            target_process = injector.wait_for_process(process_name)

        if not target_process:
            logger.error(f"Could not find process '{process_name}'")
            sys.exit(1)

    # Perform injection
    success = injector.inject_dll(target_process, dll_path)

    if success:
        logger.info("DLL injection completed successfully!")
        sys.exit(0)
    else:
        logger.error("DLL injection failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()