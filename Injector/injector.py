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
import os
import struct
import subprocess
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
        self.shell32 = ctypes.WinDLL('shell32', use_last_error=True)

        # Setup ShellExecute function for elevation
        self.shell32.ShellExecuteW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.c_int
        ]
        self.shell32.ShellExecuteW.restype = ctypes.wintypes.HINSTANCE

        # Define Windows API function signatures for DLL injection
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

        # Setup IsWow64Process for architecture detection
        if hasattr(self.kernel32, 'IsWow64Process'):
            self.kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_bool)]
            self.kernel32.IsWow64Process.restype = wintypes.BOOL

    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def is_admin(self) -> bool:
        """Check if the current process is running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run_as_admin(self, cmd_line: str) -> bool:
        """Restart the current script as administrator"""
        try:
            # Get the path to the current Python executable
            python_exe = sys.executable

            # Escape quotes in command line arguments
            cmd_line = cmd_line.replace('"', '\\"')

            # Use ShellExecute to run as admin
            result = self.shell32.ShellExecuteW(
                None,  # hwnd
                "runas",  # operation (run as administrator)
                python_exe,  # file
                cmd_line,  # parameters
                None,  # directory
                1  # show window
            )

            # ShellExecute returns a value > 32 on success
            return int(result) > 32

        except Exception as e:
            logger.error(f"Failed to elevate to administrator: {e}")
            return False

    def check_admin_privileges(self) -> bool:
        """Check for admin privileges and offer elevation if needed"""
        if self.is_admin():
            logger.info("✓ Running with Administrator privileges")
            return True
        else:
            logger.warning("⚠ This tool requires Administrator privileges for DLL injection!")
            logger.warning("  Most processes require elevated access to inject DLLs.")

            # Ask user if they want to restart as admin
            try:
                response = input("\nWould you like to restart as Administrator? (y/n): ").lower().strip()
                if response in ['y', 'yes']:
                    # Reconstruct command line arguments
                    cmd_line = f'"{sys.argv[0]}"'
                    for arg in sys.argv[1:]:
                        if ' ' in arg:
                            cmd_line += f' "{arg}"'
                        else:
                            cmd_line += f' {arg}'

                    logger.info("Restarting as Administrator...")
                    if self.run_as_admin(cmd_line):
                        logger.info("Successfully started Administrator instance.")
                        logger.info("Please wait for the elevated instance to complete...")
                        return False  # Exit current instance
                    else:
                        logger.error("Failed to start Administrator instance.")
                        logger.info("Please manually run the command prompt as Administrator and try again.")
                        return False
                else:
                    logger.warning("Continuing without Administrator privileges...")
                    logger.warning("Injection may fail for protected processes.")
                    return True  # Continue anyway

            except (EOFError, KeyboardInterrupt):
                logger.info("\nOperation cancelled by user.")
                return False

    def get_process_architecture(self, process: psutil.Process) -> str:
        """Get process architecture (32-bit or 64-bit)"""
        try:
            # Check if process is 32-bit or 64-bit
            is_32bit = process.is_32bit if hasattr(process, 'is_32bit') else None

            if is_32bit is None:
                # Fallback: check process handle
                h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process.pid)
                if h_process:
                    # Use IsWow64Process to determine if 32-bit process on 64-bit system
                    is_wow64 = ctypes.c_bool()
                    if hasattr(self.kernel32, 'IsWow64Process'):
                        self.kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64))
                        self.kernel32.CloseHandle(h_process)
                        return "32-bit" if is_wow64.value else "64-bit"
                self.kernel32.CloseHandle(h_process)
                return "Unknown"
            else:
                return "32-bit" if is_32bit else "64-bit"
        except Exception as e:
            logger.warning(f"Could not determine process architecture: {e}")
            return "Unknown"

    def get_dll_architecture(self, dll_path: str) -> str:
        """Get DLL architecture by reading PE header"""
        try:
            with open(dll_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64:
                    return "Invalid DLL"

                # Check DOS signature
                if dos_header[:2] != b'MZ':
                    return "Not a PE file"

                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE signature
                pe_header = f.read(24)
                if pe_header[:4] != b'PE\x00\x00':
                    return "Not a PE file"

                # Read machine type (offset 4 in PE header)
                machine_type = struct.unpack('<H', pe_header[4:6])[0]

                # Machine type values:
                # 0x014c = IMAGE_FILE_MACHINE_I386 (32-bit)
                # 0x0200 = IMAGE_FILE_MACHINE_IA64 (Itanium 64-bit)
                # 0x8664 = IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)

                if machine_type == 0x014c:
                    return "32-bit"
                elif machine_type in (0x0200, 0x8664):
                    return "64-bit"
                else:
                    return f"Unknown (0x{machine_type:04X})"

        except Exception as e:
            logger.warning(f"Could not determine DLL architecture: {e}")
            return "Unknown"

    def _is_gui_dll(self, dll_path: str) -> bool:
        """Check if DLL appears to be a GUI DLL by examining its structure"""
        try:
            with open(dll_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return False

                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE header
                pe_header = f.read(224)  # Read PE header + optional header
                if len(pe_header) < 224 or pe_header[:4] != b'PE\x00\x00':
                    return False

                # Check subsystem (offset 68 in optional header)
                # 2 = IMAGE_SUBSYSTEM_WINDOWS_GUI (GUI application)
                # 3 = IMAGE_SUBSYSTEM_WINDOWS_CUI (Console application)
                subsystem = struct.unpack('<H', pe_header[68:70])[0]

                # Check for common GUI-related imports
                import_section_offset = struct.unpack('<L', pe_header[114:118])[0]  # Import table RVA
                if import_section_offset > 0:
                    current_pos = f.tell()
                    f.seek(pe_offset + import_section_offset)

                    # Read import directory entries
                    while True:
                        import_entry = f.read(20)
                        if len(import_entry) < 20:
                            break

                        import_rva = struct.unpack('<L', import_entry[:4])[0]
                        if import_rva == 0:
                            break  # End of import table

                        # Check for GUI-related DLLs
                        name_rva = struct.unpack('<L', import_entry[12:16])[0]
                        if name_rva > 0:
                            name_pos = f.tell()
                            f.seek(pe_offset + name_rva)
                            dll_name = f.read(32).split(b'\x00')[0]
                            f.seek(name_pos)

                            # Common GUI DLLs
                            gui_dlls = [b'user32.dll', b'gdi32.dll', b'comctl32.dll', b'forms']
                            if any(gui_dll in dll_name.lower() for gui_dll in gui_dlls):
                                return True

                # Check subsystem
                return subsystem == 2  # GUI subsystem

        except Exception as e:
            logger.debug(f"Could not analyze DLL GUI characteristics: {e}")
            return False

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
        """Inject DLL into the target process using Windows API"""
        pid = process.pid
        logger.info(f"🔄 Starting DLL injection into process {pid} ({process.name()})")
        logger.info(f"📁 Target DLL: {dll_path}")

        # Convert DLL path to bytes (null-terminated)
        dll_path_bytes = dll_path.encode('utf-8')
        dll_path_length = len(dll_path_bytes) + 1

        logger.info(f"📊 DLL path length: {dll_path_length} bytes")

        # Open process with all access rights
        logger.info(f"🔓 Opening process {pid} with PROCESS_ALL_ACCESS rights...")
        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not h_process:
            error_code = ctypes.get_last_error()
            logger.error(f"❌ Failed to open process {pid}")
            logger.error(f"   Error code: {error_code}")
            logger.error("   This usually means:")
            logger.error("   - Process doesn't exist")
            logger.error("   - Access denied (need Administrator privileges)")
            logger.error("   - Process is protected/system process")
            return False

        logger.info(f"✅ Successfully opened process {pid}")

        try:
            # Allocate memory in target process
            logger.info(f"📝 Allocating {dll_path_length} bytes in target process memory...")
            remote_memory = self.kernel32.VirtualAllocEx(
                h_process, None, dll_path_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )

            if not remote_memory:
                error_code = ctypes.get_last_error()
                logger.error(f"❌ Failed to allocate memory in process {pid}")
                logger.error(f"   Error code: {error_code}")
                logger.error("   This usually means:")
                logger.error("   - Process memory is full")
                logger.error("   - Process is 64-bit but injector is 32-bit")
                logger.error("   - Insufficient privileges")
                return False

            logger.info(f"✅ Allocated memory at address: 0x{remote_memory:08X}")

            # Write DLL path to allocated memory
            bytes_written = ctypes.c_size_t(0)
            logger.info(f"✍️ Writing DLL path to target process memory...")
            success = self.kernel32.WriteProcessMemory(
                h_process, remote_memory, dll_path_bytes, dll_path_length, ctypes.byref(bytes_written)
            )

            if not success:
                error_code = ctypes.get_last_error()
                logger.error(f"❌ Failed to write DLL path to process memory")
                logger.error(f"   Error code: {error_code}")
                logger.error(f"   Expected to write: {dll_path_length} bytes")
                logger.error(f"   Actually wrote: {bytes_written.value} bytes")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            logger.info(f"✅ Successfully wrote {bytes_written.value} bytes to process memory")

            # Get kernel32.dll handle
            logger.info(f"🔍 Getting kernel32.dll handle from target process...")
            h_kernel32 = self.kernel32.GetModuleHandleA(b'kernel32.dll')
            if not h_kernel32:
                logger.error("❌ Failed to get kernel32.dll handle")
                logger.error("   This is unusual - kernel32.dll should always be loaded")
                self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                return False

            # Try LoadLibraryA first, then LoadLibraryW if needed
            load_library_functions = [
                ('LoadLibraryA', b'LoadLibraryA', dll_path.encode('utf-8')),
                ('LoadLibraryW', b'LoadLibraryW', dll_path.encode('utf-16le'))
            ]

            h_thread = None
            thread_id = wintypes.DWORD(0)
            successful_function = None

            for func_name, func_bytes, path_bytes in load_library_functions:
                logger.info(f"🎯 Trying {func_name}...")

                # Get function address
                load_library_addr = self.kernel32.GetProcAddress(h_kernel32, func_bytes)
                if not load_library_addr:
                    logger.warning(f"⚠️ {func_name} not found, trying next method...")
                    continue

                logger.info(f"✅ {func_name} found at address: 0x{load_library_addr:08X}")

                # Allocate memory for the DLL path (with null terminator)
                path_length = len(path_bytes) + 2  # +2 for null terminator
                remote_memory = self.kernel32.VirtualAllocEx(
                    h_process, None, path_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
                )

                if not remote_memory:
                    logger.warning(f"⚠️ Memory allocation failed for {func_name}, trying next method...")
                    continue

                # Write the DLL path to allocated memory
                bytes_written = ctypes.c_size_t(0)
                success = self.kernel32.WriteProcessMemory(
                    h_process, remote_memory, path_bytes, len(path_bytes), ctypes.byref(bytes_written)
                )

                if not success:
                    logger.warning(f"⚠️ Failed to write DLL path for {func_name}, trying next method...")
                    self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                    continue

                logger.info(f"✅ DLL path written for {func_name} ({bytes_written.value} bytes)")

                # Create remote thread to load DLL
                logger.info(f"🚀 Creating remote thread with {func_name}...")
                logger.info(f"   Target function: {func_name} (0x{load_library_addr:08X})")
                logger.info(f"   DLL path address: 0x{remote_memory:08X}")

                h_thread = self.kernel32.CreateRemoteThread(
                    h_process, None, 0, load_library_addr, remote_memory, 0, ctypes.byref(thread_id)
                )

                if not h_thread:
                    error_code = ctypes.get_last_error()
                    logger.warning(f"⚠️ Failed to create remote thread with {func_name}")
                    logger.warning(f"   Error code: {error_code}")
                    self.kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
                    continue

                logger.info(f"✅ Remote thread created with {func_name} (Thread ID: {thread_id.value})")
                successful_function = func_name
                break

            if not h_thread:
                logger.error("❌ Failed to create remote thread with any LoadLibrary method")
                logger.error("   Tried: LoadLibraryA (ANSI) and LoadLibraryW (Unicode)")
                logger.error("   This usually means:")
                logger.error("   - Process architecture mismatch")
                logger.error("   - Process is terminating")
                logger.error("   - Insufficient privileges")
                return False

            # Wait for thread to complete (5 second timeout)
            logger.info(f"⏳ Waiting for DLL to load via {successful_function} (timeout: 5 seconds)...")
            wait_result = self.kernel32.WaitForSingleObject(h_thread, 5000)

            if wait_result == 0:  # WAIT_OBJECT_0 - thread completed successfully
                logger.info(f"✅ DLL loaded successfully by {successful_function}!")
                logger.info("🎉 DLL injection completed successfully!")

                # Check if DLL creates GUI components
                if self._is_gui_dll(dll_path):
                    logger.info("📋 Note: This DLL appears to create GUI components")
                    logger.info("   - GUI windows may appear in the target process")
                    logger.info("   - Check if target process shows new windows/menus")
                    logger.info("   - Some DLLs require target process restart to show effects")
                else:
                    logger.info("🔧 DLL loaded but effects may not be immediately visible")
                    logger.info("   - Check target process for behavioral changes")
                    logger.info("   - Some DLLs hook system functions silently")

            elif wait_result == 0x102:  # WAIT_TIMEOUT
                logger.warning(f"⚠️ DLL loading timed out after 5 seconds via {successful_function}")
                logger.warning("   The DLL may still be loading or the thread may be stuck")
                logger.warning("   💡 Suggestions:")
                logger.warning("   - DLL might be waiting for user input (GUI forms)")
                logger.warning("   - Target process might need to be restarted")
                logger.warning("   - Check if DLL requires specific initialization")
                logger.info("✅ Injection framework completed (DLL may still be loading)")
            else:
                logger.warning(f"⚠️ Unexpected wait result: {wait_result} from {successful_function}")
                logger.warning("   The remote thread may have crashed or exited unexpectedly")
                logger.info("✅ Remote thread created (DLL loading status unknown)")

            # Clean up thread handle
            self.kernel32.CloseHandle(h_thread)
            logger.info("🧹 Cleaned up remote thread handle")

        except Exception as e:
            logger.error(f"❌ Unexpected error during injection: {e}")
            logger.error(f"   Error type: {type(e).__name__}")
            return False

        finally:
            # Always close process handle
            self.kernel32.CloseHandle(h_process)
            logger.info("🔒 Closed process handle")

        logger.info("🎯 DLL injection process completed")
        return True

    def _provide_post_injection_guidance(self, dll_path: str, target_process: psutil.Process):
        """Provide specific guidance after successful injection"""
        logger.info("📋 POST-INJECTION GUIDANCE:")
        logger.info("   ===========================")

        # Check DLL type and provide specific guidance
        is_gui = self._is_gui_dll(dll_path)
        process_name = target_process.name().lower()

        if is_gui:
            logger.info("🎨 GUI DLL DETECTED - Look for:")
            logger.info("   • New windows, dialogs, or menus in the target application")
            logger.info("   • Changes to existing UI elements")
            logger.info("   • Additional options or features in context menus")
            logger.info("   • Check if target app behaves differently when interacting with files")

            if "explorer" in process_name:
                logger.info("   💡 Explorer.exe specific:")
                logger.info("      - Check if new right-click menu items appear")
                logger.info("      - Look for changes in file property dialogs")
                logger.info("      - Check if file operations show additional options")

        else:
            logger.info("🔧 SYSTEM DLL DETECTED - Look for:")
            logger.info("   • Changes in how the application handles files")
            logger.info("   • Modified save/load dialogs")
            logger.info("   • Different file type associations")
            logger.info("   • Background behavior changes")

        logger.info("🔍 VERIFICATION STEPS:")
        logger.info("   1. Interact with the target application")
        logger.info("   2. Try operations the DLL is designed to modify")
        logger.info("   3. Check for new menu items, dialogs, or behaviors")
        logger.info("   4. Monitor system resources for changes")

        logger.info("⚠️ COMMON ISSUES:")
        logger.info("   • Antivirus software may block DLL functionality")
        logger.info("   • DLL may need target application restart")
        logger.info("   • Some features only activate under specific conditions")
        logger.info("   • GUI elements might be hidden or minimized")

        logger.info("💡 If no changes are visible:")
        logger.info("   • Try restarting the target application")
        logger.info("   • Check if antivirus blocked the DLL")
        logger.info("   • Verify DLL was compiled for the correct purpose")
        logger.info("   • Some DLLs require specific initialization parameters")

def main():
    # Clear screen at startup
    injector = DLLInjector()
    injector.clear_screen()

    # Check for administrator privileges
    logger.info("Checking Administrator privileges...")
    if not injector.check_admin_privileges():
        sys.exit(1)

    parser = argparse.ArgumentParser(description='DLL Injector for Windows (Administrator Mode)')
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

    logger.info("=" * 60)
    logger.info("DLL INJECTOR STARTED")
    logger.info("=" * 60)
    logger.info(f"Target DLL: {dll_path}")

    # Log DLL architecture
    dll_arch = injector.get_dll_architecture(dll_path)
    logger.info(f"DLL Architecture: {dll_arch}")

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

    # Log process architecture information
    logger.info(f"Target Process: {target_process.name()} (PID: {target_process.pid})")
    process_arch = injector.get_process_architecture(target_process)
    logger.info(f"Process Architecture: {process_arch}")

    # Log architecture compatibility warning if needed
    if dll_arch != "Unknown" and process_arch != "Unknown":
        if dll_arch != process_arch:
            logger.warning(f"Architecture MISMATCH: DLL is {dll_arch} but process is {process_arch}")
            logger.warning("Injection may fail due to architecture incompatibility!")
        else:
            logger.info(f"Architecture MATCH: Both DLL and process are {dll_arch}")

    # Perform injection
    logger.info("-" * 60)
    logger.info("STARTING DLL INJECTION...")
    logger.info("-" * 60)

    success = injector.inject_dll(target_process, dll_path)

    logger.info("-" * 60)
    if success:
        logger.info("✓ DLL INJECTION COMPLETED SUCCESSFULLY!")
        logger.info(f"✓ DLL: {dll_path} ({dll_arch})")
        logger.info(f"✓ Process: {target_process.name()} (PID: {target_process.pid}, {process_arch})")
        logger.info("-" * 60)

        # Provide post-injection guidance
        injector._provide_post_injection_guidance(dll_path, target_process)

        sys.exit(0)
    else:
        logger.error("✗ DLL INJECTION FAILED!")
        logger.error(f"✗ DLL: {dll_path} ({dll_arch})")
        logger.error(f"✗ Process: {target_process.name()} (PID: {target_process.pid}, {process_arch})")
        logger.error("-" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()