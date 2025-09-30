# DLL Injector

A pure Python3 DLL injection tool for Windows that allows you to inject DLL files into running processes.

## Features

- **Screen Clearing**: Clean console interface at startup
- **Architecture Detection**: Automatic detection of DLL and process architecture (32-bit/64-bit)
- **Architecture Compatibility Checking**: Warns about architecture mismatches
- **Process Monitoring**: Inject by Process ID (PID) or Process Name with waiting
- **Visual Feedback**: Clear status indicators and progress reporting
- **Comprehensive Logging**: Detailed logging with architecture information
- **Error Handling**: Robust error handling for all failure scenarios
- **Windows API Integration**: Uses ctypes for reliable injection

## Requirements

- Windows operating system
- Python 3.6+
- `psutil` library (`pip install psutil`)

## Usage

### Basic Syntax
```bash
python injector.py -f <dll_file> --pid <process_id>
python injector.py -f <dll_file> --process-name <process_name>
```

### Examples

**Inject by Process ID:**
```bash
python injector.py -f myhack.dll --pid 1234
```

**Inject by Process Name:**
```bash
python injector.py -f myhack.dll --process-name notepad.exe
```

**Wait for Process:**
If the target process is not running, the injector will wait until it starts:
```bash
python injector.py -f myhack.dll --process-name game.exe
# Will wait until game.exe starts, then inject
```

## How It Works

1. **Initialization**: Clears screen and displays injector header
2. **Architecture Detection**: Analyzes DLL and target process architecture
3. **Compatibility Check**: Warns if there's an architecture mismatch
4. **Process Resolution**: Finds the target process by PID or name
5. **Memory Allocation**: Allocates memory in the target process
6. **DLL Path Writing**: Writes the DLL file path to the allocated memory
7. **Remote Thread Creation**: Creates a remote thread that calls LoadLibraryA
8. **Cleanup**: Properly cleans up handles and memory
9. **Status Reporting**: Displays clear success/failure with architecture info

## Architecture Detection

The injector automatically detects and reports:

- **DLL Architecture**: Reads PE header to determine if DLL is 32-bit or 64-bit
- **Process Architecture**: Uses Windows APIs to detect process bitness
- **Compatibility Warnings**: Alerts user if there's an architecture mismatch

**Important**: 32-bit DLLs cannot be injected into 64-bit processes and vice versa. The injector will warn you about compatibility issues before attempting injection.

## Security Note

This tool is provided for legitimate purposes such as:
- Game modding and development
- Debugging and reverse engineering
- Software testing and analysis

**Use responsibly and only on processes you own or have permission to modify.**

## Error Handling

The injector includes comprehensive error handling for:
- Process not found
- Access denied errors
- Memory allocation failures
- DLL loading failures

All errors are logged with detailed information for troubleshooting.

## Logging

The tool provides detailed logging of all operations:
- Process discovery
- Memory operations
- Thread creation
- Injection results

Use logging level INFO for normal operation or DEBUG for detailed troubleshooting.