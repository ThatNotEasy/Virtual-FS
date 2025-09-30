# DLL Injector

A pure Python3 DLL injection tool for Windows that allows you to inject DLL files into running processes.

## Features

- Inject DLLs by Process ID (PID) or Process Name
- Automatic process waiting if target process is not found
- Comprehensive error handling and logging
- Uses Windows API through ctypes for reliable injection

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

1. **Process Resolution**: Finds the target process by PID or name
2. **Memory Allocation**: Allocates memory in the target process
3. **DLL Path Writing**: Writes the DLL file path to the allocated memory
4. **Remote Thread Creation**: Creates a remote thread that calls LoadLibraryA
5. **Cleanup**: Properly cleans up handles and memory

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