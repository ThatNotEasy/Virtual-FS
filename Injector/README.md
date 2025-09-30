# DLL Injector

A pure Python3 DLL injection tool for Windows that allows you to inject DLL files into running processes.

## Features

- **Administrator Privilege Management**: Automatic detection and elevation to Administrator
- **Screen Clearing**: Clean console interface at startup
- **Architecture Detection**: Automatic detection of DLL and process architecture (32-bit/64-bit)
- **Architecture Compatibility Checking**: Warns about architecture mismatches
- **Dual LoadLibrary Support**: Tries both LoadLibraryA (ANSI) and LoadLibraryW (Unicode)
- **Process Monitoring**: Inject by Process ID (PID) or Process Name with waiting
- **Visual Feedback**: Clear status indicators and progress reporting
- **Comprehensive Logging**: Detailed logging with architecture information
- **Error Handling**: Robust error handling for all failure scenarios
- **Windows API Integration**: Uses ctypes for reliable injection
- **Privilege Escalation**: Interactive elevation when Administrator rights needed
- **Post-Injection Guidance**: Specific guidance based on DLL type and target process

## Requirements

- **Administrator Privileges** (Required for DLL injection)
- Windows operating system
- Python 3.6+
- `psutil` library (`pip install psutil`)

### Administrator Privileges

DLL injection requires Administrator privileges because it needs to:
- Open processes with `PROCESS_ALL_ACCESS` rights
- Allocate memory in other processes
- Create remote threads in other processes

**The injector will automatically:**
1. Check if running as Administrator
2. Offer to restart itself as Administrator if not elevated
3. Provide clear instructions if elevation fails

## Usage

### Basic Syntax
```bash
python injector.py -f <dll_file> --pid <process_id>
python injector.py -f <dll_file> --process-name <process_name>
```

### Running as Administrator

**Method 1: Command Prompt as Administrator**
```bash
# Right-click Command Prompt → "Run as Administrator"
python injector.py -f myhack.dll --pid 1234
```

**Method 2: PowerShell as Administrator**
```powershell
# Right-click PowerShell → "Run as Administrator"
python injector.py -f myhack.dll --process-name notepad.exe
```

**Method 3: Automatic Elevation (Interactive)**
```bash
# Run normally - the injector will offer to restart as Administrator
python injector.py -f myhack.dll --process-name game.exe
# Will prompt: "Would you like to restart as Administrator? (y/n):"
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

**Note**: Always run as Administrator for successful DLL injection into system processes.

## How It Works

1. **Privilege Check**: Verifies Administrator privileges (required for injection)
2. **Elevation Option**: Offers to restart as Administrator if not elevated
3. **Initialization**: Clears screen and displays injector header
4. **Architecture Detection**: Analyzes DLL and target process architecture
5. **Compatibility Check**: Warns if there's an architecture mismatch
6. **Process Resolution**: Finds the target process by PID or name
7. **Memory Allocation**: Allocates memory in the target process
8. **DLL Path Writing**: Writes the DLL file path to the allocated memory
9. **LoadLibrary Detection**: Tries both LoadLibraryA (ANSI) and LoadLibraryW (Unicode)
10. **Remote Thread Creation**: Creates remote thread with appropriate LoadLibrary function
11. **DLL Loading**: Waits for DLL to load with timeout and status reporting
12. **Cleanup**: Properly cleans up handles and memory
13. **Post-Injection Guidance**: Provides specific guidance based on DLL type

## Architecture Detection

The injector automatically detects and reports:

- **DLL Architecture**: Reads PE header to determine if DLL is 32-bit or 64-bit
- **Process Architecture**: Uses Windows APIs to detect process bitness
- **Compatibility Warnings**: Alerts user if there's an architecture mismatch

**Important**: 32-bit DLLs cannot be injected into 64-bit processes and vice versa. The injector will warn you about compatibility issues before attempting injection.

## LoadLibrary Methods

The injector tries multiple methods to load the DLL:

### LoadLibraryA (ANSI)
- **Encoding**: Uses UTF-8 encoding for DLL path
- **Function**: `LoadLibraryA` from kernel32.dll
- **Compatibility**: Works with most standard DLLs

### LoadLibraryW (Unicode)
- **Encoding**: Uses UTF-16LE encoding for DLL path
- **Function**: `LoadLibraryW` from kernel32.dll
- **Compatibility**: Required for DLLs that expect Unicode strings

### Automatic Fallback
The injector automatically:
1. **Tries LoadLibraryA first** (most common)
2. **Falls back to LoadLibraryW** if LoadLibraryA fails
3. **Reports which method succeeded**
4. **Provides proper string encoding** for each method

This ensures maximum compatibility with different types of DLLs compiled with various string handling preferences.

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

## Understanding DLL Types

Different DLLs behave differently when injected:

### GUI DLLs (Forms/Dialogs)
- **Examples**: Delphi forms, Windows dialogs, custom UI components
- **Behavior**: May create visible windows, menus, or dialogs
- **Detection**: Look for new UI elements in target application
- **Common Issues**: Windows may be hidden, minimized, or behind other windows

### System Hook DLLs
- **Examples**: File system hooks, API intercepts, behavior modifiers
- **Behavior**: Modify application behavior without visible changes
- **Detection**: Observe changes in how application handles files/operations
- **Common Issues**: Effects may be subtle or require specific triggers

### Driver/Extension DLLs
- **Examples**: Plugin systems, extension frameworks
- **Behavior**: Add new features or modify existing functionality
- **Detection**: Check for new menu items, options, or capabilities
- **Common Issues**: May require application restart or specific initialization

## Post-Injection Verification

After successful injection, verify DLL functionality:

1. **Immediate Check**: Look for obvious changes (new windows, menus)
2. **Interaction Test**: Try operations the DLL is designed to modify
3. **Behavior Monitoring**: Observe application behavior for changes
4. **Feature Testing**: Test specific features the DLL should provide
5. **Restart Consideration**: Some DLLs require application restart

## Common Injection Scenarios

### File Manager Enhancement (vfseditor.dll)
- **Target**: explorer.exe, file management applications
- **Expected Effects**: Modified file operations, new context menus
- **Verification**: Right-click files, check properties, try file operations
- **Troubleshooting**: May need to restart explorer.exe or refresh windows

## Troubleshooting

### Administrator Privilege Issues

**Problem**: "Access denied" or "Failed to open process" errors
**Solution**: Run the injector as Administrator

**Problem**: "Failed to elevate to administrator"
**Solution**: Manually run Command Prompt as Administrator and execute the injector

**Problem**: UAC prompt doesn't appear
**Solution**: Check Windows User Account Control settings and ensure it's not disabled

### Architecture Issues

**Problem**: "Architecture MISMATCH" warning
**Solution**: Ensure DLL and target process have the same architecture (both 32-bit or both 64-bit)

**Problem**: "Unknown architecture" message
**Solution**: The injector couldn't determine architecture - verify DLL is valid and process exists

### Process Issues

**Problem**: "Process not found" when using `--process-name`
**Solution**: Ensure process name is exact (case-sensitive) and include `.exe` extension

**Problem**: "Access denied" when targeting system processes
**Solution**: Some system processes require special handling - run as Administrator and consider if injection is necessary

### DLL Functionality Issues

**Problem**: "DLL injection successful but features don't appear"
**Solution**: This is common and doesn't mean injection failed. Try:

1. **Restart Target Application**: Many DLLs require application restart to show effects
2. **Check Application Behavior**: Look for subtle changes in how the app handles files
3. **Interact with Features**: Try operations the DLL is designed to modify
4. **Check for GUI Elements**: New windows, menus, or dialogs might appear
5. **Antivirus Interference**: Disable antivirus temporarily to test
6. **DLL Compatibility**: Ensure DLL was compiled for injection purposes

**Problem**: "GUI DLL injected but no windows appear"
**Solution**:
- Target process may not support GUI components
- DLL might be creating hidden/minimized windows
- Try injecting into different process types
- Check if DLL requires specific initialization

**Problem**: "DLL loads but doesn't modify application behavior"
**Solution**:
- Some DLLs only activate under specific conditions
- Check if DLL needs configuration or parameters
- Verify DLL exports and initialization code
- Some DLLs require multiple injections or specific timing