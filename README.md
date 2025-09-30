# Virtual File System (VFS) Project

A comprehensive Virtual File System solution with DLL injection capabilities, server components, and editor tools for Windows.

## 🏗️ Project Structure

```
Virutal-FS/
├── Editor/                 # DLL Editor Component
│   └── vfseditor.dll      # Virtual File System Editor DLL
├── Injector/              # DLL Injection Tool
│   ├── injector.py        # Python3 DLL Injector
│   └── README.md          # Injector documentation
└── Server/                # Server Components
    ├── Delphi Server/     # Main server application
    │   ├── Unit1.pas     # Main server unit
    │   ├── VFSserver.dpr # Delphi project file
    │   └── *.dfm,*.res   # Forms and resources
    └── ServerCpp/         # C++ Server Extensions
        ├── main.cpp       # C++ server implementation
        ├── sender.cpp     # Communication module
        └── build/         # Compiled binaries
```

## 📋 Components Overview

### 1. DLL Injector (`Injector/`)
**Pure Python3 DLL injection tool** for Windows processes.

**Key Features:**
- Inject DLLs by Process ID (PID) or Process Name
- Automatic process waiting if target not found
- Real-time process monitoring and detection
- Comprehensive error handling and logging
- Windows API integration via ctypes

**Usage:**
```bash
# Inject by Process ID
python Injector/injector.py -f mydll.dll --pid 1234

# Inject by Process Name (waits if not found)
python Injector/injector.py -f mydll.dll --process-name notepad.exe
```

**Requirements:** Python 3.6+, psutil (`pip install psutil`)

### 2. VFS Editor DLL (`Editor/`)
**Virtual File System Editor** - Core DLL component providing file system virtualization capabilities.

**Purpose:**
- Intercepts file system operations
- Provides virtual file system functionality
- Enables custom file handling behaviors

### 3. Server Component (`Server/`)
**Multi-language server implementation** handling VFS operations.

**Delphi Server Features:**
- Main VFS server application (`VFSserver.exe`)
- Windows GUI interface (`Unit1.dfm`)
- Core server logic in Pascal/Delphi

**C++ Extensions:**
- High-performance server backend (`VFSReceiver.exe`)
- Communication module (`sender.exe`)
- Native Windows API integration

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- Python 3.6+ (for injector)
- Delphi/C++ Builder (for server compilation)

### Installation

1. **Clone or download** the project files
2. **Install Python dependencies:**
   ```bash
   pip install psutil
   ```
3. **Compile server components** (if needed):
   - Open `Server/VFSserver.dpr` in Delphi
   - Build the project
   - Compile C++ components in `Server/ServerCpp/`

### Basic Usage

1. **Start the VFS Server:**
   ```bash
   # Run the Delphi server
   cd Server
   ./VFSserver.exe

   # Or run the C++ server
   cd Server/ServerCpp/build/Release
   ./VFSReceiver.exe
   ```

2. **Inject VFS Editor DLL:**
   ```bash
   # Into a specific process
   python Injector/injector.py -f ../Editor/vfseditor.dll --pid <target_pid>

   # Into a process by name
   python Injector/injector.py -f ../Editor/vfseditor.dll --process-name <process_name>
   ```

## 🔧 How It Works

### Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   VFS Server    │◄──►│  DLL Injector    │    │ Target Process  │
│                 │    │                  │    │                 │
│ - Delphi GUI    │    │ - Python CLI     │    │ - VFS Editor    │
│ - C++ Backend   │    │ - Process Monitor│    │ - File Hooks    │
│ - Network I/O   │    │ - Memory Inject  │    │ - Virtual FS    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Injection Process

1. **Process Detection**: Injector finds target process by PID or name
2. **Memory Allocation**: Allocates space in target process memory
3. **DLL Loading**: Writes DLL path and creates remote thread
4. **Hook Installation**: VFS Editor DLL installs file system hooks
5. **Redirection**: File operations are redirected through VFS server

### Virtual File System Features

- **Transparent Operation**: Applications see virtual files as real files
- **Server-Controlled**: All file operations routed through central server
- **Custom Behaviors**: Server can modify, redirect, or block file operations
- **Real-time Monitoring**: Live process and file system monitoring

## 🛠️ Development

### Project Structure Details

#### Injector Module
- **Language**: Python 3.6+
- **Purpose**: DLL injection and process management
- **Key Files**:
  - `Injector/injector.py` - Main injection logic
  - `Injector/README.md` - Detailed documentation

#### Editor Module
- **Language**: C/C++ (compiled as DLL)
- **Purpose**: File system hooking and virtualization
- **Integration**: Injected into target processes

#### Server Module
- **Frontend**: Delphi/Pascal with GUI
- **Backend**: C++ for performance-critical operations
- **Communication**: Inter-process communication with injected DLLs

### Building from Source

#### C++ Components
```bash
cd Server/ServerCpp
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

#### Delphi Components
- Open `Server/VFSserver.dpr` in Delphi IDE
- Build → Compile Project
- Run or deploy `VFSserver.exe`

## 🔒 Security Considerations

**Important**: This software provides powerful system-level capabilities:

- **DLL Injection**: Can modify running processes
- **File System Hooking**: Intercepts file operations
- **Process Monitoring**: Tracks running applications

**Usage Guidelines:**
- Only use on systems you own or administer
- Obtain proper authorization before deployment
- Understand legal implications in your jurisdiction
- Test thoroughly in development environments first

## 📝 License

This project is provided as-is for educational and research purposes. Users are responsible for compliance with applicable laws and regulations.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues and questions:
1. Check existing documentation
2. Review error logs and debug output
3. Test with minimal configurations
4. Report bugs with detailed system information

---

**Project Version**: 1.0.0
**Last Updated**: 2024
**Platform**: Windows 10/11
**Architecture**: 32-bit and 64-bit compatible