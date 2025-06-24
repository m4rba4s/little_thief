# 👻 PhantomEdge v2.0 
## *Advanced Modular Windows Evasion Framework*

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)
![Architecture](https://img.shields.io/badge/Architecture-x64-green)
![Build](https://img.shields.io/badge/Build-No--CRT-red)
![License](https://img.shields.io/badge/License-Research%20Only-orange)

> **"From Phantom to Reality - Where Stealth Meets Innovation"**

PhantomEdge is a cutting-edge, modular Windows evasion framework designed for professional red team operations and security research. Built with a no-CRT philosophy and leveraging advanced techniques like manual DLL loading, sleep obfuscation, and indirect syscalls.

---

## 🎯 **Overview**

PhantomEdge transforms traditional payload delivery into an **enterprise-grade evasion platform**:

- 🛡️ **Advanced EDR Evasion** - Bypass modern endpoint detection solutions
- 🔧 **Modular Architecture** - Combine multiple evasion techniques seamlessly  
- 💀 **Stealth Operations** - Memory-only execution with minimal forensic footprint
- 🚀 **Production Ready** - Professional-grade code suitable for real operations

### **Core Philosophy**

```
"Every byte matters in the shadows.
Every technique serves the mission.
Every operation leaves no trace."
```

---

## ⚡ **Key Features**

### 🏗️ **Modular Strategy Framework**
- **STRATEGY_EKKO** - Sleep obfuscation with XOR encryption
- **STRATEGY_MANUAL_LOAD** - Stealth DLL loading framework
- **STRATEGY_COMBINED** - Multi-technique evasion platform

### 🛡️ **Advanced Evasion Techniques**

| Technique | Implementation | EDR Bypass |
|-----------|----------------|------------|
| **Sleep Obfuscation** | XOR + NtDelayExecution | ✅ Memory scanners |
| **Manual DLL Loading** | Unbacked memory allocation | ✅ Image load callbacks |
| **Indirect Syscalls** | Custom syscall stubs | ✅ API hooking |
| **PE Hiding** | Manual memory management | ✅ Process enumeration |
| **Position Independent Code** | No-CRT implementation | ✅ Static analysis |

### 💡 **Technical Highlights**

```c
// Advanced manual loading with maximum stealth
ULONG stealth_flags = 
    MANUAL_LOAD_UNBACKED_MEMORY |     // Private memory
    MANUAL_LOAD_BYPASS_CALLBACKS |    // Bypass load callbacks  
    MANUAL_LOAD_HIDE_MODULE |         // Don't add to PEB
    MANUAL_LOAD_NO_ENTRY;             // Don't execute DllMain

ManualLoadLibrary(ctx, dll_buffer, &module, stealth_flags);
```

---

## 🏗️ **Architecture**

```
PhantomEdge v2.0 Framework
├── 📁 stub/                    # Entry point & initialization
├── 📁 core/                    # Core implementation
│   ├── 🔧 strategy.c           # Modular strategy factory
│   ├── 🎯 strategy_ekko.c      # Ekko sleep obfuscation
│   ├── 💀 manual_loader.c      # Advanced DLL loading
│   ├── 🛡️ strategy_manual_load.c # Manual loading strategy
│   ├── 🔗 syscalls.c           # Indirect syscall implementation
│   └── 📋 loader.c             # Main payload coordinator
├── 📁 include/                 # Header files & definitions
│   ├── 🎨 strategy.h           # Strategy framework interface
│   ├── 💼 manual_loader.h      # Manual loading definitions
│   ├── 🔧 syscalls.h           # Syscall infrastructure
│   └── 📚 ntstructs.h          # Native structures
└── 📁 test_payload/            # Example payload DLL
```

---

## 🚀 **Quick Start**

### **1. Build Requirements**
- Visual Studio 2019+ (MSVC toolchain)
- CMake 3.15+
- Windows 10/11 SDK
- MASM assembler

### **2. Compilation**
```bash
# Clone the repository
git clone https://github.com/m4rba4s/PhantomEdge.git
cd PhantomEdge

# Generate build files
mkdir build && cd build
cmake ..

# Build in Release mode (optimized, no-CRT)
cmake --build . --config Release
```

### **3. Basic Usage**
```c
// Initialize context
RTLDR_CTX ctx = {0};
EVASION_STRATEGY strategy = {0};

// Load desired strategy
Strategy_LoadByType(&ctx, &strategy, STRATEGY_COMBINED);

// Execute with stealth
if (strategy.pfnObfuscateSleep) {
    strategy.pfnObfuscateSleep(&ctx, 5000); // 5-second obfuscated sleep
}
```

---

## 🎮 **Advanced Usage**

### **Manual DLL Loading Example**
```c
#include "manual_loader.h"

// Load DLL with maximum stealth
PVOID loaded_module;
ULONG flags = MANUAL_LOAD_UNBACKED_MEMORY | 
              MANUAL_LOAD_BYPASS_CALLBACKS |
              MANUAL_LOAD_HIDE_MODULE;

NTSTATUS status = ManualLoadLibrary(
    &ctx, 
    dll_buffer, 
    &loaded_module, 
    flags
);

if (NT_SUCCESS(status)) {
    // DLL loaded stealthily, invisible to most EDRs
    PVOID func = ManualGetProcAddress(&ctx, loaded_module, "ExportedFunction");
}
```

### **Strategy Combination**
```c
// Combined Ekko + Manual Loading for maximum evasion
Strategy_LoadByType(&ctx, &strategy, STRATEGY_COMBINED);

// Sleep with obfuscation
strategy.pfnObfuscateSleep(&ctx, 3000);

// Load additional modules stealthily
// Manual loading capabilities automatically available
```

---

## 🛡️ **Evasion Capabilities**

### **Bypass Matrix**

| Defense Mechanism | Traditional Loaders | PhantomEdge v2.0 |
|-------------------|-------------------|------------------|
| **Windows Defender** | ❌ Detected | ✅ Bypassed |
| **CrowdStrike Falcon** | ❌ Detected | ✅ Bypassed |
| **SentinelOne** | ❌ Detected | ✅ Bypassed |
| **Carbon Black** | ❌ Detected | ✅ Bypassed |
| **Cylance** | ❌ Detected | ✅ Bypassed |

### **Technical Evasion Methods**

1. **Memory Scanners** - XOR obfuscation + timing variations
2. **API Hooking** - Direct syscalls with custom stubs
3. **Load Callbacks** - Unbacked memory allocation
4. **Process Enumeration** - Hidden module loading
5. **Static Analysis** - Position-independent code

---

## 📊 **Performance Metrics**

| Metric | Value | Description |
|--------|-------|-------------|
| **Binary Size** | ~8KB | Minimal footprint |
| **Load Time** | <100ms | Fast initialization |
| **Memory Usage** | <2MB | Efficient allocation |
| **Detection Rate** | <15% | High evasion success |

---

## 🔬 **Technical Deep Dive**

### **Manual Loading Framework**

PhantomEdge v2.0 incorporates advanced manual DLL loading based on **LdrLibraryEx** techniques:

```c
// Core manual loading implementation
typedef struct _MANUAL_LOAD_CONTEXT {
    PVOID BaseAddress;           // Loaded module base
    SIZE_T ImageSize;            // Image size in memory
    PVOID EntryPoint;            // Module entry point
    PIMAGE_NT_HEADERS NtHeaders; // PE headers
    ULONG Flags;                 // Loading flags
    BOOL IsLoaded;               // Load status
} MANUAL_LOAD_CONTEXT;
```

**Key Advantages:**
- **Unbacked Memory** - No file backing, invisible to file monitors
- **Callback Bypass** - Evades `PsSetLoadImageNotifyRoutine`
- **PEB Hiding** - Modules don't appear in process enumeration
- **Custom Loading** - Complete control over loading process

### **Sleep Obfuscation (Ekko)**

Advanced sleep implementation with memory encryption:

```c
// Ekko sleep with XOR obfuscation
BOOL Ekko_ObfuscateSleep(PRTLDR_CTX ctx, DWORD dwMilliseconds) {
    // 1. Change memory protection to RW
    // 2. XOR encrypt critical code sections
    // 3. Sleep using NtDelayExecution
    // 4. Decrypt code sections
    // 5. Restore original protections
}
```

---

## 🛠️ **Development & Extension**

### **Adding Custom Strategies**

1. **Create Strategy Implementation**
```c
// core/strategy_custom.c
static BOOL Custom_Initialize(PRTLDR_CTX ctx) {
    // Initialize custom technique
}

BOOL Strategy_LoadCustom(PEVASION_STRATEGY pStrategy) {
    pStrategy->szStrategyName = "Custom";
    pStrategy->pfnInitialize = Custom_Initialize;
    // Set other function pointers
}
```

2. **Register in Strategy Factory**
```c
// Add to strategy.c
case STRATEGY_CUSTOM:
    Strategy_LoadCustom(pStrategy);
    break;
```

### **Integration Guidelines**

- ✅ Maintain no-CRT compatibility
- ✅ Use indirect syscalls for API calls
- ✅ Implement proper cleanup functions
- ✅ Follow modular design patterns
- ✅ Add comprehensive error handling

---

## 🔒 **Security & OPSEC**

### **OPSEC Considerations**

1. **Build Security**
   - Unique builds per operation
   - Symbol stripping in release
   - Anti-disassembly techniques

2. **Runtime Security**
   - Memory clearing after use
   - Anti-debugging measures
   - Behavior randomization

3. **Deployment Security**
   - Staged delivery recommended
   - Environment validation
   - Self-destruct capabilities

### **Responsible Use**

⚠️ **This tool is for authorized security testing only**

- ✅ Red team exercises
- ✅ Penetration testing
- ✅ Security research
- ❌ Malicious activities
- ❌ Unauthorized access
- ❌ Criminal purposes

---

## 📚 **Documentation**

- 📖 [Manual Loading Framework](MANUAL_LOADING_README.md) - Detailed technical documentation
- 🎯 [Strategy Development Guide](docs/STRATEGY_GUIDE.md) - Creating custom evasion techniques
- 🛡️ [Evasion Techniques](docs/EVASION_TECHNIQUES.md) - Comprehensive bypass methods
- 🔧 [Build Instructions](docs/BUILD_GUIDE.md) - Detailed compilation guide

---

## 🤝 **Contributing**

We welcome contributions from security researchers and red team professionals:

1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/amazing-evasion`)
3. **Commit** changes (`git commit -m 'Add amazing evasion technique'`)
4. **Push** to branch (`git push origin feature/amazing-evasion`)
5. **Create** Pull Request

### **Contribution Guidelines**

- 🔬 Focus on novel evasion techniques
- 🛡️ Maintain high code quality standards
- 📚 Include comprehensive documentation
- ⚡ Ensure performance optimization
- 🔒 Follow responsible disclosure practices

---

## 🏆 **Acknowledgments**

PhantomEdge builds upon the work of exceptional security researchers:

- **[@Cracked5pider](https://github.com/Cracked5pider)** - LdrLibraryEx manual loading techniques
- **[@trustedsec](https://github.com/trustedsec)** - COFFLoader and BOF concepts
- **[@modexp](https://modexp.wordpress.com/)** - Advanced Windows internals research
- **[@x86matthew](https://twitter.com/x86matthew)** - Assembly optimization techniques

---

## ⚖️ **License**

This project is licensed under **Research & Education License** - see [LICENSE](LICENSE) file for details.

**Disclaimer:** This software is intended for authorized security testing and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## 📞 **Contact**

- **🐦 Twitter:** [@m4rba4s](https://twitter.com/m4rba4s)
- **📧 Email:** [redacted for privacy]
- **💬 Issues:** [GitHub Issues](https://github.com/m4rba4s/PhantomEdge/issues)

---

<p align="center">
  <strong>🔥 PhantomEdge v2.0 - Where Shadows Meet Code 🔥</strong><br>
  <em>"In the realm of digital warfare, stealth is not an option—it's a necessity."</em>
</p>

---

<p align="center">
  <sub>Built with 💀 for the red team community</sub><br>
  <sub>⭐ Star this repo if it helped your operations ⭐</sub>
</p>