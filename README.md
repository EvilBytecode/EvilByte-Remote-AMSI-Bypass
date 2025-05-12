# 🛡️ EvilByte AMSI Patcher

🔍 Bypasses AMSI by remotely patching AmsiScanBuffer function in target processes.

## 🚀 Quick Usage

```
AMSI-PeParse-Patch.exe powershell.exe  # By name
AMSI-PeParse-Patch.exe 1234            # By PID (you can use in powershell $pid)
```

## ⚙️ How It Works

1. 🎯 **Target Process** 
   - Opens handle to remote process with `PROCESS_ALL_ACCESS`

2. 🔎 **Find amsi.dll**
   - Lists loaded modules with `EnumProcessModules`
   - Locates amsi.dll in target process

3. 🧠 **Memory Analysis**
   - Reads PE headers via `ReadProcessMemory`
   - Parses DOS → NT headers → Export Directory
   - All parsing done directly in target's memory!

4. 🔍 **Locate Function**
   - Reads export tables remotely
   - Searches for "AmsiScanBuffer" string
   - Translates to actual memory address

5. 💉 **Patch Memory**
   - Changes protection with `VirtualProtectEx`
   - Writes patch `B8 00 00 00 00 C3` (mov eax, 0; ret)
   - AmsiScanBuffer now returns "clean" for ANY content

# PoC:
![image](https://github.com/user-attachments/assets/bf9806b0-59a4-4fc8-bfc1-a4d2d6b53419)


## 🔐 Technical Notes

- 🧩 Works on x86 and x64 processes
- 🪄 No process restart needed
- 🏭 Common target: powershell.exe.

## 📄 License

Copyright © 2025 EvilBytecode. All rights reserved. 
