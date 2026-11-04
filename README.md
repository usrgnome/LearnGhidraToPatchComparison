# Learn Ghidra to Patch a Comparison

My goal was to build a simple C++ program and use Ghidra to understand how its password check works after compilation. Then I wanted to change that behavior while the program runs.

The original program asks for a password and shows a Windows message box. `ghidra123` gives “Success”; anything else gives “Failed”. The current version hooks the check and returns `true`, so every password succeeds.

## What I learned

- A string such as `ghidra123` can help locate a function in Ghidra.
- Assembly instructions have byte patterns that code can search for in memory.
- Some bytes change between builds. `??` wildcards let the scanner skip those bytes.
- A runtime address is the loaded module's base address plus an offset.
- A hook redirects execution to another function.
- A trampoline preserves the overwritten instructions and provides a route back into the original function.

## What this project does

The program scans its own memory for the password function. It replaces the first five-byte instruction with a jump to `hooked_check_password`.

It also creates a trampoline that runs the copied instruction and jumps back to the original function at `+5`. The current hook simply returns `true`, so it does not use that trampoline. Calling `original_check_password(password)` from the hook would run the real check instead.

The patch happens in memory. It does not rewrite the EXE on disk. Ghidra was used to inspect the compiled code; the C++ program installs the hook itself.

## What it means

I bypassed the password decision rather than finding a different valid password. A check inside a program can be changed by someone who controls that program. A local success message alone cannot prove authorization to a remote service.

Related techniques are used in debugging, profiling, testing, compatibility fixes, and game mods. This example is specific to its Windows x64 function layout, not a general-purpose hook library. Compiler changes can break the pattern or change the instructions that need to be copied.

## Build and run

Use Windows with Visual Studio's C++ build tools installed. `build.bat` currently points to Visual Studio 2026 Community; adjust its `vcvars64.bat` path if your installation differs.

```bat
build.bat
password_demo.exe
```

Enter any password to see “Success”. To check both the bypass and the original function without opening message boxes:

```bat
password_demo.exe --self-test
```

Import the EXE into Ghidra to inspect it. The build disables optimization to keep the code easier to follow. Compiled files are excluded from Git.
