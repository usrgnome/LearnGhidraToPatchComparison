#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include <cstddef>
#include <iomanip>
#include <cstring>

// Kept separate so the password check is easy to find in Ghidra.
__declspec(noinline) bool check_password(const std::string& password)
{
    return password == "ghidra123";
}

// -1 represents a wildcard; 0 through 255 represent exact bytes.
std::vector<int> ParsePattern(const std::string& pattern) {
    std::vector<int> bytes;
    std::stringstream ss(pattern);
    std::string byte;

    while(ss >> byte) {
        if (byte == "??") {
            bytes.push_back(-1);
        } else {
            bytes.push_back(static_cast<uint8_t>(std::stoul(byte, nullptr, 16)));
        }
    }

    return bytes;
}

size_t ScanPattern(const uint8_t* data,
    size_t dataSize,
    const std::vector<int>& pattern) {

        // Make sure the pattern isn't empty.
    if (pattern.empty())
        return SIZE_MAX;

    // Make sure the pattern can fit inside the buffer.
    if (pattern.size() > dataSize)
        return SIZE_MAX;

    // Check every possible starting position.
    for (size_t i = 0; i <= dataSize - pattern.size(); i++)
    {
        bool found = true;

        // Compare each byte against the pattern.
        for (size_t j = 0; j < pattern.size(); j++)
        {
            // A wildcard matches any single byte.
            if (pattern[j] != -1 && data[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }

        // Return the offset if every byte matched.
        if (found)
            return i;
    }

    // No match found.
    return SIZE_MAX;
}

using PasswordCheck = bool (*)(const std::string&);
PasswordCheck original_check_password = nullptr;
unsigned hook_calls = 0;

__declspec(noinline) bool hooked_check_password(const std::string& /*password*/)
{
    ++hook_calls;
    std::cout << "[hook] Always accepting password\n";
    // To use the trampoline instead, name the parameter password and return
    // original_check_password(password).
    return true;
}

// Specific to this x64 demo, installed before any calls on this single thread.
// The first instruction is exactly five bytes and has no relative operands.
bool InstallPasswordHook(uint8_t* target)
{
    const uint8_t expected[] = {0x48, 0x89, 0x4c, 0x24, 0x08};
    if (target != reinterpret_cast<uint8_t*>(&check_password) ||
        std::memcmp(target, expected, sizeof(expected)) != 0) {
        std::cerr << "Match is not the expected check_password entry\n";
        return false;
    }

    const auto displacement =
        reinterpret_cast<intptr_t>(&hooked_check_password) -
        reinterpret_cast<intptr_t>(target + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) {
        std::cerr << "Hook is outside the relative jump range\n";
        return false;
    }

    // Original MOV (5 bytes), then JMP [RIP+0] (6 bytes), then address (8 bytes).
    auto trampoline = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 19, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!trampoline)
        return false;

    std::memcpy(trampoline, target, 5);
    const uint8_t jump_back[] = {0xff, 0x25, 0, 0, 0, 0};
    std::memcpy(trampoline + 5, jump_back, sizeof(jump_back));
    const uintptr_t resume = reinterpret_cast<uintptr_t>(target + 5);
    std::memcpy(trampoline + 11, &resume, sizeof(resume));

    DWORD oldProtection;
    if (!VirtualProtect(trampoline, 19, PAGE_EXECUTE_READ, &oldProtection) ||
        !FlushInstructionCache(GetCurrentProcess(), trampoline, 19)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    original_check_password = reinterpret_cast<PasswordCheck>(trampoline);
    uint8_t patch[5] = {0xe9}; // JMP rel32 to our hook.
    const int32_t relative = static_cast<int32_t>(displacement);
    std::memcpy(patch + 1, &relative, sizeof(relative));
    std::memcpy(target, patch, sizeof(patch));

    DWORD ignored;
    const BOOL restored = VirtualProtect(target, 5, oldProtection, &ignored);
    const BOOL flushed = FlushInstructionCache(GetCurrentProcess(), target, 5);
    if (!restored || !flushed) {
        // Exit without executing patched code if finalization failed.
        std::cerr << "Could not finalize the hook\n";
        return false;
    }

    // Retained for the process lifetime, while the entry jump uses it.
    std::cout << "Trampoline at: " << static_cast<void*>(trampoline) << '\n';
    return true;
}

int main(int argc, char* argv[])
{
    std::string pattern = "48 89 4c 24 08 48 83 ec 28 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 30 e8 ?? ?? ?? ??";
    auto bytes = ParsePattern(pattern);

    for(int b : bytes) {
        if (b == -1)
            std::cout << "?? ";
        else
            std::cout << std::hex << std::setfill('0') << std::setw(2) << b << ' ';
    };

    std::cout << std::endl;


    HMODULE module = GetModuleHandleA(nullptr);

    if (!module)
    {
        std::cerr << "Failed to get module handle\n";
        return 1;
    }

    // Interpret the module's base as a DOS header.
    auto dosHeader =
        reinterpret_cast<PIMAGE_DOS_HEADER>(module);

    // Validate the DOS header signature.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Invalid DOS header\n";
        return 1;
    }

    // Locate the NT headers.
    auto ntHeaders =
        reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(module)
            + dosHeader->e_lfanew
        );

    // Validate the NT header signature.
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Invalid NT headers\n";
        return 1;
    }

    // Retrieve the mapped image size.
    DWORD moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);

    std::cout << "Module base: 0x"
              << std::hex
              << reinterpret_cast<uintptr_t>(module)
              << '\n';

    std::cout << "Module size: 0x"
              << moduleSize
              << '\n';


    size_t offset = ScanPattern(reinterpret_cast<uint8_t*>(moduleBase), moduleSize, bytes);

if (offset != SIZE_MAX)
{
    std::cout << "Found at offset: 0x"
              << std::hex << offset << '\n';
}
else
{
    std::cout << "Pattern not found\n";
    return 1;
}

    if (!InstallPasswordHook(reinterpret_cast<uint8_t*>(moduleBase + offset))) {
        std::cerr << "Failed to install password hook\n";
        return 1;
    }

    // Check the bypass and original trampoline separately without opening dialogs.
    if (argc > 1 && std::string(argv[1]) == "--self-test") {
        const bool accepted = check_password("ghidra123");
        const bool wrong_accepted = check_password("wrong");
        const bool empty_accepted = check_password("");
        const bool original_accepted = original_check_password("ghidra123");
        const bool original_rejected = !original_check_password("wrong");
        const bool original_empty_rejected = !original_check_password("");
        const bool passed = accepted && wrong_accepted && empty_accepted &&
            original_accepted && original_rejected && original_empty_rejected && hook_calls == 3;
        std::cout << (passed ? "Self-test passed\n" : "Self-test failed\n");
        return passed ? 0 : 1;
    }

    std::cout << "Enter password: " << std::flush;

    std::string password;
    std::getline(std::cin, password);

    if (check_password(password))
    {
        MessageBoxA(nullptr, "Success", "Password check", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    MessageBoxA(nullptr, "Failed", "Password check", MB_OK | MB_ICONERROR);
    return 1;
}
