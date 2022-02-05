#include <iostream>
#include <string>
#include <boost/crc.hpp>

#include <Windows.h>
#include <debugapi.h>
#include <winternl.h>
#include <VersionHelpers.h>
#include <wow64apiset.h>

#pragma comment(linker,"/SECTION:.text,ERW")

#include "Sudoku.h"
#include "XorString.h"

/* Anti-Disassembly techniques. */
#define NULLPAD_START asm volatile ( \
        "pushl %eax      \n"         \
        "movl  %esp, %eax\n")
#define NULLPAD       asm volatile ("addb  %al, (%eax)\n")
#define NULLPAD_END   asm volatile ("popl  %eax\n")
#define NULLPAD_10    NULLPAD_START;                                   \
                      NULLPAD;  NULLPAD;  NULLPAD;  NULLPAD;  NULLPAD; \
                      NULLPAD_END

constexpr decltype(boost::crc_32_type().checksum())
AuthorizationCRC = 3917653836;

constexpr decltype(boost::crc_32_type().checksum())
SudokuObjectCRC = 1895298911;

auto GetCrc32(const void* data) -> decltype(boost::crc_32_type().checksum()){
    boost::crc_32_type result;
    result.process_bytes(data, sizeof(&data));
    return result.checksum();
}

template <typename T>
void exitWithCode(T msg) {
    fputs(msg, stdout);
    exit(-1);
}

bool passed = false;
void authorisation() {
    fputs(XorStr("Enter your password.\n"), stdout);

    /* Disassembly trick one. */
    _asm
    {
        label:
        push eax
        xor eax, eax
        pop eax
        jmp next
        cmp eax, 0
        jz label
        jnz label
        next :
    }

    std::string line;
    char c = static_cast<char>(fgetc(stdin));
    for(; c != '\n'; c = static_cast<char>(fgetc(stdin)))
        line += c;

    /* Disassembly trick two. */
    _asm
    {
        /* Get address of changeMe label in eax*/
        mov eax, changeMe
        /* Replace first byte in changeMe by a NOP*/
        mov [eax], 0x90
        changeMe:
        nop
    }

    passed = (!line.empty());
    passed = (line == XorStr("hello") and c == '\n' and c > 0);

    /* Disassembly trick three. */
    _asm
    {
        // Will always set zero flag
        xor eax,eax
        jz valid
        // Insert long jump opcode
        _asm __emit(0xea)
        valid:
        nop // This will be obfuscated when disassembled
    }
}

void start() {
    if(passed){
        Sudoku puzzle;
        const auto sudokuTempSize = GetCrc32(&puzzle);
        if(sudokuTempSize != SudokuObjectCRC)
            exitWithCode(XorStr("Please do not change the code of Sudoku!!!"));
        puzzle.print();
    }
    else
        fputs(XorStr("Sorry. Wrong pass.\n"), stdout);
}

void debuggerCheck() {
#ifndef _WIN64
    const auto pPeb = (PPEB)__readfsdword(0x30);
    const DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);

    BOOL m_bIsWow64 = false;
    IsWow64Process(GetCurrentProcess(), &m_bIsWow64);
    const auto pHeapBase = !m_bIsWow64
                      ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
                      : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
    const DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater() ? 0x40 : 0x0C;
    const DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater() ? 0x44 : 0x10;
#else
    const auto pPeb = (PPEB)__readgsqword(0x60);
    const DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);

    const auto pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE) pPeb + 0x30));
    const DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater() ? 0x70 : 0x14;
    const DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater() ? 0x74 : 0x18;
#endif // _WIN64
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

    /* 1. IsDebuggerPresent(). */
    if(IsDebuggerPresent())
        exitWithCode(XorStr("Please do not use debugger: IsDebuggerPresent()."));

    /* 2. PEB -> BeingDebugged. */
    if (pPeb->BeingDebugged)
        exitWithCode(XorStr("Please do not use debugger: PEB -> BeingDebugged."));

    /* 3. NtGlobalFlag. */
    if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
        exitWithCode(XorStr("Please do not use debugger: NtGlobalFlag."));

    /* 4. Heap flags. ForceFlags. */
    auto pdwHeapFlags = (PDWORD)((PBYTE) pHeapBase + dwHeapFlagsOffset);
    auto pdwHeapForceFlags = (PDWORD)((PBYTE) pHeapBase + dwHeapForceFlagsOffset);
    if(!(*pdwHeapFlags & ~HEAP_GROWABLE) && (*pdwHeapForceFlags == 0))
        exitWithCode(XorStr("Please do not use debugger: Heap flags. ForceFlags."));

    /* 5. NtQueryInformationProcess (call NtQueryInformationProcess from ntdll.dll). */
    typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
            IN HANDLE           ProcessHandle,
            IN PROCESSINFOCLASS ProcessInformationClass,
            OUT PVOID           ProcessInformation,
            IN ULONG            ProcessInformationLength,
            OUT PULONG          ReturnLength
    );

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll) {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
                hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess) {
            DWORD dwProcessDebugPort, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessDebugPort,
                    &dwProcessDebugPort,
                    sizeof(DWORD),
                    &dwReturned);

            if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
                exitWithCode(XorStr("Please do not use debugger: NtQueryInformationProcess."));
        }
    }
}

int main() {
    debuggerCheck();
    const auto tempAuthSize = GetCrc32(authorisation);
    if(tempAuthSize != AuthorizationCRC)
        exitWithCode(XorStr("Please do not change the code of pass-checking!!!"));
    authorisation();
    start();
    return 0;
}
