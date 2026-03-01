"""Create minimal valid PE DLL stub files for Qiling Windows emulation.

This generates structurally valid PE DLL files with proper export tables.
The DLLs contain only a DllMain entry point (returning TRUE) and exported
functions that are simple RET instructions. Qiling's Python-based DLL shims
hook these exports at runtime to provide actual function behavior.

Usage:
    python create_stub_dlls.py <output_dir> [--bits 32|64]

Creates the standard set of Windows system DLLs needed by Qiling to emulate
common PE binaries.
"""

from __future__ import annotations

import os
import struct
import sys


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def create_pe_dll(dll_name: str, export_names: list[str], bits: int = 32) -> bytes:
    """Create a minimal valid PE DLL with the given exports.

    Args:
        dll_name: Name of the DLL (e.g., "kernel32.dll")
        export_names: List of function names to export
        bits: 32 or 64
    Returns:
        bytes: Complete PE file content
    """
    assert bits in (32, 64)

    FILE_ALIGNMENT = 0x200
    SECTION_ALIGNMENT = 0x1000

    is_64 = bits == 64
    # PE32 optional header = 224 bytes, PE32+ = 240 bytes
    opt_hdr_size = 240 if is_64 else 224
    ptr_size = 8 if is_64 else 4

    # ── Layout planning ──────────────────────────────────────

    dos_header_size = 0x80
    pe_sig_off = dos_header_size  # 0x80
    coff_hdr_off = pe_sig_off + 4  # 0x84
    opt_hdr_off = coff_hdr_off + 20  # 0x98
    sect_table_off = opt_hdr_off + opt_hdr_size  # 0x178 (32-bit) or 0x188 (64-bit)

    num_sections = 2  # .text, .edata
    headers_end = sect_table_off + num_sections * 40
    headers_size = _align(headers_end, FILE_ALIGNMENT)

    # .text section: DllMain + one RET stub per export (each at unique address)
    text_rva = SECTION_ALIGNMENT  # 0x1000
    if is_64:
        # DllMain: mov eax, 1; ret (no stdcall in x64)
        dllmain_code = b'\xB8\x01\x00\x00\x00\xC3'
        ret_stub = b'\xC3'  # simple ret for each export
    else:
        # DllMain: mov eax, 1; ret 12 (stdcall, 3 params)
        dllmain_code = b'\xB8\x01\x00\x00\x00\xC2\x0C\x00'
        ret_stub = b'\xC3'  # simple ret for each export

    # Each export function gets its own unique address (RET instruction).
    # This is critical because Qiling's hook_winapi uses the address to
    # look up which API function to intercept in import_symbols dict.
    num_exports = len(export_names)
    # Align each stub to 4-byte boundary for clean addresses
    stub_size = _align(len(ret_stub), 4)
    stubs_data = bytearray()
    export_rvas: list[int] = []
    stubs_start = len(dllmain_code)
    for i in range(num_exports):
        rva = text_rva + stubs_start + i * stub_size
        export_rvas.append(rva)
        stub_padded = ret_stub + b'\x90' * (stub_size - len(ret_stub))
        stubs_data += stub_padded

    text_data = dllmain_code + bytes(stubs_data)
    text_vsize = len(text_data)
    text_raw_size = _align(text_vsize, FILE_ALIGNMENT)
    text_file_off = headers_size

    # .edata section: export directory + tables + strings
    edata_rva = text_rva + _align(text_vsize, SECTION_ALIGNMENT)  # 0x2000

    # Build export data — each export gets its own unique RVA
    edata = _build_export_directory(dll_name, export_names, edata_rva, export_rvas)
    edata_vsize = len(edata)
    edata_raw_size = _align(edata_vsize, FILE_ALIGNMENT)
    edata_file_off = text_file_off + text_raw_size

    total_file_size = edata_file_off + edata_raw_size
    image_size = _align(edata_rva + _align(edata_vsize, SECTION_ALIGNMENT), SECTION_ALIGNMENT)

    # ── Build the PE file ────────────────────────────────────

    buf = bytearray(total_file_size)

    # DOS Header
    struct.pack_into('<2s', buf, 0, b'MZ')
    struct.pack_into('<I', buf, 0x3C, pe_sig_off)  # e_lfanew

    # PE Signature
    struct.pack_into('<4s', buf, pe_sig_off, b'PE\x00\x00')

    # COFF File Header
    machine = 0x8664 if is_64 else 0x014C
    characteristics = 0x2022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    struct.pack_into('<HHIIIHH', buf, coff_hdr_off,
                     machine,           # Machine
                     num_sections,      # NumberOfSections
                     0,                 # TimeDateStamp
                     0,                 # PointerToSymbolTable
                     0,                 # NumberOfSymbols
                     opt_hdr_size,      # SizeOfOptionalHeader
                     characteristics)   # Characteristics

    # Optional Header
    _off = opt_hdr_off
    if is_64:
        struct.pack_into('<H', buf, _off, 0x020B)  # Magic PE32+
    else:
        struct.pack_into('<H', buf, _off, 0x010B)  # Magic PE32
    struct.pack_into('<BB', buf, _off + 2, 14, 0)  # LinkerVersion

    struct.pack_into('<III', buf, _off + 4,
                     text_raw_size,     # SizeOfCode
                     edata_raw_size,    # SizeOfInitializedData
                     0)                 # SizeOfUninitializedData

    struct.pack_into('<I', buf, _off + 16, text_rva)  # AddressOfEntryPoint

    if is_64:
        struct.pack_into('<I', buf, _off + 20, text_rva)   # BaseOfCode
        struct.pack_into('<Q', buf, _off + 24, 0x180000000)  # ImageBase
        sa_off = 32
    else:
        struct.pack_into('<I', buf, _off + 20, text_rva)   # BaseOfCode
        struct.pack_into('<I', buf, _off + 24, edata_rva)  # BaseOfData
        struct.pack_into('<I', buf, _off + 28, 0x10000000)  # ImageBase
        sa_off = 32

    struct.pack_into('<II', buf, _off + sa_off,
                     SECTION_ALIGNMENT,   # SectionAlignment
                     FILE_ALIGNMENT)      # FileAlignment

    struct.pack_into('<HHHH', buf, _off + sa_off + 8, 6, 0, 0, 0)  # OS/Image versions
    struct.pack_into('<HH', buf, _off + sa_off + 16, 6, 0)         # SubsystemVersion
    struct.pack_into('<I', buf, _off + sa_off + 20, 0)              # Win32VersionValue
    struct.pack_into('<I', buf, _off + sa_off + 24, image_size)     # SizeOfImage
    struct.pack_into('<I', buf, _off + sa_off + 28, headers_size)   # SizeOfHeaders
    struct.pack_into('<I', buf, _off + sa_off + 32, 0)              # CheckSum
    struct.pack_into('<H', buf, _off + sa_off + 36, 3)              # Subsystem (CONSOLE)
    struct.pack_into('<H', buf, _off + sa_off + 38, 0x8160)        # DllCharacteristics

    if is_64:
        stack_off = _off + sa_off + 40
        struct.pack_into('<QQQQ', buf, stack_off,
                         0x100000, 0x1000, 0x100000, 0x1000)
        loader_flags_off = stack_off + 32
    else:
        stack_off = _off + sa_off + 40
        struct.pack_into('<IIII', buf, stack_off,
                         0x100000, 0x1000, 0x100000, 0x1000)
        loader_flags_off = stack_off + 16

    struct.pack_into('<I', buf, loader_flags_off, 0)           # LoaderFlags
    struct.pack_into('<I', buf, loader_flags_off + 4, 16)     # NumberOfRvaAndSizes

    # Data Directory (16 entries, 8 bytes each)
    ddoff = loader_flags_off + 8
    # Entry 0: Export Table
    struct.pack_into('<II', buf, ddoff, edata_rva, edata_vsize)
    # Entries 1-15: zeros (already zeroed)

    # ── Section Headers ──────────────────────────────────────

    # .text section
    soff = sect_table_off
    struct.pack_into('<8s', buf, soff, b'.text\x00\x00\x00')
    struct.pack_into('<IIIIIIIHHI', buf, soff + 8,
                     text_vsize,        # VirtualSize
                     text_rva,          # VirtualAddress
                     text_raw_size,     # SizeOfRawData
                     text_file_off,     # PointerToRawData
                     0, 0, 0, 0, 0,    # Relocs, Linenums, etc.
                     0x60000020)        # Characteristics: CODE|EXECUTE|READ

    # .edata section
    soff = sect_table_off + 40
    struct.pack_into('<8s', buf, soff, b'.edata\x00\x00')
    struct.pack_into('<IIIIIIIHHI', buf, soff + 8,
                     edata_vsize,       # VirtualSize
                     edata_rva,         # VirtualAddress
                     edata_raw_size,    # SizeOfRawData
                     edata_file_off,    # PointerToRawData
                     0, 0, 0, 0, 0,
                     0x40000040)        # Characteristics: INITIALIZED_DATA|READ

    # ── Section Data ─────────────────────────────────────────

    # .text
    buf[text_file_off:text_file_off + len(text_data)] = text_data

    # .edata
    buf[edata_file_off:edata_file_off + len(edata)] = edata

    return bytes(buf)


def _build_export_directory(
    dll_name: str,
    export_names: list[str],
    edata_rva: int,
    func_rvas: list[int],
) -> bytes:
    """Build the export directory data for the .edata section.

    Each exported function gets its own unique RVA so that Qiling's
    hook_winapi can correctly identify which API is being called
    (import_symbols is keyed by address).
    """
    n = len(export_names)
    sorted_pairs = sorted(zip(export_names, func_rvas), key=lambda p: p[0])

    # Export Directory Table: 40 bytes
    # Export Address Table: n * 4 bytes
    # Export Name Pointer Table: n * 4 bytes
    # Export Ordinal Table: n * 2 bytes
    # Strings: DLL name + function names

    edt_size = 40
    eat_off = edt_size
    eat_size = n * 4
    enpt_off = eat_off + eat_size
    enpt_size = n * 4
    eot_off = enpt_off + enpt_size
    eot_size = n * 2
    strings_off = _align(eot_off + eot_size, 4)

    # Build strings block
    dll_name_bytes = dll_name.encode('ascii') + b'\x00'
    dll_name_off = strings_off

    func_name_offsets = []
    current_off = strings_off + len(dll_name_bytes)
    func_name_data = bytearray()
    for name, _ in sorted_pairs:
        func_name_offsets.append(current_off)
        name_bytes = name.encode('ascii') + b'\x00'
        func_name_data += name_bytes
        current_off += len(name_bytes)

    total_size = current_off
    data = bytearray(total_size)

    # Export Directory Table
    struct.pack_into('<I', data, 0, 0)               # Characteristics
    struct.pack_into('<I', data, 4, 0)                # TimeDateStamp
    struct.pack_into('<HH', data, 8, 0, 0)            # Version
    struct.pack_into('<I', data, 12, edata_rva + dll_name_off)  # Name RVA
    struct.pack_into('<I', data, 16, 1)               # OrdinalBase
    struct.pack_into('<I', data, 20, n)               # NumberOfFunctions
    struct.pack_into('<I', data, 24, n)               # NumberOfNames
    struct.pack_into('<I', data, 28, edata_rva + eat_off)   # AddressOfFunctions
    struct.pack_into('<I', data, 32, edata_rva + enpt_off)  # AddressOfNames
    struct.pack_into('<I', data, 36, edata_rva + eot_off)   # AddressOfNameOrdinals

    # Export Address Table: each function gets its own unique RVA
    for i, (_, rva) in enumerate(sorted_pairs):
        struct.pack_into('<I', data, eat_off + i * 4, rva)

    # Export Name Pointer Table: RVAs to function name strings
    for i, off in enumerate(func_name_offsets):
        struct.pack_into('<I', data, enpt_off + i * 4, edata_rva + off)

    # Export Ordinal Table: ordinal indices (0-based)
    for i in range(n):
        struct.pack_into('<H', data, eot_off + i * 2, i)

    # Strings
    data[dll_name_off:dll_name_off + len(dll_name_bytes)] = dll_name_bytes
    data[strings_off + len(dll_name_bytes):strings_off + len(dll_name_bytes) + len(func_name_data)] = func_name_data

    return bytes(data)


# ── Standard DLL definitions ─────────────────────────────────────────

# These are the exports needed by Qiling shims + common binary imports.
# For each DLL: (filename, list of export names)

DLLS_32: dict[str, list[str]] = {
    "ntdll.dll": [
        "CsrGetProcessId", "LdrGetProcedureAddress",
        "NtQueryInformationProcess", "NtQuerySystemInformation",
        "NtSetInformationProcess", "RtlAllocateHeap",
        "ZwCreateDebugObject", "ZwQueryInformationProcess",
        "ZwQueryObject", "ZwQuerySystemInformation",
        "ZwSetInformationProcess", "ZwYieldExecution",
        "memcpy", "wcsstr",
        # Common exports that other DLLs/binaries reference
        "RtlInitUnicodeString", "RtlFreeHeap", "RtlGetVersion",
        "NtClose", "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
        "NtQueryValueKey", "NtOpenKey",
        "RtlInitializeCriticalSection", "RtlDeleteCriticalSection",
        "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
        "RtlUnwind",
    ],
    "kernel32.dll": [
        # Qiling shim hooks (most common subset)
        "AddAtomA", "AddAtomW", "CloseHandle", "CompareStringW",
        "CopyFileA", "CopyFileW", "CreateDirectoryA", "CreateDirectoryW",
        "CreateEventA", "CreateEventW", "CreateFileA", "CreateFileW",
        "CreateFileMappingA", "CreateFileMappingW",
        "CreateMutexA", "CreateMutexW", "CreateProcessA", "CreateProcessW",
        "CreateThread", "CreateToolhelp32Snapshot",
        "DecodePointer", "DeleteCriticalSection", "DeleteFileA", "DeleteFileW",
        "DeviceIoControl", "EncodePointer",
        "EnterCriticalSection", "EnumSystemLocalesA",
        "ExitProcess", "ExitThread",
        "FindClose", "FindFirstFileA", "FindFirstFileW",
        "FindNextFileA", "FindNextFileW", "FindResourceA", "FindResourceW",
        "FlushFileBuffers", "FormatMessageA", "FormatMessageW",
        "FreeEnvironmentStringsW", "FreeLibrary",
        "GetACP", "GetCPInfo", "GetCommandLineA", "GetCommandLineW",
        "GetComputerNameA", "GetComputerNameW",
        "GetConsoleCP", "GetConsoleMode",
        "GetCurrentDirectoryA", "GetCurrentDirectoryW",
        "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThreadId",
        "GetDateFormatA", "GetDateFormatW",
        "GetDiskFreeSpaceA", "GetDiskFreeSpaceW",
        "GetDriveTypeA", "GetDriveTypeW",
        "GetEnvironmentStringsW", "GetEnvironmentVariableA", "GetEnvironmentVariableW",
        "GetExitCodeProcess", "GetFileAttributesA", "GetFileAttributesW",
        "GetFileSize", "GetFileType",
        "GetLastError", "GetLocaleInfoA", "GetLocaleInfoW",
        "GetLocalTime", "GetModuleFileNameA", "GetModuleFileNameW",
        "GetModuleHandleA", "GetModuleHandleW",
        "GetNativeSystemInfo",
        "GetOEMCP", "GetProcAddress", "GetProcessHeap",
        "GetStartupInfoA", "GetStartupInfoW",
        "GetStdHandle", "GetStringTypeW",
        "GetSystemDefaultLangID", "GetSystemDirectoryA", "GetSystemDirectoryW",
        "GetSystemInfo", "GetSystemTime", "GetSystemTimeAsFileTime",
        "GetTempFileNameA", "GetTempFileNameW",
        "GetTempPathA", "GetTempPathW",
        "GetTickCount", "GetTimeFormatA", "GetTimeFormatW",
        "GetTimeZoneInformation",
        "GetUserDefaultLCID",
        "GetVersionExA", "GetVersionExW", "GetVersion",
        "GetVolumeInformationA", "GetVolumeInformationW",
        "GetWindowsDirectoryA", "GetWindowsDirectoryW",
        "GlobalAlloc", "GlobalFree", "GlobalLock", "GlobalMemoryStatusEx",
        "GlobalReAlloc", "GlobalUnlock",
        "HeapAlloc", "HeapCreate", "HeapFree", "HeapReAlloc",
        "HeapSetInformation", "HeapSize",
        "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
        "InterlockedDecrement", "InterlockedExchange", "InterlockedIncrement",
        "IsBadReadPtr", "IsDebuggerPresent", "IsProcessorFeaturePresent",
        "IsValidCodePage", "IsValidLocale",
        "LCMapStringW", "LeaveCriticalSection",
        "LoadLibraryA", "LoadLibraryExA", "LoadLibraryExW", "LoadLibraryW",
        "LoadResource", "LocalAlloc", "LocalFree", "LocalReAlloc",
        "LockResource",
        "MapViewOfFile", "MoveFileA", "MoveFileW",
        "MultiByteToWideChar",
        "OpenMutexA", "OpenMutexW", "OpenProcess",
        "OutputDebugStringA", "OutputDebugStringW",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "RaiseException", "ReadFile", "ReleaseMutex",
        "RemoveDirectoryA", "RemoveDirectoryW",
        "RtlUnwind",
        "SetConsoleTextAttribute", "SetCurrentDirectoryA", "SetCurrentDirectoryW",
        "SetEndOfFile", "SetEnvironmentVariableA", "SetEnvironmentVariableW",
        "SetErrorMode", "SetEvent",
        "SetFilePointer", "SetFilePointerEx",
        "SetHandleCount", "SetLastError",
        "SetStdHandle", "SetUnhandledExceptionFilter",
        "SizeofResource", "Sleep", "SleepEx",
        "TerminateProcess",
        "TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue",
        "UnhandledExceptionFilter", "UnmapViewOfFile",
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
        "WaitForSingleObject", "WaitForSingleObjectEx",
        "WideCharToMultiByte", "WriteConsoleW", "WriteFile",
        "lstrlenA", "lstrlenW", "lstrcmpA", "lstrcmpW",
        "lstrcmpiA", "lstrcmpiW",
    ],
    "kernelbase.dll": [
        # Many api-ms-win-* redirects point here
        "CloseHandle", "CreateFileA", "CreateFileW",
        "GetLastError", "SetLastError",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "GetModuleHandleA", "GetModuleHandleW",
        "GetModuleFileNameA", "GetModuleFileNameW",
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
        "GetProcessHeap", "GetCurrentProcess", "GetCurrentProcessId",
        "GetCurrentThreadId", "GetTickCount",
        "QueryPerformanceCounter",
        "InitializeCriticalSectionEx",
        "IsDebuggerPresent", "OutputDebugStringA",
        "WideCharToMultiByte", "MultiByteToWideChar",
        "GetACP", "GetCPInfo", "IsValidCodePage",
        "GetStringTypeW", "LCMapStringW",
        "GetLocaleInfoW", "GetUserDefaultLCID",
        "GetEnvironmentStringsW", "FreeEnvironmentStringsW",
        "GetCommandLineA", "GetCommandLineW",
        "GetStartupInfoW", "GetStdHandle",
        "GetFileType", "ReadFile", "WriteFile",
        "SetFilePointer", "FlushFileBuffers",
    ],
    "user32.dll": [
        # Qiling shim hooks
        "CharUpperA", "CheckRemoteDebuggerPresent",
        "CreateWindowExA", "CreateWindowExW",
        "DefWindowProcA", "DefWindowProcW",
        "DestroyIcon", "DestroyWindow",
        "DialogBoxIndirectParamA", "DispatchMessageA",
        "DrawTextA", "DrawTextW",
        "EnumDisplayMonitors",
        "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW",
        "GetClientRect", "GetCursorPos",
        "GetDC", "GetDesktopWindow", "GetDlgItem",
        "GetForegroundWindow", "GetKeyboardLayout",
        "GetProcessWindowStation", "GetScrollInfo",
        "GetSystemMetrics", "GetUserObjectInformationW",
        "GetWindowLongA", "GetWindowLongW",
        "GetWindowRect", "GetWindowTextA", "GetWindowTextW",
        "LoadCursorA", "LoadCursorW", "LoadIconA", "LoadIconW",
        "LoadStringA", "LoadStringW",
        "MapVirtualKeyA", "MapVirtualKeyW",
        "MessageBoxA", "MessageBoxW",
        "PeekMessageA", "PostMessageA", "PostQuitMessage",
        "RegisterClassA", "RegisterClassExA", "RegisterClassExW",
        "RegisterClassW", "RegisterWindowMessageA",
        "ReleaseDC",
        "SendMessageA", "SendMessageW",
        "SetTimer", "SetWindowLongA", "SetWindowLongW",
        "SetWindowTextA", "SetWindowTextW",
        "Shell_NotifyIconA",
        "ShowWindow", "SystemParametersInfoA", "SystemParametersInfoW",
        "TranslateMessage", "UpdateWindow",
        "wsprintfA", "wsprintfW",
    ],
    "advapi32.dll": [
        # Qiling shim hooks
        "AdjustTokenPrivileges",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptCreateHash", "CryptDecrypt", "CryptDeriveKey",
        "CryptDestroyHash", "CryptDestroyKey",
        "CryptEncrypt", "CryptExportKey",
        "CryptGenKey", "CryptGenRandom",
        "CryptGetHashParam", "CryptHashData",
        "CryptImportKey", "CryptReleaseContext",
        "GetTokenInformation", "GetUserNameA", "GetUserNameW",
        "LookupAccountSidA", "LookupAccountSidW",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "OpenProcessToken", "OpenThreadToken",
        "RegCloseKey", "RegCreateKeyA", "RegCreateKeyExA",
        "RegDeleteValueA", "RegEnumKeyExA", "RegEnumValueA",
        "RegOpenKeyA", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegQueryInfoKeyA", "RegQueryValueExA", "RegQueryValueExW",
        "RegSetValueExA", "RegSetValueExW",
    ],
    "shell32.dll": [
        "SHGetFileInfoA", "SHGetFileInfoW",
        "SHGetSpecialFolderPathW",
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW",
        "Shell_NotifyIconA",
    ],
    "mscoree.dll": [
        "CorExitProcess",
    ],
    "ucrtbase.dll": [
        # Qiling hooks these as ucrtbased but we also need ucrtbase
        "__acrt_iob_func", "__getmainargs", "__lconv_init",
        "__p___argc", "__p___argv", "__p__acmdln", "__p__commode",
        "__p__environ", "__p__fmode", "__p__wcmdln",
        "__set_app_type",
        "__stdio_common_vfprintf", "__stdio_common_vfprintf_s",
        "__stdio_common_vfwprintf", "__stdio_common_vfwprintf_s",
        "__stdio_common_vsprintf", "__stdio_common_vsprintf_s",
        "__stdio_common_vswprintf", "__stdio_common_vswprintf_s",
        "__strncnt", "__wgetmainargs",
        "_calloc_base", "_cexit", "_controlfp",
        "_free_base", "_get_initial_narrow_environment",
        "_initterm", "_initterm_e", "_ismbblead",
        "_malloc_base", "_onexit", "_time64", "_wfopen_s",
        "atexit", "calloc", "exit", "free", "malloc",
        "memmove", "memset", "printf", "puts", "sprintf",
        "strlen", "strncmp", "wprintf",
    ],
    "psapi.dll": [
        "EnumProcessModules", "EnumProcesses",
        "GetModuleBaseNameA", "GetModuleBaseNameW",
        "GetModuleFileNameExA", "GetModuleFileNameExW",
        "GetModuleInformation",
        "GetProcessMemoryInfo",
    ],
    "urlmon.dll": [
        "URLDownloadToFileA", "URLDownloadToFileW",
        "URLDownloadToCacheFileA",
    ],
    "ws2_32.dll": [
        "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASetLastError",
        "accept", "bind", "closesocket", "connect",
        "gethostbyname", "gethostname", "getpeername", "getsockname",
        "getsockopt", "htonl", "htons", "inet_addr", "inet_ntoa",
        "ioctlsocket", "listen", "ntohl", "ntohs",
        "recv", "recvfrom", "select", "send", "sendto",
        "setsockopt", "shutdown", "socket",
    ],
    "wininet.dll": [
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW",
        "InternetReadFile", "InternetCloseHandle",
        "HttpOpenRequestA", "HttpSendRequestA",
        "InternetCrackUrlA",
    ],
    "ole32.dll": [
        "CoInitialize", "CoInitializeEx", "CoUninitialize",
        "CoCreateInstance", "CoTaskMemAlloc", "CoTaskMemFree",
        "OleInitialize", "OleUninitialize",
    ],
    "oleaut32.dll": [
        "SysAllocStringLen", "SysFreeString", "SysStringLen",
        "VariantInit", "VariantClear",
    ],
    "crypt32.dll": [
        "CertOpenStore", "CertCloseStore",
        "CertFindCertificateInStore",
        "CertGetCertificateChain", "CertVerifyCertificateChainPolicy",
        "CryptDecodeObjectEx", "CryptStringToBinaryA",
    ],
    "shlwapi.dll": [
        "PathFindExtensionA", "PathFindExtensionW",
        "PathFindFileNameA", "PathFindFileNameW",
        "PathIsRelativeA", "PathIsRelativeW",
        "StrCmpIW", "StrStrIA", "StrStrIW",
    ],
    "msvcrt.dll": [
        "__getmainargs", "__set_app_type", "__p__fmode",
        "__p__commode", "__p___argv", "__p___argc",
        "_acmdln", "_amsg_exit", "_cexit", "_controlfp",
        "_exit", "_initterm", "_iob", "_ismbblead",
        "_onexit", "_XcptFilter",
        "abort", "atexit", "atoi", "atol",
        "calloc", "exit", "fclose", "fflush", "fopen", "fprintf",
        "fread", "free", "fwrite",
        "malloc", "memcmp", "memcpy", "memmove", "memset",
        "printf", "puts", "realloc",
        "sprintf", "sscanf", "strcat", "strcmp", "strcpy",
        "strlen", "strncmp", "strncpy", "strstr",
        "vfprintf", "vsnprintf", "vsprintf",
        "wcscat", "wcscmp", "wcscpy", "wcslen",
    ],
}

# 64-bit DLLs use the same names
DLLS_64: dict[str, list[str]] = DLLS_32.copy()


def create_all_dlls(output_dir: str, bits: int = 32) -> None:
    """Create all standard DLL stubs in the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    dlls = DLLS_32 if bits == 32 else DLLS_64

    for dll_name, exports in dlls.items():
        data = create_pe_dll(dll_name, exports, bits)
        path = os.path.join(output_dir, dll_name)
        with open(path, 'wb') as f:
            f.write(data)

        # Also create uppercase variant for case-sensitive lookups
        upper_name = dll_name.upper()
        if upper_name != dll_name:
            upper_path = os.path.join(output_dir, upper_name)
            if not os.path.exists(upper_path):
                with open(upper_path, 'wb') as f:
                    f.write(data)

        print(f"  Created {dll_name} ({len(data)} bytes, {len(exports)} exports)")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_dir> [--bits 32|64]")
        sys.exit(1)

    output_dir = sys.argv[1]
    bits = 32
    if "--bits" in sys.argv:
        idx = sys.argv.index("--bits")
        if idx + 1 < len(sys.argv):
            bits = int(sys.argv[idx + 1])

    print(f"Creating {bits}-bit stub DLLs in {output_dir}")
    create_all_dlls(output_dir, bits)
    print("Done.")


if __name__ == "__main__":
    main()
