#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>

// Explicit thread_local storage forces MSVC to generate IMAGE_DIRECTORY_ENTRY_TLS
// in the PE data directory table, enabling TLS callback registration tests.
thread_local int g_thread_init_counter = 1337;

static void NTAPI on_tls_callback(PVOID dll_handle, DWORD reason, PVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        std::printf("  [payload] TLS callback executed at base 0x%p\n", dll_handle);
        g_thread_init_counter += 1;
    }
}

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_callback_entry = on_tls_callback;

// Exported symbol used to verify Import Address Table resolution and export walking.
extern "C" __declspec(dllexport) int calculate_integrity_token(int seed) {
    return (seed ^ 0x5A5A5A5A) + 42;
}

// Module entry point executed upon successful manual mapping.
// Uses lightweight C runtime primitives to avoid C++ stream synchronization overhead under loader lock.
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            std::printf("  [payload] Attached to host process at base 0x%p\n", static_cast<void*>(hinstDLL));
            std::printf("  [payload] Integrity verification token: %d\n", calculate_integrity_token(100));
            break;

        case DLL_PROCESS_DETACH:
            std::printf("  [payload] Detaching from host process\n");
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
