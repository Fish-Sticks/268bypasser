#include <Windows.h>
#include <thread>
#include <iostream>

void make_console()
{
    FILE* f;
    AllocConsole();
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
    SetConsoleTitleA("268 bypasser | fishy");
}


// Only use this to scan for code, not data.
std::uint32_t sig_scanner(const char* sig, const char* mask, std::size_t len)
{
    for (std::uint32_t current_addy = 0; current_addy < 0x7FFFFFFF; ++current_addy)
    {
        MEMORY_BASIC_INFORMATION MBI{};
        if (VirtualQuery(reinterpret_cast<void*>(current_addy), &MBI, sizeof(MBI)))
        {
            // If it's valid executable memory
            if (!((MBI.Protect & PAGE_NOACCESS) | (MBI.Protect & PAGE_GUARD)) && ((MBI.Protect & PAGE_EXECUTE_READ)))
            {
                std::uint32_t base = reinterpret_cast<std::uint32_t>(MBI.BaseAddress);
                for (std::uint32_t address = base; address < (base + MBI.RegionSize) - len; ++address)
                {
                    bool is_valid = true;
                    for (std::uint32_t offset = 0; offset < len; ++offset)
                    {
                        if (mask[offset] == 'W' && *reinterpret_cast<char*>(address + offset) != sig[offset])
                        {
                            is_valid = false;
                            break;
                        }
                    }

                    if (is_valid)
                        return address;
                }
            }

            // go to next memory region, no point in calling virtualquery over and over on same module
            current_addy = reinterpret_cast<std::uint32_t>(MBI.BaseAddress) + MBI.RegionSize;
        }
    }
}

std::uint32_t scan_for_patch_spot()
{
    const char* sig = "\x74\x14\x8B\x45\xE0";
    const char* mask = "WWWWW";
    std::uint32_t scanner = sig_scanner(sig, mask, strlen(mask));
    return scanner;
}

void obliterate_checker()
{
    DWORD old;
    std::uint32_t spot = scan_for_patch_spot();

    std::printf("Located scanner: [0x%p]\n", spot);

    VirtualProtect(reinterpret_cast<void*>(spot), 1, PAGE_EXECUTE_READWRITE, &old);
    *reinterpret_cast<byte*>(spot) = 0xEB; // https://www.felixcloutier.com/x86/jmp  jmp rel8
    VirtualProtect(reinterpret_cast<void*>(spot), 1, old, &old);

    std::printf("Successfully patched the scanner! Have fun injecting ur skidware\n");
}

void main_thread()
{
    make_console();
    std::printf("[WARNING]: Make sure this is injected into the SECOND process!\n");
    std::printf("Use this bypasser on an alt to avoid HWID bans. (It may or may not still silent log)\n");
    std::printf("This works by patching the scanner, and making it exit before it's done scanning so it'll only do one iteration.\n");
    std::printf("For best experience, wait 30 seconds before injecting the bypass.\n");

    obliterate_checker();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        std::thread(main_thread).detach();
        break;
    }
    return TRUE;
}