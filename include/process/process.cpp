// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#include <nt.hpp>
#include <process/process.hpp>

#if defined(_WIN32)
    #include <windows.h>
    #include <wow64apiset.h>
#endif

namespace turmoil {

namespace process {

using IsWow64Process2Ptr = BOOL (WINAPI *) (HANDLE, USHORT *, USHORT *);
std::optional<bool> is_process_WOW64(const HANDLE process)
{
    // IsWow64Process2() was introduced in NT 10 version 1511
    if (platform::get_version_extended().value_or(platform::OSInformation()).GetBuildNumber() >= 1511) {
        const HMODULE module = ::GetModuleHandle("kernel32.dll");
        if (module != nullptr)
        {
            const IsWow64Process2Ptr f = (IsWow64Process2Ptr) ::GetProcAddress(module, "IsWow64Process2");
            USHORT target_info, host_info;
            if (f != nullptr && f(process, &target_info, &host_info) != 0) {
                return target_info != IMAGE_FILE_MACHINE_UNKNOWN; // target_info returns IMAGE_FILE_MACHINE_UNKNOWN if is not a WOW64 process.
            }
        }
    }
    else {
        BOOL status;
        if (::IsWow64Process(process, &status) != 0)
            return status;
    }

    return std::nullopt;
}

}

}
