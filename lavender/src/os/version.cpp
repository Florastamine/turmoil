// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#include <nt.hpp>
#include <os/version.hpp>

#include <string>
#include <optional>
#include <unordered_map>

#if defined(_WIN32)
    #include <windows.h>
    #include <ntstatus.h>
#endif

namespace lavender {

namespace os {

static const std::unordered_map<OSVersion, std::string> version_code_map = {
    {OSVersion::NT_UNIDENTIFIED, "Unidentified"},
    {OSVersion::NT_2000, "2000"},
    {OSVersion::NT_XP, "XP"},
    {OSVersion::NT_XP_64, "XP x64"},
    {OSVersion::NT_VISTA_2008, "Vista/Server 2008"},
    {OSVersion::NT_7_2008_R2, "7/Server 2008 R2"},
    {OSVersion::NT_8_2012, "8/Server 2012"},
    {OSVersion::NT_8_1_2012_R2, "8.1/Server 2012 R2"},
    {OSVersion::NT_10_2016_2019, "10/Server 2016/Server 2019"}
};


// As you'll be needing the DDK for proper RtlGetVersion() access, just fetch it from ntdll.dll.
// Note that RtlGetVersion() is the kernel-mode equivalent of GetVersionEx*() which is deprecated.
using RtlGetVersionPtr = NTSTATUS (WINAPI *)(PRTL_OSVERSIONINFOW);
static bool GetNTVersionInformation(RTL_OSVERSIONINFOW *r)
{
    const HMODULE module = ::GetModuleHandle("ntdll.dll");
    if (module != nullptr)
    {
        const RtlGetVersionPtr f = (RtlGetVersionPtr) ::GetProcAddress(module, "RtlGetVersion");
        if (f != nullptr && r != nullptr && f(r) == STATUS_SUCCESS) {
            r->dwOSVersionInfoSize = sizeof *r;
            return true;
        }
    }

    return false;
}

static OSVersion GetNTVersionCode(const uint32_t major, const uint32_t minor)
{
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
    if (major == 5 && minor == 0)
        return OSVersion::NT_2000;
    else if (major == 5 && minor == 1)
        return OSVersion::NT_XP;
    else if (major == 5 && minor == 2)
        return OSVersion::NT_XP_64;
    else if (major == 6 && minor == 0)
        return OSVersion::NT_VISTA_2008;
    else if (major == 6 && minor == 1)
        return OSVersion::NT_7_2008_R2;
    else if (major == 6 && minor == 2)
        return OSVersion::NT_8_2012;
    else if (major == 6 && minor == 3)
        return OSVersion::NT_8_1_2012_R2;
    else if (major == 10 && minor == 0)
        return OSVersion::NT_10_2016_2019;
    else
        return OSVersion::NT_UNIDENTIFIED;
}

bool OSVersionInformation::Initialize()
{
    RTL_OSVERSIONINFOW r = {0};

    if (GetNTVersionInformation(&r)) {
        version_ = GetNTVersionCode(r.dwMajorVersion, r.dwMinorVersion);
        build_number_ = r.dwBuildNumber;

        if (const auto ptr = version_code_map.find(version_); ptr != version_code_map.end())
            version_string_ = ptr->second;
        
        return true;
    }

    return false;
}

}

}
