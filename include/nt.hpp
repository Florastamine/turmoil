// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#pragma once

#include <optional>
#include <unordered_map>

#if defined(_WIN32)
    #include <windows.h>
    #include <ntstatus.h>
#endif

namespace turmoil {

namespace platform {

enum class OSVersion {
    NT_UNIDENTIFIED,
    NT_2000,
    NT_XP,
    NT_XP_64,
    NT_VISTA_2008,
    NT_7_2008_R2,
    NT_8_2012,
    NT_8_1_2012_R2,
    NT_10_2016_2019
};

struct OSInformation {
private:
    OSVersion version_ = OSVersion::NT_UNIDENTIFIED;
    uint32_t build_number_ = 0;
public:
    OSInformation() {}

    OSInformation(OSVersion version, uint32_t build_number) : 
        version_(version),
        build_number_(build_number)
    {}

    uint32_t GetBuildNumber() const { return build_number_; }
    OSVersion GetVersion() const { return version_; }
};

// As you'll be needing the DDK for proper RtlGetVersion() access, just fetch it from ntdll.dll.
// Note that RtlGetVersion() is the kernel-mode equivalent of GetVersionEx*() which is deprecated.
using RtlGetVersionPtr = NTSTATUS (WINAPI *)(PRTL_OSVERSIONINFOW);
static bool get_NT_version_information(RTL_OSVERSIONINFOW *r)
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

static OSVersion get_NT_version_code(const uint32_t major, const uint32_t minor)
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

std::optional<OSVersion> get_version()
{
    RTL_OSVERSIONINFOW r = {0};

    if (get_NT_version_information(&r))
        return get_NT_version_code(r.dwMajorVersion, r.dwMinorVersion);

    return std::nullopt;
}

std::optional<OSInformation> get_version_extended()
{
    RTL_OSVERSIONINFOW r = {0};

    if (get_NT_version_information(&r)) {
        return OSInformation(get_NT_version_code(r.dwMajorVersion, r.dwMinorVersion), r.dwBuildNumber);
    }

    return std::nullopt;
}

std::optional<std::string> get_version_string()
{
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

    const auto version = get_version();

    if (version.has_value()) {
        if (const auto ptr = version_code_map.find(version.value()); ptr != version_code_map.end())
            return ptr->second;
    }

    return std::nullopt;
}

}

}
