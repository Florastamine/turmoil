// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#include <nt.hpp>

#if defined(_WIN32)
    #include <sddl.h>
    #include <winternl.h>
    #include <ntsecapi.h>
#endif

namespace lavender {

namespace platform {

bool IsProcessElevated(const ::HANDLE process)
{
    if (process) {
        if (::HANDLE token = nullptr; ::OpenProcessToken(process, TOKEN_QUERY, &token) != 0) {
            ::DWORD unused = 0;
            if (::TOKEN_ELEVATION_TYPE elevation_type = TOKEN_ELEVATION_TYPE::TokenElevationTypeDefault; ::GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenElevationType, (::LPVOID) &elevation_type, sizeof(elevation_type), &unused) != 0) {
                return elevation_type == TOKEN_ELEVATION_TYPE::TokenElevationTypeFull;
            }

            ::CloseHandle(token);
        }
    }

    return false;
}

std::optional<::ULONG> GetSystemErrorFromNTStatus(const ::NTSTATUS status)
{
    if (::ULONG error = ::RtlNtStatusToDosError(status); error != ERROR_MR_MID_NOT_FOUND)
        return error;
    
    return std::nullopt;
}

std::optional<::ULONG> GetSystemErrorFromLSAStatus(const ::NTSTATUS status)
{
    if (::ULONG error = ::LsaNtStatusToWinError(status); error != ERROR_MR_MID_NOT_FOUND)
        return error;
    
    return std::nullopt;
}

std::optional<std::string> GetStringSIDFromPSID(const ::PSID psid)
{
    if (::LPSTR buffer = nullptr; ::ConvertSidToStringSidA(psid, &buffer) != 0) {
        std::string sid(buffer);
        ::LocalFree(buffer);
        return sid;
    }

    return std::nullopt;
}

}

}
