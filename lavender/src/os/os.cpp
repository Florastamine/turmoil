// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>

#include <helpers.hpp>
#include <nt.hpp>
#include <os/os.hpp>
#include <os/version.hpp>

#if defined(_WIN32)
    #include <windows.h>
    #include <slpublic.h>
    #include <rpcdce.h>
    #include <ntstatus.h>
    #include <lmcons.h>
    #include <tlhelp32.h>
    #include <shlobj.h> // It is <shlobj.h> that has ::SHGetKnownFolderPath(), and not <shlobj_core.h>
#endif

#include <third_party/magic_enum.hpp>

namespace lavender {

namespace os {

bool OSInformation::Initialize()
{
    if (!ready_) {
        ready_ = 
            ParseOSVersion() &&
            ParseUserInformation() &&
            ParseComputerName() &&
            ParseEnvironmentStrings() &&
            ParseLocale() &&
            ParseArchitecture() &&
            ParseFixedPaths() &&
            TakeSnapshot(SnapshotType::Everything);
        
        genuine_ = ParseGenuine();
    }

    return ready_;
}

bool OSInformation::ParseArchitecture()
{
    if (environment_strings_.empty())
        ParseEnvironmentStrings();
    
    architecture_ = (uint16_t) (HasEnvironmentString("ProgramW6432") ? 64u : 32u);

    return true;
}

static std::optional<std::wstring> GetInternalFolderPath(const ::KNOWNFOLDERID &folder)
{
    ::PWSTR path_string = nullptr;
    
    if (::SHGetKnownFolderPath(folder, KF_FLAG_NO_ALIAS, NULL, &path_string) == S_OK) {
        std::wstring path(path_string);
        ::CoTaskMemFree(path_string);

        return path;
    }

    return std::nullopt;
}

bool OSInformation::ParseSHGetKnownFolderPathDirectory()
{
    struct folder_path_hasher {
    public:
        std::size_t operator()(const ::KNOWNFOLDERID GUID) const noexcept
        {
            return  std::hash<decltype(GUID.Data1)>{}(GUID.Data1)
                  + std::hash<decltype(GUID.Data2)>{}(GUID.Data2)
                  + std::hash<decltype(GUID.Data3)>{}(GUID.Data3)
                  + std::hash<std::string>{}(std::string(GUID.Data4, GUID.Data4 + sizeof(GUID.Data4) / sizeof(GUID.Data4[0])));
        }
    };

    static const std::unordered_map<::KNOWNFOLDERID, PathType, folder_path_hasher> paths = {
        {::FOLDERID_Windows, PathType::Windows},
        {::FOLDERID_ProgramData, PathType::ProgramData},
        // PathType::Temporary is queried using a separate API call.
        {::FOLDERID_ProgramFilesX86, PathType::ProgramFiles32},
        {::FOLDERID_ProgramFilesX64, PathType::ProgramFiles64},
        {::FOLDERID_ProgramFilesCommonX86, PathType::CommonFiles32},
        {::FOLDERID_ProgramFilesCommonX64, PathType::CommonFiles64},
        {::FOLDERID_Profile, PathType::UserProfile},
        {::FOLDERID_Startup, PathType::UserStartup},
        {::FOLDERID_StartMenu, PathType::UserStartMenu},
        {::FOLDERID_Desktop, PathType::UserDesktop},
        {::FOLDERID_Documents, PathType::UserDocuments},
        {::FOLDERID_Downloads, PathType::UserDownloads},
        {::FOLDERID_LocalAppData, PathType::UserAppData},
        {::FOLDERID_LocalAppDataLow, PathType::UserAppDataLow},
        {::FOLDERID_RoamingAppData, PathType::UserAppDataRoaming},
        {::FOLDERID_AppDataDesktop, PathType::UserAppDataDesktop},
    };

    for (const auto &[GUID, type] : paths) {
        paths_[type] = std::wstring();

        if (const auto path = GetInternalFolderPath(GUID); path.has_value())
            paths_[type] = *path + L'\\';        
    }

    return true;
}

bool OSInformation::ParseGetTempPathWDirectory()
{
    wchar_t path[MAX_PATH + 1];
    const ::DWORD path_size = MAX_PATH + 1;

    if (::GetTempPathW(path_size, path)) {
        paths_[PathType::Temporary] = std::wstring(path);
        return true;
    }

    return false;
}

bool OSInformation::ParseSystemParametersInfoWDirectory()
{
    wchar_t path[MAX_PATH + 1];
    if (::SystemParametersInfoW(SPI_GETDESKWALLPAPER, ::UINT(MAX_PATH + 1), (LPVOID) path, 0)) {
        paths_[PathType::UserWallpaper] = std::wstring(path);
        return true;
    }
    
    return false;
}

bool OSInformation::ParseFixedPaths()
{
    return ParseSHGetKnownFolderPathDirectory() &&
           ParseSystemParametersInfoWDirectory() &&
           ParseGetTempPathWDirectory();
}

bool OSInformation::ParseEnvironmentStrings()
{
    for(int i = 0; environ[i] != nullptr; ++i) {
        std::string path = std::string(environ[i]);
        if (const auto p = path.find('='); p != std::string::npos) {
            environment_strings_[path.substr(0, p)] = path.substr(p + 1, path.size());
        }
    }

    return true;
}

bool OSInformation::ParseLocale()
{
    wchar_t buffer[LOCALE_NAME_MAX_LENGTH];
    if (::GetUserDefaultLocaleName(buffer, LOCALE_NAME_MAX_LENGTH)) {
        locale_ = std::wstring(buffer);
        return true;
    }

    return false;
}

bool OSInformation::ParseComputerName()
{
    static const std::unordered_map<::COMPUTER_NAME_FORMAT, std::string> ids = {
        { ::COMPUTER_NAME_FORMAT::ComputerNameNetBIOS, "NetBIOS" },
        { ::COMPUTER_NAME_FORMAT::ComputerNameDnsHostname, "DNS Hostname" },
        { ::COMPUTER_NAME_FORMAT::ComputerNameDnsDomain, "DNS Domain" },
        { ::COMPUTER_NAME_FORMAT::ComputerNameDnsFullyQualified, "DNS Fully-Qualified Name" },
        { ::COMPUTER_NAME_FORMAT::ComputerNamePhysicalNetBIOS, "Physical NetBIOS" },
        { ::COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsHostname, "Physical DNS Hostname" },
        { ::COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsDomain, "Physical DNS Domain" },
        { ::COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsFullyQualified, "Physical DNS Fully-Qualified Name" }
    };
    
    for (int i = 0; i < ::COMPUTER_NAME_FORMAT::ComputerNameMax; ++i)
    {
        char buffer[256];
        ::DWORD buffer_size = sizeof(buffer);

        if (::GetComputerNameExA((::COMPUTER_NAME_FORMAT)i, buffer, &buffer_size)) {
            computer_names_[ids.at((::COMPUTER_NAME_FORMAT) i)] = std::string(buffer);
        }
        else {
            return false;
        }
    }

    return true;
}

bool OSInformation::ParseUserInformation()
{
    return user_information_.Initialize();
}

bool OSInformation::ParseOSVersion()
{
    return version_information_.Initialize();
}

bool OSInformation::ParseGenuine()
{
    static ::GUID UID;
    static bool ready;

    if (!ready) {
        ready = ::UuidFromStringA((::RPC_CSTR) "55c92734-d682-4d71-983e-d6ec3f16059f", &UID) == RPC_S_OK;
    }

    if (ready) {
        ::SL_GENUINE_STATE state;
        ::SLIsGenuineLocal(&UID, &state, nullptr);

        return state == ::SL_GENUINE_STATE::SL_GEN_STATE_IS_GENUINE;
    }

    return false;
}

static bool TakeServicesSnapshot(SystemSnapshot &os)
{
    bool r = false;

    if (::SC_HANDLE services_control = ::OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE); services_control != nullptr) {
        static constexpr const uint32_t service_type_flags = 
              SERVICE_KERNEL_DRIVER
            | SERVICE_FILE_SYSTEM_DRIVER
            | SERVICE_WIN32
            | SERVICE_WIN32_OWN_PROCESS
            | SERVICE_WIN32_SHARE_PROCESS;
        
        static constexpr const uint32_t service_status_flags = SERVICE_ACTIVE | SERVICE_INACTIVE;
        
        ::ENUM_SERVICE_STATUS *services = new ::ENUM_SERVICE_STATUS;
        ::DWORD bytes = 0;
        ::DWORD count = 0;
        ::DWORD handler = 0;

        // Probe ::EnumServicesStatus() once to get the total buffer size, which is used to contain all services' status.
        // It's almost always guaranteed to return FALSE during the first run, as we've only allocated enough for one entry to be available.
        if (::EnumServicesStatus(
            services_control, 
            service_type_flags, 
            service_status_flags, 
            services, 
            sizeof(::ENUM_SERVICE_STATUS), 
            &bytes, 
            &count, 
            &handler) == FALSE)
        {
            if (services) {
                delete services;
                services = nullptr;
            }

            if (::GetLastError() == ERROR_MORE_DATA) {
                bytes += sizeof(::ENUM_SERVICE_STATUS);
                if (services = new ::ENUM_SERVICE_STATUS[bytes]; services != nullptr) {
                    if (::EnumServicesStatus(
                        services_control, 
                        service_type_flags, 
                        service_status_flags, 
                        services,
                        bytes,
                        &bytes,
                        &count,
                        &handler) == TRUE)
                    {
                        if (os.ReserveServiceEntries()) {
                            for(::DWORD i = 0; i < count; ++i)
                            {
                                if (ServiceSnapshot service; service.Initialize(services[i]))
                                    os.AddServiceEntry(service);
                            }
                            r = true;   
                        }
                    }
                    delete [] services;
                }
            }
        }
        else {
            if (services) {
                delete services;
                services = nullptr;
            }
        }

        ::CloseServiceHandle(services_control);
    }

    return r;
}

static bool TakeProcessesSnapshot(SystemSnapshot &os)
{
    ::HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // A value of 0 passed to th32ProcessID indicates the calling process ID 
                                                                           // to be included with the snapshot.
    if(snapshot == INVALID_HANDLE_VALUE)
        return false;
    
    ::PROCESSENTRY32 process_entry = {0};
    process_entry.dwSize = sizeof(::PROCESSENTRY32);
    if(!::Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
    }
    else {
        if (os.ReserveProcessEntries()) {
            do {
                if (ProcessSnapshot process; process.Initialize(process_entry))
                    os.AddProcessEntry(process);
                
            } while(::Process32Next(snapshot, &process_entry));

            ::CloseHandle(snapshot);
            return true;
        }
    }

    return false;
}

bool OSInformation::TakeSnapshot(const SnapshotType &flags)
{
    if ((flags & SnapshotType::Processes) && TakeProcessesSnapshot(snapshot_)) {
        std::printf("processes count: %i\n", snapshot_.GetProcesses().size());
    }
    
    if ((flags & SnapshotType::Services) && TakeServicesSnapshot(snapshot_)) {
        std::printf("services count: %i\n", snapshot_.GetServices().size());
    }
    
    return true;
}

static constexpr const int start = 52;
static const std::string digits = "BCDFGHJKMPQRTVWXY2346789";

// The Microsoft Windows product key is hidden in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion, 
// which is base24-encoded & encrypted in a binary string.
// Decoding routines are provided by the WinProdKeyFinder project (github.com/mrpeardotnet/WinProdKeyFinder), 
// ported to C++11.
static std::string DecodeKeyFor7AndLower(const ::BYTE *bytes)
{
    if (!bytes)
        return std::string();
    
    static constexpr const int end = start + 15;
    static constexpr const int decodeLength  =   29;
    static constexpr int decodeStringLength = 15;

    std::string chars;
    chars.resize(decodeLength + 1);

    ::byte hexPid[end - start + 1];

    for (int i = start; i <= end; ++i)
        hexPid[i - start] = bytes[i];
    
    for (int i = decodeLength - 1; i >= 0; i--)
    {
        if ((i + 1) % 6 == 0)
            chars[i] = '-';
        else
        {
            int digitMapIndex = 0;
            for (int j = decodeStringLength - 1; j >= 0; j--)
            {
                int byteValue = (digitMapIndex << 8) | hexPid[j];
                hexPid[j] = (::byte) (byteValue / 24);
                digitMapIndex = byteValue % 24;
                chars[i] = digits[digitMapIndex];
            }
        }
    }

    return chars;
}

static std::string DecodeKeyFor8AndHigher(/* const */ ::BYTE *bytes)
{
    if (!bytes)
        return std::string();

    std::string chars = {};
    bytes[66] = (byte)((bytes[66] & 0xf7) | (1 & 2) * 4);
    
    int last = 0;
    for (int i = 24; i >= 0; i--)
    {
        int current = 0;
        for (int j = 14; j >= 0; j--)
        {
            current = current*256;
            current = bytes[j + start] + current;
            bytes[j + start] = (byte)(current/24);
            current = current%24;
            last = current;
        }
        chars = digits[current] + chars;
    }

    chars = chars.substr(1, last) + "N" + chars.substr(last + 1, chars.size() - (last + 1));

    for (auto i = 5; i < chars.size(); i += 6)
        chars.insert(i, "-");

    return chars;
}

std::string OSInformation::GetRegisteredProductKey() const
{
    static constexpr const uint32_t flags = KEY_QUERY_VALUE | KEY_WOW64_64KEY; // KEY_WOW64_64KEY is crucial, as 32-bit processes by default points to 
                                                                               // the 32-bit registry. The flag is there to make sure it always points to 
                                                                               // its 64-bit counterpart, so that the given key ("DigitalProductId") can always 
                                                                               // be found.
    static /* constexpr const */ ::DWORD length = PATH_MAX;

    if (::HKEY key; ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, flags, &key) == ERROR_SUCCESS) {
        if (::BYTE buffer[PATH_MAX]; ::RegQueryValueExA(key, "DigitalProductId", nullptr, nullptr, (::LPBYTE) buffer, &length) == ERROR_SUCCESS) {
            if (lavender::os::OSVersionInformation version; version.Initialize()) {
                if (version.Is8OrHigher())
                    return DecodeKeyFor8AndHigher(buffer);
                else
                    return DecodeKeyFor7AndLower(buffer);
            }
        }
        ::RegCloseKey(key);
    }
}

bool ServiceSnapshot::Initialize(const ::ENUM_SERVICE_STATUS &service)
{
    name_ = service.lpDisplayName;

    switch (service.ServiceStatus.dwServiceType) {
        case SERVICE_KERNEL_DRIVER:
            type_ = ServiceType::KernelDriver;
            break;
        case SERVICE_FILE_SYSTEM_DRIVER:
            type_ = ServiceType::FileSystemDriver;
            break;
        case SERVICE_WIN32_OWN_PROCESS:
            type_ = ServiceType::Win32Process;
            break;
        case SERVICE_WIN32_SHARE_PROCESS:
            type_ = ServiceType::Win32SharedProcess;
            break;
        case 0x00000050 /* SERVICE_USER_OWN_PROCESS */:
            type_ = ServiceType::UserProcess;
            break;
        case 0x00000060 /* SERVICE_USER_SHARE_PROCESS */:
            type_ = ServiceType::UserSharedProcess;
            break;
    }

    switch (service.ServiceStatus.dwCurrentState) {
        case SERVICE_PAUSED:
            status_ = ServiceStatus::Paused;
            break;
        case SERVICE_STOPPED:
            status_ = ServiceStatus::Stopped;
            break;
        case SERVICE_RUNNING:
            status_ = ServiceStatus::Running;
            break;
        case SERVICE_START_PENDING:
            status_ = ServiceStatus::Starting;
            break;
        case SERVICE_STOP_PENDING:
            status_ = ServiceStatus::Stopping;
            break;
        case SERVICE_PAUSE_PENDING:
            status_ = ServiceStatus::Pausing;
            break;
        case SERVICE_CONTINUE_PENDING:
            status_ = ServiceStatus::Resuming;
            break;
    }

    return true;
}

bool ProcessSnapshot::Initialize(const ::PROCESSENTRY32 &process)
{
    return InitializeProcessEntryData(process) &&
           InitializeAssociatedImageData();
}

bool ProcessSnapshot::InitializeAssociatedImageData()
{
    ::HANDLE module = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_ID_ );
    if(module == INVALID_HANDLE_VALUE)
        return false;

    ::MODULEENTRY32 module_entry;
    module_entry.dwSize = sizeof(::MODULEENTRY32);

    if(!::Module32First(module, &module_entry)) {
        ::CloseHandle(module);
        return false;
    }
    else {
        do
        {
            modules_.push_back(ProcessModuleSnapshot(module_entry.szModule, module_entry.szExePath, module_entry.th32ProcessID));
        } while(::Module32Next(module, &module_entry));
    }

  ::CloseHandle(module);
  return true;
}

bool ProcessSnapshot::InitializeProcessEntryData(const ::PROCESSENTRY32 &entry)
{
    name_ = entry.szExeFile;
    process_ID_ = entry.th32ProcessID;
    parent_process_ID_ = entry.th32ParentProcessID;
    threads_ = entry.cntThreads;
    base_priority_ = entry.pcPriClassBase;

    // Transparently handling process priority from ::PROCESSENTRY32 - this information couldn't be deduced from ::PROCESSENTRY32 so we have 
    // to open a handle to our process in order to query for priority class.
    ::HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);

    if(process != nullptr)
    {
        priority_ = ::GetPriorityClass(process);
        ::CloseHandle(process);
    }
    
    return true;
}

void SystemSnapshot::AddProcessEntry(const ProcessSnapshot &snapshot)
{
    processes_.push_back(snapshot);
}

void SystemSnapshot::AddServiceEntry(const ServiceSnapshot &snapshot)
{
    services_.push_back(snapshot);
}

bool SystemSnapshot::ReserveProcessEntries()
{
    // For now the return value is just a placeholder, as we'd actually like to verify if the buffer has successfully been reserved to contain all possible entries.
    processes_.clear();
    return true;
}

bool SystemSnapshot::ReserveServiceEntries()
{
    // Ditto!
    services_.clear();
    return true;
}

}

}
