// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#pragma once

#include <type_traits>
#include <os/version.hpp>
#include <os/user.hpp>

#include <unordered_map>

#if defined(_WIN32)
    #include <windows.h>
    #include <tlhelp32.h> // ::PROCESSENTRY32
    #include <lm.h> // ::USER_INFO_3
#endif

namespace lavender {

namespace os {

class ProcessModuleSnapshot {
private:
    std::string name_;
    std::string image_;
    uint32_t process_ID_;

public:
    ProcessModuleSnapshot(const std::string &name, const std::string &image, const uint32_t process_ID)
        : name_(name),
          image_(image),
          process_ID_(process_ID)
    {}

    const std::string &GetName() const { return name_; }
    const std::string &GetImagePath() const { return image_; }
    uint32_t GetParentID() const { return process_ID_; }
};

class ProcessSnapshot {
private:
    std::vector<ProcessModuleSnapshot> modules_;
    std::string name_;
    uint32_t process_ID_;
    uint32_t parent_process_ID_;
    uint32_t threads_;
    uint32_t priority_;
    uint32_t base_priority_;

    bool InitializeProcessEntryData(const ::PROCESSENTRY32 &process);
    bool InitializeAssociatedImageData();

public:
    const std::vector<ProcessModuleSnapshot> &GetModules() const { return modules_; }
    const std::string &GetName() const { return name_; }
    uint32_t GetID() const { return process_ID_; }
    uint32_t GetParentID() const { return parent_process_ID_; }
    uint32_t GetPriority() const { return priority_; }
    uint32_t GetBasePriority() const { return base_priority_; }
    uint32_t GetThreadCount() const { return threads_; }

    ProcessSnapshot() {}
    bool Initialize(const ::PROCESSENTRY32 &process);
};

enum class ServiceStatus {
    Unknown,
    Paused, // SERVICE_PAUSED (0x00000007)
    Stopped, // SERVICE_STOPPED (0x00000001)
    Running, // SERVICE_RUNNING (0x00000004)
    Starting, // SERVICE_START_PENDING (0x00000002)
    Stopping, // SERVICE_STOP_PENDING (0x00000003)
    Pausing, // SERVICE_PAUSE_PENDING (0x00000006)
    Resuming // SERVICE_CONTINUE_PENDING (0x00000005)
};

enum class ServiceType {
    Unknown,
    KernelDriver, // SERVICE_KERNEL_DRIVER (0x00000001)
    FileSystemDriver, // SERVICE_FILE_SYSTEM_DRIVER(0x00000002)
    Win32Process, // SERVICE_WIN32_OWN_PROCESS (0x00000010)
    Win32SharedProcess, // SERVICE_WIN32_SHARE_PROCESS (0x00000020)
    UserProcess, // SERVICE_USER_OWN_PROCESS (0x00000050)
    UserSharedProcess // SERVICE_USER_SHARE_PROCESS (0x00000060)
};

class ServiceSnapshot {
private:
    bool ready_ = false;
    ServiceType type_ = ServiceType::Unknown;
    ServiceStatus status_ = ServiceStatus::Unknown;
    std::string name_ = {};

public:
    ~ServiceSnapshot() = default;
    ServiceSnapshot() = default;
    
    const std::string &GetName() const { return name_; }
    ServiceType GetType() const { return type_; }
    ServiceStatus GetStatus() const { return status_; }

    bool IsReady() const { return ready_; }
    bool Initialize(const ::ENUM_SERVICE_STATUS &service);
};

enum class UserPrivilegeType {
   Reserved,
   Guest,
   User,
   Administrator
};

class UserSnapshot {
private:
   typedef const std::wstring & wstring_cref;
   std::wstring name_ = {};
   std::wstring full_name_ = {};
   std::wstring description_ = {};
   std::wstring SID_ = {};
   uint32_t login_count_ = 0;
   uint32_t relative_ID_ = 0;
   UserPrivilegeType privilege_type_ = UserPrivilegeType::Reserved;
   time_t time_last_login_;
   time_t time_last_logout_;
   bool active_ = false;

   UserPrivilegeType GetPrivilegeType(const uint32_t privilege);

public:
   wstring_cref GetName() const { return name_; }
   wstring_cref GetFullName() const { return full_name_; }
   wstring_cref GetDescription() const { return description_; }
   UserPrivilegeType GetPrivilege() const { return privilege_type_; }
   uint32_t GetLoginCount() const { return login_count_; }

   time_t GetLastLoginTime() const { return time_last_login_; }
   std::string GetLastLoginTimeAsString() const;
   
   time_t GetLastLogoutTime() const { return time_last_logout_; }
   std::string GetLastLogoutTimeAsString() const;

   uint32_t GetRelativeID() const { return relative_ID_; }

   wstring_cref GetSID() const { return SID_; }

   bool IsActive() const { return active_; }

   UserSnapshot() {}
   bool Initialize(const ::USER_INFO_3 *user);
};

enum class SnapshotType {
    Processes = 1 << 0,
    Services = 1 << 1,
    Users = 1 << 2,
    Everything = Processes | Services | Users
};

template <typename E, typename = std::enable_if<std::is_enum<E>::value>>
auto operator|(const E &lhs, const E &rhs) -> E
{
    return static_cast<E>(
        static_cast<typename std::underlying_type<E>::type>(lhs) | static_cast<typename std::underlying_type<E>::type>(rhs)
    );
}

template <typename E, typename = std::enable_if<std::is_enum<E>::value>>
auto operator&(const E &lhs, const E &rhs) -> bool
{
    return static_cast<typename std::underlying_type<E>::type>(lhs) & static_cast<typename std::underlying_type<E>::type>(rhs);
}

class SystemSnapshot {
private:
    std::vector<ProcessSnapshot> processes_ = {};
    std::vector<ServiceSnapshot> services_ = {};
    std::vector<UserSnapshot> users_ = {};

    friend bool TakeProcessesSnapshot(SystemSnapshot &os);
    friend bool TakeServicesSnapshot(SystemSnapshot &os);
    friend bool TakeUsersSnapshot(SystemSnapshot &os);

public:
    const std::vector<ProcessSnapshot> &GetProcesses() const { return processes_; }
    const std::vector<ServiceSnapshot> &GetServices() const { return services_; }
    const std::vector<UserSnapshot> &GetUsers() const { return users_; }

    bool ReserveProcessEntries();
    bool ReserveServiceEntries();
};

enum class PathType : uint16_t {
    Windows,
    ProgramData,
    Temporary,
    ProgramFiles32,
    ProgramFiles64,
    CommonFiles32,
    CommonFiles64,
    UserProfile,
    UserStartup,
    UserStartMenu,
    UserDesktop,
    UserDocuments,
    UserDownloads,
    UserWallpaper,
    UserAppData,
    UserAppDataLow,
    UserAppDataRoaming,
    UserAppDataDesktop, // Introduced in NT 10 1709
};

class OSInformation {
private:
    typedef const std::string & string_cref;
    typedef const std::wstring & wstring_cref;

    typedef const std::unordered_map<std::string, std::string> & map_string_cref;
    typedef std::unordered_map<std::string, std::string> map_string;

    typedef const std::unordered_map<PathType, std::wstring> & folder_path_map_cref;
    typedef std::unordered_map<PathType, std::wstring> folder_path_map;

    bool ready_ = false;
    bool genuine_ = false;

    uint16_t architecture_ = 0;
    map_string computer_names_ = {};
    map_string environment_strings_ = {};
    folder_path_map paths_ = {};
    std::string user_name_ = {};
    std::wstring locale_ = {};
    OSVersionInformation version_information_;
    user::UserInformation user_information_;
    SystemSnapshot snapshot_;

    bool ParseLocale();
    bool ParseOSVersion();
    bool ParseComputerName();
    bool ParseGenuine();
    bool ParseEnvironmentStrings();
    bool ParseArchitecture();
    bool ParseFixedPaths();
    bool ParseUserInformation();

    bool ParseSHGetKnownFolderPathDirectory();
    bool ParseGetTempPathWDirectory();
    bool ParseSystemParametersInfoWDirectory();

public:
    OSInformation() {}

    bool IsReady() const { return ready_; }
    bool Initialize();

    std::string GetRegisteredProductKey() const;
    bool IsGenuine() const { return genuine_; }

    uint16_t GetArchitecture() const { return architecture_; }
    wstring_cref GetLocale() const { return locale_; }
    string_cref GetUserName() const { return user_name_; }
    map_string_cref GetComputerName() const { return computer_names_; }

    const OSVersionInformation &GetVersionInformation() const { return version_information_; }
    const user::UserInformation &GetUserInformation() const { return user_information_; }
    bool TakeSnapshot(const SnapshotType &flags = SnapshotType::Everything);
    const SystemSnapshot &GetSystemSnapshot() const { return snapshot_; }

    map_string_cref GetEnvironmentStrings() const { return environment_strings_; }
    bool HasEnvironmentString(const std::string &v) const { return environment_strings_.find(v) != environment_strings_.end(); }

    folder_path_map_cref GetPaths() const { return paths_; }
};

}

}