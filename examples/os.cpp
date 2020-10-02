#include <iostream>
#include <vector>
#include <os/os.hpp>

#include <third_party/magic_enum.hpp>

#if defined(_WIN32)
    #include <winbase.h>
#endif

static constexpr const char n = '\n';

static std::string ConvertPriorityClass(const uint32_t priority)
{
    switch (priority) {
        case ABOVE_NORMAL_PRIORITY_CLASS: return "ABOVE_NORMAL_PRIORITY_CLASS";
        case BELOW_NORMAL_PRIORITY_CLASS: return "BELOW_NORMAL_PRIORITY_CLASS";
        case HIGH_PRIORITY_CLASS: return "HIGH_PRIORITY_CLASS";
        case IDLE_PRIORITY_CLASS: return "IDLE_PRIORITY_CLASS";
        case NORMAL_PRIORITY_CLASS: return "NORMAL_PRIORITY_CLASS";
        case REALTIME_PRIORITY_CLASS: return "REALTIME_PRIORITY_CLASS";
        default: return "(?)";
    }
}

int main(int, const char *[])
{
    using std::cout;
    using std::wcout;
    using std::endl;
    using std::flush;
    
    if (lavender::os::OSInformation os; os.Initialize()) {
        cout << "IsGenuine(): " << os.IsGenuine() << n;
        cout << "GetUserName(): " << os.GetUserName() << n;
        wcout << "GetLocale(): " << os.GetLocale() << n;

        if (const lavender::os::OSVersionInformation &version = os.GetVersionInformation(); version.IsReady()) {
            cout << "GetBuildNumber(): " << version.GetBuildNumber() << n;
            cout << "GetVersion(): " << magic_enum::enum_name(version.GetVersion()) << n;
            cout << "GetVersionAsString(): " << version.GetVersionAsString() << n;
            cout << "GetProductType(): " << version.GetProductType() << n;
        }

        cout << "GetComputerName():\n";
        for (const auto &name : os.GetComputerName())
            cout << ' ' << ' ' << name.first << ' ' << name.second << n;

        cout << "GetEnvironmentStrings():\n";
        for (auto &str : os.GetEnvironmentStrings())
            cout << ' ' << ' ' << str.first << " = " << str.second << n;
        
        cout << "GetRegisteredProductKey(): " << os.GetRegisteredProductKey() << n;

        if (os.TakeSnapshot(lavender::os::SnapshotType::Services | lavender::os::SnapshotType::Processes)) {
            const auto snapshot = os.GetSystemSnapshot();
            for (const auto &service : snapshot.GetServices()) {
                cout << service.GetName() << " (" << magic_enum::enum_name(service.GetType()) << ", " << magic_enum::enum_name(service.GetStatus()) << ")\n";
            }

            for (const auto &process : snapshot.GetProcesses()) {
                cout << process.GetName() << " (ID: " << process.GetID() << " (parent: " << process.GetParentID() << "), priority: " << ConvertPriorityClass(process.GetPriority()) << ", threads: " << process.GetThreadCount() << ")" << n;
                for (const auto &module : process.GetModules()) {
                    cout << "  GetName(): " << module.GetName() << n;
                    cout << "  GetImagePath(): " << module.GetImagePath() << n;
                    cout << "  GetParentID(): " << module.GetParentID() << n;
                }
                cout << n << n;
            }
        }

        cout << flush;
    }
}

