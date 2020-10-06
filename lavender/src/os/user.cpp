// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#include <os/user.hpp>

#if defined(_WIN32)
    #include <windows.h>
    #include <lmcons.h>
#endif

namespace lavender {

namespace os {

namespace user {

bool UserInformation::ParseUserName()
{
    char buffer[UNLEN + 1];
    ::DWORD buffer_size = sizeof(buffer);

    if (::GetUserNameA(buffer, &buffer_size)) {
        name_ = std::string(buffer);
        return true;
    }

    return false;
}

bool UserInformation::Initialize()
{
    if (!ready_) {
        ready_ = 
            ParseUserName();
    }

    return ready_;
}

}

}

}
