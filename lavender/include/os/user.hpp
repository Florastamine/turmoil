// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#pragma once

#include <string>

namespace lavender {

namespace os {

namespace user {

class UserInformation {
private:
    typedef const std::string & string_cref;
    typedef const std::wstring & wstring_cref;

    bool ready_ = false;
    std::string name_ = {};

    bool ParseUserName();

public:
    UserInformation() = default;

    bool IsReady() const { return ready_; }
    bool Initialize();
    
    string_cref GetName() const { return name_; }
};

}

}

}
