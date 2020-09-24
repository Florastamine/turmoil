// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace lavender {

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

std::optional<OSVersion> get_version();
std::optional<OSInformation> get_version_extended();
std::optional<std::string> get_version_string();

}

}
