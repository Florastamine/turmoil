// Licensed under GPLv2 or later until the library is deemed stable enough for general use, see LICENSE in the source tree.
#pragma once

#include <optional>

#if defined(_WIN32)
    #include <windows.h>
#endif

namespace lavender {

namespace process {

std::optional<bool> is_process_WOW64(const HANDLE process);

}

}
