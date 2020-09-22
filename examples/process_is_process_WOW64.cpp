#include <iostream>
#include <process/process.hpp>

int main(int, const char *[])
{
    std::cout << turmoil::process::is_process_WOW64(::GetCurrentProcess()).value_or(false) << '\n';
}
