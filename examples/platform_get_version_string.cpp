#include <iostream>
#include <string>
#include <nt.hpp>

int main(int, const char *[])
{
    std::cout << turmoil::platform::get_version_string().value_or(std::string::empty()) << '\n';
}
