#include <iostream>
#include <string>
#include <nt.hpp>

int main(int, const char *[])
{
    std::cout << lavender::platform::get_version_string().value_or(std::string()) << '\n';
}
