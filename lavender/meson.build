source = [
    'src/nt.cpp',
    'src/cpu/cpu.cpp',
    'src/process/process.cpp'
]

cc = meson.get_compiler('cpp')

if cc.get_id() == 'msvc'
    cpp_args = ['/std:c++17']
    link_args = ['PowrProf.lib']
else
    cpp_args = ['-std=c++17', '-g']
    link_args = ['-lPowrProf', '-lstdc++']
endif

lavender = static_library (
    'lavender',
    sources : source,
    cpp_args : cpp_args,
    link_args : link_args,
    include_directories : [
        include_directories('include')
    ]
)

install_subdir (
    'include',
    install_dir : meson.current_build_dir()
)
