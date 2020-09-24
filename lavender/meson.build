source = [
    'src/nt.cpp',
    'src/cpu/cpu.cpp',
    'src/process/process.cpp'
]

lavender = static_library (
    'lavender',
    sources : source,
    cpp_args : ['-std=c++17', '-g'],
    link_args : [
        '-lPowrprof' 
    ],
    include_directories : [
        include_directories('include')
    ],
    # install : true,
    # install_dir : meson.current_build_dir()
)

install_subdir (
    'include',
    install_dir : meson.current_build_dir()
)
