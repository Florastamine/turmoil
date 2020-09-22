project (
    'turmoil', 
    ['cpp'],
    
    # Due to cpp_std not being honored (github.com/mesonbuild/meson/issues/5590), for now we'll have to resort to setting C++ standard through cpp_args.
)

subdir('turmoil')

cpp_args = [
    '-std=c++17', 
    '-g'
]

link_args = [
    '-lPowrprof' 
]

include_directories = [
    include_directories('include')
]

executable (
    'platform_get_version_string',
    sources : [ 'examples/platform_get_version_string.cpp' ],
    cpp_args : cpp_args,
    link_args : link_args,
    include_directories : include_directories,
    link_with : turmoil
)

executable (
    'process_is_process_WOW64',
    sources : [ 'examples/process_is_process_WOW64.cpp' ],
    cpp_args : cpp_args,
    link_args : link_args,
    include_directories : include_directories,
    link_with : turmoil
)
