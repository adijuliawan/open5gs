libeap_sources = files('''
    eap.c
    eap.h
'''.split())

libeap_inc = include_directories('.')

#liboqs = cc.find_library('liboqs', dirs: meson.current_source_dir())

libeap = static_library('ogseap',
    sources : libeap_sources,
    #version : libogslib_version,
    c_args : '-DOGS_EAP_COMPILATION',
    include_directories : [libeap_inc,libinc],
    dependencies: [libcore_dep, libcrypt_dep],
    install: true)

#libeap_dep = declare_dependency(
#    link_with : libeap,
#    include_directories : [libeap_inc, libinc],
#    dependencies: [libcore_dep, libcrypt_dep]
#    #link_args: ['-L' + meson.current_source_dir(), '-logseap'],
#)

libeap_dep = declare_dependency(
    link_with : libeap,
    include_directories : [libeap_inc, libinc],
    #dependencies: [libcore_dep, libcrypt_dep]
    link_args: [
        '-L' + meson.current_source_dir(), '-logseap',
        '-L' + meson.current_source_dir(), '-loqs'
    ],
)  


#libeap_inc = include_directories('.')
#
#liboqs_dep = declare_dependency(
#    include_directories: include_directories('./oqs'),
#    link_args: [
#        '-L' + meson.current_source_dir(), '-loqs'
#    ]
#)
#
#libeap_dep = declare_dependency(
#    include_directories: [libeap_inc, libinc],
#    link_args: [
#        '-L' + meson.current_source_dir(), '-logseap'
#    ],
#    dependencies: [libcore_dep,liboqs_dep]
#)