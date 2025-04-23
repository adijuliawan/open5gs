libeap_sources = files('''
    eap.c
    eap.h
'''.split())

libeap_inc = include_directories('.')

libeap = library('ogseap',
    sources : libeap_sources,
    version : libogslib_version,
    c_args : '-DOGS_EAP_COMPILATION',
    include_directories : [libeap_inc,libinc],
    dependencies: [libcore_dep],
    install: true)

libeap_dep = declare_dependency(
    link_with : libeap,
    include_directories : [libeap_inc, libinc],
    dependencies: [libcore_dep])