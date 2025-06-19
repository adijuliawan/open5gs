subdir('crypt')
subdir('eap')
subdir('eap_aka')

libkmu_sources = crypt_sources + eap_sources + eap_aka_sources

libkmu_inc = include_directories('crypt','eap','eap_aka','oqs')

libkmu = static_library('kmu',
    sources : libkmu_sources,
    c_args : '-DKMU_COMPILATION',
    include_directories : [libkmu_inc,libinc],
    install: false)

libkmu_dep = declare_dependency(
    link_with : libkmu,
    include_directories : [libkmu_inc,libinc],
    link_args: [
        '-L' + meson.current_source_dir(), '-lkmu',
        '-L' + meson.current_source_dir(), '-loqs'
    ],
)  
