cmake = import('cmake')

cmake.write_basic_package_version_file(
    name: 'liboqs', 
    version: '0.13.0'
)

opt_var = cmake.subproject_options()

# Call CMake with `-DSOME_OTHER_VAR=ON`
opt_var.add_cmake_defines({'BUILD_SHARED_LIBS': 'OFF'})
opt_var.add_cmake_defines({'OQS_BUILD_ONLY_LIB': 'ON'})
opt_var.add_cmake_defines({'OQS_DIST_BUILD': 'ON'})
opt_var.add_cmake_defines({'OQS_MINIMAL_BUILD': 'KEM_ml_kem_768'})

liboqs_proj = cmake.subproject('liboqs', options: opt_var)

# Fetch the dependency object
liboqs_dep = liboqs_proj.dependency('oqs')

