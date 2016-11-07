# About this package



# Development

## Add thirdy-party

- Build the source code of the thirdy package for all the ABIs.
- Copy the static/shared library file to the corresponding `src/main/libs/<ABI>` directory.
- Copy the required header files to the new directory `src/main/cpp/<libname>/include` directory.
- Update CMakeLists.txt file.
    - Add add_library .
    - Add set_target_properties.
    - Add the include directory to include_directories.
- Add sourceSets.main to build.gradle if not added before. 

