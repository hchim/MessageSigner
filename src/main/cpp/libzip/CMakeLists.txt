# Sets the minimum version of CMake required to build the native
# library. You should either keep the default value or only pass a
# value of 3.4.0 or lower.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds it for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             zip

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             # Associated headers in the same location as their source
             # file are automatically included.
            src/main/cpp/libzip/mkstemp.c
            src/main/cpp/libzip/zip_add.c
            src/main/cpp/libzip/zip_add_dir.c
            src/main/cpp/libzip/zip_close.c
            src/main/cpp/libzip/zip_delete.c
            src/main/cpp/libzip/zip_dirent.c
            src/main/cpp/libzip/zip_entry_free.c
            src/main/cpp/libzip/zip_entry_new.c
            src/main/cpp/libzip/zip_err_str.c
            src/main/cpp/libzip/zip_error.c
            src/main/cpp/libzip/zip_error_clear.c
            src/main/cpp/libzip/zip_error_get.c
            src/main/cpp/libzip/zip_error_get_sys_type.c
            src/main/cpp/libzip/zip_error_strerror.c
            src/main/cpp/libzip/zip_error_to_str.c
            src/main/cpp/libzip/zip_fclose.c
            src/main/cpp/libzip/zip_file_error_clear.c
            src/main/cpp/libzip/zip_file_error_get.c
            src/main/cpp/libzip/zip_file_get_offset.c
            src/main/cpp/libzip/zip_file_strerror.c
            src/main/cpp/libzip/zip_filerange_crc.c
            src/main/cpp/libzip/zip_fopen.c
            src/main/cpp/libzip/zip_fopen_index.c
            src/main/cpp/libzip/zip_fread.c
            src/main/cpp/libzip/zip_free.c
            src/main/cpp/libzip/zip_get_archive_comment.c
            src/main/cpp/libzip/zip_get_archive_flag.c
            src/main/cpp/libzip/zip_get_file_comment.c
            src/main/cpp/libzip/zip_get_num_files.c
            src/main/cpp/libzip/zip_get_name.c
            src/main/cpp/libzip/zip_memdup.c
            src/main/cpp/libzip/zip_name_locate.c
            src/main/cpp/libzip/zip_new.c
            src/main/cpp/libzip/zip_open.c
            src/main/cpp/libzip/zip_rename.c
            src/main/cpp/libzip/zip_replace.c
            src/main/cpp/libzip/zip_set_archive_comment.c
            src/main/cpp/libzip/zip_set_archive_flag.c
            src/main/cpp/libzip/zip_set_file_comment.c
            src/main/cpp/libzip/zip_source_buffer.c
            src/main/cpp/libzip/zip_source_file.c
            src/main/cpp/libzip/zip_source_filep.c
            src/main/cpp/libzip/zip_source_free.c
            src/main/cpp/libzip/zip_source_function.c
            src/main/cpp/libzip/zip_source_zip.c
            src/main/cpp/libzip/zip_set_name.c
            src/main/cpp/libzip/zip_stat.c
            src/main/cpp/libzip/zip_stat_index.c
            src/main/cpp/libzip/zip_stat_init.c
            src/main/cpp/libzip/zip_strerror.c
            src/main/cpp/libzip/zip_unchange.c
            src/main/cpp/libzip/zip_unchange_all.c
            src/main/cpp/libzip/zip_unchange_archive.c
            src/main/cpp/libzip/zip_unchange_data.c
             )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because system libraries are included in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              z-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              z
              )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in the
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       zip

                       # Links the target library to the log library
                       # included in the NDK.
                       ${z-lib}
                       )