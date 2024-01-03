cmake_minimum_required(VERSION 3.15.0)
get_filename_component(ProjectId ${CMAKE_CURRENT_SOURCE_DIR} NAME)
string(REPLACE " " "_" ProjectId ${ProjectId})

message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")

# Treat string as is, do not treat as variables to be expanded
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0079 NEW)   # target not created in current directory hack.

project(${ProjectId} VERSION 0.1.0)

# Enable CCache
# https://stackoverflow.com/a/64600661/19336104
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
endif()

#Set the default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Choose the type of build: None, Debug, Release, RelWithDebInfo, MinSizeRel"
        FORCE)
else()
    # Case-insensitive correction hack
    string(TOLOWER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_LOWER)
    if(CMAKE_BUILD_TYPE_LOWER STREQUAL "release")
        set(CMAKE_BUILD_TYPE "Release")
    elseif(CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
        set(CMAKE_BUILD_TYPE "Debug")
    elseif(CMAKE_BUILD_TYPE_LOWER STREQUAL "relwithdebinfo")
        set(CMAKE_BUILD_TYPE "RelWithDebInfo")
    elseif(CMAKE_BUILD_TYPE_LOWER STREQUAL "minsizerel")
        set(CMAKE_BUILD_TYPE "MinSizeRel")
    endif()
endif()

if(WIN32)
    add_compile_definitions(_WIN32)
endif()

if(${CMAKE_CXX_COMPILER_ID} MATCHES "Clang")
    add_compile_options(
        -Werror=return-type     # Clang by default does not file error when return type does not match function return
        -Wno-int-conversion
        -Wno-visibility
        -Wno-pragma-pack
        -Wno-microsoft-enum-forward-reference
        -Wno-sizeof-pointer-memaccess
    )

    # Windows LLVM/Clang does not use libstdc++ like the Clang/GCC counterpart,
    # Linux Clang counterpart does not require GCC as base
    if("${CMAKE_CXX_SIMULATE_ID}" MATCHES "MSVC")
        # Need to use quotes around CMAKE_CXX_SIMULATE_ID as not every configuration have this definition
        # https://blog.conan.io/2022/10/13/Different-flavors-Clang-compiler-Windows.html
        message(STATUS "LLVM/Clang outputs natvis debug information by default.")
    elseif(${CMAKE_BUILD_TYPE} MATCHES "Debug")
        # Clang workaround to emit string to libstdc++
        # https://stackoverflow.com/a/44727479/19336104
        message(STATUS "Clang does not output to libstdc++, enabling 'no-limit-debug-info'")
        add_compile_options(-fno-limit-debug-info)
    endif()
endif()

if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    # Debug mode have weird behaviors relocating symbols in static library if linked by shared library
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    if(NOT MSVC)
        # This is for compatibility with MSVC
        # CMake Tools uses "--config Debug" which doesn't have _DEBUG definition
        # this is added instead of explicitly adding -D_DEBUG when calling cmake
        # https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library?view=msvc-170
        add_compile_definitions(_DEBUG)
    endif()
elseif(${CMAKE_BUILD_TYPE} MATCHES "Release")
    if(NOT MSVC)
        # This is for compatibility with MSVC
        # CMake Tools uses "--config Debug" which doesn't have _DEBUG definition
        # this is added instead of explicitly adding -D_DEBUG when calling cmake
        # https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library?view=msvc-170
        add_compile_definitions(NDEBUG)
    endif()
endif()

if(MSVC)
    # add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

    # Remove default /W3 and /W4 by CMake MSVC
    # https://stackoverflow.com/a/58711983/19336104
    string(REGEX REPLACE "/W[3|4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REGEX REPLACE "  " " " CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REGEX REPLACE "/W[3|4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "  " " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin) # .exe for executable
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin) # .lib for linker
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin) # .dll for runtime load library

# Use C++17
set(CMAKE_CXX_STANDARD 17)

# Add phnt headers
file(GLOB DIR_LIST ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/phnt/*)
list(LENGTH DIR_LIST DIR_LEN)
if(DIR_LEN EQUAL 0)
    # phnt directory is empty
    message(STATUS "Initializing phnt submodule")
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} submodule update --init Dependencies/phnt
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE GIT_RETURN
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
    endif()

    if(NOT GIT_FOUND OR NOT ${GIT_RETURN} EQUAL 0)
        message(FATAL_ERROR "Failed to initialize phnt submodule!")
    endif()
endif()
include_directories(Dependencies/phnt)

# Link to Nt libraries
# Cannot use find_library
# Windows SDK will not be added to PATH if LLVM/Clang was set as compiler without calling vcvarsall.bat
link_libraries(ntdll)

# Executable
add_subdirectory(1.NtCreateUserProcess)
add_subdirectory(2.RtlCloneUserProcess)
add_subdirectory(3.CloneAndMinidump)
add_subdirectory(4.InspectClonedMemory)
add_subdirectory(5.Library)