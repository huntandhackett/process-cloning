include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)

# Cannot use find_library as well
link_libraries(Dbghelp)

add_executable(CloneAndMinidump main.c CloneAndMinidump.rc)