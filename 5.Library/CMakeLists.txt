add_subdirectory(Library)

add_executable(example example.c)
target_link_libraries(example PUBLIC cloning)

# Hack: Possible bug, target_link_libraries didn't inherit include_directories
#       Haven't figure out what went wrong, cmake is already at latest 3.28.1...
get_target_property(INCLUDE_DIRECTORIES cloning INCLUDE_DIRECTORIES)
target_include_directories(example PUBLIC ${INCLUDE_DIRECTORIES})