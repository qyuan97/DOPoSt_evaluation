project(DPoSt)
cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 17)
set(INC_DIR /usr/local/include)
set(LINK_DIR /usr/local/lib)

find_package(OpenMP 4.5 REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})

include_directories(include tinymt64/include)

add_subdirectory(tests)
add_subdirectory(src)
add_subdirectory(tinymt64)