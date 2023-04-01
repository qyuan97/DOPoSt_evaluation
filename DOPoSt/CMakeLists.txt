cmake_minimum_required (VERSION 3.15)
project (Dynamic-PoSt)
set(NAME "Secure-DPoSt")
set (CMAKE_CXX_STANDARD 20)

add_subdirectory(extern/ABY)

# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,stack-size=8589934592")

SET(CMAKE_BUILD_TYPE "Debug")  
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")  
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

add_executable(dpost main.cpp dpost.cpp)
target_link_libraries(dpost ABY::aby ENCRYPTO_utils::encrypto_utils cryptopp)