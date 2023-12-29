cmake_minimum_required(VERSION 3.13)

project(elliptic-hmac-cpp VERSION 0.0.0 LANGUAGES C CXX)

add_subdirectory(secp256k1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(elliptic main.cpp)
target_link_libraries(elliptic secp256k1)
target_include_directories(elliptic PRIVATE "secp256k1")
target_compile_options(elliptic PRIVATE "-fpermissive")

