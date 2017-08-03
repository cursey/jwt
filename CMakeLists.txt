cmake_minimum_required(VERSION 2.8)
project(jwt)

option(build_tests "Build tests (run as 'test' target)" ON)
option(shared_lib "Build as shared library" OFF)

# These flags are for binaries built by this particular CMake project (test_cppcodec, base64enc, etc.).
# In your own project that uses cppcodec, you might want to specify a different standard or error level.
if (MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -pedantic")
endif()

set(PUBLIC_HEADERS
    jwt/jwt.hpp
)

set(PRIVATE_SOURCES
    jwt/jwt.cpp
)

if (shared_lib)
    add_library(jwt OBJECT ${PUBLIC_HEADERS} ${PRIVATE_SOURCES}) 
else()
    add_library(jwt STATIC ${PUBLIC_HEADERS} ${PRIVATE_SOURCES})
endif()

set_target_properties(jwt PROPERTIES LINKER_LANGUAGE CXX)

if (build_tests)
    enable_testing()
    add_subdirectory(test)
endif()

foreach(h ${PUBLIC_HEADERS})
    get_filename_component(HEADER_INCLUDE_DIRECTORY include/${h} PATH) # use DIRECTORY instead of PATH once requiring CMake 3.0
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${h} DESTINATION ${HEADER_INCLUDE_DIRECTORY} COMPONENT "headers")
endforeach()