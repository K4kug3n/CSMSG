cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(include)

Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.0.1 # or a later release
)

FetchContent_MakeAvailable(Catch2)

file(GLOB CSMSG_SOURCES src/*.cpp)

project(CSMSG)
add_executable(CSMSG example/main.cpp)
target_sources(CSMSG PRIVATE ${CSMSG_SOURCES})
target_sources(CSMSG PRIVATE ${CSMSG_SOURCES})

file(GLOB TESTS_SOURCES tests/Curve.cpp)

project(tests)
add_executable(tests tests/main.cpp)
target_sources(tests PRIVATE ${TESTS_SOURCES})
target_sources(tests PRIVATE ${CSMSG_SOURCES})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)



