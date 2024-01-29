cmake_minimum_required(VERSION 3.10)

project(ipdumb CXX)
set(CMAKE_CXX_STANDARD 14)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(PROJECT_FILES ${SRC_DIR}/main.cpp
                  ${SRC_DIR}/network.h
                  ${SRC_DIR}/network.cpp
                  ${SRC_DIR}/tests.h
                  ${SRC_DIR}/tests.cpp
                  ${SRC_DIR}/sequence.h
                  ${SRC_DIR}/sequence.cpp
                  ${SRC_DIR}/command_line.h
    )

add_executable(ipdumb ${PROJECT_FILES})

target_include_directories(ipdumb PUBLIC ${SRC_DIR})

target_link_libraries(ipdumb pcap)