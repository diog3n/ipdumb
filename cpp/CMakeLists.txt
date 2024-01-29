cmake_minimum_required(VERSION 3.10)

project(ipdumb CXX)
set(CMAKE_CXX_STANDARD 14)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB PCAP_HDR_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h 
                         ${CMAKE_CURRENT_SOURCE_DIR}/include/pcap/*.h)

set(PROJECT_FILES ${SRC_DIR}/main.cpp
                  ${SRC_DIR}/network.h
                  ${SRC_DIR}/network.cpp
                  ${SRC_DIR}/tests.h
                  ${SRC_DIR}/tests.cpp
                  ${SRC_DIR}/sequence.h
                  ${SRC_DIR}/sequence.cpp
                  ${SRC_DIR}/command_line.h
    )

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(ipdumb ${PROJECT_FILES} ${PCAP_HDR_FILES})

target_include_directories(ipdumb PUBLIC ${SRC_DIR})
target_include_directories(ipdumb PUBLIC ${INCLUDE_DIR})

target_link_libraries(ipdumb -L./lib/pcap/ libpcap.so)