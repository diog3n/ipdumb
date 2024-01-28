#pragma once

/* Some macros used for debugging */
#define TEST_MESSAGE "(TEST)"
#define DEBUG_MESSAGE "(DEBUG)"

#define PRINT_VAL(val) std::cout << DEBUG_MESSAGE " " #val " = " \
                                 << (val) \
                                 << std::endl

#define PRINT_VAL_HEX(val) std::cout << std::hex \
                                     << DEBUG_MESSAGE " " #val " = " \
                                     << (val) \
                                     << std::dec \
                                     << std::endl

#define TEST_STREAM std::cerr << TEST_MESSAGE " "
#define DEBUG_STREAM std::cerr << DEBUG_MESSAGE " "

void TestIpAddress();

void TestHeaders();