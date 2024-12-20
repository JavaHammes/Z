cmake_minimum_required(VERSION 3.28)

project(
    "Z Anti-Anti-Debugger"
    VERSION 0.0.1
    LANGUAGES C)

set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(BIN_DIR "${CMAKE_SOURCE_DIR}/bin")
set(MOCK_TARGET_DIR "${CMAKE_SOURCE_DIR}/mock_target")

file(MAKE_DIRECTORY ${BIN_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_definitions(_POSIX_C_SOURCE=200809L)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS "-Wall -Wextra -pedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-Os")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

if(CAPSTONE_FOUND)
    add_compile_definitions(${CAPSTONE_CFLAGS_OTHER})
else()
    message(FATAL_ERROR "Capstone library not found. Please install Capstone.")
endif()

add_library(z_lib STATIC
    ${SRC_DIR}/debugger.c
    ${SRC_DIR}/debugger_commands.c
    ${SRC_DIR}/debuggee.c
    ${SRC_DIR}/breakpoint_handler.c
)

target_include_directories(z_lib PUBLIC
    ${INCLUDE_DIR}
    ${CAPSTONE_INCLUDE_DIRS}
)

target_link_libraries(z_lib PUBLIC
    ${CAPSTONE_LIBRARIES}
)

add_executable(z ${SRC_DIR}/main.c)
target_link_libraries(z PRIVATE z_lib)
set_target_properties(z PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)

if(CRITERION_FOUND)
    target_include_directories(z_lib PUBLIC ${CRITERION_INCLUDE_DIRS})
    target_link_libraries(z_lib PUBLIC ${CRITERION_LIBRARIES})

    add_executable(z_tests "${TESTS_DIR}/test_debugger.c")
    target_include_directories(z_tests PRIVATE ${INCLUDE_DIR})
    target_link_libraries(z_tests PRIVATE z_lib criterion)

    enable_testing()
    add_test(NAME ZProjectTests COMMAND z_tests)
else()
    message(FATAL_ERROR "Criterion library not found. Please install Criterion.")
endif()

add_executable(mock_target ${MOCK_TARGET_DIR}/mock_target.c)
set_target_properties(mock_target PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

find_program(LINTER clang-tidy-18)
find_program(FORMATTER clang-format-18)

add_custom_target(lint
    COMMAND ${LINTER} -p ${CMAKE_BINARY_DIR} --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy ${SRC_DIR}/*.c ${INCLUDE_DIR}/*.h ${TESTS_DIR}/*.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(format
    COMMAND find ${SRC_DIR} -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find ${TESTS_DIR} -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find ${INCLUDE_DIR} -name "*.h" -exec ${FORMATTER} -style=file -i {} +
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BIN_DIR}
)
