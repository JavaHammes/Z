cmake_minimum_required(VERSION 3.28)

project("Z Anti-Anti-Debugger" VERSION 0.0.1 LANGUAGES C)

# -----------------------------------------------------------------------------
# Global Settings
# -----------------------------------------------------------------------------

# C Standard and global compile options
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Specify compiler and flags
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-Os")

# Global compile definitions and options
add_compile_definitions(_POSIX_C_SOURCE=200809L)
add_compile_options(-Wall -Wextra -pedantic)

# -----------------------------------------------------------------------------
# Directory Variables
# -----------------------------------------------------------------------------

set(SRC_DIR         "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR     "${CMAKE_SOURCE_DIR}/include")
set(LIB_DIR         "${CMAKE_SOURCE_DIR}/lib")
set(TESTS_DIR       "${CMAKE_SOURCE_DIR}/tests")
set(BIN_DIR         "${CMAKE_SOURCE_DIR}/bin")
set(MOCK_TARGET_DIR "${CMAKE_SOURCE_DIR}/mock_target")

# Ensure the binary directory exists
file(MAKE_DIRECTORY "${BIN_DIR}")

# -----------------------------------------------------------------------------
# External Dependencies (using pkg-config)
# -----------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)

# Capstone library
pkg_check_modules(CAPSTONE REQUIRED capstone)
if(CAPSTONE_FOUND)
    # Apply any extra flags provided by Capstone
    add_compile_definitions(${CAPSTONE_CFLAGS_OTHER})
else()
    message(FATAL_ERROR "Capstone library not found. Please install Capstone.")
endif()

# Criterion library (for testing)
pkg_check_modules(CRITERION REQUIRED criterion)
if(NOT CRITERION_FOUND)
    message(FATAL_ERROR "Criterion library not found. Please install Criterion.")
endif()

# -----------------------------------------------------------------------------
# Library Targets
# -----------------------------------------------------------------------------

# Main project library
add_library(z_lib STATIC
    "${SRC_DIR}/debugger.c"
    "${SRC_DIR}/debugger_commands.c"
    "${SRC_DIR}/debuggee.c"
    "${SRC_DIR}/breakpoint_handler.c"
    "${SRC_DIR}/symtab.c"
    "${SRC_DIR}/ui.c"
    "${SRC_DIR}/ld_preload.c"
)

target_include_directories(z_lib PUBLIC
    "${INCLUDE_DIR}"
    ${CAPSTONE_INCLUDE_DIRS}
    ${CRITERION_INCLUDE_DIRS}
)

target_link_libraries(z_lib PUBLIC
    ${CAPSTONE_LIBRARIES}
    ${CRITERION_LIBRARIES}
)

# Linenoise library (compiled without warnings)
add_library(linenoise STATIC
    "${LIB_DIR}/linenoise/linenoise.c"
)

target_include_directories(linenoise PUBLIC
    "${LIB_DIR}/linenoise"
)

target_link_libraries(z_lib PRIVATE linenoise)
set_source_files_properties("${LIB_DIR}/linenoise/linenoise.c"
    PROPERTIES COMPILE_FLAGS "-w"
)

# -----------------------------------------------------------------------------
# Executable Targets
# -----------------------------------------------------------------------------

# Main executable
add_executable(z "${SRC_DIR}/main.c")
target_link_libraries(z PRIVATE z_lib)
set_target_properties(z PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}")

# Test executable
add_executable(z_tests "${TESTS_DIR}/test_debugger.c")
target_include_directories(z_tests PRIVATE "${INCLUDE_DIR}")
target_link_libraries(z_tests PRIVATE z_lib criterion)

enable_testing()
add_test(NAME ZProjectTests COMMAND z_tests)

# Mock target executable
add_executable(mock_target "${MOCK_TARGET_DIR}/mock_target.c")
set_target_properties(mock_target PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}")

# -----------------------------------------------------------------------------
# Override Libraries
# -----------------------------------------------------------------------------

function(add_override_library name source)
    add_library(${name}_override SHARED "${LIB_DIR}/${source}.c")
    set_target_properties(${name}_override PROPERTIES
        OUTPUT_NAME              "${name}_intercept"
        LIBRARY_OUTPUT_DIRECTORY "${BIN_DIR}"
        RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}"
        POSITION_INDEPENDENT_CODE ON
    )
    target_link_libraries(${name}_override PRIVATE dl)
endfunction()

add_override_library(ptrace  ptrace_override)
add_override_library(fopen   fopen_override)
add_override_library(prctl   prctl_override)
add_override_library(getenv  getenv_override)

add_library(setvbuf_unbuffered SHARED "${LIB_DIR}/setvbuf_unbuffered.c")
set_target_properties(setvbuf_unbuffered PROPERTIES
    OUTPUT_NAME              "setvbuf_unbuffered"
    LIBRARY_OUTPUT_DIRECTORY "${BIN_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}"
    POSITION_INDEPENDENT_CODE ON
)
target_link_libraries(setvbuf_unbuffered PRIVATE dl)

# -----------------------------------------------------------------------------
# Code Quality Targets
# -----------------------------------------------------------------------------

find_program(LINTER clang-tidy-18)
find_program(FORMATTER clang-format-18)

add_custom_target(lint
    COMMAND ${LINTER} -p ${CMAKE_BINARY_DIR} --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy ${SRC_DIR}/*.c ${INCLUDE_DIR}/*.h ${TESTS_DIR}/*.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(format
    COMMAND find "${SRC_DIR}" -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find "${TESTS_DIR}" -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find "${INCLUDE_DIR}" -name "*.h" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find "${MOCK_TARGET_DIR}" -name "*.c" -exec ${FORMATTER} -style=file -i {} +
    COMMAND find "${LIB_DIR}" -maxdepth 1 -type f -exec ${FORMATTER} -style=file -i {} +
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}"
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${BIN_DIR}"
)
