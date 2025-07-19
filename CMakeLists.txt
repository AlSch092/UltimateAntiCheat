cmake_minimum_required(VERSION 3.13)

project(UltimateAnticheat VERSION 1.0)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define the location of the splash.png in the project root
set(EXECUTABLE_NAME "UltimateAntiCheat.exe")

set(LIB_DIR "${CMAKE_SOURCE_DIR}/Libs")

# Collect all .cpp files from the base directory and subdirectories
file(GLOB_RECURSE SOURCES "*.cpp")

# Collect all .hpp, .h files from the base directory and subdirectories
file(GLOB_RECURSE HEADERS "*.h" "*.hpp")

# Collect resource files like .aps, .rc
file(GLOB_RECURSE RESOURCES  "*.aps"  "*.rc")

# Explicitly remove CMakeCXXCompilerId.cpp if it's in the list of sources
list(FILTER SOURCES EXCLUDE REGEX ".*CMakeCXXCompilerId.cpp$")

# Define the location of the splash.png in the project root
set(SPLASH_IMAGE "${CMAKE_SOURCE_DIR}/splash.png")

# Define the base output directory (e.g., the "bin" folder)
set(BASE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")

# Create the executable
add_executable(UltimateAnticheat ${SOURCES} ${HEADERS} ${RESOURCES})

# Add .asm files
target_sources(UltimateAnticheat PRIVATE
    "${CMAKE_SOURCE_DIR}/Obscure/ASMStubs.asm"
)

# Target windows version -> change this if you're on a different major version of windows
target_compile_definitions(UltimateAnticheat PRIVATE _WIN32_WINNT=0x0A00)

# Module name 
target_compile_definitions(UltimateAnticheat PUBLIC _MAIN_MODULE_NAME="${EXECUTABLE_NAME}")
target_compile_definitions(UltimateAnticheat PUBLIC _MAIN_MODULE_NAME_W=L"${EXECUTABLE_NAME}")


# Check for MSVC compiler and add MSVC-specific definitions
if(MSVC)
    target_compile_definitions(UltimateAnticheat PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(UltimateAnticheat PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

# Optionally, check for Clang and add Clang-specific definitions (if needed)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_definitions(UltimateAnticheat PRIVATE CLANG_COMPILER)
endif()

# Ensure output directories are set correctly for Debug, Release, etc.
set_target_properties(UltimateAnticheat PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${BASE_OUTPUT_DIR}/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${BASE_OUTPUT_DIR}/Release"
)

# Add a post-build step to copy splash.png after the build
add_custom_command(TARGET UltimateAnticheat POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${SPLASH_IMAGE} $<TARGET_FILE_DIR:UltimateAnticheat>/splash.png
    COMMENT "Copying splash.png to the build directory"
)

# Link to ntdll.lib
target_link_libraries(UltimateAnticheat PRIVATE ntdll.lib)

# Link to libraries in Libs folder
target_link_libraries(UltimateAnticheat PRIVATE
    "${LIB_DIR}/brotlicommon.lib"
    "${LIB_DIR}/brotlidec.lib"
    "${LIB_DIR}/brotlienc.lib"
    "$<$<CONFIG:Debug>:${LIB_DIR}/libcurl-d.lib>"
    "$<$<CONFIG:Release>:${LIB_DIR}/libcurl.lib>"
    "$<$<CONFIG:Debug>:${LIB_DIR}/zlibd.lib>"
    "$<$<CONFIG:Release>:${LIB_DIR}/zlib.lib>"
)

# Add the TSAWARE flag and linker options if using LLVM/Clang
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_link_options(UltimateAnticheat PRIVATE "/TSAWARE")
    target_link_options(UltimateAnticheat PRIVATE "/ALIGN:0x10000")
endif()

# Set Unicode character set (UNICODE _UNICODE)
target_compile_definitions(UltimateAnticheat PRIVATE UNICODE _UNICODE)

# Optional: If ntdll.lib is not in the default library search path,
# specify the full path to the library:
# target_link_libraries(UltimateAnticheat PRIVATE ${CMAKE_SOURCE_DIR}/path/to/ntdll.lib)

# Enable compiler warnings for MSVC
if(MSVC)
    target_compile_options(UltimateAnticheat PRIVATE /W3)  # Enable all warnings
endif()

# Define DEBUG_MODE for Debug builds
target_compile_definitions(UltimateAnticheat PRIVATE
    "$<$<CONFIG:Debug>:DEBUG_MODE>"
)

