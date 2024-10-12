cmake_minimum_required(VERSION 3.10)

project(PQCModule)

# Paths to liboqs include directory
set(INCLUDE_DIR G:/FYP/SoftEtherVPN/liboqs/build/include)

# Specify the library based on the build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(LIB_DIR G:/FYP/SoftEtherVPN/liboqs/build/lib/Debug)
    set(OQS_LIB ${LIB_DIR}/oqs.lib)
else()
    set(LIB_DIR G:/FYP/SoftEtherVPN/liboqs/build/lib/Release)
    set(OQS_LIB ${LIB_DIR}/oqs.lib)
endif()

# Source files
set(SOURCE_FILES main.c PQCModule.c)

# Executable target
add_executable(PQCModule ${SOURCE_FILES})

# Include directory for OQS headers
target_include_directories(PQCModule PRIVATE ${INCLUDE_DIR})

# Link the liboqs library
target_link_libraries(PQCModule PRIVATE ${OQS_LIB})
