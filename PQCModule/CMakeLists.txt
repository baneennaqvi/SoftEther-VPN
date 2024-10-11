cmake_minimum_required(VERSION 3.10)

# Set the project name
project(PQCModule)

# Set the path to the OQS library include directory
include_directories(
    G:/FYP/SoftEtherVPN/liboqs/build/include/oqs  # This includes the 'oqs' directory
)

# Set the sources
set(SOURCES
    PQCModule.c
    main.c  # Ensure main.c exists in the same directory as CMakeLists.txt
)

# Create the executable
add_executable(PQCModule ${SOURCES})
