#[[==
  If running a nxserver and nxclient in the same process you need to link libnxclienet_local instead of
  nxclient. Only one client can run as a local client, the IPC mechanism will still be available
  for other clients
#==]]

set(TARGET NXServer)

option(WPEFRAMEWORK_PLUGIN_COMPOSITOR_HARDWAREREADY "Manual overrule of the time it takes to initialisize all hardware (s) [0 - UINT16_MAX]." 0)
option(WPEFRAMEWORK_PLUGIN_COMPOSITOR_BOXMODE "Allows for selecting a boxmode (Nexus only).")
option(WPEFRAMEWORK_PLUGIN_COMPOSITOR_GRAPHICS_HEAP_SIZE "Change graphic heap of driver (Nexus only).")

message("Setup WPEFramework${TARGET} v${VERSION}...")

find_package(Nexus REQUIRED)
find_package(NXServer REQUIRED)
find_package(Core REQUIRED)
find_package(Plugins REQUIRED)

add_library(${TARGET} SHARED
        NexusServerImplementation.cpp
        )

set(PUBLIC_HEADERS
        IPlatform.h
        )

target_link_libraries(${TARGET}
        PUBLIC
            NEXUS::NEXUS
            NEXUS::NXSERVER
            WPEFramework::Core
            WPEFramework::Plugins
        )

target_compile_definitions(${TARGET}
        INTERFACE
        USE_WPEFRAMEWORK_NXSERVER
        )

set_target_properties(${TARGET}
        PROPERTIES
            CXX_STANDARD 11
            CXX_STANDARD_REQUIRED YES
            FRAMEWORK FALSE
            PUBLIC_HEADER "${PUBLIC_HEADERS}" # specify the public headers
            VERSION ${VERSION}
            SOVERSION ${VERSION_MAJOR}
            OUTPUT_NAME WPEFramework${TARGET}
            POSITION_INDEPENDENT_CODE ON
        )

target_include_directories( ${TARGET}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

string(REPLACE ${NAMESPACE} "" TARGET_STRIPED ${TARGET})
add_library(${NAMESPACE}::${TARGET_STRIPED} ALIAS ${TARGET})

install(
        TARGETS ${TARGET}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
