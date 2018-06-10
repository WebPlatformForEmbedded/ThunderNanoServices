set(TARGET NexusCompositor)

message("Setting up ${TARGET} for Nexus platfrom")

find_package(Nexus REQUIRED)
find_package(Core REQUIRED)
find_package(Plugins REQUIRED)

add_library(${TARGET}
        Nexus.cpp
        )

target_link_libraries(${TARGET}
        PRIVATE
        NEXUS::NXCLIENT_LOCAL
        WPEFramework::Core
        WPEFramework::Plugins
        WPEFramework::NXServer
        )

set_target_properties(${TARGET}
        PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES
        FRAMEWORK FALSE
        VERSION ${VERSION}
        OUTPUT_NAME ${compositor_artefact}
        )

install(TARGETS ${TARGET}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/Compositor
        )
