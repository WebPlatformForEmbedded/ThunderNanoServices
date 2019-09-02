
set(TARGET ${PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION_TARGET})

message("setting up ${TARGET}")

find_package(${NAMESPACE}Plugins REQUIRED)
find_package(${NAMESPACE}Definitions REQUIRED)

add_library(${TARGET} SHARED
    Module.cpp
    VideoPlaybackCheckerImpl.cpp
    prdy30_svp.cpp
    bpiff.c
    piff_parser.c
)

set_target_properties(${TARGET} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
)

target_link_libraries(${TARGET}
    PRIVATE
        ${NAMESPACE}Plugins::${NAMESPACE}Plugins
        ${NAMESPACE}Definitions::${NAMESPACE}Definitions
)

# NEXUS
# TODO: Think about when Nexus server is internal
find_package(NXCLIENT REQUIRED)
target_link_libraries(${TARGET}
    PRIVATE
    NXCLIENT::NXCLIENT)

# PLAYREADY
# TODO: What about Widevine?
# TODO: Fix BSTD_CPU (it's already in nexus_config.h)
find_package(NexusPlayready REQUIRED)

target_compile_definitions(${TARGET}
    PRIVATE
        BSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE
        USE_PK_NAMESPACES=1
        DRM_INCLUDE_PK_NAMESPACE_USING_STATEMENT=1
        DRM_BUILD_PROFILE=900
)

target_link_libraries(${TARGET}
    PRIVATE
        NexusPlayready::NexusPlayready
        playready30pk
)

# MAGIC DEFINES
target_compile_definitions(${TARGET}
    PRIVATE
        SAGE_ENABLE
        OLD_PLAYREADY_SERVER
)

# enable OCDM
option(PLUGIN_VIDEOPLAYBACKCHECKER_USE_OCDM "Use OCDM from Thunder" ON)
if(${PLUGIN_VIDEOPLAYBACKCHECKER_USE_OCDM})
    find_package(ocdm REQUIRED)

    target_compile_definitions(${TARGET}
    PRIVATE
    USE_OCDM)
    target_link_libraries(${TARGET}
    PRIVATE
    ocdm::ocdm)
endif()


install(TARGETS ${TARGET}
    DESTINATION lib/${STORAGE_DIRECTORY}/plugins)

# add -fpermissive due to goto error C desing
# TODO: get rid of it ;)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -fdiagnostics-color=always")


write_config(${PLUGIN_NAME})