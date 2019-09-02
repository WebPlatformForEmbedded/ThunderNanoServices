set(PLUGIN_NAME VideoPlaybackChecker)
set(MODULE_NAME ${NAMESPACE}${PLUGIN_NAME})

message("Setting up ${PLUGIN_NAME}")

# TODO: Set default value to None
set(PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION "NexusSVP" CACHE STRING "Defines which platform implementation should be used")
set(PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION_TARGET "${MODULE_NAME}${PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION}Impl")
set(PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION_LIB "lib${PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION_TARGET}.so")

find_package(${NAMESPACE}Plugins REQUIRED)
find_package(${NAMESPACE}Definitions REQUIRED)

add_library(${MODULE_NAME} SHARED
        Module.cpp
        VideoPlaybackChecker.cpp
        VideoPlaybackCheckerJsonRpc.cpp)

set_target_properties(${MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES)

target_link_libraries(${MODULE_NAME}
        PRIVATE
                ${NAMESPACE}Plugins::${NAMESPACE}Plugins
                ${NAMESPACE}Definitions::${NAMESPACE}Definitions)

install(TARGETS ${MODULE_NAME}
        DESTINATION lib/${STORAGE_DIRECTORY}/plugins)

if(${PLUGIN_VIDEPLAYBACKCHECKER_IMPLEMENTATION} STREQUAL "NexusSVP")
        add_subdirectory(Implementation/NexusSVP)
else()
        message(FATAL_ERROR "Missing VideoPlaybackChecker implementation")
endif()

write_config(${PLUGIN_NAME})
