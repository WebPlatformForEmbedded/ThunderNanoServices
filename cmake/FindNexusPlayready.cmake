# - Try to find Broadcom Nexus Playready.
# Once done this will define
#  NexusPlayready_FOUND     - System has a Nexus Playready
#  NexusPlayready::NexusPlayready - The Nexus Playready library
#
# Copyright (C) 2019 Metrological B.V
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND ITS CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR ITS
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

find_path(LIBNexusPlayready_INCLUDE_DIR drmmanager.h
        PATH_SUFFIXES playready refsw)

find_path(LIBNexusSVP_INCLUDE_DIR b_secbuf.h
        PATH_SUFFIXES refsw)

list(APPEND LIBNexusPlayready_INCLUDE_DIRS ${LIBNexusPlayready_INCLUDE_DIR} ${LIBNexusSVP_INCLUDE_DIR})

# main lib
find_library(LIBNexusPlayready_LIBRARY playready30pk)

# needed libs
list(APPEND NeededLibs prdyhttp)

# needed svp libs
list(APPEND NeededLibs drmrootfs srai b_secbuf)

foreach (_library ${NeededLibs})
    find_library(LIBRARY_${_library} ${_library})
    if(NOT EXISTS "${LIBRARY_${_library}}")
        message(SEND_ERROR "Could not find mandatory library: ${_library}")
    endif()
    list(APPEND LIBNexusPlayready_LIBRARIES ${LIBRARY_${_library}})
endforeach ()


if(EXISTS "${LIBNexusPlayready_LIBRARY}")
    include(FindPackageHandleStandardArgs)

    set(NexusPlayready_FOUND TRUE)

    find_package_handle_standard_args(LIBNexusPlayready DEFAULT_MSG LIBNEXUS_INCLUDE LIBNexusPlayready_LIBRARY)
    mark_as_advanced(LIBNexusPlayready_LIBRARY)

    if(NOT TARGET NexusPlayready::NexusPlayready)
        add_library(NexusPlayready::NexusPlayready UNKNOWN IMPORTED)
        
        set_target_properties(NexusPlayready::NexusPlayready PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LIBNexusPlayready_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNexusPlayready_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIBNexusPlayready_LIBRARIES}"
                )
    endif()
endif()