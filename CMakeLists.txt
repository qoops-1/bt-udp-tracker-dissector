# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

project("Bittorrent UDP Tracker Dissector" VERSION 0.0.1 DESCRIPTION "Wireshark Bittorrent UDP Tracker Dissector Plugin" LANGUAGES C)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(udp-bttracker MODULE packet-bt-udp-tracker.c)
target_link_libraries(udp-bttracker epan)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS udp-bttracker
	LIBRARY DESTINATION "3.6/epan" NAMELINK_SKIP
)
