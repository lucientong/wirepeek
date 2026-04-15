# FindPcap.cmake
# Find the libpcap library and headers.
#
# Defines:
#   Pcap_FOUND       - True if libpcap was found
#   Pcap_INCLUDE_DIR - Directory containing pcap.h
#   Pcap_LIBRARY     - Path to the pcap library
#   Pcap::Pcap       - Imported target for linking

find_path(Pcap_INCLUDE_DIR
  NAMES pcap.h pcap/pcap.h
  HINTS
    /usr/include
    /usr/local/include
    /opt/homebrew/include
)

# When building fully static binaries, prefer the static library.
if(BUILD_SHARED_LIBS OR NOT CMAKE_EXE_LINKER_FLAGS MATCHES "-static")
  find_library(Pcap_LIBRARY
    NAMES pcap
    HINTS
      /usr/lib
      /usr/local/lib
      /opt/homebrew/lib
  )
else()
  # Look for static library first, then fall back to any.
  find_library(Pcap_LIBRARY
    NAMES libpcap.a pcap
    HINTS
      /usr/lib
      /usr/local/lib
      /opt/homebrew/lib
  )
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Pcap
  REQUIRED_VARS Pcap_LIBRARY Pcap_INCLUDE_DIR
)

if(Pcap_FOUND AND NOT TARGET Pcap::Pcap)
  add_library(Pcap::Pcap UNKNOWN IMPORTED)
  set_target_properties(Pcap::Pcap PROPERTIES
    IMPORTED_LOCATION "${Pcap_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Pcap_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(Pcap_INCLUDE_DIR Pcap_LIBRARY)
