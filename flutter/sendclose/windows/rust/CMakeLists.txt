
include(../../cmake/rust.cmake)

set_property(TARGET ${CRATE_NAME} PROPERTY IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/sendclose_flutter.dll")
set_property(TARGET ${CRATE_NAME} PROPERTY IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/sendclose_flutter.lib")