add_subdirectory(rust)
target_link_libraries(${PLUGIN_NAME} PRIVATE ${CRATE_NAME})