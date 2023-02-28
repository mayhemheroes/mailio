# "inline" function to add mailio sources easily.
function(add_mailio_fuzz SOURCE_FILE)
    get_filename_component(file_name ${SOURCE_FILE} NAME_WE)
    add_executable(${file_name} ${SOURCE_FILE})
    target_link_libraries(${file_name} PUBLIC mailio ${CMAKE_THREAD_LIBS_INIT})
    target_compile_options(${file_name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${file_name} PRIVATE -fsanitize=fuzzer,address,undefined)
    install(TARGETS ${file_name} DESTINATION "${SHARE_INSTALL_DIR}/${PROJECT_NAME}/fuzz")
endfunction(add_mailio_fuzz)

# find all the example files.
file(GLOB fuzz_files ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# loop through each file and add the example
foreach (file_name ${fuzz_files})
    add_mailio_fuzz(${file_name})
endforeach (file_name ${fuzz_files})
