find_package(SDL2 REQUIRED)
set(LV_BUILD_CONF_PATH "${CMAKE_CURRENT_LIST_DIR}/lv_conf.h" CACHE STRING "Desktop LVGL config" FORCE)
set(CONFIG_LV_BUILD_EXAMPLES OFF CACHE BOOL "Do not build LVGL examples")
set(CONFIG_LV_BUILD_DEMOS OFF CACHE BOOL "Do not build LVGL demos")
add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/lvgl ${CMAKE_BINARY_DIR}/lvgl EXCLUDE_FROM_ALL)
target_sources(pico_fido2 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    ${CMAKE_CURRENT_LIST_DIR}/platform.c
    ${CMAKE_SOURCE_DIR}/src/fido2/gui/gui_screens.c
    ${CMAKE_SOURCE_DIR}/src/fido2/gui/gui_controller.c
    ${CMAKE_SOURCE_DIR}/src/fido2/gui/gui_anim.c
    ${CMAKE_SOURCE_DIR}/src/fido2/gui/gui_sprites.c)
target_include_directories(pico_fido2 PRIVATE ${CMAKE_SOURCE_DIR}/src/fido2/gui)
target_compile_definitions(pico_fido2 PRIVATE TDONGLE_DESKTOP=1)
target_link_libraries(pico_fido2 PRIVATE lvgl::lvgl SDL2::SDL2)
enable_testing()
add_test(NAME gui-behavior COMMAND pico_fido2 --self-test ${CMAKE_BINARY_DIR}/screenshots)
add_test(NAME gui-card-behavior COMMAND pico_fido2 --self-test ${CMAKE_BINARY_DIR}/screenshots-card --test-card)
set_tests_properties(gui-behavior gui-card-behavior PROPERTIES ENVIRONMENT "SDL_VIDEODRIVER=dummy")
