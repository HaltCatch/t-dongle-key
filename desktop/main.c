#define _POSIX_C_SOURCE 200809L
#include <SDL2/SDL.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lvgl.h"
#include "gui_config.h"
#include "gui_platform.h"
#include "gui_controller.h"
#include "gui_screens.h"
#include "led.h"

extern int tdongle_protocol_main(void);
extern void emul_set_button(bool down);
extern bool is_req_button_pending(void);
extern void desktop_set_sd_fixture(bool mounted, bool error);
static SDL_Window *window;
static SDL_Renderer *renderer;
static SDL_Texture *texture;
static uint32_t pixels[GUI_LCD_WIDTH * GUI_LCD_HEIGHT];
static uint16_t draw_buffer[GUI_LCD_WIDTH * 40];
static gui_controller_t controller;
static bool button_down;
static bool button_release_pending;
static uint32_t button_pressed_tick;

void picokey_boot_message(const char *message) {
    fprintf(stderr, "BOOT: %s\n", message);
    if (!window) return;
    gui_platform_lock(100);
    gui_boot_log(message);
    lv_refr_now(NULL);
    gui_platform_unlock();
}

void picokey_boot_complete(void) {
    fprintf(stderr, "BOOT: Component startup complete\n");
    gui_boot_complete();
}

static void fail(const char *message) { fprintf(stderr, "%s: %s\n", message, SDL_GetError()); exit(1); }
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL: %s (line %d)\n", #condition, __LINE__); exit(1); } } while (0)

static void flush(lv_display_t *display, const lv_area_t *area, uint8_t *map) {
    const uint16_t *colors = (const uint16_t *)map;
    for (int y = area->y1; y <= area->y2; ++y) {
        for (int x = area->x1; x <= area->x2; ++x) {
            uint16_t rgb = *colors++;
            unsigned r = (rgb >> 11) & 31, g = (rgb >> 5) & 63, b = rgb & 31;
            pixels[y * GUI_LCD_WIDTH + x] = 0xff000000u |
                ((r << 3 | r >> 2) << 16) | ((g << 2 | g >> 4) << 8) | (b << 3 | b >> 2);
        }
    }
    lv_display_flush_ready(display);
}
static bool has_label(lv_obj_t *object, const char *text) {
    if (lv_obj_check_type(object, &lv_label_class) &&
        strcmp(lv_label_get_text(object), text) == 0) return true;
    for (uint32_t i = 0; i < lv_obj_get_child_cnt(object); ++i)
        if (has_label(lv_obj_get_child(object, i), text)) return true;
    return false;
}
static void check_label_layout(void) {
    lv_obj_t *screen = lv_screen_active();
    lv_obj_update_layout(screen);
    for (uint32_t i = 0; i < lv_obj_get_child_count(screen); ++i) {
        lv_obj_t *a = lv_obj_get_child(screen, i);
        if (!lv_obj_check_type(a, &lv_label_class) || !*lv_label_get_text(a)) continue;
        lv_area_t x;
        lv_obj_get_coords(a, &x);
        CHECK(x.x1 >= 0 && x.y1 >= 0 && x.x2 < GUI_LCD_WIDTH && x.y2 < GUI_LCD_HEIGHT);
        for (uint32_t j = i + 1; j < lv_obj_get_child_count(screen); ++j) {
            lv_obj_t *b = lv_obj_get_child(screen, j);
            if (!lv_obj_check_type(b, &lv_label_class) || !*lv_label_get_text(b)) continue;
            lv_area_t y;
            lv_obj_get_coords(b, &y);
            if (x.x1 <= y.x2 && y.x1 <= x.x2 && x.y1 <= y.y2 && y.y1 <= x.y2) {
                fprintf(stderr, "Overlapping labels: '%s' and '%s'\n", lv_label_get_text(a), lv_label_get_text(b));
                exit(1);
            }
        }
    }
}
static void check_animation_layout(void) {
    lv_obj_t *screen = lv_screen_active();
    lv_obj_update_layout(screen);
    lv_area_t visible[4];
    unsigned count = 0;
    for (uint32_t i = 0; i < lv_obj_get_child_count(screen); ++i) {
        lv_obj_t *sprite = lv_obj_get_child(screen, i);
        if (!lv_obj_check_type(sprite, &lv_image_class)) continue;
        lv_area_t a;
        lv_obj_get_coords(sprite, &a);
        CHECK(a.y1 >= 40 && a.y2 < GUI_LCD_HEIGHT);
        if (a.x2 < 0 || a.x1 >= GUI_LCD_WIDTH) continue; // Entering/leaving the screen is intentional.
        CHECK(count < sizeof(visible) / sizeof(*visible));
        for (unsigned j = 0; j < count; ++j)
            CHECK(a.x2 < visible[j].x1 || visible[j].x2 < a.x1);
        visible[count++] = a;
    }
    CHECK(count > 0);
}
static void present(void) {
    static uint32_t black[GUI_LCD_WIDTH * GUI_LCD_HEIGHT];
    SDL_UpdateTexture(texture, NULL, controller.asleep ? black : pixels, GUI_LCD_WIDTH * 4);
    SDL_RenderClear(renderer);
    SDL_RenderCopy(renderer, texture, NULL, NULL);
    SDL_RenderPresent(renderer);
}
static void snapshot(const char *directory, const char *name) {
    if (!directory) return;
    if (!controller.asleep) {
        lv_refr_now(NULL);
        check_label_layout();
    }
    char path[1024];
    CHECK(snprintf(path, sizeof(path), "%s/%s.bmp", directory, name) < (int)sizeof(path));
    uint32_t black[GUI_LCD_WIDTH * GUI_LCD_HEIGHT] = {0};
    SDL_Surface *surface = SDL_CreateRGBSurfaceWithFormatFrom(
        controller.asleep ? black : pixels, GUI_LCD_WIDTH, GUI_LCD_HEIGHT, 32,
        GUI_LCD_WIDTH * 4, SDL_PIXELFORMAT_ARGB8888);
    CHECK(surface && SDL_SaveBMP(surface, path) == 0);
    SDL_FreeSurface(surface);
}
static void step(uint32_t now, uint32_t mode, bool button, bool pending) {
    uint32_t delta = now - lv_tick_get();
    lv_tick_inc(delta);
    bool was_asleep = controller.asleep;
    gui_view_t previous_view = controller.view;
    gui_controller_step(&controller, now, mode, button, pending);
    lv_timer_handler();
    if (!controller.asleep && previous_view != controller.view) {
        // Match the device: publish the new frame immediately when the view changes.
        lv_refr_now(NULL);
    }
    present();
    if (was_asleep != controller.asleep) {
        fprintf(stderr, "GUI_PORT: Display %s\n", controller.asleep ? "asleep" : "awake");
    }
}
static int self_test(const char *directory, bool with_card) {
    CHECK(directory);
    CHECK(mkdir(directory, 0700) == 0 || access(directory, W_OK) == 0);
    step(40, MODE_MOUNTED, false, false);
    CHECK(controller.booting);
    snapshot(directory, "boot");
    step(5000, MODE_MOUNTED, false, false);
    CHECK(controller.booting); // Slow initialization must never claim USB ready.
    const char *lines[] = {"Device identity ready", "Device key ready", "Credential scan ready",
                          "Key storage ready", "USB stack ready", "Protocols ready"};
    for (unsigned i = 0; i < 6; ++i) gui_boot_log(lines[i]);
    step(5010, MODE_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "Device identity ready\nDevice key ready\nCredential scan ready\nKey storage ready\nUSB stack ready\nProtocols ready"));
    snapshot(directory, "boot-scroll");
    gui_boot_log("ERROR: storage upgrade");
    gui_boot_log("Protocols ready"); // A later message cannot hide the failure.
    gui_boot_complete();
    step(5020, MODE_BUTTON, true, true);
    CHECK(controller.booting && controller.view == GUI_VIEW_BOOT_ERROR);
    CHECK(gui_status(controller.view)->color == LED_COLOR_RED);
    snapshot(directory, "boot-error");
    gui_controller_init(&controller, 5020);
    gui_boot_complete();
    step(5030, MODE_MOUNTED, false, false);
    CHECK(!controller.booting && has_label(lv_scr_act(), "USB ready"));
    CHECK(has_label(lv_scr_act(), with_card ? "SD:128 G" : "SD:N/A"));
    snapshot(directory, "idle");
    uint32_t now = 5130;
    step(now, MODE_BUTTON, false, true);
    CHECK(has_label(lv_scr_act(), "Confirm request"));
    snapshot(directory, "fido");
    static uint32_t touch_frame[GUI_LCD_WIDTH * GUI_LCD_HEIGHT];
    memcpy(touch_frame, pixels, sizeof(pixels));
    step(now + 10, MODE_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "Request ended"));
    CHECK(has_label(lv_scr_act(), "Check the host"));
    CHECK(!has_label(lv_scr_act(), "Press button"));
    CHECK(memcmp(touch_frame, pixels, sizeof(pixels)) != 0);
    snapshot(directory, "request-ended");
    step(now + GUI_FIDO_REQUEST_MIN_DUR_MS, MODE_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "USB ready"));
    step(now + 900, MODE_PROCESSING, false, false);
    CHECK(has_label(lv_scr_act(), "Card activity"));
    CHECK(gui_status(controller.view)->color == LED_COLOR_BLUE);
    snapshot(directory, "ccid");
    step(now + 920, MODE_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "Card activity"));
    step(now + 900 + GUI_CARD_ACTIVITY_VISIBLE_MS, MODE_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "USB ready"));
    step(now + 1500, MODE_SUSPENDED, false, false);
    CHECK(has_label(lv_scr_act(), "USB suspended"));
    CHECK(gui_status(controller.view)->color == LED_COLOR_YELLOW);
    snapshot(directory, "usb-suspended");
    step(now + 1510, MODE_NOT_MOUNTED, false, false);
    CHECK(has_label(lv_scr_act(), "USB not ready"));
    CHECK(gui_status(controller.view)->color == LED_COLOR_RED);
    snapshot(directory, "usb-detached");
    step(now + 1520, MODE_MOUNTED, false, false);
    // Routine CCID polling must not prevent sleep.
    now += GUI_SCREEN_SLEEP_TIMEOUT_MS + 2000;
    step(now, MODE_PROCESSING, false, false);
    CHECK(controller.asleep);
    CHECK(!gui_led_lit(gui_status(controller.view), 0));
    snapshot(directory, "sleep");
    step(now + 10, MODE_MOUNTED, false, false);
    CHECK(controller.asleep);
    step(now + 20, MODE_BUTTON, false, true);
    CHECK(!controller.asleep && has_label(lv_scr_act(), "Confirm request"));
    CHECK(pixels[0] == 0xffad0000u);
    CHECK(memcmp(touch_frame, pixels, sizeof(pixels)) == 0);
    CHECK(has_label(lv_scr_act(), "Press button"));
    CHECK(gui_status(controller.view)->color == LED_COLOR_RED);
    CHECK(gui_led_lit(gui_status(controller.view), 0));
    CHECK(gui_led_lit(gui_status(controller.view), 399));
    CHECK(!gui_led_lit(gui_status(controller.view), 400));
    CHECK(!gui_led_lit(gui_status(controller.view), 799));
    CHECK(gui_led_lit(gui_status(controller.view), 800));
    snapshot(directory, "wake-fido");
    step(now + GUI_SCREEN_SLEEP_TIMEOUT_MS * 2, MODE_BUTTON, false, true);
    CHECK(!controller.asleep); // Never blank a pending physical confirmation.
    // Rapid transitions reuse objects, animations and timers, without leaks.
    now += GUI_SCREEN_SLEEP_TIMEOUT_MS * 2 + 1000;
    step(now, MODE_MOUNTED, false, false);
    size_t baseline;
    lv_mem_monitor_t memory;
    lv_mem_monitor(&memory);
    baseline = memory.free_size;
    for (int i = 0; i < 1000; ++i) {
        now += 1000;
        step(now, MODE_BUTTON, false, true);
        step(now + GUI_FIDO_REQUEST_MIN_DUR_MS, MODE_MOUNTED, true, false);
    }
    lv_mem_monitor(&memory);
    CHECK(memory.free_size + 1024 >= baseline);
    CHECK(has_label(lv_scr_act(), "USB ready"));
    snapshot(directory, "after-stress");
    now += GUI_SCREEN_SLEEP_TIMEOUT_MS + 1000;
    step(now, MODE_MOUNTED, false, false);
    CHECK(controller.asleep);
    step(now + 10, MODE_NOT_MOUNTED, false, false);
    CHECK(controller.asleep);
    step(now + 20, MODE_MOUNTED, false, false);
    CHECK(!controller.asleep && has_label(lv_scr_act(), "USB ready"));
    snapshot(directory, "wake-reconnect");
    if (with_card) {
        desktop_set_sd_fixture(true, true);
        step(now + 2030, MODE_MOUNTED, false, false);
        CHECK(has_label(lv_scr_act(), "SD:ERR"));
        CHECK(has_label(lv_scr_act(), "USB ready"));
        snapshot(directory, "card-error");
    }
    now += 3000;
    // Walk a complete horizontal animation cycle, including track wrap.
    for (unsigned i = 0; i < 200; ++i) {
        step(now += 50, MODE_MOUNTED, false, false);
        check_animation_layout();
    }
    gui_controller_init(&controller, now);
    step(now + 10, MODE_BUTTON, false, true);
    CHECK(controller.booting);
    gui_boot_complete();
    step(now + 20, MODE_BUTTON, false, true);
    CHECK(!controller.booting && has_label(lv_scr_act(), "Press button"));
    CHECK(memcmp(touch_frame, pixels, sizeof(pixels)) == 0);
    snapshot(directory, "request-during-boot");
    printf("PASS: shared GUI boot, anti-flicker, CCID timeout, sleep, wake, pending touch, 1000 transitions, animation cycle, layout, USB reconnect and SD status\n");
    return 0;
}
static void *protocol_thread(void *unused) {
    (void)unused;
    int result = tdongle_protocol_main();
    fprintf(stderr, "Protocol worker exited: %d\n", result);
    exit(result ? result : 1);
    return NULL;
}
static void prepare_state(const char *path) {
    CHECK(path && mkdir(path, 0700) == 0 ? true : path && access(path, W_OK) == 0);
    CHECK(chdir(path) == 0);
}
int main(int argc, char **argv) {
    bool headless = false, demo = false, testing = false, with_card = false;
    const char *directory = NULL, *state_dir = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--headless")) headless = true;
        else if (!strcmp(argv[i], "--demo")) demo = true;
        else if (!strcmp(argv[i], "--test-card")) with_card = true;
        else if (!strcmp(argv[i], "--self-test") && i + 1 < argc) { testing = true; directory = argv[++i]; }
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc) state_dir = argv[++i];
        else { fprintf(stderr, "Usage: %s [--demo | --headless | --self-test OUTPUT_DIR [--test-card]] [--state-dir DIR]\n", argv[0]); return 2; }
    }
    setenv("PICOKEYS_EMULATION_CCID_LISTEN", "1", 0);
    if (headless || (!demo && !testing)) {
        if (!state_dir) { fprintf(stderr, "Specify --state-dir for isolated simulator credentials\n"); return 2; }
        prepare_state(state_dir);
    }
    if (headless) return tdongle_protocol_main();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) fail("SDL init");
    window = SDL_CreateWindow("T-Dongle S3 simulator | metrics simulated | Space: button | Esc: quit",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, GUI_LCD_WIDTH * 5, GUI_LCD_HEIGHT * 5, 0);
    if (!window) fail("window");
    renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    if (!renderer) fail("renderer");
    SDL_RenderSetLogicalSize(renderer, GUI_LCD_WIDTH, GUI_LCD_HEIGHT);
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, GUI_LCD_WIDTH, GUI_LCD_HEIGHT);
    if (!texture) fail("texture");
    lv_init();
    lv_display_t *display = lv_display_create(GUI_LCD_WIDTH, GUI_LCD_HEIGHT);
    CHECK(display);
    lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
    lv_display_set_buffers(display, draw_buffer, NULL, sizeof(draw_buffer), LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(display, flush);
    CHECK(!with_card || testing);
    if (with_card) desktop_set_sd_fixture(true, false);
    gui_screens_init();
    gui_controller_init(&controller, 0);
    if (testing) return self_test(directory, with_card);
    if (!demo) { pthread_t worker; CHECK(pthread_create(&worker, NULL, protocol_thread, NULL) == 0); }
    else gui_boot_complete();
    uint32_t simulated_mode = MODE_MOUNTED, start = SDL_GetTicks();
    bool running = true;
    while (running) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) running = false;
            if (event.type == SDL_KEYUP && event.key.keysym.sym == SDLK_SPACE) {
                button_down = false;
                button_release_pending = true;
            }
            if (event.type == SDL_KEYDOWN && !event.key.repeat) {
                switch (event.key.keysym.sym) {
                case SDLK_ESCAPE: running = false; break;
                case SDLK_SPACE:
                    button_down = true;
                    button_release_pending = false;
                    button_pressed_tick = SDL_GetTicks();
                    emul_set_button(true);
                    break;
                case SDLK_f: if (demo) simulated_mode = MODE_BUTTON; break;
                case SDLK_c: if (demo) simulated_mode = MODE_PROCESSING; break;
                case SDLK_m: if (demo) simulated_mode = MODE_MOUNTED; break;
                case SDLK_n: if (demo) simulated_mode = MODE_NOT_MOUNTED; break;
                default: break;
                }
            }
        }
          /* SDL can deliver a short tap's down/up in one frame. Keep it visible
           * for three firmware button polls; held keys retain their duration. */
          if (button_release_pending && (uint32_t)(SDL_GetTicks() - button_pressed_tick) >= 30) {
              emul_set_button(false);
              button_release_pending = false;
          }
          gui_platform_lock(100);
        step(SDL_GetTicks() - start, demo ? simulated_mode : led_get_mode(),
            button_down, demo ? simulated_mode == MODE_BUTTON : is_req_button_pending());
        gui_platform_unlock();
        SDL_Delay(10);
    }
    SDL_Quit();
    return 0;
}
