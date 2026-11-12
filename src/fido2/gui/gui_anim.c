#include "gui_anim.h"
#include <stdlib.h>

extern const lv_img_dsc_t img_gcat_0, img_gcat_1, img_gcat_2, img_gcat_3, img_gcat_4, img_gcat_5, img_gcat_6, img_gcat_7, img_gcat_8, img_gcat_9;
extern const lv_img_dsc_t img_dino_0, img_dino_1, img_dino_2, img_dino_3, img_dino_4, img_dino_5, img_dino_6;
extern const lv_img_dsc_t img_deer_0, img_deer_1, img_deer_2, img_deer_3, img_deer_4;
extern const lv_img_dsc_t img_duck_0, img_duck_1, img_duck_2, img_duck_3, img_duck_4;

static const lv_img_dsc_t* gcat_frames[] = {&img_gcat_0, &img_gcat_1, &img_gcat_2, &img_gcat_3, &img_gcat_4, &img_gcat_5, &img_gcat_6, &img_gcat_7, &img_gcat_8, &img_gcat_9};
static const lv_img_dsc_t* dino_frames[] = {&img_dino_0, &img_dino_1, &img_dino_2, &img_dino_3, &img_dino_4, &img_dino_5, &img_dino_6};
static const lv_img_dsc_t* deer_frames[] = {&img_deer_0, &img_deer_1, &img_deer_2, &img_deer_3, &img_deer_4};
static const lv_img_dsc_t* duck_frames[] = {&img_duck_0, &img_duck_1, &img_duck_2, &img_duck_3, &img_duck_4};

static lv_obj_t *obj_gcat = NULL;
static lv_obj_t *obj_dino = NULL;
static lv_obj_t *obj_deer = NULL;
static lv_obj_t *obj_duck = NULL;

static lv_timer_t *anim_timer = NULL;

static int offset_x = 0;
static int ticks = 0;

#define TRACK_LEN 400

static void anim_timer_cb(lv_timer_t *timer) {
    // All four objects are created together in gui_anim_start() and are never
    // deleted, so they are either all NULL (not started yet) or all valid.
    if (!obj_gcat || !obj_dino || !obj_deer || !obj_duck) {
        return;
    }

    ticks++;

    // Animate frames (update every 2 ticks = 100ms per frame)
    lv_img_set_src(obj_gcat, gcat_frames[(ticks / 2) % 10]);
    lv_img_set_src(obj_dino, dino_frames[(ticks / 2) % 7]);
    lv_img_set_src(obj_deer, deer_frames[(ticks / 2) % 5]);
    lv_img_set_src(obj_duck, duck_frames[(ticks / 2) % 5]);
    
    // Move continuously
    offset_x += 2;
    if (offset_x >= TRACK_LEN) offset_x = 0;
    
    // Distribute the 4 animals along the 400px track to prevent overlapping
    // Screen is 160px wide, so subtract 120 so they enter from the left side smoothly.
    int gcat_x = (offset_x + 0) % TRACK_LEN - 120;
    int dino_x = (offset_x + 115) % TRACK_LEN - 120;
    int deer_x = (offset_x + 190) % TRACK_LEN - 120;
    int duck_x = (offset_x + 330) % TRACK_LEN - 120;
    
    // All images are 36px high. Screen is 80px high. 
    // Move them down closer to the bottom (e.g. 80 - 36 - 4 = 40).
    int y_pos = 40;
    
    lv_obj_set_pos(obj_gcat, gcat_x, y_pos);
    lv_obj_set_pos(obj_dino, dino_x, y_pos);
    lv_obj_set_pos(obj_deer, deer_x, y_pos);
    lv_obj_set_pos(obj_duck, duck_x, y_pos);
}

void gui_anim_start(lv_obj_t *parent) {
    if (obj_gcat) {
        if (!anim_timer) {
            // Resuming after gui_anim_stop(): restart from the track origin so the
            // animals do not jump from a stale offset when the screen wakes up.
            offset_x = 0;
            ticks = 0;
            anim_timer_cb(NULL);
            anim_timer_cb(NULL);
            anim_timer = lv_timer_create(anim_timer_cb, 50, NULL);
        }
        return;
    }
    
    obj_gcat = lv_img_create(parent);
    lv_img_set_src(obj_gcat, &img_gcat_0);
    
    obj_dino = lv_img_create(parent);
    lv_img_set_src(obj_dino, &img_dino_0);
    
    obj_deer = lv_img_create(parent);
    lv_img_set_src(obj_deer, &img_deer_0);
    
    obj_duck = lv_img_create(parent);
    lv_img_set_src(obj_duck, &img_duck_0);
    
    offset_x = 0;
    ticks = 0;
    
    anim_timer_cb(NULL);
    anim_timer_cb(NULL);
    anim_timer = lv_timer_create(anim_timer_cb, 50, NULL);
}

void gui_anim_stop(void) {
    if (anim_timer) {
        lv_timer_del(anim_timer);
        anim_timer = NULL;
    }
    // We intentionally DO NOT delete the image objects here.
    // Repeatedly creating and deleting LVGL objects can cause heap fragmentation 
    // and OOM crashes, especially when the host (like ykman) rapidly switches states.
}
