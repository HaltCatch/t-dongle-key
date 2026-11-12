#pragma once

// ==========================================
// 屏幕配置参数 (Screen Configuration)
// ==========================================

// 屏幕自动休眠时间，单位：毫秒 (默认 300000 毫秒 = 5 分钟)
// Screen auto-sleep timeout in milliseconds
#define GUI_SCREEN_SLEEP_TIMEOUT_MS 150000

// 屏幕背光亮度，范围：0 - 255 (默认 255 = 最亮)
// 注意：如果亮度太低可能导致白天看不清。
// Screen backlight brightness from 0 to 255
#define GUI_BACKLIGHT_BRIGHTNESS 255

// 背后主板 RGB 氛围灯亮度，范围：0 - 15 (默认 2)
// APA102 RGB LED brightness from 0 to 15 (Max is 15)
#define GUI_APA102_BRIGHTNESS 2

// ==========================================
// 硬件监控显示模式 (Hardware Monitor Mode)
// ==========================================
// 0 = 显示 SD 卡容量 (例如 SD: 7G)
// 1 = 显示 CPU 状态 (例如 CPU:240M T:14)
#define GUI_MONITOR_DISPLAY_MODE 0
// 启动日志在真实组件就绪后结束，不增加固定显示等待。

// FIDO 认证请求最小显示时长，单位：毫秒 (防闪烁，默认 800 毫秒)
// Minimum display duration for FIDO request screen in milliseconds
#define GUI_FIDO_REQUEST_MIN_DUR_MS 800

// Keep a detected card command visible long enough to read it.
#define GUI_CARD_ACTIVITY_VISIBLE_MS 240

#define GUI_LCD_WIDTH 160
#define GUI_LCD_HEIGHT 80
