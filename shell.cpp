#include <stddef.h>
#include <stdint.h>

struct Time {
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
};

extern "C" {
void put_pixel(int x, int y, uint32_t color);
void memset(void *ptr, uint8_t value, uint32_t size);
void memcpy(void *dest, const void *src, uint32_t size);
uint8_t get_keyboard_input_nonblock();
Time get_time();
uint32_t get_total_ram_mb();
void string_copy(char *dest, const char *src);
int string_length(const char *str);
int get_shell_file_count();
void get_shell_file_name(int index, char *out);
uint32_t get_shell_file_size(int index);
bool get_shell_file_is_dir(int index);
void shell_refresh_files();
bool shell_is_fs_mounted();
}

extern int mouse_x;
extern int mouse_y;
extern bool mouse_left;

struct Graphics {
  uint32_t *framebuffer;
  uint32_t width;
  uint32_t height;
  uint32_t pitch;
  bool active;
};

extern Graphics screen;

extern uint8_t _binary_fds_raw_start[];
extern uint8_t _binary_edit_raw_start[];
extern uint8_t _binary_folder_raw_start[];
extern uint8_t _binary_calc_raw_start[];
extern uint8_t _binary_off_raw_start[];
extern uint8_t _binary_logo1_raw_start[];
extern uint8_t _binary_logo2_raw_start[];

// Alpha blending: (src * alpha + dest * (255 - alpha)) / 255
uint32_t blend(uint32_t src, uint32_t dest, uint8_t alpha) {
  uint32_t rb = (src & 0xFF00FF) * alpha + (dest & 0xFF00FF) * (256 - alpha);
  uint32_t g = (src & 0x00FF00) * alpha + (dest & 0x00FF00) * (256 - alpha);
  return ((rb >> 8) & 0xFF00FF) | ((g >> 8) & 0x00FF00);
}

void draw_rect_alpha(int x, int y, int w, int h, uint32_t color,
                     uint8_t alpha) {
  for (int i = y; i < y + h; i++) {
    for (int j = x; j < x + w; j++) {
      if (j < 0 || (uint32_t)j >= screen.width || i < 0 ||
          (uint32_t)i >= screen.height)
        continue;
      if (alpha == 255) {
        put_pixel(j, i, color);
      } else {
        uint32_t dest = screen.framebuffer[i * (screen.pitch / 4) + j];
        put_pixel(j, i, blend(color, dest, alpha));
      }
    }
  }
}

// Simple 8x8 font
uint8_t font8x8_basic[128][8] = {0};

void init_minimal_font() {
  // Very basic 8x8 bitmap font data for the used strings
  struct CharDef {
    char c;
    uint8_t data[8];
  };
  CharDef chars[] = {{'A', {0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00}},
                     {'B', {0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00}},
                     {'C', {0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00}},
                     {'D', {0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00}},
                     {'E', {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00}},
                     {'F', {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00}},
                     {'G', {0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00}},
                     {'H', {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00}},
                     {'I', {0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00}},
                     {'L', {0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00}},
                     {'M', {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00}},
                     {'N', {0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00}},
                     {'O', {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}},
                     {'P', {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00}},
                     {'R', {0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00}},
                     {'S', {0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00}},
                     {'T', {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
                     {'U', {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}},
                     {'W', {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00}},
                     {'X', {0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00}},
                     {'Y', {0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00}},
                     {'a', {0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00}},
                     {'b', {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00}},
                     {'c', {0x00, 0x00, 0x3C, 0x60, 0x60, 0x66, 0x3C, 0x00}},
                     {'d', {0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00}},
                     {'e', {0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00}},
                     {'f', {0x1C, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x30, 0x00}},
                     {'g', {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C}},
                     {'i', {0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
                     {'l', {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x1C, 0x00}},
                     {'m', {0x00, 0x00, 0x76, 0x7F, 0x6B, 0x6B, 0x6B, 0x00}},
                     {'n', {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00}},
                     {'o', {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00}},
                     {'p', {0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60}},
                     {'r', {0x00, 0x00, 0x3E, 0x60, 0x60, 0x60, 0x60, 0x00}},
                     {'s', {0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00}},
                     {'t', {0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00}},
                     {'u', {0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00}},
                     {'v', {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00}},
                     {'w', {0x00, 0x00, 0x63, 0x6B, 0x7F, 0x3E, 0x36, 0x00}},
                     {'x', {0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00}},
                     {'y', {0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C}},
                     {'0', {0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00}},
                     {'1', {0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00}},
                     {'2', {0x3C, 0x66, 0x06, 0x0C, 0x30, 0x60, 0x7E, 0x00}},
                     {'3', {0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00}},
                     {'4', {0x06, 0x0E, 0x1E, 0x36, 0x7F, 0x06, 0x06, 0x00}},
                     {'5', {0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00}},
                     {'6', {0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00}},
                     {'7', {0x7E, 0x66, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x00}},
                     {'8', {0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00}},
                     {'9', {0x3C, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00}},
                     {'.', {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00}},
                     {':', {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00}},
                     {' ', {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
                     {'-', {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00}},
                     {'(', {0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00}},
                     {')', {0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00}},
                     {'@', {0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x66, 0x3C, 0x00}},
                     {',', {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30}},
                     {'+', {0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00}},
                     {'K', {0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00}},
                     {'J', {0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00}},
                     {'Q', {0x3C, 0x66, 0x66, 0x66, 0x6A, 0x3C, 0x06, 0x00}},
                     {'V', {0x66, 0x66, 0x66, 0x66, 0x3C, 0x3C, 0x18, 0x00}},
                     {'Z', {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00}},
                     {'h', {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00}},
                     {'k', {0x60, 0x60, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x00}},
                     {'j', {0x06, 0x00, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00}},
                     {'z', {0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00}},
                     {'/', {0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00, 0x00}},
                     {'_', {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00}},
                     {'>', {0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00}},
                     {'<', {0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00}},
                     {'|', {0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
                     {'*', {0x00, 0x00, 0x14, 0x08, 0x3E, 0x08, 0x14, 0x00}},
                     {'=', {0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00}}};
  for (unsigned i = 0; i < sizeof(chars) / sizeof(chars[0]); i++) {
    for (int j = 0; j < 8; j++)
      font8x8_basic[(uint8_t)chars[i].c][j] = chars[i].data[j];
  }
}

void draw_char(int x, int y, char c, uint32_t color) {
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      if (font8x8_basic[(uint8_t)c][i] & (1 << (7 - j))) {
        put_pixel(x + j, y + i, color);
      }
    }
  }
}

void draw_string(int x, int y, const char *str, uint32_t color) {
  while (*str) {
    draw_char(x, y, *str, color);
    x += 8;
    str++;
  }
}

void draw_image(int x, int y, int w, int h, uint8_t *data) {
  uint32_t *pixels = (uint32_t *)data;
  for (int i = 0; i < h; i++) {
    for (int j = 0; j < w; j++) {
      if (x + j >= (int)screen.width || y + i >= (int)screen.height ||
          x + j < 0 || y + i < 0)
        continue;
      uint32_t col = pixels[i * w + j];
      uint8_t r = col & 0xFF;
      uint8_t g = (col >> 8) & 0xFF;
      uint8_t b = (col >> 16) & 0xFF;
      uint8_t a = (col >> 24) & 0xFF;
      if (a > 128)
        put_pixel(x + j, y + i, (r << 16) | (g << 8) | b);
    }
  }
}

void draw_image_scaled(int x, int y, int w, int h, uint8_t *data, int src_w,
                       int src_h) {
  uint32_t *pixels = (uint32_t *)data;
  for (int i = 0; i < h; i++) {
    for (int j = 0; j < w; j++) {
      if (x + j >= (int)screen.width || y + i >= (int)screen.height ||
          x + j < 0 || y + i < 0)
        continue;
      int src_x = (j * src_w) / w;
      int src_y = (i * src_h) / h;
      uint32_t col = pixels[src_y * src_w + src_x];
      uint8_t r = col & 0xFF;
      uint8_t g = (col >> 8) & 0xFF;
      uint8_t b = (col >> 16) & 0xFF;
      uint8_t a = (col >> 24) & 0xFF;
      if (a > 128)
        put_pixel(x + j, y + i, (r << 16) | (g << 8) | b);
    }
  }
}

void draw_wallpaper() {
  uint32_t *wallpaper = (uint32_t *)_binary_fds_raw_start;
  for (uint32_t y = 0; y < screen.height; y++) {
    for (uint32_t x = 0; x < screen.width; x++) {
      uint32_t col = wallpaper[y * screen.width + x];
      uint8_t r = col & 0xFF;
      uint8_t g = (col >> 8) & 0xFF;
      uint8_t b = (col >> 16) & 0xFF;
      put_pixel(x, y, (r << 16) | (g << 8) | b);
    }
  }
}

uint32_t mouse_bg[11][11];
int last_mouse_x = -1;
int last_mouse_y = -1;

void save_mouse_bg(int cx, int cy) {
  for (int i = -5; i <= 5; i++) {
    for (int j = -5; j <= 5; j++) {
      int px = cx + j;
      int py = cy + i;
      if (px >= 0 && (uint32_t)px < screen.width && py >= 0 &&
          (uint32_t)py < screen.height) {
        mouse_bg[i + 5][j + 5] =
            screen.framebuffer[py * (screen.pitch / 4) + px];
      }
    }
  }
}

void restore_mouse_bg(int cx, int cy) {
  if (cx == -1 || cy == -1)
    return;
  for (int i = -5; i <= 5; i++) {
    for (int j = -5; j <= 5; j++) {
      int px = cx + j;
      int py = cy + i;
      if (px >= 0 && (uint32_t)px < screen.width && py >= 0 &&
          (uint32_t)py < screen.height) {
        screen.framebuffer[py * (screen.pitch / 4) + px] =
            mouse_bg[i + 5][j + 5];
      }
    }
  }
}

void draw_mouse() {
  for (int i = -5; i <= 5; i++) {
    put_pixel(mouse_x + i, mouse_y, 0xFFFFFF);
    put_pixel(mouse_x, mouse_y + i, 0xFFFFFF);
  }
}

void uint_to_string(uint32_t value, char *str) {
  if (value == 0) {
    str[0] = '0';
    str[1] = '\0';
    return;
  }
  char buf[16];
  int i = 0;
  while (value > 0) {
    buf[i++] = '0' + (value % 10);
    value /= 10;
  }
  int j = 0;
  while (i > 0) {
    str[j++] = buf[--i];
  }
  str[j] = '\0';
}

void draw_top_bar() {
  draw_rect_alpha(0, 0, screen.width, 25, 0x000000, 160);

  // Red menu button - top right
  int btn_x = screen.width - 70;
  draw_rect_alpha(btn_x, 2, 60, 21, 0xCC2222, 230);
  draw_string(btn_x + 10, 8, "Menu", 0xFFFFFF);

  uint32_t ram = get_total_ram_mb();
  Time t = get_time();

  char bar_text[40];
  string_copy(bar_text, "RAM: ");
  char ram_str[10];
  uint_to_string(ram, ram_str);
  string_copy(bar_text + 5, ram_str);
  int len = string_length(bar_text);
  string_copy(bar_text + len, "MB   ");
  len = string_length(bar_text);

  bar_text[len++] = '0' + (t.hour / 10);
  bar_text[len++] = '0' + (t.hour % 10);
  bar_text[len++] = ':';
  bar_text[len++] = '0' + (t.minute / 10);
  bar_text[len++] = '0' + (t.minute % 10);
  bar_text[len++] = ':';
  bar_text[len++] = '0' + (t.second / 10);
  bar_text[len++] = '0' + (t.second % 10);
  bar_text[len] = '\0';

  draw_string(10, 8, bar_text, 0xDDDDDD);
}

void draw_window(int x, int y, int w, int h, const char *title, bool active) {
  draw_rect_alpha(x + 4, y + 4, w, h, 0x000000, 80); // Shadow
  draw_rect_alpha(x, y, w, h, 0xEEEEEE, 250);
  draw_rect_alpha(x, y, w, 28, active ? 0x005A9E : 0x777777, 255);
  draw_string(x + 10, y + 10, title, 0xFFFFFF);
  draw_string(x + w - 40, y + 10, "- x", 0xFFFFFF);
}

// ============================================================================
// FILE MANAGER WINDOW
// ============================================================================

void size_to_string(uint32_t size, char *out) {
  if (size == 0) {
    out[0] = '0';
    out[1] = ' ';
    out[2] = 'B';
    out[3] = '\0';
    return;
  }
  // Show in B, KB, or MB
  const char *suffix = "B";
  uint32_t display = size;
  if (size >= 1024 * 1024) {
    display = size / (1024 * 1024);
    suffix = "MB";
  } else if (size >= 1024) {
    display = size / 1024;
    suffix = "KB";
  }
  // Convert number to string
  char tmp[12];
  int len = 0;
  uint32_t n = display;
  if (n == 0) {
    tmp[len++] = '0';
  } else {
    while (n > 0) {
      tmp[len++] = '0' + (n % 10);
      n /= 10;
    }
  }
  int pos = 0;
  for (int i = len - 1; i >= 0; i--)
    out[pos++] = tmp[i];
  out[pos++] = ' ';
  for (int i = 0; suffix[i]; i++)
    out[pos++] = suffix[i];
  out[pos] = '\0';
}

void draw_file_manager_content(int x, int y, int w, int h, int selected,
                               int scroll_offset) {
  // Background area below title bar
  int content_y = y + 28;
  int content_h = h - 28;

  // Header bar
  draw_rect_alpha(x, content_y, w, 20, 0xDDDDDD, 255);
  draw_string(x + 10, content_y + 6, "Name", 0x333333);
  draw_string(x + w / 2, content_y + 6, "Size", 0x333333);
  draw_string(x + w - 80, content_y + 6, "Type", 0x333333);

  // Separator line
  draw_rect_alpha(x, content_y + 20, w, 1, 0xBBBBBB, 255);

  int row_height = 20;
  int list_y = content_y + 22;
  int max_visible = (content_h - 24) / row_height;

  if (!shell_is_fs_mounted()) {
    draw_string(x + 20, list_y + 20, "No filesystem mounted.", 0x999999);
    return;
  }

  int count = get_shell_file_count();
  if (count == 0) {
    draw_string(x + 20, list_y + 20, "No files found.", 0x999999);
    return;
  }

  for (int i = 0; i < max_visible && (i + scroll_offset) < count; i++) {
    int file_idx = i + scroll_offset;
    bool is_selected = (file_idx == selected);

    // Row background
    uint32_t row_bg =
        is_selected ? 0x005A9E : ((file_idx % 2 == 0) ? 0xF5F5F5 : 0xEEEEEE);
    uint32_t text_color = is_selected ? 0xFFFFFF : 0x333333;
    draw_rect_alpha(x + 1, list_y + i * row_height, w - 2, row_height, row_bg,
                    is_selected ? 255 : 240);

    // File name
    char name[16];
    get_shell_file_name(file_idx, name);
    draw_string(x + 10, list_y + i * row_height + 6, name, text_color);

    // File size
    if (!get_shell_file_is_dir(file_idx)) {
      char size_str[16];
      size_to_string(get_shell_file_size(file_idx), size_str);
      draw_string(x + w / 2, list_y + i * row_height + 6, size_str, text_color);
    }

    // Type
    draw_string(x + w - 80, list_y + i * row_height + 6,
                get_shell_file_is_dir(file_idx) ? "DIR" : "FILE", text_color);
  }

  // Scroll indicator
  if (count > max_visible) {
    int bar_h = content_h - 24;
    int thumb_h = (max_visible * bar_h) / count;
    if (thumb_h < 10)
      thumb_h = 10;
    int thumb_y =
        list_y + (scroll_offset * (bar_h - thumb_h)) / (count - max_visible);
    draw_rect_alpha(x + w - 6, list_y, 4, bar_h, 0xCCCCCC, 200);
    draw_rect_alpha(x + w - 6, thumb_y, 4, thumb_h, 0x888888, 255);
  }
}

// ============================================================================
// CALCULATOR WINDOW
// ============================================================================

struct CalcState {
  char display[16];
  int first_val;
  char last_op;
  bool next_clears;
};

void draw_calculator_content(int x, int y, int w, int h, CalcState &cs) {
  int cy = y + 28;
  // Display area
  draw_rect_alpha(x + 10, cy + 10, w - 20, 30, 0xFFFFFF, 255);
  draw_rect_alpha(x + 10, cy + 10, w - 20, 1, 0x999999, 255); // Top border
  draw_rect_alpha(x + 10, cy + 10, 1, 30, 0x999999, 255);     // Left border

  draw_string(x + 20, cy + 20, cs.display, 0x000000);

  const char *btns[4][4] = {{"7", "8", "9", "/"},
                            {"4", "5", "6", "*"},
                            {"1", "2", "3", "-"},
                            {"C", "0", "=", "+"}};

  int bx = x + 10;
  int by = cy + 50;
  int bw = (w - 30) / 4;
  int bh = (h - 28 - 60) / 4;

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      int cur_x = bx + j * (bw + 3);
      int cur_y = by + i * (bh + 3);

      // Hover effect
      bool hover = (mouse_x >= cur_x && mouse_x < cur_x + bw &&
                    mouse_y >= cur_y && mouse_y < cur_y + bh);
      uint32_t btn_col = hover ? 0xDDDDDD : 0xCCCCCC;
      if (btns[i][j][0] == '=' || btns[i][j][0] == '+' ||
          btns[i][j][0] == '-' || btns[i][j][0] == '*' ||
          btns[i][j][0] == '/') {
        btn_col = hover ? 0x0078D7 : 0x005A9E;
      } else if (btns[i][j][0] == 'C') {
        btn_col = hover ? 0xEE3333 : 0xCC2222;
      }

      draw_rect_alpha(cur_x, cur_y, bw, bh, btn_col, 255);
      draw_string(cur_x + (bw / 2) - 4, cur_y + (bh / 2) - 4, btns[i][j],
                  (btn_col == 0xCCCCCC || btn_col == 0xDDDDDD) ? 0x000000
                                                               : 0xFFFFFF);
    }
  }
}

void handle_calculator_click(CalcState &cs, int x, int y, int w, int h) {
  int cy = y + 28;
  int bx = x + 10;
  int by = cy + 50;
  int bw = (w - 30) / 4;
  int bh = (h - 28 - 60) / 4;

  const char *btns[4][4] = {{"7", "8", "9", "/"},
                            {"4", "5", "6", "*"},
                            {"1", "2", "3", "-"},
                            {"C", "0", "=", "+"}};

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      int cur_x = bx + j * (bw + 3);
      int cur_y = by + i * (bh + 3);

      if (mouse_x >= cur_x && mouse_x < cur_x + bw && mouse_y >= cur_y &&
          mouse_y < cur_y + bh) {
        char c = btns[i][j][0];
        if (c >= '0' && c <= '9') {
          if (cs.next_clears) {
            cs.display[0] = c;
            cs.display[1] = '\0';
            cs.next_clears = false;
          } else {
            int len = string_length(cs.display);
            if (len < 10) {
              if (len == 1 && cs.display[0] == '0') {
                cs.display[0] = c;
              } else {
                cs.display[len] = c;
                cs.display[len + 1] = '\0';
              }
            }
          }
        } else if (c == 'C') {
          string_copy(cs.display, "0");
          cs.first_val = 0;
          cs.last_op = 0;
          cs.next_clears = true;
        } else if (c == '=') {
          int second_val = 0;
          char *p = cs.display;
          while (*p) {
            second_val = second_val * 10 + (*p - '0');
            p++;
          }

          int result = 0;
          if (cs.last_op == '+')
            result = cs.first_val + second_val;
          else if (cs.last_op == '-')
            result = cs.first_val - second_val;
          else if (cs.last_op == '*')
            result = cs.first_val * second_val;
          else if (cs.last_op == '/') {
            if (second_val != 0)
              result = cs.first_val / second_val;
          } else
            result = second_val;

          uint_to_string(result, cs.display);
          cs.next_clears = true;
          cs.last_op = 0;
        } else {
          int val = 0;
          char *p = cs.display;
          while (*p) {
            val = val * 10 + (*p - '0');
            p++;
          }
          cs.first_val = val;
          cs.last_op = c;
          cs.next_clears = true;
        }
      }
    }
  }
}

// ============================================================================
// UI COMPOSITION
// ============================================================================

struct WinState {
  int x, y, w, h;
  bool open;
  bool minimized;
  bool dragging;
  int drag_ox, drag_oy;
};

void draw_all_ui(WinState &welcome, WinState &fm, WinState &calc, CalcState &cs,
                 int fm_selected, int fm_scroll) {
  draw_wallpaper();

  // Draw Welcome window
  if (welcome.open) {
    if (!welcome.minimized) {
      draw_window(welcome.x, welcome.y, welcome.w, welcome.h, "Milla Welcome",
                  true);
      draw_string(welcome.x + 20, welcome.y + 50, "Wellcome to Milla OS 2.0",
                  0x000000);
      draw_image_scaled(welcome.x + 20, welcome.y + 80, 100, 100,
                        _binary_logo1_raw_start, 1024, 1024);
      draw_string(welcome.x + 140, welcome.y + 80,
                  "Milla OS is a FOSS Operating System.", 0x333333);
      draw_string(welcome.x + 140, welcome.y + 100,
                  "Written in C++ in Germany.", 0x333333);
      draw_rect_alpha(welcome.x + 20, welcome.y + 200, 500, 1, 0xCCCCCC, 255);
      draw_image_scaled(welcome.x + 20, welcome.y + 220, 80, 80,
                        _binary_logo2_raw_start, 460, 460);
      draw_string(welcome.x + 120, welcome.y + 220,
                  "(c) 2025 - 2026 @FloriDevs", 0x555555);
    } else {
      draw_window(welcome.x, welcome.y, welcome.w, 28, "Milla Welcome", true);
    }
  }

  // Draw File Manager window
  if (fm.open) {
    if (!fm.minimized) {
      draw_window(fm.x, fm.y, fm.w, fm.h, "File Manager", true);
      draw_file_manager_content(fm.x, fm.y, fm.w, fm.h, fm_selected, fm_scroll);
    } else {
      draw_window(fm.x, fm.y, fm.w, 28, "File Manager", true);
    }
  }

  // Draw Calculator window
  if (calc.open) {
    if (!calc.minimized) {
      draw_window(calc.x, calc.y, calc.w, calc.h, "Calculator", true);
      draw_calculator_content(calc.x, calc.y, calc.w, calc.h, cs);
    } else {
      draw_window(calc.x, calc.y, calc.w, 28, "Calculator", true);
    }
  }

  draw_top_bar();
}

void draw_menu_dropdown() {
  int mw = 180;
  int item_h = 30;
  int item_count = 3;
  int mh = item_count * item_h + 10;
  int mx = (screen.width - mw) / 2;
  int my = (screen.height - mh) / 2;

  // Drop shadow + transparent dark background (like top bar)
  draw_rect_alpha(mx + 4, my + 4, mw, mh, 0x000000, 80);
  draw_rect_alpha(mx, my, mw, mh, 0x000000, 180);

  const char *labels[3] = {"Welcome", "File Manager", "Calculator"};
  for (int i = 0; i < item_count; i++) {
    int iy = my + 5 + i * item_h;
    // Hover highlight
    if (mouse_x >= mx && mouse_x <= mx + mw && mouse_y >= iy &&
        mouse_y < iy + item_h) {
      draw_rect_alpha(mx + 5, iy, mw - 10, item_h, 0xCC2222, 200);
      draw_string(mx + 20, iy + 10, labels[i], 0xFFFFFF);
    } else {
      draw_string(mx + 20, iy + 10, labels[i], 0xDDDDDD);
    }
  }
}

// Handle title-bar clicks (minimize, close, drag) for a window
bool handle_window_titlebar(WinState &win, int mx, int my, bool clicked) {
  if (!win.open || !clicked)
    return false;
  if (my >= win.y && my <= win.y + 28 && mx >= win.x && mx <= win.x + win.w) {
    if (mx >= win.x + win.w - 28 && mx <= win.x + win.w - 8) {
      win.open = false;
      return true;
    } else if (mx >= win.x + win.w - 48 && mx <= win.x + win.w - 28) {
      win.minimized = !win.minimized;
      return true;
    } else {
      win.dragging = true;
      win.minimized = true; // Minimize while dragging
      win.drag_ox = mx - win.x;
      win.drag_oy = my - win.y;
      return true;
    }
  }
  return false;
}

extern "C" void start_graphical_shell() {
  init_minimal_font();

  WinState welcome = {80, 60, 640, 340, true, false, false, 0, 0};
  WinState fm = {120, 80, 500, 380, false, false, false, 0, 0};
  WinState calc = {200, 100, 200, 280, false, false, false, 0, 0};

  CalcState cs;
  string_copy(cs.display, "0");
  cs.first_val = 0;
  cs.last_op = 0;
  cs.next_clears = true;

  int fm_selected = 0;
  int fm_scroll = 0;
  bool fm_files_loaded = false;
  bool menu_open = false;

  bool last_mouse_left_state = false;

  int menu_btn_x = screen.width - 70;

  // Initial draw
  draw_all_ui(welcome, fm, calc, cs, fm_selected, fm_scroll);
  save_mouse_bg(mouse_x, mouse_y);
  last_mouse_x = mouse_x;
  last_mouse_y = mouse_y;
  draw_mouse();

  while (1) {
    get_keyboard_input_nonblock();

    bool mouse_clicked = mouse_left && !last_mouse_left_state;
    bool mouse_released = !mouse_left && last_mouse_left_state;
    bool needs_redraw = false;

    // --- Menu button click ---
    if (mouse_clicked) {
      // Red menu button in top-right
      if (mouse_y >= 2 && mouse_y <= 23 && mouse_x >= menu_btn_x &&
          mouse_x <= menu_btn_x + 60) {
        menu_open = !menu_open;
        needs_redraw = true;
      }
      // Menu dropdown item clicks
      else if (menu_open) {
        int mw = 180;
        int item_h = 30;
        int item_count = 3;
        int mh = item_count * item_h + 10;
        int mx_menu = (screen.width - mw) / 2;
        int my_menu = (screen.height - mh) / 2;

        if (mouse_x >= mx_menu && mouse_x <= mx_menu + mw &&
            mouse_y >= my_menu + 5 &&
            mouse_y < my_menu + 5 + item_count * item_h) {
          int item = (mouse_y - my_menu - 5) / item_h;
          if (item == 0) { // Welcome
            welcome.open = true;
            welcome.minimized = false;
          } else if (item == 1) { // File Manager
            fm.open = true;
            fm.minimized = false;
            if (!fm_files_loaded) {
              shell_refresh_files();
              fm_files_loaded = true;
              fm_selected = 0;
              fm_scroll = 0;
            }
          } else if (item == 2) { // Calculator
            calc.open = true;
            calc.minimized = false;
          }
        }
        menu_open = false;
        needs_redraw = true;
      }
    }

    // --- Calculator content clicks ---
    if (mouse_clicked && calc.open && !calc.minimized) {
      handle_calculator_click(cs, calc.x, calc.y, calc.w, calc.h);
      needs_redraw = true;
    }

    // --- File Manager content clicks ---
    if (mouse_clicked && fm.open && !fm.minimized) {
      int content_y = fm.y + 28 + 22;
      int row_height = 20;
      int max_visible = (fm.h - 28 - 24) / row_height;
      if (mouse_x >= fm.x && mouse_x <= fm.x + fm.w && mouse_y >= content_y &&
          mouse_y < content_y + max_visible * row_height) {
        int clicked_row = (mouse_y - content_y) / row_height;
        int new_sel = clicked_row + fm_scroll;
        if (new_sel >= 0 && new_sel < get_shell_file_count()) {
          fm_selected = new_sel;
          needs_redraw = true;
        }
      }
    }

    // --- Title bar interactions ---
    if (mouse_clicked) {
      // Calculator > FM > Welcome (priority)
      if (!handle_window_titlebar(calc, mouse_x, mouse_y, true)) {
        if (!handle_window_titlebar(fm, mouse_x, mouse_y, true)) {
          handle_window_titlebar(welcome, mouse_x, mouse_y, true);
        }
      }
      needs_redraw = true;
    }

    // --- Release drag ---
    if (mouse_released) {
      if (welcome.dragging || fm.dragging || calc.dragging) {
        if (welcome.dragging)
          welcome.minimized = false;
        if (fm.dragging)
          fm.minimized = false;
        if (calc.dragging)
          calc.minimized = false;
        needs_redraw = true;
      }
      welcome.dragging = false;
      fm.dragging = false;
      calc.dragging = false;
    }

    // --- Dragging ---
    if (mouse_x != last_mouse_x || mouse_y != last_mouse_y) {
      if (welcome.dragging) {
        welcome.x = mouse_x - welcome.drag_ox;
        welcome.y = mouse_y - welcome.drag_oy;
        needs_redraw = true;
      }
      if (fm.dragging) {
        fm.x = mouse_x - fm.drag_ox;
        fm.y = mouse_y - fm.drag_oy;
        needs_redraw = true;
      }
      if (calc.dragging) {
        calc.x = mouse_x - calc.drag_ox;
        calc.y = mouse_y - calc.drag_oy;
        needs_redraw = true;
      }
    }

    // --- Redraw ---
    if (needs_redraw) {
      draw_all_ui(welcome, fm, calc, cs, fm_selected, fm_scroll);
      if (menu_open)
        draw_menu_dropdown();
      save_mouse_bg(mouse_x, mouse_y);
      draw_mouse();
      last_mouse_x = mouse_x;
      last_mouse_y = mouse_y;
    } else if (mouse_x != last_mouse_x || mouse_y != last_mouse_y) {
      restore_mouse_bg(last_mouse_x, last_mouse_y);
      save_mouse_bg(mouse_x, mouse_y);
      draw_mouse();
      last_mouse_x = mouse_x;
      last_mouse_y = mouse_y;
    }

    last_mouse_left_state = mouse_left;

    for (int i = 0; i < 5000; i++)
      asm volatile("nop");
  }
}
