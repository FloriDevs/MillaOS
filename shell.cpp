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
void *malloc(uint32_t size);
char shell_scancode_to_ascii(uint8_t scancode, bool shift);
void shell_set_language(int lang);
bool shell_read_file(const char *filename, char *buffer, uint32_t max_size);
bool shell_write_file(const char *filename, const char *data, uint32_t size);
bool shell_format_disk(int disk_id);
bool shell_mount_disk(int disk_id);
void shell_unmount_disk();
int shell_get_active_disk();
bool shell_is_hdd_present();
}

bool string_starts_with(const char *str, const char *prefix) {
  while (*prefix)
    if (*str++ != *prefix++)
      return false;
  return true;
}

void itoa_light(int n, char *s) {
  if (n == 0) {
    s[0] = '0';
    s[1] = '\0';
    return;
  }
  int i = 0;
  bool neg = false;
  if (n < 0) {
    neg = true;
    n = -n;
  }
  while (n > 0) {
    s[i++] = (n % 10) + '0';
    n /= 10;
  }
  if (neg)
    s[i++] = '-';
  s[i] = '\0';
  for (int j = 0; j < i / 2; j++) {
    char t = s[j];
    s[j] = s[i - 1 - j];
    s[i - 1 - j] = t;
  }
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

uint32_t *ui_buffer = nullptr;
uint32_t *frontbuffer = nullptr;

void my_put_pixel(int x, int y, uint32_t color) {
  if (x < 0 || (uint32_t)x >= screen.width || y < 0 ||
      (uint32_t)y >= screen.height)
    return;
  ui_buffer[y * screen.width + x] = color;
}

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
        my_put_pixel(j, i, color);
      } else {
        uint32_t dest = ui_buffer[i * screen.width + j];
        my_put_pixel(j, i, blend(color, dest, alpha));
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
        my_put_pixel(x + j, y + i, color);
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
        my_put_pixel(x + j, y + i, (r << 16) | (g << 8) | b);
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
        my_put_pixel(x + j, y + i, (r << 16) | (g << 8) | b);
    }
  }
}

void draw_wallpaper() {
  uint32_t *wallpaper = (uint32_t *)_binary_fds_raw_start;
  for (uint32_t y = 0; y < screen.height; y++) {
    for (uint32_t x = 0; x < screen.width; x++) {
      // Tile 800x600 wallpaper safely
      uint32_t col = wallpaper[(y % 600) * 800 + (x % 800)];
      uint8_t r = col & 0xFF;
      uint8_t g = (col >> 8) & 0xFF;
      uint8_t b = (col >> 16) & 0xFF;
      my_put_pixel(x, y, (r << 16) | (g << 8) | b);
    }
  }
}

int last_mouse_x = -1;
int last_mouse_y = -1;

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
// SETTINGS APP
// ============================================================================

struct SettingsState {
  int language; // 0=EN, 1=DE, 2=FR
};

void draw_settings_content(int x, int y, int w, int h, SettingsState &ss) {
  int cy = y + 28;
  draw_string(x + 10, cy + 10, "Language Settings", 0x333333);

  // Buttons for language
  draw_rect_alpha(x + 10, cy + 30, 80, 25,
                  ss.language == 0 ? 0x005A9E : 0xCCCCCC, 255);
  draw_string(x + 25, cy + 38, "English",
              ss.language == 0 ? 0xFFFFFF : 0x000000);

  draw_rect_alpha(x + 100, cy + 30, 80, 25,
                  ss.language == 1 ? 0x005A9E : 0xCCCCCC, 255);
  draw_string(x + 115, cy + 38, "German",
              ss.language == 1 ? 0xFFFFFF : 0x000000);

  draw_rect_alpha(x + 190, cy + 30, 80, 25,
                  ss.language == 2 ? 0x005A9E : 0xCCCCCC, 255);
  draw_string(x + 205, cy + 38, "French",
              ss.language == 2 ? 0xFFFFFF : 0x000000);
}

// ============================================================================
// DISK MANAGER APP
// ============================================================================

void draw_disk_manager_content(int x, int y, int w, int h) {
  int cy = y + 28;
  draw_string(x + 10, cy + 10, "Disk Manager", 0x333333);

  int active_disk = shell_get_active_disk();
  bool hdd_present = shell_is_hdd_present();
  bool mounted = shell_is_fs_mounted();

  char disk_info[50];
  if (active_disk == 1) {
    string_copy(disk_info, "[MRD0] RAM Disk - ");
  } else if (active_disk == 2) {
    string_copy(disk_info, "[HDD0] Hard Disk - ");
  } else {
    string_copy(disk_info, "[---] No active disk - ");
  }

  if (active_disk > 0 && mounted) {
    string_copy(disk_info + string_length(disk_info), "FAT16 (Ready)");
  } else if (active_disk > 0) {
    string_copy(disk_info + string_length(disk_info), "Not mounted");
  }

  draw_string(x + 10, cy + 35, disk_info, 0x000000);

  draw_rect_alpha(x, cy + 55, w, 1, 0xCCCCCC, 255);

  // RAM Disk Buttons
  draw_string(x + 10, cy + 65, "RAM Disk:", 0x333333);
  draw_rect_alpha(x + 10, cy + 85, 120, 25, 0x005A9E, 255);
  draw_string(x + 20, cy + 93, "Mount RAM", 0xFFFFFF);
  draw_rect_alpha(x + 140, cy + 85, 120, 25, 0xEE7700, 255);
  draw_string(x + 150, cy + 93, "Format RAM", 0xFFFFFF);

  // HDD Buttons
  draw_string(x + 10, cy + 125,
              hdd_present ? "Hard Disk:" : "Hard Disk: Not Found", 0x333333);
  if (hdd_present) {
    draw_rect_alpha(x + 10, cy + 145, 120, 25, 0x005A9E, 255);
    draw_string(x + 20, cy + 153, "Mount HDD", 0xFFFFFF);
    draw_rect_alpha(x + 140, cy + 145, 120, 25, 0xEE7700, 255);
    draw_string(x + 150, cy + 153, "Format HDD", 0xFFFFFF);
  }

  // Global Unmount
  draw_rect_alpha(x + 10, cy + 185, w - 20, 25, 0xCC2222, 255);
  draw_string(x + (w / 2) - 30, cy + 193, "Unmount", 0xFFFFFF);
}

bool handle_disk_manager_click(int x, int y, int w) {
  int cy = y + 28;
  bool disk_changed = false;

  if (mouse_y >= cy + 85 && mouse_y <= cy + 110) {
    if (mouse_x >= x + 10 && mouse_x <= x + 130) {
      shell_mount_disk(1);
      disk_changed = true;
    } // Mount RAM
    else if (mouse_x >= x + 140 && mouse_x <= x + 260) {
      shell_format_disk(1);
      disk_changed = true;
    } // Format RAM
  }

  bool hdd_present = shell_is_hdd_present();
  if (hdd_present && mouse_y >= cy + 145 && mouse_y <= cy + 170) {
    if (mouse_x >= x + 10 && mouse_x <= x + 130) {
      shell_mount_disk(2);
      disk_changed = true;
    } // Mount HDD
    else if (mouse_x >= x + 140 && mouse_x <= x + 260) {
      shell_format_disk(2);
      disk_changed = true;
    } // Format HDD
  }

  if (mouse_y >= cy + 185 && mouse_y <= cy + 210) {
    if (mouse_x >= x + 10 && mouse_x <= x + w - 10) {
      shell_unmount_disk();
      disk_changed = true;
    }
  }

  return disk_changed;
}

void handle_settings_click(SettingsState &ss, int x, int y) {
  int cy = y + 28;
  // Language clicks
  if (mouse_y >= cy + 30 && mouse_y <= cy + 55) {
    if (mouse_x >= x + 10 && mouse_x <= x + 90)
      ss.language = 0;
    else if (mouse_x >= x + 100 && mouse_x <= x + 180)
      ss.language = 1;
    else if (mouse_x >= x + 190 && mouse_x <= x + 270)
      ss.language = 2;
    shell_set_language(ss.language);
  }
}

// ============================================================================
// WORD APP
// ============================================================================

struct WordState {
  char buffer[4096];
  int cursor_pos;
  char filename[13];
  int filename_len;
  bool shift_pressed;
  bool editing_filename;
  bool show_open_dialog;
};

// ============================================================================
// tabels (SPREADSHEET) APP
// ============================================================================

struct SheetState {
  char cells[6][10][32]; // larger for formulas
  int sel_x, sel_y;
  char filename[13];
  int filename_len;
  bool shift_pressed;
  bool show_open_dialog;
};

// Helper for formulas
int get_cell_int(SheetState &ss, int col, int row, int depth);

int resolve_ref(SheetState &ss, const char *ref, int depth) {
  if (depth > 5)
    return 0;
  if (ref[0] >= 'A' && ref[0] <= 'F' && ref[1] >= '1' && ref[1] <= '9') {
    int c = ref[0] - 'A';
    int r = (ref[1] - '1');
    if (ref[2] == '0')
      r = 9; // Handle row 10
    return get_cell_int(ss, c, r, depth + 1);
  }
  // Is it just a number?
  bool num = true;
  for (int i = 0; ref[i]; i++)
    if (!(ref[i] >= '0' && ref[i] <= '9') && ref[i] != '-')
      num = false;
  if (num) {
    int res = 0;
    bool neg = false;
    int i = 0;
    if (ref[i] == '-') {
      neg = true;
      i++;
    }
    while (ref[i] >= '0' && ref[i] <= '9')
      res = res * 10 + (ref[i++] - '0');
    return neg ? -res : res;
  }
  return 0;
}

int get_cell_int(SheetState &ss, int col, int row, int depth) {
  if (col < 0 || col >= 6 || row < 0 || row >= 10)
    return 0;
  const char *v = ss.cells[col][row];
  if (v[0] == '\0')
    return 0;
  if (v[0] == '=') {
    // Formula!
    if (string_starts_with(v + 1, "SUM(")) {
      // SUM(A1:A5)
      int sc = v[5] - 'A';
      int sr = v[6] - '1';
      int ec = v[8] - 'A';
      int er = v[9] - '1';
      if (v[7] == '0') {
        sr = 9;
        ec = v[9] - 'A';
        er = v[10] - '1';
      } // Offset check
      // Simpler: assume format A1:A5 (5 chars) or A1:A10 (6 chars)
      // Just parse row/col manually for robustness:
      sc = v[5] - 'A';
      sr = v[6] - '1';
      if (v[7] == '0')
        sr = 9;
      int colon = 7;
      if (sr == 9)
        colon = 8;
      ec = v[colon + 1] - 'A';
      er = v[colon + 2] - '1';
      if (v[colon + 3] == '0')
        er = 9;

      int sum = 0;
      for (int r = sr; r <= er; r++)
        for (int c = sc; c <= ec; c++)
          sum += get_cell_int(ss, c, r, depth + 1);
      return sum;
    }
    // Basic A1+B2
    char r1[8] = {0}, r2[8] = {0};
    char op = 0;
    int i = 1, j = 0;
    while (v[i] && v[i] != '+' && v[i] != '-' && v[i] != '*' && v[i] != '/')
      r1[j++] = v[i++];
    if (v[i]) {
      op = v[i++];
      j = 0;
      while (v[i])
        r2[j++] = v[i++];
      int v1 = resolve_ref(ss, r1, depth);
      int v2 = resolve_ref(ss, r2, depth);
      if (op == '+')
        return v1 + v2;
      if (op == '-')
        return v1 - v2;
      if (op == '*')
        return v1 * v2;
      if (op == '/')
        return v2 ? v1 / v2 : 0;
    }
    return resolve_ref(ss, r1, depth);
  }
  // Raw number
  int res = 0;
  bool neg = false;
  int i = 0;
  if (v[i] == '-') {
    neg = true;
    i++;
  }
  while (v[i] >= '0' && v[i] <= '9')
    res = res * 10 + (v[i++] - '0');
  return neg ? -res : res;
}

void draw_sheet_content(int x, int y, int w, int h, SheetState &ss) {
  int cy = y + 28;
  // Toolbar
  draw_rect_alpha(x, cy, w, 30, 0xEEEEEE, 255);

  // Save/Load buttons
  draw_rect_alpha(x + 10, cy + 5, 50, 20, 0x107C10, 255); // tabels green
  draw_string(x + 15, cy + 11, "Save", 0xFFFFFF);

  draw_rect_alpha(x + 70, cy + 5, 50, 20, 0x107C10, 255);
  draw_string(x + 75, cy + 11, "Load", 0xFFFFFF);

  draw_string(x + 130, cy + 11, ss.filename, 0x333333);

  int grid_y = cy + 30;
  int cell_w = (w - 20) / 6;
  int cell_h = (h - 28 - 30) / 10;

  // Draw Column Headers (A-F)
  for (int col = 0; col < 6; col++) {
    char label[2] = {(char)('A' + col), '\0'};
    draw_rect_alpha(x + col * cell_w, grid_y, cell_w, 20, 0xCCCCCC, 255);
    draw_string(x + col * cell_w + (cell_w / 2) - 4, grid_y + 6, label,
                0x000000);
  }

  // Draw grid
  for (int row = 0; row < 10; row++) {
    for (int col = 0; col < 6; col++) {
      int cx = x + col * cell_w;
      int cy_cell = grid_y + 20 + row * cell_h;

      uint32_t bg = (ss.sel_x == col && ss.sel_y == row) ? 0xCCFFCC : 0xFFFFFF;
      draw_rect_alpha(cx, cy_cell, cell_w, cell_h, bg, 255);

      // Border
      draw_rect_alpha(cx, cy_cell, cell_w, 1, 0xBBBBBB, 255);
      draw_rect_alpha(cx, cy_cell, 1, cell_h, 0xBBBBBB, 255);

      if (ss.sel_x == col && ss.sel_y == row) {
        // Show formula while editing
        draw_string(cx + 4, cy_cell + (cell_h / 2) - 4, ss.cells[col][row],
                    0x000000);
      } else {
        // Show result
        if (ss.cells[col][row][0] == '=') {
          int val = get_cell_int(ss, col, row, 0);
          char buf[16];
          itoa_light(val, buf);
          draw_string(cx + 4, cy_cell + (cell_h / 2) - 4, buf,
                      0x015A01); // Dark green for formulas
        } else {
          draw_string(cx + 4, cy_cell + (cell_h / 2) - 4, ss.cells[col][row],
                      0x000000);
        }
      }
    }
  }

  if (ss.show_open_dialog) {
    draw_rect_alpha(x + 20, y + 60, w - 40, h - 100, 0xFFFFFF, 255);
    draw_rect_alpha(x + 20, y + 60, w - 40, 25, 0x107C10, 255);
    draw_string(x + 30, y + 68, "Select File (.SHT)", 0xFFFFFF);

    int count = get_shell_file_count();
    int visible = 0;
    for (int i = 0; i < count && visible < 8; i++) {
      char name[16];
      get_shell_file_name(i, name);
      if (!get_shell_file_is_dir(i)) {
        draw_string(x + 30, y + 95 + visible * 20, name, 0x000000);
        visible++;
      }
    }
  }
}

bool handle_sheet_click(SheetState &ss, int x, int y, int w, int h) {
  int cy = y + 28;

  if (ss.show_open_dialog) {
    if (mouse_y >= y + 90 && mouse_y < y + 90 + 160) {
      int idx = (mouse_y - (y + 90)) / 20;
      // Find the idx-th non-directory file
      int found = -1;
      int current = 0;
      for (int i = 0; i < get_shell_file_count(); i++) {
        if (!get_shell_file_is_dir(i)) {
          if (current == idx) {
            found = i;
            break;
          }
          current++;
        }
      }
      if (found != -1) {
        get_shell_file_name(found, ss.filename);
        ss.filename_len = string_length(ss.filename);
        shell_read_file(ss.filename, (char *)ss.cells, sizeof(ss.cells));
        ss.show_open_dialog = false;
        return true;
      }
    }
    if (mouse_x < x + 20 || mouse_x > x + w - 20 || mouse_y < y + 60 ||
        mouse_y > y + h - 40) {
      ss.show_open_dialog = false;
      return true;
    }
    return false;
  }

  // Save/Load
  if (mouse_y >= cy + 5 && mouse_y <= cy + 25) {
    if (mouse_x >= x + 10 && mouse_x <= x + 60) {
      shell_write_file(ss.filename, (char *)ss.cells, sizeof(ss.cells));
      return true;
    }
    if (mouse_x >= x + 70 && mouse_x <= x + 120) {
      ss.show_open_dialog = true;
      return true;
    }
  }

  // Grid selection
  int grid_y = cy + 30;
  int cell_w = (w - 20) / 6;
  int cell_h = (h - 28 - 30) / 10;
  if (mouse_x >= x && mouse_x < x + cell_w * 6 && mouse_y >= grid_y + 20) {
    ss.sel_x = (mouse_x - x) / cell_w;
    ss.sel_y = (mouse_y - (grid_y + 20)) / cell_h;
    if (ss.sel_x < 0)
      ss.sel_x = 0;
    if (ss.sel_x > 5)
      ss.sel_x = 5;
    if (ss.sel_y < 0)
      ss.sel_y = 0;
    if (ss.sel_y > 9)
      ss.sel_y = 9;
    return true;
  }

  return false;
}

void draw_word_content(int x, int y, int w, int h, WordState &ws) {
  int cy = y + 28;
  // Toolbar
  draw_rect_alpha(x, cy, w, 30, 0xDDDDDD, 255);

  // Save/Load buttons
  draw_rect_alpha(x + 10, cy + 5, 60, 20, 0x005A9E, 255);
  draw_string(x + 20, cy + 11, "Save", 0xFFFFFF);

  draw_rect_alpha(x + 80, cy + 5, 60, 20, 0x005A9E, 255);
  draw_string(x + 90, cy + 11, "Load", 0xFFFFFF);

  draw_string(x + 150, cy + 11, "File:", 0x333333);

  draw_rect_alpha(x + 190, cy + 5, 100, 20,
                  ws.editing_filename ? 0xBBBBBB : 0xFFFFFF, 255);
  draw_string(x + 195, cy + 11, ws.filename, 0x000000);

  if (ws.show_open_dialog) {
    draw_rect_alpha(x + 10, cy + 40, w - 20, h - 75, 0xEEEEEE, 255);
    int list_y = cy + 45;
    int count = get_shell_file_count();
    draw_string(x + 15, list_y, "Select a file to load:", 0x000000);
    for (int i = 0; i < count && i < 10; i++) {
      char name[16];
      get_shell_file_name(i, name);
      draw_rect_alpha(x + 15, list_y + 20 + i * 20, w - 30, 18, 0xFFFFFF, 255);
      draw_string(x + 20, list_y + 25 + i * 20, name, 0x000000);
    }
    return; // Don't draw text area behind
  }

  // Text area
  draw_rect_alpha(x + 10, cy + 40, w - 20, h - 75, 0xFFFFFF, 255);
  draw_rect_alpha(x + 10, cy + 40, w - 20, h - 75, 0x999999,
                  255); // wait, to draw black outline I'd need edges
  // Just draw a thin outline manually:
  draw_rect_alpha(x + 10, cy + 40, w - 20, 1, 0x999999, 255);
  draw_rect_alpha(x + 10, cy + 40, 1, h - 75, 0x999999, 255);

  // Draw text
  int tx = x + 15;
  int ty = cy + 45;
  for (int i = 0; i <= ws.cursor_pos; i++) {
    if (i == ws.cursor_pos && !ws.editing_filename) {
      // Draw cursor (blinking)
      Time t = get_time();
      if (t.second % 2 == 0) {
        draw_rect_alpha(tx, ty, 6, 12, 0x000000, 255);
      }
      break;
    }
    if (i == ws.cursor_pos)
      break;

    char c = ws.buffer[i];
    if (c == '\n') {
      tx = x + 15;
      ty += 14;
    } else {
      draw_char(tx, ty, c, 0x000000);
      tx += 8;
      if (tx > x + w - 25) {
        tx = x + 15;
        ty += 14;
      }
    }
  }
}

void handle_word_click(WordState &ws, int x, int y) {
  int cy = y + 28;

  if (ws.show_open_dialog) {
    int list_y = cy + 45;
    int count = get_shell_file_count();
    for (int i = 0; i < count && i < 10; i++) {
      if (mouse_y >= list_y + 20 + i * 20 && mouse_y <= list_y + 38 + i * 20) {
        // picked a file
        char name[16];
        get_shell_file_name(i, name);
        string_copy(ws.filename, name);
        ws.filename_len = string_length(name);
        if (shell_read_file(ws.filename, ws.buffer, 4096)) {
          ws.cursor_pos = 0;
          while (ws.buffer[ws.cursor_pos] != '\0' && ws.cursor_pos < 4096)
            ws.cursor_pos++;
        } else {
          ws.buffer[0] = '\0';
          ws.cursor_pos = 0;
        }
        ws.show_open_dialog = false;
        return;
      }
    }
    ws.show_open_dialog = false;
    return;
  }

  // buttons
  if (mouse_y >= cy + 5 && mouse_y <= cy + 25) {
    if (mouse_x >= x + 10 && mouse_x <= x + 70) {
      shell_write_file(ws.filename, ws.buffer, ws.cursor_pos);
    } else if (mouse_x >= x + 80 && mouse_x <= x + 140) {
      ws.show_open_dialog = true;
    } else if (mouse_x >= x + 190 && mouse_x <= x + 290) {
      ws.editing_filename = true;
      return;
    }
  }
  ws.editing_filename = false;
}

void handle_word_key(WordState &ws, uint8_t scancode) {
  if (scancode == 0x2A || scancode == 0x36)
    ws.shift_pressed = true;
  else if (scancode == 0xAA || scancode == 0xB6)
    ws.shift_pressed = false;
  else if ((scancode & 0x80) == 0) { // key press
    if (ws.editing_filename) {
      if (scancode == 0x0E && ws.filename_len > 0) { // Backspace
        ws.filename[--ws.filename_len] = '\0';
      } else if (scancode == 0x1C) { // Enter
        ws.editing_filename = false;
      } else {
        char ch = shell_scancode_to_ascii(scancode, ws.shift_pressed);
        if (ch && ws.filename_len < 12) {
          ws.filename[ws.filename_len++] = ch;
          ws.filename[ws.filename_len] = '\0';
        }
      }
    } else {
      if (scancode == 0x0E && ws.cursor_pos > 0) { // Backspace
        ws.cursor_pos--;
        ws.buffer[ws.cursor_pos] = '\0';
      } else if (scancode == 0x1C && ws.cursor_pos < 4095) { // Enter
        ws.buffer[ws.cursor_pos++] = '\n';
        ws.buffer[ws.cursor_pos] = '\0';
      } else {
        char ch = shell_scancode_to_ascii(scancode, ws.shift_pressed);
        // Simple printable ascii
        if (ch >= 32 && ch <= 126 && ws.cursor_pos < 4095) {
          ws.buffer[ws.cursor_pos++] = ch;
          ws.buffer[ws.cursor_pos] = '\0';
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

void draw_all_ui(WinState &welcome, WinState &fm, WinState &calc,
                 WinState &word, WinState &tabels, WinState &settings,
                 WinState &disk_manager, CalcState &cs, WordState &ws,
                 SheetState &sss, SettingsState &ss, int fm_selected,
                 int fm_scroll) {
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

  // Draw Word window (Documents)
  if (word.open) {
    if (!word.minimized) {
      draw_window(word.x, word.y, word.w, word.h, "Documents", true);
      draw_word_content(word.x, word.y, word.w, word.h, ws);
    } else {
      draw_window(word.x, word.y, word.w, 28, "Documents", true);
    }
  }

  // Draw tabels window (tabels)
  if (tabels.open) {
    if (!tabels.minimized) {
      draw_window(tabels.x, tabels.y, tabels.w, tabels.h, "tabels", true);
      draw_sheet_content(tabels.x, tabels.y, tabels.w, tabels.h, sss);
    } else {
      draw_window(tabels.x, tabels.y, tabels.w, 28, "tabels", true);
    }
  }

  // Draw Settings window
  if (settings.open) {
    if (!settings.minimized) {
      draw_window(settings.x, settings.y, settings.w, settings.h, "Settings",
                  true);
      draw_settings_content(settings.x, settings.y, settings.w, settings.h, ss);
    } else {
      draw_window(settings.x, settings.y, settings.w, 28, "Settings", true);
    }
  }

  // Draw Disk Manager window
  if (disk_manager.open) {
    if (!disk_manager.minimized) {
      draw_window(disk_manager.x, disk_manager.y, disk_manager.w,
                  disk_manager.h, "Disk Manager", true);
      draw_disk_manager_content(disk_manager.x, disk_manager.y, disk_manager.w,
                                disk_manager.h);
    } else {
      draw_window(disk_manager.x, disk_manager.y, disk_manager.w, 28,
                  "Disk Manager", true);
    }
  }

  draw_top_bar();
}

void draw_menu_dropdown() {
  int mw = 180;
  int item_h = 30;
  int item_count = 7;
  int mh = item_count * item_h + 10;
  int mx = (screen.width - mw) / 2;
  int my = (screen.height - mh) / 2;

  // Drop shadow + transparent dark background (like top bar)
  draw_rect_alpha(mx + 4, my + 4, mw, mh, 0x000000, 80);
  draw_rect_alpha(mx, my, mw, mh, 0x000000, 180);

  const char *labels[7] = {"Welcome",     "File Manager", "Calculator",
                           "Documents",   "tabels",       "Settings",
                           "Disk Manager"};
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
  ui_buffer = (uint32_t *)malloc(screen.width * screen.height * 4);
  frontbuffer = (uint32_t *)malloc(screen.width * screen.height * 4);

  if (!ui_buffer || !frontbuffer) {
    // Emergency fallback if heap fails
    return;
  }

  // Initialize buffers
  for (uint32_t i = 0; i < screen.width * screen.height; i++) {
    ui_buffer[i] = 0;
    frontbuffer[i] = 0x00000001; // Distinct value
  }

  init_minimal_font();

  static WinState welcome = {80, 60, 640, 340, true, false, false, 0, 0};
  static WinState fm = {120, 80, 500, 380, false, false, false, 0, 0};
  static WinState calc = {200, 100, 200, 280, false, false, false, 0, 0};
  static WinState word = {50, 50, 500, 400, false, false, false, 0, 0};
  static WinState tabels = {100, 100, 500, 300, false, false, false, 0, 0};
  static WinState settings = {300, 100, 300, 100, false, false, false, 0, 0};
  static WinState disk_manager = {350,   150,   300, 250, false,
                                  false, false, 0,   0};

  static CalcState cs;
  string_copy(cs.display, "0");
  cs.first_val = 0;
  cs.last_op = 0;
  cs.next_clears = true;

  static WordState ws;
  string_copy(ws.filename, "DOC.TXT");
  ws.filename_len = 7;
  ws.buffer[0] = '\0';
  ws.cursor_pos = 0;
  ws.shift_pressed = false;
  ws.editing_filename = false;
  ws.show_open_dialog = false;

  static SheetState sss;
  static bool sss_init = false;
  if (!sss_init) {
    for (int r = 0; r < 10; r++) {
      for (int c = 0; c < 6; c++) {
        sss.cells[c][r][0] = '\0';
      }
    }
    sss.sel_x = 0;
    sss.sel_y = 0;
    string_copy(sss.filename, "BOOK.SHT");
    sss.filename_len = 8;
    sss.shift_pressed = false;
    sss.show_open_dialog = false;
    sss_init = true;
  }

  static SettingsState ss = {0}; // 0 = EN

  int fm_selected = 0;
  int fm_scroll = 0;
  bool fm_files_loaded = false;
  bool menu_open = false;

  bool last_mouse_left_state = false;

  int menu_btn_x = screen.width - 70;

  bool first_frame = true;

  while (1) {
    uint8_t scancode = get_keyboard_input_nonblock();

    bool needs_redraw = first_frame;
    first_frame = false;

    if (scancode == 0x3B) { // F1 - Global Super Key for Milla OS
      menu_open = !menu_open;
      needs_redraw = true;
    }

    if (scancode != 0 && word.open && !word.minimized) {
      handle_word_key(ws, scancode);
      needs_redraw = true;
    }

    // Keyboard in tabels
    if (scancode != 0 && tabels.open && !tabels.minimized && !tabels.dragging) {
      if (scancode == 0x2A || scancode == 0x36)
        sss.shift_pressed = true;
      else if (scancode == (0x2A | 0x80) || scancode == (0x36 | 0x80))
        sss.shift_pressed = false;
      else if (!(scancode & 0x80)) {
        if (scancode == 0x0E) { // Backspace
          int len = string_length(sss.cells[sss.sel_x][sss.sel_y]);
          if (len > 0)
            sss.cells[sss.sel_x][sss.sel_y][len - 1] = '\0';
          needs_redraw = true;
        } else if (scancode == 0x1C) { // Enter moves down
          sss.sel_y = (sss.sel_y + 1) % 10;
          needs_redraw = true;
        } else if (scancode == 0x48) { // Up
          sss.sel_y = (sss.sel_y + 9) % 10;
          needs_redraw = true;
        } else if (scancode == 0x50) { // Down
          sss.sel_y = (sss.sel_y + 1) % 10;
          needs_redraw = true;
        } else if (scancode == 0x4B) { // Left
          sss.sel_x = (sss.sel_x + 5) % 6;
          needs_redraw = true;
        } else if (scancode == 0x4D) { // Right
          sss.sel_x = (sss.sel_x + 1) % 6;
          needs_redraw = true;
        } else {
          char c = shell_scancode_to_ascii(scancode, sss.shift_pressed);
          if (c >= 32 && c <= 126) {
            int len = string_length(sss.cells[sss.sel_x][sss.sel_y]);
            if (len < 31) {
              sss.cells[sss.sel_x][sss.sel_y][len] = c;
              sss.cells[sss.sel_x][sss.sel_y][len + 1] = '\0';
              needs_redraw = true;
            }
          }
        }
      }
    }

    bool mouse_clicked = mouse_left && !last_mouse_left_state;
    bool mouse_released = !mouse_left && last_mouse_left_state;

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
        int item_count = 7;
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
          } else if (item == 3) { // Documents
            word.open = true;
            word.minimized = false;
          } else if (item == 4) { // tabels
            tabels.open = true;
            tabels.minimized = false;
          } else if (item == 5) { // Settings
            settings.open = true;
            settings.minimized = false;
          } else if (item == 6) { // Disk Manager
            disk_manager.open = true;
            disk_manager.minimized = false;
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

    // --- Word content clicks ---
    if (mouse_clicked && word.open && !word.minimized) {
      handle_word_click(ws, word.x, word.y);
      needs_redraw = true;
    }

    // --- tabels content clicks ---
    if (mouse_clicked && tabels.open && !tabels.minimized) {
      handle_sheet_click(sss, tabels.x, tabels.y, tabels.w, tabels.h);
      needs_redraw = true;
    }

    // --- Settings content clicks ---
    if (mouse_clicked && settings.open && !settings.minimized) {
      handle_settings_click(ss, settings.x, settings.y);
      needs_redraw = true;
    }

    // --- Disk Manager content clicks ---
    if (mouse_clicked && disk_manager.open && !disk_manager.minimized) {
      if (handle_disk_manager_click(disk_manager.x, disk_manager.y,
                                    disk_manager.w)) {
        fm_files_loaded = false; // force fm refresh
      }
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
          if (fm_selected == new_sel && !get_shell_file_is_dir(new_sel)) {
            // Double clicked: Open in Documents
            char name[16];
            get_shell_file_name(new_sel, name);
            string_copy(ws.filename, name);
            ws.filename_len = string_length(name);
            if (shell_read_file(ws.filename, ws.buffer, 4096)) {
              ws.cursor_pos = 0;
              while (ws.buffer[ws.cursor_pos] != '\0' && ws.cursor_pos < 4096)
                ws.cursor_pos++;
            } else {
              ws.buffer[0] = '\0';
              ws.cursor_pos = 0;
            }
            word.open = true;
            word.minimized = false;
          }
          fm_selected = new_sel;
          needs_redraw = true;
        }
      }
    }

    // --- Title bar interactions ---
    if (mouse_clicked) {
      // Priority: Disk Manager > Settings > tabels > Word > Calculator > FM >
      // Welcome
      if (!handle_window_titlebar(disk_manager, mouse_x, mouse_y, true)) {
        if (!handle_window_titlebar(settings, mouse_x, mouse_y, true)) {
          if (!handle_window_titlebar(tabels, mouse_x, mouse_y, true)) {
            if (!handle_window_titlebar(word, mouse_x, mouse_y, true)) {
              if (!handle_window_titlebar(calc, mouse_x, mouse_y, true)) {
                if (!handle_window_titlebar(fm, mouse_x, mouse_y, true)) {
                  handle_window_titlebar(welcome, mouse_x, mouse_y, true);
                }
              }
            }
          }
        }
      }
      needs_redraw = true;
    }

    // --- Release drag ---
    if (mouse_released) {
      if (welcome.dragging || fm.dragging || calc.dragging || word.dragging ||
          settings.dragging || disk_manager.dragging) {
        if (welcome.dragging)
          welcome.minimized = false;
        if (fm.dragging)
          fm.minimized = false;
        if (calc.dragging)
          calc.minimized = false;
        if (word.dragging)
          word.minimized = false;
        if (tabels.dragging)
          tabels.minimized = false;
        if (settings.dragging)
          settings.minimized = false;
        if (disk_manager.dragging)
          disk_manager.minimized = false;
        needs_redraw = true;
      }
      welcome.dragging = false;
      fm.dragging = false;
      calc.dragging = false;
      word.dragging = false;
      tabels.dragging = false;
      settings.dragging = false;
      disk_manager.dragging = false;
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
      if (word.dragging) {
        word.x = mouse_x - word.drag_ox;
        word.y = mouse_y - word.drag_oy;
        needs_redraw = true;
      }
      if (settings.dragging) {
        settings.x = mouse_x - settings.drag_ox;
        settings.y = mouse_y - settings.drag_oy;
        needs_redraw = true;
      }
      if (tabels.dragging) {
        tabels.x = mouse_x - tabels.drag_ox;
        tabels.y = mouse_y - tabels.drag_oy;
        needs_redraw = true;
      }
      if (disk_manager.dragging) {
        disk_manager.x = mouse_x - disk_manager.drag_ox;
        disk_manager.y = mouse_y - disk_manager.drag_oy;
        needs_redraw = true;
      }
    }

    // --- Redraw ---
    if (needs_redraw) {
      draw_all_ui(welcome, fm, calc, word, tabels, settings, disk_manager, cs,
                  ws, sss, ss, fm_selected, fm_scroll);
      if (menu_open)
        draw_menu_dropdown();
    }

    if (needs_redraw || mouse_x != last_mouse_x || mouse_y != last_mouse_y) {
      for (int y = 0; y < (int)screen.height; y++) {
        for (int x = 0; x < (int)screen.width; x++) {
          uint32_t pixel = ui_buffer[y * screen.width + x];

          bool is_mouse = false;
          if (x == mouse_x && y >= mouse_y - 5 && y <= mouse_y + 5)
            is_mouse = true;
          if (y == mouse_y && x >= mouse_x - 5 && x <= mouse_x + 5)
            is_mouse = true;

          if (is_mouse) {
            pixel = 0xFFFFFF;
          }

          if (frontbuffer[y * screen.width + x] != pixel) {
            frontbuffer[y * screen.width + x] = pixel;
            put_pixel(x, y, pixel);
          }
        }
      }
      last_mouse_x = mouse_x;
      last_mouse_y = mouse_y;
    }

    last_mouse_left_state = mouse_left;

    for (int i = 0; i < 5000; i++)
      asm volatile("nop");
  }
}
