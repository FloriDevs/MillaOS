#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

extern "C" {
uint8_t get_keyboard_input_nonblock();
char shell_scancode_to_ascii(uint8_t scancode, bool shift);
int get_shell_file_count();
void get_shell_file_name(int index, char *out);
uint32_t get_shell_file_size(int index);
bool get_shell_file_is_dir(int index);
void shell_refresh_files();
bool shell_is_fs_mounted();
bool shell_read_file(const char *filename, char *buffer, uint32_t max_size);
bool shell_write_file(const char *filename, const char *data, uint32_t size);
bool shell_delete_file(const char *filename);
void put_pixel(int x, int y, uint32_t color);
void delay(uint32_t count);
}

struct Graphics {
  uint32_t *framebuffer;
  uint32_t width;
  uint32_t height;
  uint32_t pitch;
  bool active;
};
extern Graphics screen;

// ============================================================================
// 8x8 BITMAP FONT FOR Oyster (CHARACTER MAP INITIALIZER)
// ============================================================================
static uint8_t Oyster_font[128][8] = {0};

static void Oyster_init_font() {
  static bool font_inited = false;
  if (font_inited)
    return;
  font_inited = true;

  struct CharDef {
    char c;
    uint8_t data[8];
  };

  CharDef chars[] = {
      {'A', {0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00}},
      {'B', {0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00}},
      {'C', {0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00}},
      {'D', {0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00}},
      {'E', {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00}},
      {'F', {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00}},
      {'G', {0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00}},
      {'H', {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00}},
      {'I', {0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00}},
      {'J', {0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00}},
      {'K', {0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00}},
      {'L', {0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00}},
      {'M', {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00}},
      {'N', {0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00}},
      {'O', {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}},
      {'P', {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00}},
      {'Q', {0x3C, 0x66, 0x66, 0x66, 0x6A, 0x3C, 0x06, 0x00}},
      {'R', {0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00}},
      {'S', {0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00}},
      {'T', {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
      {'U', {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}},
      {'V', {0x66, 0x66, 0x66, 0x66, 0x3C, 0x3C, 0x18, 0x00}},
      {'W', {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00}},
      {'X', {0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00}},
      {'Y', {0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00}},
      {'Z', {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00}},
      {'a', {0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00}},
      {'b', {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00}},
      {'c', {0x00, 0x00, 0x3C, 0x60, 0x60, 0x66, 0x3C, 0x00}},
      {'d', {0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00}},
      {'e', {0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00}},
      {'f', {0x1C, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x30, 0x00}},
      {'g', {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C}},
      {'h', {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00}},
      {'i', {0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
      {'j', {0x06, 0x00, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00}},
      {'k', {0x60, 0x60, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x00}},
      {'l', {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x1C, 0x00}},
      {'m', {0x00, 0x00, 0x76, 0x7F, 0x6B, 0x6B, 0x6B, 0x00}},
      {'n', {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00}},
      {'o', {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00}},
      {'p', {0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60}},
      {'q', {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06}},
      {'r', {0x00, 0x00, 0x3E, 0x60, 0x60, 0x60, 0x60, 0x00}},
      {'s', {0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00}},
      {'t', {0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00}},
      {'u', {0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00}},
      {'v', {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00}},
      {'w', {0x00, 0x00, 0x63, 0x6B, 0x7F, 0x3E, 0x36, 0x00}},
      {'x', {0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00}},
      {'y', {0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C}},
      {'z', {0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00}},
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
      {'/', {0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00, 0x00}},
      {'_', {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00}},
      {'>', {0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00}},
      {'<', {0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00}},
      {'|', {0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}},
      {'*', {0x00, 0x00, 0x14, 0x08, 0x3E, 0x08, 0x14, 0x00}},
      {'=', {0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00}},
      {'!', {0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00}},
      {'"', {0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00}},
      {'#', {0x66, 0x66, 0x7E, 0x66, 0x7E, 0x66, 0x66, 0x00}},
      {'$', {0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00}},
      {'%', {0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00}},
      {'&', {0x3C, 0x66, 0x3C, 0x38, 0x6E, 0x66, 0x3B, 0x00}},
      {'\'', {0x06, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00}},
      {';', {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00}},
      {'?', {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00}},
      {'[', {0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00}},
      {'\\', {0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x00, 0x00}},
      {']', {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00}},
      {'^', {0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00}},
      {'`', {0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}},
      {'{', {0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00}},
      {'}', {0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00}},
      {'~', {0x3B, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}};

  for (unsigned i = 0; i < sizeof(chars) / sizeof(chars[0]); i++) {
    uint8_t code = (uint8_t)chars[i].c;
    if (code < 128) {
      for (int j = 0; j < 8; j++) {
        Oyster_font[code][j] = chars[i].data[j];
      }
    }
  }
}

// ============================================================================
// Oyster SCREEN OUTPUT ENGINE
// ============================================================================
#define Oyster_BG_COLOR 0x0A0F1D
#define Oyster_FG_COLOR 0x00FF66

static int Oyster_cursor_x = 0; // column (0 .. Oyster_COLS - 1)
static int Oyster_cursor_y = 0; // row (0 .. Oyster_ROWS - 1)

static int Oyster_COLS = 100;
static int Oyster_ROWS = 75;

static void Oyster_draw_glyph(int col, int row, char c, uint32_t fg, uint32_t bg) {
  if (!screen.active || !screen.framebuffer)
    return;

  Oyster_init_font();

  int start_x = col * 8;
  int start_y = row * 8;
  uint8_t glyph_idx = (uint8_t)c;
  if (glyph_idx > 127)
    glyph_idx = '?';

  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      int px = start_x + j;
      int py = start_y + i;
      if (px >= (int)screen.width || py >= (int)screen.height)
        continue;

      bool pixel_set = (Oyster_font[glyph_idx][i] & (1 << (7 - j))) != 0;
      screen.framebuffer[py * (screen.pitch / 4) + px] = pixel_set ? fg : bg;
    }
  }
}

static void Oyster_scroll_up() {
  if (!screen.active || !screen.framebuffer)
    return;

  uint32_t pitch_dwords = screen.pitch / 4;
  uint32_t line_height = 8;
  uint32_t total_scroll_pixels = (screen.height - line_height) * pitch_dwords;

  // Shift screen buffer up by 8 pixel lines
  for (uint32_t i = 0; i < total_scroll_pixels; i++) {
    screen.framebuffer[i] = screen.framebuffer[i + (line_height * pitch_dwords)];
  }

  // Clear bottom 8 pixel lines
  uint32_t bottom_start = total_scroll_pixels;
  uint32_t total_pixels = screen.width * screen.height;
  for (uint32_t i = bottom_start; i < total_pixels; i++) {
    screen.framebuffer[i] = Oyster_BG_COLOR;
  }
}

extern "C" void Oyster_clear() {
  if (!screen.active || !screen.framebuffer)
    return;

  uint32_t total_pixels = screen.width * screen.height;
  for (uint32_t i = 0; i < total_pixels; i++) {
    screen.framebuffer[i] = Oyster_BG_COLOR;
  }
  Oyster_cursor_x = 0;
  Oyster_cursor_y = 0;

  Oyster_COLS = screen.width / 8;
  Oyster_ROWS = screen.height / 8;
}

extern "C" void Oyster_putchar(char c) {
  if (c == '\n') {
    Oyster_cursor_x = 0;
    Oyster_cursor_y++;
  } else if (c == '\r') {
    Oyster_cursor_x = 0;
  } else if (c == '\b') {
    if (Oyster_cursor_x > 0) {
      Oyster_cursor_x--;
      Oyster_draw_glyph(Oyster_cursor_x, Oyster_cursor_y, ' ', Oyster_FG_COLOR, Oyster_BG_COLOR);
    }
  } else if (c == '\t') {
    int spaces = 4 - (Oyster_cursor_x % 4);
    for (int i = 0; i < spaces; i++) {
      Oyster_putchar(' ');
    }
  } else {
    Oyster_draw_glyph(Oyster_cursor_x, Oyster_cursor_y, c, Oyster_FG_COLOR, Oyster_BG_COLOR);
    Oyster_cursor_x++;
    if (Oyster_cursor_x >= Oyster_COLS) {
      Oyster_cursor_x = 0;
      Oyster_cursor_y++;
    }
  }

  while (Oyster_cursor_y >= Oyster_ROWS) {
    Oyster_scroll_up();
    Oyster_cursor_y = Oyster_ROWS - 1;
  }
}

extern "C" void Oyster_print(const char *str) {
  while (*str) {
    Oyster_putchar(*str++);
  }
}

extern "C" void Oyster_println(const char *str) {
  Oyster_print(str);
  Oyster_putchar('\n');
}

// Simple integer formatting helper for Oyster_printf
static void Oyster_print_num(int val, int base) {
  char buf[32];
  if (val == 0) {
    Oyster_putchar('0');
    return;
  }
  bool neg = false;
  if (val < 0 && base == 10) {
    neg = true;
    val = -val;
  }
  int pos = 0;
  const char *digits = "0123456789ABCDEF";
  while (val > 0) {
    buf[pos++] = digits[val % base];
    val /= base;
  }
  if (neg) buf[pos++] = '-';
  while (pos > 0) {
    Oyster_putchar(buf[--pos]);
  }
}

extern "C" void Oyster_printf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  while (*fmt) {
    if (*fmt == '%') {
      fmt++;
      if (*fmt == 's') {
        const char *s = va_arg(args, const char *);
        Oyster_print(s ? s : "(null)");
      } else if (*fmt == 'd' || *fmt == 'i') {
        int d = va_arg(args, int);
        Oyster_print_num(d, 10);
      } else if (*fmt == 'u') {
        unsigned int u = va_arg(args, unsigned int);
        Oyster_print_num(u, 10);
      } else if (*fmt == 'x' || *fmt == 'X') {
        int x = va_arg(args, int);
        Oyster_print_num(x, 16);
      } else if (*fmt == 'c') {
        char c = (char)va_arg(args, int);
        Oyster_putchar(c);
      } else if (*fmt == '%') {
        Oyster_putchar('%');
      }
    } else {
      Oyster_putchar(*fmt);
    }
    fmt++;
  }
  va_end(args);
}

// ============================================================================
// HELPER UTILITIES FOR STRING MANIPULATION
// ============================================================================
static int Oyster_strlen(const char *s) {
  int len = 0;
  while (s[len]) len++;
  return len;
}

static bool Oyster_strcmp(const char *s1, const char *s2) {
  while (*s1 && *s2) {
    if (*s1 != *s2) return false;
    s1++;
    s2++;
  }
  return *s1 == *s2;
}

static const char *Oyster_strstr(const char *haystack, const char *needle) {
  if (!*needle) return haystack;
  for (; *haystack; haystack++) {
    const char *h = haystack;
    const char *n = needle;
    while (*h && *n && *h == *n) {
      h++;
      n++;
    }
    if (!*n) return haystack;
  }
  return NULL;
}

// ============================================================================
// COMMAND REGISTRATION SYSTEM
// ============================================================================
typedef void (*Oyster_cmd_func_t)(int argc, char **argv);

struct OysterCommand {
  char name[32];
  char description[64];
  Oyster_cmd_func_t func;
};

#define MAX_Oyster_COMMANDS 64
static OysterCommand Oyster_commands[MAX_Oyster_COMMANDS];
static int Oyster_command_count = 0;

extern "C" bool Oyster_register_command(const char *name, const char *description,
                                    Oyster_cmd_func_t func) {
  if (Oyster_command_count >= MAX_Oyster_COMMANDS)
    return false;

  int i = 0;
  while (name[i] && i < 31) {
    Oyster_commands[Oyster_command_count].name[i] = name[i];
    i++;
  }
  Oyster_commands[Oyster_command_count].name[i] = '\0';

  i = 0;
  while (description[i] && i < 63) {
    Oyster_commands[Oyster_command_count].description[i] = description[i];
    i++;
  }
  Oyster_commands[Oyster_command_count].description[i] = '\0';

  Oyster_commands[Oyster_command_count].func = func;
  Oyster_command_count++;
  return true;
}

// ============================================================================
// BUILT-IN UNIX & SYSTEM COMMANDS
// ============================================================================
static bool Oyster_running = true;

static void cmd_help(int argc, char **argv) {
  Oyster_println("Available Commands:");
  Oyster_println("------------------------------------------------------------");
  for (int i = 0; i < Oyster_command_count; i++) {
    Oyster_printf("  %-10s : %s\n", Oyster_commands[i].name,
               Oyster_commands[i].description);
  }
  Oyster_println("------------------------------------------------------------");
  Oyster_println("Press F12 to switch back to MNDE (Milla Next Desktop environment).");
}

static void cmd_clear(int argc, char **argv) {
  Oyster_clear();
}

static void cmd_echo(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    Oyster_print(argv[i]);
    if (i < argc - 1)
      Oyster_print(" ");
  }
  Oyster_println("");
}

static void cmd_exit(int argc, char **argv) {
  Oyster_running = false;
}

static void cmd_ls(int argc, char **argv) {
  shell_refresh_files();
  if (!shell_is_fs_mounted()) {
    Oyster_println("ls: No mounted filesystem found.");
    return;
  }
  int count = get_shell_file_count();
  if (count == 0) {
    Oyster_println("ls: Directory is empty.");
    return;
  }
  Oyster_printf("Directory Listing (%d files):\n", count);
  for (int i = 0; i < count; i++) {
    char fname[64];
    get_shell_file_name(i, fname);
    uint32_t fsize = get_shell_file_size(i);
    bool is_dir = get_shell_file_is_dir(i);

    if (is_dir) {
      Oyster_printf("  [DIR]  %-24s\n", fname);
    } else {
      Oyster_printf("  [FILE] %-24s  %u bytes\n", fname, fsize);
    }
  }
}

static void cmd_cat(int argc, char **argv) {
  if (argc < 2) {
    Oyster_println("Usage: cat <filename>");
    return;
  }
  static char cat_buf[32768];
  if (shell_read_file(argv[1], cat_buf, sizeof(cat_buf) - 1)) {
    Oyster_println(cat_buf);
  } else {
    Oyster_printf("cat: %s: No such file or unable to read\n", argv[1]);
  }
}

static void cmd_grep(int argc, char **argv) {
  if (argc < 3) {
    Oyster_println("Usage: grep <pattern> <filename>");
    return;
  }
  const char *pattern = argv[1];
  const char *filename = argv[2];

  static char grep_buf[32768];
  if (!shell_read_file(filename, grep_buf, sizeof(grep_buf) - 1)) {
    Oyster_printf("grep: %s: No such file or unable to read\n", filename);
    return;
  }

  char *line = grep_buf;
  while (*line) {
    char *end = line;
    while (*end && *end != '\n' && *end != '\r') {
      end++;
    }
    char saved = *end;
    *end = '\0';

    if (Oyster_strstr(line, pattern)) {
      Oyster_println(line);
    }

    if (saved == '\0')
      break;
    line = end + 1;
    if (saved == '\r' && *line == '\n')
      line++;
  }
}

static void cmd_rm(int argc, char **argv) {
  if (argc < 2) {
    Oyster_println("Usage: rm <filename>");
    return;
  }
  if (shell_delete_file(argv[1])) {
    Oyster_printf("rm: File '%s' deleted successfully.\n", argv[1]);
  } else {
    Oyster_printf("rm: cannot remove '%s': No such file or operation failed\n",
               argv[1]);
  }
}
static void cmd_mname(int argc, char **argv) {
  Oyster_clear();
  Oyster_println(" ");
  Oyster_println("Kernel: 2.1");
  Oyster_println("MPra-RE 2.0.1");
  Oyster_println("Milla-Next-Desktop-Enviroment: 1.1.3");
  Oyster_println("Oyster Command Line: 1.0");
  Oyster_println("Dev. Date: 17.09.2026");
  Oyster_println(" ");
  Oyster_println("===================================================");
  Oyster_println("                     Milla OS                     ");
  Oyster_println("                 Version 2.1.4");
  Oyster_println("                Codename: Appril");


  Oyster_println("===================================================");
  Oyster_println(" ");
  Oyster_println("          MillaOS is still in development   ");
  Oyster_println("If you have problems or questions fell free to send an email to:");
  Oyster_println("millaos@floridevs.dedyn.io");
  Oyster_println(" ");
  

}

static void Oyster_init_commands() { //set commands
  if (Oyster_command_count > 0)
    return; 

  Oyster_register_command("help", "List all available Oyster commands", cmd_help);
  Oyster_register_command("ls", "List files in current volume", cmd_ls);
  Oyster_register_command("cat", "Display file contents", cmd_cat);
  Oyster_register_command("grep", "Search pattern in file line-by-line", cmd_grep);
  Oyster_register_command("rm", "Remove/delete specified file", cmd_rm);
  Oyster_register_command("echo", "Print argument text to output", cmd_echo);
  Oyster_register_command("clear", "Clear terminal screen", cmd_clear);
  Oyster_register_command("exit", "Exit Oyster and return to Graphical Shell", cmd_exit);
  Oyster_register_command("startmnde", "Exit Oyster and return to Graphical Shell", cmd_exit);
  Oyster_register_command("mname", "Shows everything about M.I.L.L.A. OS", cmd_mname);
  Oyster_register_command("startn", "Exit Oyster and return to Graphical Shell", cmd_exit);
}

// ============================================================================
// MAIN Oyster LOOP & ENTRY POINT
// ============================================================================
extern "C" void start_cli() {
  Oyster_init_font();
  Oyster_init_commands();
  Oyster_clear();

  Oyster_println("===============================================================================");
  Oyster_println("                               Oyster - Milla OS Command Line                      ");
  Oyster_println("===============================================================================");
  Oyster_println("Type 'help' for a list of available commands.");
  Oyster_println("Press F12 or type 'exit' to switch back to the Graphical Shell.\n");

  Oyster_running = true;

  char input_buffer[256];
  int input_pos = 0;
  input_buffer[0] = '\0';

  bool shift_pressed = false;

  Oyster_print("o> ");

  while (Oyster_running) {
    uint8_t sc = get_keyboard_input_nonblock();
    if (sc == 0) {
      continue;
    }

    // F12 key (scancode 0x58) -> exit Oyster
    if (sc == 0x58) {
      Oyster_running = false;
      break;
    }

    // Shift key press / release
    if (sc == 0x2A || sc == 0x36) {
      shift_pressed = true;
      continue;
    } else if (sc == (0x2A | 0x80) || sc == (0x36 | 0x80)) {
      shift_pressed = false;
      continue;
    }

    // Key release filter
    if (sc & 0x80)
      continue;

    // Backspace (scancode 0x0E)
    if (sc == 0x0E) {
      if (input_pos > 0) {
        input_pos--;
        input_buffer[input_pos] = '\0';
        Oyster_putchar('\b');
      }
      continue;
    }

    // Enter key (scancode 0x1C)
    if (sc == 0x1C) {
      Oyster_putchar('\n');
      input_buffer[input_pos] = '\0';

      if (input_pos > 0) {
        // Parse arguments
        char *argv[16];
        int argc = 0;
        char *p = input_buffer;

        while (*p && argc < 16) {
          while (*p == ' ') p++;
          if (*p == '\0') break;

          argv[argc++] = p;
          while (*p && *p != ' ') p++;

          if (*p == ' ') {
            *p = '\0';
            p++;
          }
        }

        if (argc > 0) {
          bool found = false;
          for (int i = 0; i < Oyster_command_count; i++) {
            if (Oyster_strcmp(Oyster_commands[i].name, argv[0])) {
              Oyster_commands[i].func(argc, argv);
              found = true;
              break;
            }
          }
          if (!found) {
            Oyster_printf("Command not found: %s. Type 'help' for available commands.\n", argv[0]);
          }
        }
      }

      input_pos = 0;
      input_buffer[0] = '\0';

      if (Oyster_running) {
        Oyster_print("o> ");
      }
      continue;
    }

    // ASCII character input
    char ascii = shell_scancode_to_ascii(sc, shift_pressed);
    if (ascii >= 32 && ascii <= 126) {
      if (input_pos < (int)sizeof(input_buffer) - 1) {
        input_buffer[input_pos++] = ascii;
        input_buffer[input_pos] = '\0';
        Oyster_putchar(ascii);
      }
    }
  }

  Oyster_println("\nExiting Oyster mode...");
  delay(100);
}
