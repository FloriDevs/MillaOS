#include <stdint.h>

// Multiboot-Header-Struktur
struct multiboot_header {
    uint32_t magic;
    uint32_t flags;
    uint32_t checksum;
};

const uint32_t MULTIBOOT_MAGIC = 0x1BADB002;
const uint32_t MULTIBOOT_FLAGS = 0x00000003;
const uint32_t MULTIBOOT_CHECKSUM = -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS);

__attribute__((section(".multiboot_header"))) struct multiboot_header header = {
    .magic = MULTIBOOT_MAGIC,
    .flags = MULTIBOOT_FLAGS,
    .checksum = MULTIBOOT_CHECKSUM
};

// ============================================================================
// I/O PORT FUNKTIONEN
// ============================================================================

extern "C" uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

extern "C" void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

void delay(uint32_t count) {
    for (volatile uint32_t i = 0; i < count * 100000; ++i) {
        asm volatile("nop");
    }
}

// ============================================================================
// GRUNDLEGENDE VGA FUNKTIONEN
// ============================================================================

void print_char(int row, int col, char character, uint16_t color) {
    uint16_t* video_memory = (uint16_t*)0xb8000;
    int offset = row * 80 + col;
    video_memory[offset] = (color << 8) | character;
}

void print_string(int row, int col, const char* str, uint16_t color) {
    int i = 0;
    while (str[i] != '\0') {
        print_char(row, col + i, str[i], color);
        i++;
    }
}

void print_string_centered(int row, const char* str, uint16_t color) {
    int len = 0;
    while (str[len] != '\0') len++;
    int col = (80 - len) / 2;
    print_string(row, col, str, color);
}

void clear_screen(uint16_t color) {
    uint16_t* video_memory = (uint16_t*)0xb8000;
    for (int i = 0; i < 80 * 25; ++i) {
        video_memory[i] = (color << 8) | ' ';
    }
}

int string_length(const char* str) {
    int len = 0;
    while (str[len] != '\0') len++;
    return len;
}

void string_copy(char* dest, const char* src) {
    int i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

bool string_compare(const char* s1, const char* s2) {
    int i = 0;
    while (s1[i] != '\0' && s2[i] != '\0') {
        if (s1[i] != s2[i]) return false;
        i++;
    }
    return s1[i] == s2[i];
}

// ============================================================================
// FAT16 DATEISYSTEM SUPPORT
// ============================================================================

#define SECTOR_SIZE 512
#define MAX_FILES 16
#define MAX_FILENAME 11
#define MAX_FILE_SIZE 2048

struct FAT16_BootSector {
    uint8_t jump[3];
    char oem[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t media_type;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t head_count;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;
} __attribute__((packed));

struct FAT16_DirEntry {
    char filename[11];
    uint8_t attributes;
    uint8_t reserved;
    uint8_t creation_time_ms;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high;
    uint16_t last_modified_time;
    uint16_t last_modified_date;
    uint16_t first_cluster_low;
    uint32_t file_size;
} __attribute__((packed));

struct FileEntry {
    char name[MAX_FILENAME + 1];
    uint32_t size;
    bool is_directory;
    char content[MAX_FILE_SIZE];
};

FileEntry virtual_filesystem[MAX_FILES];
int file_count = 0;

void init_filesystem() {
    // Erstelle einige Demo-Dateien
    string_copy(virtual_filesystem[0].name, "README.TXT");
    virtual_filesystem[0].size = 52;
    virtual_filesystem[0].is_directory = false;
    string_copy(virtual_filesystem[0].content, "Welcome to Milla OS!\nThis is a demo text file.");
    
    string_copy(virtual_filesystem[1].name, "HELLO.TXT");
    virtual_filesystem[1].size = 30;
    virtual_filesystem[1].is_directory = false;
    string_copy(virtual_filesystem[1].content, "Hello from the filesystem!");
    
    string_copy(virtual_filesystem[2].name, "NOTES.TXT");
    virtual_filesystem[2].size = 0;
    virtual_filesystem[2].is_directory = false;
    virtual_filesystem[2].content[0] = '\0';
    
    file_count = 3;
}

int find_file(const char* name) {
    for (int i = 0; i < file_count; i++) {
        if (string_compare(virtual_filesystem[i].name, name)) {
            return i;
        }
    }
    return -1;
}

bool save_file(const char* name, const char* content, int size) {
    int idx = find_file(name);
    
    if (idx == -1) {
        if (file_count >= MAX_FILES) return false;
        idx = file_count++;
        string_copy(virtual_filesystem[idx].name, name);
        virtual_filesystem[idx].is_directory = false;
    }
    
    if (size > MAX_FILE_SIZE) size = MAX_FILE_SIZE;
    
    for (int i = 0; i < size; i++) {
        virtual_filesystem[idx].content[i] = content[i];
    }
    virtual_filesystem[idx].content[size] = '\0';
    virtual_filesystem[idx].size = size;
    
    return true;
}

// ============================================================================
// GUI FUNKTIONEN
// ============================================================================

void draw_window(int start_row, int start_col, int height, int width, const char* title, uint16_t border_color) {
    print_char(start_row, start_col, 201, border_color);
    for (int i = 1; i < width - 1; i++) {
        print_char(start_row, start_col + i, 205, border_color);
    }
    print_char(start_row, start_col + width - 1, 187, border_color);
    
    int title_len = string_length(title);
    int title_start = (width - title_len - 2) / 2;
    print_char(start_row, start_col + title_start, 185, border_color);
    print_string(start_row, start_col + title_start + 1, title, 0x0E);
    print_char(start_row, start_col + title_start + title_len + 1, 204, border_color);
    
    for (int i = 1; i < height - 1; i++) {
        print_char(start_row + i, start_col, 186, border_color);
        print_char(start_row + i, start_col + width - 1, 186, border_color);
        for (int j = 1; j < width - 1; j++) {
            print_char(start_row + i, start_col + j, ' ', 0x70);
        }
    }
    
    print_char(start_row + height - 1, start_col, 200, border_color);
    for (int i = 1; i < width - 1; i++) {
        print_char(start_row + height - 1, start_col + i, 205, border_color);
    }
    print_char(start_row + height - 1, start_col + width - 1, 188, border_color);
}

void draw_flower() {
    clear_screen(0x09);
    print_string_centered(8, "     .-.", 0x0D);
    print_string_centered(9, "   .'   '.", 0x0D);
    print_string_centered(10, "  /  o o  \\", 0x0D);
    print_string_centered(11, " |    *    |", 0x0E);
    print_string_centered(12, "  \\  '-'  /", 0x0D);
    print_string_centered(13, "   '.___.'", 0x0D);
    print_string_centered(14, "      |", 0x0A);
    print_string_centered(15, "      |", 0x0A);
    print_string_centered(16, "     / \\", 0x0A);
    print_string_centered(19, "Milla OS 0.30 Beta", 0x0F);
    print_string_centered(20, "Loading...", 0x07);
}

uint8_t get_keyboard_input() {
    while ((inb(0x64) & 0x01) == 0);
    return inb(0x60);
}

char scancode_to_ascii(uint8_t scancode, bool shift) {
    const char scancode_map[] = {
        0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0, 0,
        'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0, 0,
        'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, 0, 0, ' '
    };
    
    const char scancode_map_shift[] = {
        0, 0, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0, 0,
        'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 0, 0,
        'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|',
        'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, 0, 0, ' '
    };
    
    if (scancode < 58) {
        return shift ? scancode_map_shift[scancode] : scancode_map[scancode];
    }
    return 0;
}

// ============================================================================
// DATEIMANAGER
// ============================================================================

void file_manager() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) {
        print_char(0, i, ' ', 0x1F);
    }
    print_string(0, 2, "File Manager", 0x1E);
    print_string(0, 60, "ESC=Exit", 0x1F);
    
    draw_window(2, 5, 20, 70, " Files ", 0x0B);
    
    print_string(4, 8, "Filename", 0x70);
    print_string(4, 30, "Size", 0x70);
    print_string(4, 45, "Type", 0x70);
    
    for (int i = 0; i < 68; i++) {
        print_char(5, 6 + i, 196, 0x70);
    }
    
    int selected = 0;
    bool running = true;
    
    while (running) {
        for (int i = 0; i < file_count && i < 12; i++) {
            uint16_t color = (i == selected) ? 0x07 : 0x70;
            
            print_string(6 + i, 8, "                                                  ", color);
            print_string(6 + i, 8, virtual_filesystem[i].name, color);
            
            char size_str[10] = "        ";
            int size = virtual_filesystem[i].size;
            int pos = 7;
            if (size == 0) {
                size_str[pos--] = '0';
            } else {
                while (size > 0 && pos >= 0) {
                    size_str[pos--] = '0' + (size % 10);
                    size /= 10;
                }
            }
            print_string(6 + i, 30, size_str, color);
            print_string(6 + i, 45, virtual_filesystem[i].is_directory ? "DIR" : "FILE", color);
        }
        
        for (int i = 0; i < 80; i++) {
            print_char(24, i, ' ', 0x70);
        }
        print_string(24, 2, "UP/DOWN=Select ENTER=Open ESC=Exit", 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) { // ESC
            running = false;
        } else if (scancode == 0x48 && selected > 0) { // UP
            selected--;
        } else if (scancode == 0x50 && selected < file_count - 1) { // DOWN
            selected++;
        } else if (scancode == 0x1C) { // ENTER
            // Öffne Datei im Editor (wird später implementiert)
            running = false;
        }
    }
}

// ============================================================================
// TEXTEDITOR
// ============================================================================

void text_editor() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) {
        print_char(0, i, ' ', 0x1F);
    }
    print_string(0, 2, "Text Editor - UNTITLED.TXT", 0x1E);
    print_string(0, 50, "F1=Save ESC=Exit", 0x1F);
    
    char buffer[800];
    int buffer_pos = 0;
    for (int i = 0; i < 800; i++) buffer[i] = ' ';
    
    int cursor_row = 2;
    int cursor_col = 0;
    bool shift_pressed = false;
    bool running = true;
    
    while (running) {
        // Zeige Text an
        for (int row = 2; row < 24; row++) {
            for (int col = 0; col < 80; col++) {
                int pos = (row - 2) * 80 + col;
                print_char(row, col, buffer[pos], 0x0F);
            }
        }
        
        // Cursor anzeigen
        print_char(cursor_row, cursor_col, 219, 0x0E);
        
        // Statusleiste
        for (int i = 0; i < 80; i++) {
            print_char(24, i, ' ', 0x70);
        }
        char status[40];
        string_copy(status, "Row: ");
        status[5] = '0' + (cursor_row / 10);
        status[6] = '0' + (cursor_row % 10);
        status[7] = ' ';
        status[8] = 'C';
        status[9] = 'o';
        status[10] = 'l';
        status[11] = ':';
        status[12] = ' ';
        status[13] = '0' + (cursor_col / 10);
        status[14] = '0' + (cursor_col % 10);
        status[15] = '\0';
        print_string(24, 2, status, 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) { // ESC
            running = false;
        } else if (scancode == 0x3B) { // F1 - Save
            save_file("UNTITLED.TXT", buffer, 800);
            print_string(24, 30, "File saved!", 0x70);
            delay(2);
        } else if (scancode == 0x2A || scancode == 0x36) { // Shift
            shift_pressed = true;
        } else if (scancode == 0xAA || scancode == 0xB6) { // Shift released
            shift_pressed = false;
        } else if (scancode == 0x48 && cursor_row > 2) { // UP
            cursor_row--;
        } else if (scancode == 0x50 && cursor_row < 23) { // DOWN
            cursor_row++;
        } else if (scancode == 0x4B && cursor_col > 0) { // LEFT
            cursor_col--;
        } else if (scancode == 0x4D && cursor_col < 79) { // RIGHT
            cursor_col++;
        } else if (scancode == 0x0E) { // Backspace
            int pos = (cursor_row - 2) * 80 + cursor_col;
            if (pos > 0) {
                buffer[pos - 1] = ' ';
                if (cursor_col > 0) {
                    cursor_col--;
                } else if (cursor_row > 2) {
                    cursor_row--;
                    cursor_col = 79;
                }
            }
        } else if (scancode == 0x1C) { // Enter
            if (cursor_row < 23) {
                cursor_row++;
                cursor_col = 0;
            }
        } else {
            char ch = scancode_to_ascii(scancode, shift_pressed);
            if (ch != 0) {
                int pos = (cursor_row - 2) * 80 + cursor_col;
                buffer[pos] = ch;
                if (cursor_col < 79) {
                    cursor_col++;
                } else if (cursor_row < 23) {
                    cursor_row++;
                    cursor_col = 0;
                }
            }
        }
    }
}

// ============================================================================
// TASCHENRECHNER
// ============================================================================

void calculator() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) {
        print_char(0, i, ' ', 0x1F);
    }
    print_string(0, 2, "Calculator", 0x1E);
    print_string(0, 60, "ESC=Exit", 0x1F);
    
    draw_window(3, 20, 18, 40, " Calculator ", 0x0B);
    
    char display[20] = "0";
    int display_len = 1;
    int num1 = 0;
    int num2 = 0;
    char operation = 0;
    bool new_number = true;
    bool running = true;
    bool shift_pressed = false;
    
    while (running) {
        // Display anzeigen
        print_string(5, 22, "                                  ", 0x70);
        print_string(5, 22, display, 0x0F);
        
        // Buttons
        const char* buttons[] = {
            "7", "8", "9", "/",
            "4", "5", "6", "*",
            "1", "2", "3", "-",
            "0", "C", "=", "+"
        };
        
        for (int i = 0; i < 16; i++) {
            int row = 7 + (i / 4) * 2;
            int col = 23 + (i % 4) * 8;
            print_string(row, col, "[", 0x70);
            print_string(row, col + 1, buttons[i], 0x0E);
            print_string(row, col + 2, "]", 0x70);
        }
        
        for (int i = 0; i < 80; i++) {
            print_char(24, i, ' ', 0x70);
        }
        print_string(24, 2, "Type numbers and operators, ESC=Exit", 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) { // ESC
            running = false;
        } else if (scancode == 0x2A || scancode == 0x36) {
            shift_pressed = true;
        } else if (scancode == 0xAA || scancode == 0xB6) {
            shift_pressed = false;
        } else {
            char ch = scancode_to_ascii(scancode, shift_pressed);
            
            if (ch >= '0' && ch <= '9') {
                if (new_number) {
                    display[0] = ch;
                    display[1] = '\0';
                    display_len = 1;
                    new_number = false;
                } else if (display_len < 15) {
                    display[display_len++] = ch;
                    display[display_len] = '\0';
                }
            } else if (ch == '+' || ch == '-' || ch == '*' || ch == '/') {
                num1 = 0;
                for (int i = 0; i < display_len; i++) {
                    num1 = num1 * 10 + (display[i] - '0');
                }
                operation = ch;
                new_number = true;
            } else if (ch == '=' || scancode == 0x1C) { // Enter
                num2 = 0;
                for (int i = 0; i < display_len; i++) {
                    num2 = num2 * 10 + (display[i] - '0');
                }
                
                int result = 0;
                if (operation == '+') result = num1 + num2;
                else if (operation == '-') result = num1 - num2;
                else if (operation == '*') result = num1 * num2;
                else if (operation == '/' && num2 != 0) result = num1 / num2;
                
                display_len = 0;
                if (result == 0) {
                    display[0] = '0';
                    display_len = 1;
                } else {
                    char temp[20];
                    int temp_len = 0;
                    int r = result;
                    bool negative = false;
                    
                    if (r < 0) {
                        negative = true;
                        r = -r;
                    }
                    
                    while (r > 0) {
                        temp[temp_len++] = '0' + (r % 10);
                        r /= 10;
                    }
                    
                    if (negative) display[display_len++] = '-';
                    
                    for (int i = temp_len - 1; i >= 0; i--) {
                        display[display_len++] = temp[i];
                    }
                }
                display[display_len] = '\0';
                operation = 0;
                new_number = true;
            } else if (ch == 'c' || ch == 'C') {
                display[0] = '0';
                display[1] = '\0';
                display_len = 1;
                num1 = 0;
                num2 = 0;
                operation = 0;
                new_number = true;
            }
        }
    }
}

// ============================================================================
// HAUPTMENÜ
// ============================================================================

void main_menu() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) {
        print_char(0, i, ' ', 0x1F);
    }
    print_string(0, 2, "Milla OS 0.30 Beta - Main Menu", 0x1E);
    
    draw_window(5, 25, 14, 30, " Menu ", 0x0B);
    
    const char* menu_items[] = {
        "1. File Manager",
        "2. Text Editor",
        "3. Calculator",
        "4. Exit to Desktop"
    };
    
    int selected = 0;
    bool running = true;
    
    while (running) {
        for (int i = 0; i < 4; i++) {
            uint16_t color = (i == selected) ? 0x07 : 0x70;
            print_string(7 + i * 2, 28, "                        ", color);
            print_string(7 + i * 2, 28, menu_items[i], color);
        }
        
        for (int i = 0; i < 80; i++) {
            print_char(24, i, ' ', 0x70);
        }
        print_string(24, 2, "UP/DOWN=Select ENTER=Open ESC=Desktop", 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) { // ESC
            running = false;
        } else if (scancode == 0x48 && selected > 0) { // UP
            selected--;
        } else if (scancode == 0x50 && selected < 3) { // DOWN
            selected++;
        } else if (scancode == 0x1C) { // ENTER
            if (selected == 0) {
                file_manager();
                clear_screen(0x03);
                for (int i = 0; i < 80; i++) {
                    print_char(0, i, ' ', 0x1F);
                }
                print_string(0, 2, "Milla OS 0.30 Beta - Main Menu", 0x1E);
                draw_window(5, 25, 14, 30, " Menu ", 0x0B);
            } else if (selected == 1) {
                text_editor();
                clear_screen(0x03);
                for (int i = 0; i < 80; i++) {
                    print_char(0, i, ' ', 0x1F);
                }
                print_string(0, 2, "Milla OS 0.30 Beta - Main Menu", 0x1E);
                draw_window(5, 25, 14, 30, " Menu ", 0x0B);
            } else if (selected == 2) {
                calculator();
                clear_screen(0x03);
                for (int i = 0; i < 80; i++) {
                    print_char(0, i, ' ', 0x1F);
                }
                print_string(0, 2, "Milla OS 0.30 Beta - Main Menu", 0x1E);
                draw_window(5, 25, 14, 30, " Menu ", 0x0B);
            } else if (selected == 3) {
                running = false;
            }
        }
    }
}

// ============================================================================
// DESKTOP
// ============================================================================

void desktop() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) {
        print_char(0, i, ' ', 0x1F);
    }
    print_string(0, 2, "Milla OS 0.30 Beta", 0x1E);
    print_string(0, 60, "[MENU]", 0x4F);
    
    draw_window(3, 10, 12, 60, " Welcome ", 0x0B);
    print_string(5, 15, "Welcome to Milla OS!", 0x70);
    print_string(7, 15, "A FOSS Operating System", 0x78);
    print_string(8, 15, "by FloriDevs", 0x78);
    print_string(10, 15, "Press F1 for Menu", 0x70);
    print_string(11, 15, "Arrow keys to move cursor", 0x70);
    
    for (int i = 0; i < 80; i++) {
        print_char(24, i, ' ', 0x70);
    }
    print_string(24, 2, "Ready", 0x70);
    
    int cursor_row = 12;
    int cursor_col = 40;
    
    while (1) {
        print_char(cursor_row, cursor_col, 219, 0x0E);
        
        char status[30] = "Cursor: [  ,  ]";
        status[9] = '0' + (cursor_row / 10);
        status[10] = '0' + (cursor_row % 10);
        status[12] = '0' + (cursor_col / 10);
        status[13] = '0' + (cursor_col % 10);
        print_string(24, 60, status, 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        print_char(cursor_row, cursor_col, ' ', 0x03);
        
        if (scancode == 0x3B) { // F1
            main_menu();
            clear_screen(0x03);
            for (int i = 0; i < 80; i++) {
                print_char(0, i, ' ', 0x1F);
            }
            print_string(0, 2, "Milla OS 0.30 Beta", 0x1E);
            print_string(0, 60, "[MENU]", 0x4F);
            draw_window(3, 10, 12, 60, " Welcome ", 0x0B);
            print_string(5, 15, "Welcome to Milla OS!", 0x70);
            print_string(7, 15, "A FOSS Operating System", 0x78);
            print_string(8, 15, "by FloriDevs", 0x78);
            print_string(10, 15, "Press F1 for Menu", 0x70);
            print_string(11, 15, "Arrow keys to move cursor", 0x70);
            for (int i = 0; i < 80; i++) {
                print_char(24, i, ' ', 0x70);
            }
            print_string(24, 2, "Ready", 0x70);
        } else if (scancode == 0x4B && cursor_col > 0) { // LEFT
            cursor_col--;
        } else if (scancode == 0x4D && cursor_col < 79) { // RIGHT
            cursor_col++;
        } else if (scancode == 0x48 && cursor_row > 1) { // UP
            cursor_row--;
        } else if (scancode == 0x50 && cursor_row < 23) { // DOWN
            cursor_row++;
        }
    }
}

// ============================================================================
// KERNEL MAIN
// ============================================================================

extern "C" void kernel_main() {
    // Initialisiere Dateisystem
    init_filesystem();
    
    // Startanimation mit Blume
    draw_flower();
    delay(10); // ~1 Sekunde
    
    // Starte Desktop
    desktop();
}