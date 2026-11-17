#include <stddef.h>
#include <stdint.h>

extern "C" {
void *malloc(size_t size);
void free(void *ptr);

// Date/Time
struct Time {
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
};
Time get_time();

// C-String und Speicherfunktionen
int string_length(const char *str);
void string_copy(char *dest, const char *src);
bool string_compare(const char *s1, const char *s2);
void memset(void *ptr, uint8_t value, uint32_t size);
void memcpy(void *dest, const void *src, uint32_t size);
}


static uint8_t kernel_heap[16 * 1024 * 1024]; // 3 MB heap
static size_t heap_top = 0;

extern "C" void *malloc(size_t size) {
  if (heap_top + size >= sizeof(kernel_heap))
    return nullptr;
  void *ptr = &kernel_heap[heap_top];
  heap_top += size;
  return ptr;
}

extern "C" void free(void *) {
  // no-op for now
}

// C++ operators
void *operator new(size_t size) { return malloc(size); }
void *operator new[](size_t size) { return malloc(size); }
void operator delete(void *p) noexcept { free(p); }
void operator delete[](void *p) noexcept { free(p); }

// Multiboot-Header-Struktur
struct multiboot_header {
  uint32_t magic;
  uint32_t flags;
  uint32_t checksum;
  // Padding/Address fields (must be present to reach offset 32 for graphics
  // fields)
  uint32_t header_addr;
  uint32_t load_addr;
  uint32_t load_end_addr;
  uint32_t bss_end_addr;
  uint32_t entry_addr;
  // Graphics fields (Offset 32)
  uint32_t mode_type;
  uint32_t width;
  uint32_t height;
  uint32_t depth;
};

const uint32_t MULTIBOOT_MAGIC = 0x1BADB002;
// Flags: Modules aligned (1), Mem info (2), Graphics mode (4)
const uint32_t MULTIBOOT_FLAGS = 0x00000007;
const uint32_t MULTIBOOT_CHECKSUM = -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS);

__attribute__((section(".multiboot_header"))) struct multiboot_header header = {
    .magic = MULTIBOOT_MAGIC,
    .flags = MULTIBOOT_FLAGS,
    .checksum = MULTIBOOT_CHECKSUM,
    .header_addr = 0,
    .load_addr = 0,
    .load_end_addr = 0,
    .bss_end_addr = 0,
    .entry_addr = 0,
    .mode_type = 0, // 0 = linear graphics mode
    .width = 800,
    .height = 600,
    .depth = 32};

// VBE Info Structures
struct vbe_mode_info {
  uint16_t attributes;
  uint8_t win_a, win_b;
  uint16_t granularity;
  uint16_t winsize;
  uint16_t segment_a, segment_b;
  uint32_t win_funcptr;
  uint16_t bytes_per_scanline;
  uint16_t x_res, y_res;
  uint8_t x_charsize, y_charsize, planes, bpp, banks;
  uint8_t memory_model, bank_size, image_pages, reserved0;
  uint8_t red_mask, red_position;
  uint8_t green_mask, green_position;
  uint8_t blue_mask, blue_position;
  uint8_t reserved_mask, reserved_position;
  uint8_t direct_color_attributes;
  uint32_t framebuffer;
  uint32_t off_screen_mem_off;
  uint16_t off_screen_mem_size;
  uint8_t reserved1[206];
} __attribute__((packed));

struct multiboot_info {
  uint32_t flags;
  uint32_t mem_lower;
  uint32_t mem_upper;
  uint32_t boot_device;
  uint32_t cmdline;
  uint32_t mods_count;
  uint32_t mods_addr;
  uint32_t syms[4];
  uint32_t mmap_length;
  uint32_t mmap_addr;
  uint32_t drives_length;
  uint32_t drives_addr;
  uint32_t config_table;
  uint32_t boot_loader_name;
  uint32_t apm_table;
  uint32_t vbe_control_info;
  uint32_t vbe_mode_info;
  uint16_t vbe_mode;
  uint16_t vbe_interface_seg;
  uint16_t vbe_interface_off;
  uint16_t vbe_interface_len;

  // Framebuffer info (Bit 12)
  uint64_t framebuffer_addr;
  uint32_t framebuffer_pitch;
  uint32_t framebuffer_width;
  uint32_t framebuffer_height;
  uint8_t framebuffer_bpp;
  uint8_t framebuffer_type;
  uint8_t color_info[6];
} __attribute__((packed));

struct Graphics {
  uint32_t *framebuffer;
  uint32_t width;
  uint32_t height;
  uint32_t pitch;
  bool active;
} screen;

extern "C" void put_pixel(int x, int y, uint32_t color) {
  if (!screen.active || x < 0 || (uint32_t)x >= screen.width || y < 0 ||
      (uint32_t)y >= screen.height)
    return;
  screen.framebuffer[y * (screen.pitch / 4) + x] = color;
}

uint32_t system_ram_mb = 0;

extern "C" uint32_t get_total_ram_mb() { return system_ram_mb; }

// ============================================================================
// I/O PORT FUNKTIONEN
// ============================================================================

extern "C" uint8_t inb(uint16_t port) {
  uint8_t ret;
  asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

extern "C" uint16_t inw(uint16_t port) {
  uint16_t ret;
  asm volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

extern "C" uint32_t inl(uint16_t port) {
  uint32_t ret;
  asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
  return ret;
}

extern "C" void outb(uint16_t port, uint8_t val) {
  asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

extern "C" void outw(uint16_t port, uint16_t val) {
  asm volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

extern "C" void outl(uint16_t port, uint32_t val) {
  asm volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

extern "C" void insl(uint16_t port, void *addr, uint32_t count) {
  asm volatile("cld; rep insl"
               : "+D"(addr), "+c"(count)
               : "d"(port)
               : "memory");
}

extern "C" void outsl(uint16_t port, const void *addr, uint32_t count) {
  asm volatile("cld; rep outsl"
               : "+S"(addr), "+c"(count)
               : "d"(port)
               : "memory");
}

// Verbesserte Delay-Funktion (wichtig!)
extern "C" void delay(uint32_t count) {
  for (volatile uint32_t i = 0; i < count * 1000000; ++i) {
    asm volatile("nop");
  }
}

// Kürzere Delay für I/O-Operationen
void io_wait() {
  for (volatile int i = 0; i < 4; ++i) {
    inb(0x80); // Port 0x80 für I/O-Delay
  }
}

// ============================================================================
// GRUNDLEGENDE VGA FUNKTIONEN
// ============================================================================

void print_char(int row, int col, char character, uint16_t color) {
  if (row < 0 || row >= 25 || col < 0 || col >= 80)
    return;
  uint16_t *video_memory = (uint16_t *)0xb8000;
  int offset = row * 80 + col;
  video_memory[offset] = (color << 8) | character;
}

void print_string(int row, int col, const char *str, uint16_t color);

void print_string(int row, int col, const char *str, uint16_t color) {
  int i = 0;
  while (str[i] != '\0') {
    print_char(row, col + i, str[i], color);
    i++;
  }
}

void print_string_centered(int row, const char *str, uint16_t color) {
  int len = string_length(str);
  int col = (80 - len) / 2;
  print_string(row, col, str, color);
}

void clear_screen(uint16_t color) {
  uint16_t *video_memory = (uint16_t *)0xb8000;
  for (int i = 0; i < 80 * 25; ++i) {
    video_memory[i] = (color << 8) | ' ';
  }
}

// ============================================================================
// MOUSE DRIVER & WALLPAPER
// ============================================================================

int mouse_x = 40;
int mouse_y = 12;
int global_mouse_speed = 3; // 0=Slowest, 1=Slow, 2=Normal, 3=Fast
uint8_t mouse_cycle = 0;
int8_t mouse_byte[3];
bool mouse_left = false;
bool mouse_right = false;
bool mouse_middle = false;
bool show_wallpaper = false;

void mouse_wait(uint8_t type) {
  uint32_t timeout = 100000;
  if (type == 0) {
    while (timeout--) {
      if ((inb(0x64) & 1) == 1)
        return;
    }
  } else {
    while (timeout--) {
      if ((inb(0x64) & 2) == 0)
        return;
    }
  }
}

void mouse_write(uint8_t w) {
  mouse_wait(1);
  outb(0x64, 0xD4);
  mouse_wait(1);
  outb(0x60, w);
}

uint8_t mouse_read() {
  mouse_wait(0);
  return inb(0x60);
}

void init_mouse() {
  mouse_wait(1);
  outb(0x64, 0xA8);
  mouse_wait(1);
  outb(0x64, 0x20);
  mouse_wait(0);
  uint8_t status = inb(0x60) | 2;
  mouse_wait(1);
  outb(0x64, 0x60);
  mouse_wait(1);
  outb(0x60, status);
  mouse_write(0xF6);
  mouse_read();
  mouse_write(0xF4);
  mouse_read();
}

void handle_mouse_byte(uint8_t b) {
  if (mouse_cycle == 0) {
    if ((b & 0x08) == 0x08) {
      mouse_byte[0] = b;
      mouse_cycle++;
    }
  } else if (mouse_cycle == 1) {
    mouse_byte[1] = b;
    mouse_cycle++;
  } else {
    mouse_byte[2] = b;
    mouse_cycle = 0;

    mouse_left = mouse_byte[0] & 1;
    mouse_right = mouse_byte[0] & 2;
    mouse_middle = mouse_byte[0] & 4;

    int dx = (int8_t)mouse_byte[1];
    int dy = (int8_t)mouse_byte[2];
    int divisor = 4 - global_mouse_speed;
    if (divisor < 1)
      divisor = 1;
    mouse_x += dx / divisor;
    mouse_y -= dy / divisor;

    if (screen.active) {
      if (mouse_x < 0)
        mouse_x = 0;
      if ((uint32_t)mouse_x > screen.width - 1)
        mouse_x = screen.width - 1;
      if (mouse_y < 0)
        mouse_y = 0;
      if ((uint32_t)mouse_y > screen.height - 1)
        mouse_y = screen.height - 1;
    } else {
      if (mouse_x < 0)
        mouse_x = 0;
      if (mouse_x > 79)
        mouse_x = 79;
      if (mouse_y < 0)
        mouse_y = 0;
      if (mouse_y > 24)
        mouse_y = 24;
    }
  }
}

void draw_wallpaper_text() {
  clear_screen(0x20); // Green bg
  // Daisy Field Pattern
  for (int y = 0; y < 25; y++) {
    for (int x = 0; x < 80; x++) {
      int seed = (x * 37 + y * 89);
      if (seed % 17 == 0) {
        print_char(y, x, 'o', 0x2E); // Yellow center
      } else if ((seed % 17) >= 1 && (seed % 17) <= 4) {
        print_char(y, x, '*', 0x2F); // White petals
      }
    }
  }
}

// ============================================================================
// C-STRING UND SPEICHER FUNKTIONEN (JETZT EXTERN C)
// ============================================================================
extern "C" {
int string_length(const char *str) {
  int len = 0;
  while (str[len] != '\0')
    len++;
  return len;
}

void string_copy(char *dest, const char *src) {
  int i = 0;
  while (src[i] != '\0') {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

bool string_compare(const char *s1, const char *s2) {
  int i = 0;
  while (s1[i] != '\0' && s2[i] != '\0') {
    if (s1[i] != s2[i])
      return false;
    i++;
  }
  return s1[i] == s2[i];
}

void memset(void *ptr, uint8_t value, uint32_t size) {
  uint8_t *p = (uint8_t *)ptr;
  for (uint32_t i = 0; i < size; i++) {
    p[i] = value;
  }
}

void memcpy(void *dest, const void *src, uint32_t size) {
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (uint32_t i = 0; i < size; i++) {
    d[i] = s[i];
  }
}
} // Ende extern "C"

const char *get_filename_ext(const char *filename) {
  const char *dot = nullptr;
  while (*filename) {
    if (*filename == '.')
      dot = filename;
    filename++;
  }
  return dot ? dot + 1 : "";
}

// ============================================================================
// RTC (REAL TIME CLOCK)
// ============================================================================

uint8_t get_rtc_register(int reg) {
  outb(0x70, reg);
  return inb(0x71);
}

extern "C" Time get_time() {
  Time t;
  t.second = get_rtc_register(0x00);
  t.minute = get_rtc_register(0x02);
  t.hour = get_rtc_register(0x04);

  // BCD conversion
  t.second = (t.second & 0x0F) + ((t.second / 16) * 10);
  t.minute = (t.minute & 0x0F) + ((t.minute / 16) * 10);
  t.hour = ((t.hour & 0x0F) + ((t.hour & 0x70) / 16) * 10) | (t.hour & 0x80);

  return t;
}

// ============================================================================

// Dummy-Struktur, um FAT-Treiber-Signatur anzupassen
struct ATADevice {
  uint16_t io_base;
  uint16_t control_base;
  uint8_t drive;
  bool present;
  uint32_t size_sectors;
};

ATADevice *active_disk = nullptr; // Zeigt auf die RAM-Disk

// +++ BEGINN RAM-DISK IMPLEMENTIERUNG +++
const size_t RAMDISK_SIZE_BYTES = 200 * 1024; // 200KB
const size_t RAMDISK_SIZE_SECTORS = RAMDISK_SIZE_BYTES / 512;
uint8_t *ramdisk_storage = nullptr; // Zeiger auf den Speicher der RAM-Disk
ATADevice ramdisk_device;           // Ein virtuelles ATADevice für die RAM-Disk
#define RAMDISK_MAGIC_IO 0xDEAD     // Eindeutige ID statt I/O-Port
#define SECTOR_SIZE 512             // Definiert hier, da es global genutzt wird
// +++ ENDE RAM-DISK IMPLEMENTIERUNG +++

// ============================================================================
// ATA PIO DRIVER (HDD SUPPORT)
// ============================================================================

bool ata_identify(ATADevice *dev) {
  if (dev->io_base == RAMDISK_MAGIC_IO)
    return true;

  // Select Drive
  outb(dev->io_base + 6, dev->drive == 0 ? 0xA0 : 0xB0);
  // Zero Sectorcount & LBA
  outb(dev->io_base + 2, 0);
  outb(dev->io_base + 3, 0);
  outb(dev->io_base + 4, 0);
  outb(dev->io_base + 5, 0);
  // Send Command
  outb(dev->io_base + 7, 0xEC); // IDENTIFY

  // Read Status
  uint8_t status = inb(dev->io_base + 7);
  if (status == 0)
    return false; // No drive

  // Poll until ready or error
  while (1) {
    status = inb(dev->io_base + 7);
    if ((status & 1))
      return false; // ERR
    if ((status & 8))
      break; // DRQ ready
  }

  // Read 256 words (discard for now, just checking presence)
  for (int i = 0; i < 256; i++)
    inw(dev->io_base);

  dev->present = true;
  dev->size_sectors = 0; // TODO: Parse size from identify data
  // For now assume standard size or read from MBR/Partition table later
  // Actually for FAT16 minimal support we just need read/write.
  return true;
}

void ata_wait_400ns(uint16_t io_base) {
  inb(io_base + 7);
  inb(io_base + 7);
  inb(io_base + 7);
  inb(io_base + 7);
}

// 28-bit LBA PIO Read
bool ata_read_sector_pio(ATADevice *dev, uint32_t lba, uint8_t *buffer) {
  // 0xE0 for Master, 0xF0 for Slave + upper 4 bits of LBA
  uint8_t drive_head = 0xE0 | (dev->drive << 4) | ((lba >> 24) & 0x0F);

  outb(dev->io_base + 6, drive_head); // Drive/Head
  outb(dev->io_base + 2, 1);          // Count = 1
  outb(dev->io_base + 3, (uint8_t)lba);
  outb(dev->io_base + 4, (uint8_t)(lba >> 8));
  outb(dev->io_base + 5, (uint8_t)(lba >> 16));
  outb(dev->io_base + 7, 0x20); // COMMAND READ SECTORS

  // Poll
  while (1) {
    uint8_t status = inb(dev->io_base + 7);
    if (status & 1)
      return false; // ERR
    if (status & 8)
      break; // DRQ
  }

  // Read Data
  insl(dev->io_base, buffer, 128); // Read 128 uint32s -> 512 bytes
  ata_wait_400ns(dev->io_base);
  return true;
}

// 28-bit LBA PIO Write
bool ata_write_sector_pio(ATADevice *dev, uint32_t lba, const uint8_t *buffer) {
  uint8_t drive_head = 0xE0 | (dev->drive << 4) | ((lba >> 24) & 0x0F);

  outb(dev->io_base + 6, drive_head);
  outb(dev->io_base + 2, 1);
  outb(dev->io_base + 3, (uint8_t)lba);
  outb(dev->io_base + 4, (uint8_t)(lba >> 8));
  outb(dev->io_base + 5, (uint8_t)(lba >> 16));
  outb(dev->io_base + 7, 0x30); // COMMAND WRITE SECTORS

  // Poll
  while (1) {
    uint8_t status = inb(dev->io_base + 7);
    if (status & 1)
      return false;
    if (status & 8)
      break;
  }

  // Write Data
  outsl(dev->io_base, buffer, 128);

  // Flush / Wait
  outb(dev->io_base + 7, 0xE7); // CACHE FLUSH
  while (inb(dev->io_base + 7) & 0x80)
    ; // Wait BSY

  return true;
}

bool ata_read_sector(ATADevice *dev, uint32_t lba, uint8_t *buffer) {
  if (dev->io_base == RAMDISK_MAGIC_IO) {
    if (!dev->present || lba >= dev->size_sectors)
      return false;
    uint32_t offset = lba * SECTOR_SIZE;
    memcpy(buffer, &ramdisk_storage[offset], SECTOR_SIZE);
    return true;
  } else {
    // HDD PIO Read
    return ata_read_sector_pio(dev, lba, buffer);
  }
}

bool ata_write_sector(ATADevice *dev, uint32_t lba, const uint8_t *buffer) {
  if (dev->io_base == RAMDISK_MAGIC_IO) {
    if (!dev->present || lba >= dev->size_sectors)
      return false;
    uint32_t offset = lba * SECTOR_SIZE;
    memcpy(&ramdisk_storage[offset], buffer, SECTOR_SIZE);
    return true;
  } else {
    // HDD PIO Write
    return ata_write_sector_pio(dev, lba, buffer);
  }
}

// ============================================================================
// FAT16 DATEISYSTEM
// ============================================================================

#define MAX_FILES 64
#define MAX_FILENAME 12

struct PartitionEntry {
  uint8_t bootable;
  uint8_t start_head;
  uint8_t start_sect_cyl;
  uint8_t start_cyl_low;
  uint8_t system_id;
  uint8_t end_head;
  uint8_t end_sect_cyl;
  uint8_t end_cyl_low;
  uint32_t start_lba;
  uint32_t total_sectors;
} __attribute__((packed));

struct MBR {
  uint8_t bootstrap[446];
  PartitionEntry partitions[4];
  uint16_t signature;
} __attribute__((packed));

struct BootSector {
  uint8_t jump[3];
  char oem[8];
  uint16_t bytes_per_sector;
  uint8_t sectors_per_cluster;
  uint16_t reserved_sectors;
  uint8_t fat_count;
  uint16_t root_entry_count;
  uint16_t total_sectors_16;
  uint8_t media_type;
  uint16_t sectors_per_fat_16;
  uint16_t sectors_per_track;
  uint16_t head_count;
  uint32_t hidden_sectors;
  uint32_t total_sectors_32;
  // FAT16/12 specific
  uint8_t drive_number;
  uint8_t reserved1;
  uint8_t boot_signature;
  uint32_t volume_id;
  char volume_label[11];
  char fs_type[8];
} __attribute__((packed));

struct DirEntry {
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
  uint32_t first_cluster;
};

FileEntry file_cache[MAX_FILES];
int file_count = 0;

BootSector boot_sector;
uint8_t sector_buffer[SECTOR_SIZE];
bool fs_mounted = false;

uint32_t active_partition_lba = 0;
uint32_t active_partition_sectors = 0;

uint32_t fat_begin_lba = 0;
uint32_t cluster_begin_lba = 0;
uint32_t sectors_per_cluster = 0;
uint32_t root_dir_lba = 0;
uint32_t root_dir_sectors = 0;
uint32_t root_dir_first_cluster = 0;
uint32_t current_dir_cluster = 0;
char current_dir_path[128] = "/";

bool format_fat16(ATADevice *dev, uint32_t offset, uint32_t size_sectors) {
  if (!dev->present)
    return false;

  // Initialisiere Boot Sector
  memset(&boot_sector, 0, sizeof(BootSector));

  boot_sector.jump[0] = 0xEB;
  boot_sector.jump[1] = 0x3C;
  boot_sector.jump[2] = 0x90;

  memcpy(boot_sector.oem, "MILLAFAT", 8);
  boot_sector.bytes_per_sector = 512;
  boot_sector.sectors_per_cluster = 8;
  boot_sector.reserved_sectors = 1;
  boot_sector.fat_count = 2;
  boot_sector.root_entry_count = 512;
  boot_sector.media_type = 0xF8;
  boot_sector.sectors_per_track = 63;
  boot_sector.head_count = 255;
  boot_sector.hidden_sectors = offset;

  // Setze Sektorgrößen
  uint32_t total_sectors = size_sectors;
  if (total_sectors < 0x10000) {
    boot_sector.total_sectors_16 = (uint16_t)total_sectors;
    boot_sector.total_sectors_32 = 0;
  } else {
    boot_sector.total_sectors_16 = 0;
    boot_sector.total_sectors_32 = total_sectors;
  }

  // Berechne Root-Verzeichnis-Größe
  root_dir_sectors = (boot_sector.root_entry_count * sizeof(DirEntry) +
                      boot_sector.bytes_per_sector - 1) /
                     boot_sector.bytes_per_sector;

  // Berechne FAT-Größe
  uint32_t data_sectors =
      total_sectors - boot_sector.reserved_sectors - root_dir_sectors;
  uint32_t cluster_count = data_sectors / boot_sector.sectors_per_cluster;
  uint32_t fat_size_sectors =
      (cluster_count * 2 + boot_sector.bytes_per_sector - 1) /
      boot_sector.bytes_per_sector;

  boot_sector.sectors_per_fat_16 = fat_size_sectors;

  boot_sector.drive_number = 0x80;
  boot_sector.boot_signature = 0x29;
  boot_sector.volume_id = 0x12345678;
  memcpy(boot_sector.volume_label, "MILLA OS   ", 11);
  memcpy(boot_sector.fs_type, "FAT16   ", 8);

  // Schreibe Boot Sector
  memset(sector_buffer, 0, SECTOR_SIZE);
  memcpy(sector_buffer, &boot_sector, sizeof(BootSector));
  sector_buffer[510] = 0x55;
  sector_buffer[511] = 0xAA;

  if (!ata_write_sector(dev, offset, sector_buffer))
    return false;

  // Initialisiere FAT (beide Kopien)
  memset(sector_buffer, 0, SECTOR_SIZE);
  ((uint16_t *)sector_buffer)[0] = 0xFFF8;
  ((uint16_t *)sector_buffer)[1] = 0xFFFF;

  uint32_t fat1_lba = offset + boot_sector.reserved_sectors;
  uint32_t fat2_lba = fat1_lba + boot_sector.sectors_per_fat_16;

  if (!ata_write_sector(dev, fat1_lba, sector_buffer))
    return false;
  if (!ata_write_sector(dev, fat2_lba, sector_buffer))
    return false;

  // Lösche restliche FAT Sektoren
  memset(sector_buffer, 0, SECTOR_SIZE);
  for (uint32_t i = 1; i < boot_sector.sectors_per_fat_16; i++) {
    ata_write_sector(dev, fat1_lba + i, sector_buffer);
    ata_write_sector(dev, fat2_lba + i, sector_buffer);
  }

  // Initialisiere Root Directory
  uint32_t root_lba =
      fat1_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);

  memset(sector_buffer, 0, SECTOR_SIZE);
  for (uint32_t i = 0; i < root_dir_sectors; i++) {
    if (!ata_write_sector(dev, root_lba + i, sector_buffer))
      return false;
  }

  return true;
}

bool format_mbr(ATADevice *dev) {
  if (!dev->present)
    return false;
  memset(sector_buffer, 0, SECTOR_SIZE);
  MBR *mbr = (MBR *)sector_buffer;
  mbr->signature = 0xAA55;

  // Create one large partition
  mbr->partitions[0].bootable = 0x80;
  mbr->partitions[0].system_id = 0x06; // FAT16
  mbr->partitions[0].start_lba = 63;   // Standard offset
  mbr->partitions[0].total_sectors = dev->size_sectors - 63;

  return ata_write_sector(dev, 0, sector_buffer);
}

bool mount_fat16(ATADevice *dev, uint32_t offset) {
  if (!dev->present)
    return false;

  if (!ata_read_sector(dev, offset, sector_buffer))
    return false;

  // Überprüfe die Magische Zahl
  if (sector_buffer[510] != 0x55 || sector_buffer[511] != 0xAA)
    return false;

  memcpy(&boot_sector, sector_buffer, sizeof(BootSector));

  if (boot_sector.bytes_per_sector != 512)
    return false;
  if (boot_sector.fat_count == 0)
    return false;

  fat_begin_lba = offset + boot_sector.reserved_sectors;

  // Berechne Positionen für FAT16
  root_dir_sectors = (boot_sector.root_entry_count * sizeof(DirEntry) +
                      boot_sector.bytes_per_sector - 1) /
                     boot_sector.bytes_per_sector;
  root_dir_lba =
      fat_begin_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);
  cluster_begin_lba = root_dir_lba + root_dir_sectors;

  sectors_per_cluster = boot_sector.sectors_per_cluster;
  root_dir_first_cluster = 0;
  current_dir_cluster = 0;
  string_copy(current_dir_path, "/");

  active_partition_lba = offset;

  fs_mounted = true;
  return true;
}

uint32_t cluster_to_lba(uint32_t cluster) {
  return cluster_begin_lba + (cluster - 2) * sectors_per_cluster;
}

uint32_t get_fat_entry(ATADevice *dev, uint32_t cluster) {
  uint32_t fat_offset = cluster * 2;
  uint32_t fat_sector = fat_begin_lba + (fat_offset / SECTOR_SIZE);
  uint32_t entry_offset = fat_offset % SECTOR_SIZE;

  if (!ata_read_sector(dev, fat_sector, sector_buffer))
    return 0xFFFF;

  return *((uint16_t *)&sector_buffer[entry_offset]);
}

void set_fat_entry(ATADevice *dev, uint32_t cluster, uint32_t value) {
  uint32_t fat_offset = cluster * 2;
  uint32_t fat_sector = fat_begin_lba + (fat_offset / SECTOR_SIZE);
  uint32_t entry_offset = fat_offset % SECTOR_SIZE;

  ata_read_sector(dev, fat_sector, sector_buffer);
  *((uint16_t *)&sector_buffer[entry_offset]) = value & 0xFFFF;
  ata_write_sector(dev, fat_sector, sector_buffer);

  // Update second FAT copy
  uint32_t fat2_sector = fat_sector + boot_sector.sectors_per_fat_16;
  ata_read_sector(dev, fat2_sector, sector_buffer);
  *((uint16_t *)&sector_buffer[entry_offset]) = value & 0xFFFF;
  ata_write_sector(dev, fat2_sector, sector_buffer);
}

uint32_t allocate_cluster(ATADevice *dev) {
  for (uint32_t cluster = 2; cluster < 0xFFF0; cluster++) {
    uint32_t entry = get_fat_entry(dev, cluster);
    if (entry == 0) {
      set_fat_entry(dev, cluster, 0xFFFF); // FAT16 EOF
      return cluster;
    }
  }
  return 0;
}

struct DirSectorIterator {
  ATADevice *dev;
  uint32_t dir_cluster;
  uint32_t curr_cluster;
  uint32_t sec_in_cluster;
  uint32_t root_sec;
  bool is_root;
  bool finished;
};

void dir_iter_init(DirSectorIterator *it, ATADevice *dev, uint32_t dir_cluster) {
  it->dev = dev;
  it->dir_cluster = dir_cluster;
  it->curr_cluster = dir_cluster;
  it->sec_in_cluster = 0;
  it->root_sec = 0;
  it->is_root = (dir_cluster == 0);
  it->finished = false;
}

bool dir_iter_next_sector(DirSectorIterator *it, uint32_t *out_lba) {
  if (it->finished || !it->dev)
    return false;

  if (it->is_root) {
    if (it->root_sec >= root_dir_sectors) {
      it->finished = true;
      return false;
    }
    *out_lba = root_dir_lba + it->root_sec;
    it->root_sec++;
    return true;
  } else {
    if (it->curr_cluster < 2 || it->curr_cluster >= 0xFFF8) {
      it->finished = true;
      return false;
    }
    *out_lba = cluster_to_lba(it->curr_cluster) + it->sec_in_cluster;
    it->sec_in_cluster++;
    if (it->sec_in_cluster >= sectors_per_cluster) {
      it->sec_in_cluster = 0;
      it->curr_cluster = get_fat_entry(it->dev, it->curr_cluster);
    }
    return true;
  }
}

void filename_to_fat83(const char *filename, char *target_name) {
  for (int i = 0; i < 11; i++)
    target_name[i] = ' ';

  if (!filename)
    return;

  if (filename[0] == '.' && filename[1] == '\0') {
    target_name[0] = '.';
    return;
  }
  if (filename[0] == '.' && filename[1] == '.' && filename[2] == '\0') {
    target_name[0] = '.';
    target_name[1] = '.';
    return;
  }

  int name_pos = 0;
  int ext_pos = 8;
  bool found_dot = false;
  for (int i = 0; filename[i] != '\0'; i++) {
    char c = filename[i];
    if (c == '.') {
      found_dot = true;
      continue;
    }
    if (c >= 'a' && c <= 'z')
      c -= 32;
    if (found_dot) {
      if (ext_pos < 11)
        target_name[ext_pos++] = c;
    } else {
      if (name_pos < 8)
        target_name[name_pos++] = c;
    }
  }
}

bool read_directory(ATADevice *dev, uint32_t cluster) {
  file_count = 0;

  if (cluster == 0) {
    for (uint32_t sec = 0; sec < root_dir_sectors; sec++) {
      if (!ata_read_sector(dev, root_dir_lba + sec, sector_buffer))
        return false;

      DirEntry *entries = (DirEntry *)sector_buffer;

      for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
        if (entries[i].filename[0] == 0x00)
          return true;
        if (entries[i].filename[0] == 0xE5)
          continue;
        if (entries[i].attributes == 0x0F)
          continue;

        if (file_count >= MAX_FILES)
          return true;

        int name_pos = 0;
        for (int j = 0; j < 8 && entries[i].filename[j] != ' '; j++) {
          file_cache[file_count].name[name_pos++] = entries[i].filename[j];
        }

        if (entries[i].filename[8] != ' ') {
          file_cache[file_count].name[name_pos++] = '.';
          for (int j = 8; j < 11 && entries[i].filename[j] != ' '; j++) {
            file_cache[file_count].name[name_pos++] = entries[i].filename[j];
          }
        }
        file_cache[file_count].name[name_pos] = '\0';

        file_cache[file_count].size = entries[i].file_size;
        file_cache[file_count].is_directory =
            (entries[i].attributes & 0x10) != 0;
        file_cache[file_count].first_cluster =
            ((uint32_t)entries[i].first_cluster_high << 16) |
            entries[i].first_cluster_low;
        file_count++;
      }
    }
  } else {
    while (cluster < 0xFFF8) {
      uint32_t lba = cluster_to_lba(cluster);

      for (uint8_t sec = 0; sec < sectors_per_cluster; sec++) {
        if (!ata_read_sector(dev, lba + sec, sector_buffer))
          return false;

        DirEntry *entries = (DirEntry *)sector_buffer;

        for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
          if (entries[i].filename[0] == 0x00)
            return true;
          if (entries[i].filename[0] == 0xE5)
            continue;
          if (entries[i].attributes == 0x0F)
            continue;
          if (entries[i].filename[0] == '.' && entries[i].filename[1] == ' ')
            continue;

          if (file_count >= MAX_FILES)
            return true;

          int name_pos = 0;
          for (int j = 0; j < 8 && entries[i].filename[j] != ' '; j++) {
            file_cache[file_count].name[name_pos++] = entries[i].filename[j];
          }
          if (entries[i].filename[8] != ' ') {
            file_cache[file_count].name[name_pos++] = '.';
            for (int j = 8; j < 11 && entries[i].filename[j] != ' '; j++) {
              file_cache[file_count].name[name_pos++] = entries[i].filename[j];
            }
          }
          file_cache[file_count].name[name_pos] = '\0';
          file_cache[file_count].size = entries[i].file_size;
          file_cache[file_count].is_directory =
              (entries[i].attributes & 0x10) != 0;
          file_cache[file_count].first_cluster =
              ((uint32_t)entries[i].first_cluster_high << 16) |
              entries[i].first_cluster_low;
          file_count++;
        }
      }
      cluster = get_fat_entry(dev, cluster);
    }
  }
  return true;
}

int find_file(const char *name) {
  for (int i = 0; i < file_count; i++) {
    bool match = true;
    int j = 0;
    while (file_cache[i].name[j] != '\0' && name[j] != '\0') {
      char c1 = file_cache[i].name[j];
      char c2 = name[j];
      if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
      if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
      if (c1 != c2) { match = false; break; }
      j++;
    }
    if (match && file_cache[i].name[j] == '\0' && name[j] == '\0') {
      return i;
    }
  }
  return -1;
}

bool file_exists(const char *name) {
  return find_file(name) != -1;
}

bool read_file(ATADevice *dev, uint32_t cluster, char *buffer,
               uint32_t max_size) {
  uint32_t pos = 0;

  while (cluster >= 2 && cluster < 0xFFF8 && pos < max_size) {
    uint32_t lba = cluster_to_lba(cluster);

    for (uint8_t sec = 0; sec < sectors_per_cluster && pos < max_size; sec++) {
      if (!ata_read_sector(dev, lba + sec, sector_buffer))
        return false;

      uint32_t to_copy =
          (max_size - pos < SECTOR_SIZE) ? (max_size - pos) : SECTOR_SIZE;
      memcpy(buffer + pos, sector_buffer, to_copy);
      pos += to_copy;
    }

    cluster = get_fat_entry(dev, cluster);
  }

  // KORREKTUR: Stelle sicher, dass der Puffer nullterminiert ist,
  // wenn die Datei kleiner als der Puffer ist (und Platz dafür ist).
  if (pos < max_size) {
    buffer[pos] = '\0';
  } else if (max_size > 0) {
    buffer[max_size - 1] =
        '\0'; // Erzwinge Nullterminierung, falls max_size erreicht wurde
  }

  return true;
}

bool write_file(ATADevice *dev, const char *filename, const char *data,
                uint32_t size) {
  if (!dev || !fs_mounted || !filename)
    return false;

  char target_name[11];
  filename_to_fat83(filename, target_name);

  // Scan current directory for existing entry or first empty entry
  DirSectorIterator it;
  dir_iter_init(&it, dev, current_dir_cluster);

  int existing_idx = -1;
  uint32_t existing_lba = 0;
  bool file_already_exists = false;
  uint32_t old_first_cluster = 0;

  int first_empty_idx = -1;
  uint32_t first_empty_lba = 0;

  uint32_t cur_lba = 0;
  while (dir_iter_next_sector(&it, &cur_lba)) {
    if (!ata_read_sector(dev, cur_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    bool end_reached = false;

    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) {
        if (first_empty_idx == -1) {
          first_empty_idx = i;
          first_empty_lba = cur_lba;
        }
        end_reached = true;
        break;
      }
      if (entries[i].filename[0] == 0xE5) {
        if (first_empty_idx == -1) {
          first_empty_idx = i;
          first_empty_lba = cur_lba;
        }
        continue;
      }
      if (entries[i].attributes == 0x0F) {
        continue;
      }

      bool matches = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != target_name[k]) {
          matches = false;
          break;
        }
      }

      if (matches) {
        if (!file_already_exists) {
          file_already_exists = true;
          existing_idx = i;
          existing_lba = cur_lba;
          old_first_cluster = ((uint32_t)entries[i].first_cluster_high << 16) |
                              entries[i].first_cluster_low;
        } else {
          // Free duplicate entry clusters and mark deleted
          uint32_t dup_cluster = ((uint32_t)entries[i].first_cluster_high << 16) |
                                 entries[i].first_cluster_low;
          while (dup_cluster >= 2 && dup_cluster < 0xFFF8) {
            uint32_t next = get_fat_entry(dev, dup_cluster);
            set_fat_entry(dev, dup_cluster, 0x0000);
            dup_cluster = next;
          }
          entries[i].filename[0] = 0xE5;
          ata_write_sector(dev, cur_lba, sector_buffer);
        }
      }
    }

    if (end_reached && !file_already_exists) {
      break;
    }
  }

  int target_entry_idx;
  uint32_t target_entry_lba;

  if (file_already_exists) {
    target_entry_idx = existing_idx;
    target_entry_lba = existing_lba;

    // Free the old cluster chain in FAT
    uint32_t cluster_to_free = old_first_cluster;
    while (cluster_to_free >= 2 && cluster_to_free < 0xFFF8) {
      uint32_t next = get_fat_entry(dev, cluster_to_free);
      set_fat_entry(dev, cluster_to_free, 0x0000);
      cluster_to_free = next;
    }
  } else {
    // If subdirectory is full, allocate another cluster for the directory
    if (first_empty_idx == -1 && current_dir_cluster >= 2) {
      uint32_t new_dir_cluster = allocate_cluster(dev);
      if (new_dir_cluster != 0) {
        for (uint8_t s = 0; s < sectors_per_cluster; s++) {
          memset(sector_buffer, 0, SECTOR_SIZE);
          ata_write_sector(dev, cluster_to_lba(new_dir_cluster) + s, sector_buffer);
        }
        uint32_t c = current_dir_cluster;
        while (get_fat_entry(dev, c) < 0xFFF8) {
          c = get_fat_entry(dev, c);
        }
        set_fat_entry(dev, c, new_dir_cluster);
        first_empty_lba = cluster_to_lba(new_dir_cluster);
        first_empty_idx = 0;
      }
    }
    if (first_empty_idx == -1) {
      return false; // Directory full
    }
    target_entry_idx = first_empty_idx;
    target_entry_lba = first_empty_lba;
  }

  // 3. Allocate clusters and write new data
  uint32_t file_cluster = 0;
  if (size > 0) {
    file_cluster = allocate_cluster(dev);
    if (file_cluster == 0)
      return false; // Disk full

    uint32_t written = 0;
    uint32_t current_cluster = file_cluster;

    while (written < size) {
      uint32_t file_lba = cluster_to_lba(current_cluster);

      for (uint8_t sec = 0; sec < sectors_per_cluster && written < size; sec++) {
        memset(sector_buffer, 0, SECTOR_SIZE);
        uint32_t to_write =
            (size - written < SECTOR_SIZE) ? (size - written) : SECTOR_SIZE;
        memcpy(sector_buffer, data + written, to_write);

        if (!ata_write_sector(dev, file_lba + sec, sector_buffer))
          return false;
        written += to_write;
      }

      if (written < size) {
        uint32_t next_cluster = allocate_cluster(dev);
        if (next_cluster == 0)
          return false; // Out of disk space
        set_fat_entry(dev, current_cluster, next_cluster);
        current_cluster = next_cluster;
      }
    }
  }

  // 4. Update the directory entry
  if (!ata_read_sector(dev, target_entry_lba, sector_buffer))
    return false;

  DirEntry *entries = (DirEntry *)sector_buffer;
  DirEntry *entry = &entries[target_entry_idx];

  memset(entry, 0, sizeof(DirEntry));
  memcpy(entry->filename, target_name, 11);
  entry->attributes = 0x20; // Archive
  entry->first_cluster_high = (file_cluster >> 16) & 0xFFFF;
  entry->first_cluster_low = file_cluster & 0xFFFF;
  entry->file_size = size;

  if (!ata_write_sector(dev, target_entry_lba, sector_buffer))
    return false;

  read_directory(dev, current_dir_cluster);
  return true;
}

bool create_directory(ATADevice *dev, uint32_t parent_cluster, const char *dirname) {
  if (!dev || !fs_mounted || !dirname || dirname[0] == '\0')
    return false;

  if (dirname[0] == '.' && (dirname[1] == '\0' || (dirname[1] == '.' && dirname[2] == '\0')))
    return false;

  char target_name[11];
  filename_to_fat83(dirname, target_name);

  // Check if name already exists in parent_cluster & find first empty slot
  DirSectorIterator it;
  dir_iter_init(&it, dev, parent_cluster);

  int first_empty_idx = -1;
  uint32_t first_empty_lba = 0;
  uint32_t cur_lba = 0;

  while (dir_iter_next_sector(&it, &cur_lba)) {
    if (!ata_read_sector(dev, cur_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    bool end_reached = false;

    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) {
        if (first_empty_idx == -1) {
          first_empty_idx = i;
          first_empty_lba = cur_lba;
        }
        end_reached = true;
        break;
      }
      if (entries[i].filename[0] == 0xE5) {
        if (first_empty_idx == -1) {
          first_empty_idx = i;
          first_empty_lba = cur_lba;
        }
        continue;
      }
      if (entries[i].attributes == 0x0F) continue;

      bool matches = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != target_name[k]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        return false; // Already exists!
      }
    }
    if (end_reached) break;
  }

  // Expand parent directory cluster if needed
  if (first_empty_idx == -1 && parent_cluster >= 2) {
    uint32_t new_cluster = allocate_cluster(dev);
    if (new_cluster != 0) {
      for (uint8_t s = 0; s < sectors_per_cluster; s++) {
        memset(sector_buffer, 0, SECTOR_SIZE);
        ata_write_sector(dev, cluster_to_lba(new_cluster) + s, sector_buffer);
      }
      uint32_t c = parent_cluster;
      while (get_fat_entry(dev, c) < 0xFFF8) {
        c = get_fat_entry(dev, c);
      }
      set_fat_entry(dev, c, new_cluster);
      first_empty_lba = cluster_to_lba(new_cluster);
      first_empty_idx = 0;
    }
  }

  if (first_empty_idx == -1)
    return false; // Parent directory full

  // Allocate cluster for new directory
  uint32_t new_dir_cluster = allocate_cluster(dev);
  if (new_dir_cluster == 0)
    return false; // Disk full

  // Clear new cluster sectors
  for (uint8_t s = 0; s < sectors_per_cluster; s++) {
    memset(sector_buffer, 0, SECTOR_SIZE);
    ata_write_sector(dev, cluster_to_lba(new_dir_cluster) + s, sector_buffer);
  }

  // Initialize '.' and '..' entries in first sector
  DirEntry *new_entries = (DirEntry *)sector_buffer;
  memset(new_entries, 0, SECTOR_SIZE);

  // '.' entry
  memcpy(new_entries[0].filename, ".          ", 11);
  new_entries[0].attributes = 0x10; // Directory
  new_entries[0].first_cluster_high = (new_dir_cluster >> 16) & 0xFFFF;
  new_entries[0].first_cluster_low = new_dir_cluster & 0xFFFF;
  new_entries[0].file_size = 0;

  // '..' entry
  memcpy(new_entries[1].filename, "..         ", 11);
  new_entries[1].attributes = 0x10; // Directory
  new_entries[1].first_cluster_high = (parent_cluster >> 16) & 0xFFFF;
  new_entries[1].first_cluster_low = parent_cluster & 0xFFFF;
  new_entries[1].file_size = 0;

  if (!ata_write_sector(dev, cluster_to_lba(new_dir_cluster), sector_buffer))
    return false;

  // Write directory entry in parent directory
  if (!ata_read_sector(dev, first_empty_lba, sector_buffer))
    return false;

  DirEntry *parent_entries = (DirEntry *)sector_buffer;
  DirEntry *parent_slot = &parent_entries[first_empty_idx];

  memset(parent_slot, 0, sizeof(DirEntry));
  memcpy(parent_slot->filename, target_name, 11);
  parent_slot->attributes = 0x10; // Directory
  parent_slot->first_cluster_high = (new_dir_cluster >> 16) & 0xFFFF;
  parent_slot->first_cluster_low = new_dir_cluster & 0xFFFF;
  parent_slot->file_size = 0;

  if (!ata_write_sector(dev, first_empty_lba, sector_buffer))
    return false;

  read_directory(dev, current_dir_cluster);
  return true;
}

bool remove_directory(ATADevice *dev, uint32_t parent_cluster, const char *dirname) {
  if (!dev || !fs_mounted || !dirname || dirname[0] == '\0')
    return false;

  if (dirname[0] == '.' && (dirname[1] == '\0' || (dirname[1] == '.' && dirname[2] == '\0')))
    return false;

  char target_name[11];
  filename_to_fat83(dirname, target_name);

  DirSectorIterator it;
  dir_iter_init(&it, dev, parent_cluster);

  uint32_t entry_lba = 0;
  int entry_idx = -1;
  uint32_t dir_target_cluster = 0;
  uint32_t cur_lba = 0;
  bool found = false;

  while (dir_iter_next_sector(&it, &cur_lba)) {
    if (!ata_read_sector(dev, cur_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) break;
      if (entries[i].filename[0] == 0xE5 || entries[i].attributes == 0x0F) continue;

      bool match = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != target_name[k]) {
          match = false;
          break;
        }
      }
      if (match) {
        if ((entries[i].attributes & 0x10) == 0) {
          return false; // Not a directory!
        }
        entry_lba = cur_lba;
        entry_idx = i;
        dir_target_cluster = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
        found = true;
        break;
      }
    }
    if (found) break;
  }

  if (!found || dir_target_cluster < 2)
    return false;

  // Check if directory is empty
  DirSectorIterator sub_it;
  dir_iter_init(&sub_it, dev, dir_target_cluster);
  uint32_t sub_lba = 0;
  uint8_t check_buf[512];

  while (dir_iter_next_sector(&sub_it, &sub_lba)) {
    if (!ata_read_sector(dev, sub_lba, check_buf))
      return false;

    DirEntry *sub_entries = (DirEntry *)check_buf;
    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (sub_entries[i].filename[0] == 0x00) break;
      if (sub_entries[i].filename[0] == 0xE5 || sub_entries[i].attributes == 0x0F) continue;
      // Skip '.' and '..'
      if (sub_entries[i].filename[0] == '.') continue;
      return false; // Directory has files/subdirectories!
    }
  }

  // Free clusters in FAT
  uint32_t c = dir_target_cluster;
  while (c >= 2 && c < 0xFFF8) {
    uint32_t next = get_fat_entry(dev, c);
    set_fat_entry(dev, c, 0x0000);
    c = next;
  }

  // Mark entry in parent directory as 0xE5
  if (!ata_read_sector(dev, entry_lba, sector_buffer))
    return false;

  DirEntry *entries = (DirEntry *)sector_buffer;
  entries[entry_idx].filename[0] = 0xE5;
  ata_write_sector(dev, entry_lba, sector_buffer);

  read_directory(dev, current_dir_cluster);
  return true;
}

bool move_file(ATADevice *dev, const char *src_name, const char *dest_name) {
  if (!dev || !fs_mounted || !src_name || !dest_name)
    return false;

  char src_fat83[11];
  filename_to_fat83(src_name, src_fat83);

  DirSectorIterator it;
  dir_iter_init(&it, dev, current_dir_cluster);

  uint32_t src_lba = 0;
  int src_idx = -1;
  DirEntry saved_entry;
  bool src_found = false;
  uint32_t cur_lba = 0;

  while (dir_iter_next_sector(&it, &cur_lba)) {
    if (!ata_read_sector(dev, cur_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) break;
      if (entries[i].filename[0] == 0xE5 || entries[i].attributes == 0x0F) continue;

      bool match = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != src_fat83[k]) {
          match = false;
          break;
        }
      }
      if (match) {
        src_lba = cur_lba;
        src_idx = i;
        memcpy(&saved_entry, &entries[i], sizeof(DirEntry));
        src_found = true;
        break;
      }
    }
    if (src_found) break;
  }

  if (!src_found)
    return false;

  if (saved_entry.filename[0] == '.')
    return false;

  uint32_t dest_dir_cluster = current_dir_cluster;
  bool moving_into_dir = false;
  char final_target_name[11];

  if (dest_name[0] == '.' && dest_name[1] == '.' && dest_name[2] == '\0') {
    DirSectorIterator p_it;
    dir_iter_init(&p_it, dev, current_dir_cluster);
    uint32_t p_lba = 0;
    bool found_parent = false;
    while (dir_iter_next_sector(&p_it, &p_lba)) {
      if (ata_read_sector(dev, p_lba, sector_buffer)) {
        DirEntry *entries = (DirEntry *)sector_buffer;
        for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
          if (entries[i].filename[0] == '.' && entries[i].filename[1] == '.') {
            dest_dir_cluster = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
            found_parent = true;
            break;
          }
        }
      }
      if (found_parent) break;
    }
    if (!found_parent && current_dir_cluster == 0) return false;
    moving_into_dir = true;
    memcpy(final_target_name, src_fat83, 11);
  } else {
    char dest_fat83[11];
    filename_to_fat83(dest_name, dest_fat83);

    DirSectorIterator d_it;
    dir_iter_init(&d_it, dev, current_dir_cluster);
    uint32_t d_lba = 0;
    bool dest_is_dir = false;

    while (dir_iter_next_sector(&d_it, &d_lba)) {
      if (ata_read_sector(dev, d_lba, sector_buffer)) {
        DirEntry *entries = (DirEntry *)sector_buffer;
        for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
          if (entries[i].filename[0] == 0x00) break;
          if (entries[i].filename[0] == 0xE5 || entries[i].attributes == 0x0F) continue;

          bool match = true;
          for (int k = 0; k < 11; k++) {
            if (entries[i].filename[k] != dest_fat83[k]) {
              match = false;
              break;
            }
          }
          if (match && (entries[i].attributes & 0x10)) {
            dest_is_dir = true;
            dest_dir_cluster = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
            break;
          }
        }
      }
      if (dest_is_dir) break;
    }

    if (dest_is_dir) {
      moving_into_dir = true;
      memcpy(final_target_name, src_fat83, 11);
    } else {
      moving_into_dir = false;
      filename_to_fat83(dest_name, final_target_name);
    }
  }

  // Renaming in the same directory:
  if (!moving_into_dir) {
    if (!ata_read_sector(dev, src_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    memcpy(entries[src_idx].filename, final_target_name, 11);
    ata_write_sector(dev, src_lba, sector_buffer);

    read_directory(dev, current_dir_cluster);
    return true;
  }

  // Moving into another directory:
  DirSectorIterator dst_it;
  dir_iter_init(&dst_it, dev, dest_dir_cluster);

  int dst_empty_idx = -1;
  uint32_t dst_empty_lba = 0;
  uint32_t dcur_lba = 0;

  while (dir_iter_next_sector(&dst_it, &dcur_lba)) {
    if (!ata_read_sector(dev, dcur_lba, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    bool end_reached = false;

    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) {
        if (dst_empty_idx == -1) {
          dst_empty_idx = i;
          dst_empty_lba = dcur_lba;
        }
        end_reached = true;
        break;
      }
      if (entries[i].filename[0] == 0xE5) {
        if (dst_empty_idx == -1) {
          dst_empty_idx = i;
          dst_empty_lba = dcur_lba;
        }
        continue;
      }
      if (entries[i].attributes == 0x0F) continue;

      bool matches = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != final_target_name[k]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        uint32_t old_c = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
        while (old_c >= 2 && old_c < 0xFFF8) {
          uint32_t next = get_fat_entry(dev, old_c);
          set_fat_entry(dev, old_c, 0x0000);
          old_c = next;
        }
        dst_empty_idx = i;
        dst_empty_lba = dcur_lba;
        end_reached = true;
        break;
      }
    }
    if (end_reached) break;
  }

  if (dst_empty_idx == -1)
    return false; // Destination directory full

  if (!ata_read_sector(dev, dst_empty_lba, sector_buffer))
    return false;

  DirEntry *d_entries = (DirEntry *)sector_buffer;
  memcpy(&d_entries[dst_empty_idx], &saved_entry, sizeof(DirEntry));
  memcpy(d_entries[dst_empty_idx].filename, final_target_name, 11);
  if (!ata_write_sector(dev, dst_empty_lba, sector_buffer))
    return false;

  if (ata_read_sector(dev, src_lba, sector_buffer)) {
    DirEntry *s_entries = (DirEntry *)sector_buffer;
    s_entries[src_idx].filename[0] = 0xE5;
    ata_write_sector(dev, src_lba, sector_buffer);
  }

  read_directory(dev, current_dir_cluster);
  return true;
}

// Initialisierung
ATADevice hdd_device;

extern "C" bool create_mou_file_if_needed(ATADevice *dev) {
  if (!dev || dev == &ramdisk_device || !fs_mounted) {
    return false;
  }
  read_directory(dev, root_dir_first_cluster);
  if (file_exists(".mou")) {
    return true;
  }
  bool created = write_file(dev, ".mou", "1", 1);
  if (created) {
    read_directory(dev, root_dir_first_cluster);
  }
  return created;
}

void init_filesystem() {

  // +++ ERSTELLE RAM-DISK +++
  print_string(21, 10, "Creating RAM disk...", 0x0E);

  // Speicher allozieren (MUSS VOR ANDEREN MALLOCS PASSIEREN)
  ramdisk_storage = (uint8_t *)malloc(RAMDISK_SIZE_BYTES);

  if (ramdisk_storage == nullptr) {
    print_string(22, 10, "RAM disk creation failed! (Out of memory)", 0x0C);
    active_disk = nullptr;
  } else {
    // RAM-Disk mit 0 füllen (wichtig für leeres Dateisystem)
    memset(ramdisk_storage, 0, RAMDISK_SIZE_BYTES);

    // Virtuelles Gerät einrichten
    ramdisk_device.io_base = RAMDISK_MAGIC_IO; // Magische Zahl
    ramdisk_device.control_base = 0;
    ramdisk_device.drive = 0;
    ramdisk_device.present = true;
    ramdisk_device.size_sectors = RAMDISK_SIZE_SECTORS;

    active_disk = &ramdisk_device;
    print_string(22, 10, "RAM disk (800KB) created.", 0x0A);
  }
  // +++ ENDE RAM-DISK ERSTELLUNG +++

  // +++ HDD PROBE +++
  print_string(21, 45, "Probing HDD...", 0x0E);
  hdd_device.io_base = 0x1F0; // Primary
  hdd_device.control_base = 0x3F6;
  hdd_device.drive = 0; // Master
  hdd_device.present = false;

  if (ata_identify(&hdd_device)) {
    print_string(22, 45, "HDD Found (Master)", 0x0A);
    hdd_device.present = true;
    hdd_device.size_sectors = 131072; // Assume 64MB for now (TODO: Identify)
    // We don't mount it as active by default, user must switch
  } else {
    print_string(22, 45, "No HDD Found", 0x0C);
  }

  // Mount logic
  if (active_disk) {
    if (!mount_fat16(active_disk, 0)) {
      // Only format RAM disk automatically
      if (active_disk == &ramdisk_device) {
        print_string(23, 10, "Formatting RAM disk...    ", 0x0E);
        if (format_fat16(active_disk, 0, active_disk->size_sectors)) {
          mount_fat16(active_disk, 0);
          print_string(23, 10, "Format complete.          ", 0x0A);
        } else {
          print_string(23, 10, "Format failed!            ", 0x0C);
        }
      }
    }
  }

  // AUTO-MOUNT HDD on boot ONLY IF .mou EXISTS ON THE VOLUME
  if (hdd_device.present) {
    bool hdd_mounted_on_boot = false;
    if (ata_read_sector(&hdd_device, 0, sector_buffer)) {
      if (sector_buffer[510] == 0x55 && sector_buffer[511] == 0xAA) {
        MBR *mbr = (MBR *)sector_buffer;
        for (int i = 0; i < 4; i++) {
          if (mbr->partitions[i].total_sectors > 0) {
            if (mount_fat16(&hdd_device, mbr->partitions[i].start_lba)) {
              read_directory(&hdd_device, root_dir_first_cluster);
              if (file_exists(".mou")) {
                active_disk = &hdd_device;
                hdd_mounted_on_boot = true;
                print_string(23, 45, "HDD Mounted (.mou present)", 0x0A);
                break;
              }
            }
          }
        }
        if (!hdd_mounted_on_boot && mount_fat16(&hdd_device, 0)) {
          read_directory(&hdd_device, root_dir_first_cluster);
          if (file_exists(".mou")) {
            active_disk = &hdd_device;
            hdd_mounted_on_boot = true;
            print_string(23, 45, "HDD Superfloppy (.mou present)", 0x0A);
          }
        }
      }
    }

    if (hdd_mounted_on_boot) {
      // RAM disk is unmounted; HDD is now active disk
      read_directory(active_disk, root_dir_first_cluster);
      create_mou_file_if_needed(active_disk);
    } else {
      // Re-mount RAM disk as active disk since HDD does not have .mou
      active_disk = &ramdisk_device;
      mount_fat16(active_disk, 0);
      read_directory(active_disk, root_dir_first_cluster);
      print_string(23, 45, "RAM disk active (No .mou) ", 0x0E);
    }
  }

  if (fs_mounted) {
    read_directory(active_disk, root_dir_first_cluster);
  }
  delay(1); // Kurze Pause
}

// ============================================================================
// GUI FUNKTIONEN
// ============================================================================

void draw_window(int start_row, int start_col, int height, int width,
                 const char *title, uint16_t border_color) {
  print_char(start_row, start_col, 201, border_color);
  for (int i = 1; i < width - 1; i++) {
    print_char(start_row, start_col + i, 205, border_color);
  }
  print_char(start_row, start_col + width - 1, 187, border_color);

  int title_len = string_length(title);
  if (title_len > 0) {
    int title_start = (width - title_len - 2) / 2;
    print_char(start_row, start_col + title_start, 185, border_color);
    print_string(start_row, start_col + title_start + 1, title, 0x0E);
    print_char(start_row, start_col + title_start + title_len + 1, 204,
               border_color);
  }

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
  print_string_centered(8, " __  __ _ _ _          ___  ____  ", 0x0D);
  print_string_centered(9, "|  \\/  (_) | | __ _   / _ \\/ ___| ", 0x0D);
  print_string_centered(10, "| |\\/| | | | |/ _` | | | | \\___ \\ ", 0x0D);
  print_string_centered(11, "| |  | | | | | (_| | | |_| |___) |", 0x0E);
  print_string_centered(12, "|_|  |_|_|_|_|\\__,_|  \\___/|____/ ", 0x0D);

  print_string_centered(14, "(Micro Integrated Low-Level Application OS)",
                        0x0A);
  print_string_centered(15, "An Free an open source OS.", 0x0A);
  print_string_centered(16, "by", 0x0A);
  print_string_centered(19, "FloriDevs", 0x0F);
}

// Modified to handle mouse internally
extern "C" uint8_t get_keyboard_input_nonblock() {
  uint8_t status = inb(0x64);
  if (status & 0x01) {
    uint8_t data = inb(0x60);
    if (status & 0x20) {
      handle_mouse_byte(data);
      return 0;
    } else {
      return data;
    }
  }
  return 0;
}

uint8_t get_keyboard_input() {
  while (true) {
    uint8_t status = inb(0x64);
    if (status & 0x01) {
      uint8_t data = inb(0x60);
      if (status & 0x20) {
        handle_mouse_byte(data);
        return 0;
      } else {
        return data;
      }
    }
  }
}

// ============================================================================
// SETTINGS
// ============================================================================

// Tastaturlayouts
// Tastaturlayouts
const char scancode_map_us[] = {
    0,   0,   '1', '2', '3', '4', '5', '6', '7', '8', '9',  '0', '-', '=',  0,
    0,   'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',  '[', ']', 0,    0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,   '\\', 'z',
    'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,   0,    0,   ' '};
const char scancode_map_us_shift[] = {
    0,   0,   '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0,
    0,   'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 0,   0,
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0,   '|', 'Z',
    'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,   0,   0,   ' '};
const char scancode_map_de[] = {
    0,   0,   '1', '2',        '3',        '4', '5', '6', '7',
    '8', '9', '0', (char)0xE1, 0x27,       0,   0,   'q', 'w',
    'e', 'r', 't', 'z',        'u',        'i', 'o', 'p', (char)0x81,
    '+', 0,   0,   'a',        's',        'd', 'f', 'g', 'h',
    'j', 'k', 'l', (char)0x94, (char)0x84, '^', 0,   '#', 'y',
    'x', 'c', 'v', 'b',        'n',        'm', ',', '.', '-',
    0,   0,   0,   ' '};
const char scancode_map_de_shift[] = {
    0,   0,   '!', '"',        0x15,       '$',        '%', '&',  '/',
    '(', ')', '=', '?',        '`',        0,          0,   'Q',  'W',
    'E', 'R', 'T', 'Z',        'U',        'I',        'O', 'P',  (char)0x9A,
    '*', 0,   0,   'A',        'S',        'D',        'F', 'G',  'H',
    'J', 'K', 'L', (char)0x99, (char)0x8E, (char)0xF8, 0,   '\'', 'Y',
    'X', 'C', 'V', 'B',        'N',        'M',        ';', ':',  '_',
    0,   0,   0,   ' '};
const char scancode_map_fr[] = {
    0,          0,   '&',        (char)0xE9, '"', '\'', '(', '-',
    (char)0xE8, '_', (char)0xE7, (char)0xE0, ')', '=',  0,   0,
    'a',        'z', 'e',        'r',        't', 'y',  'u', 'i',
    'o',        'p', '^',        '$',        0,   0,    'q', 's',
    'd',        'f', 'g',        'h',        'j', 'k',  'l', 'm',
    (char)0xF9, '*', 0,          '\\',       'w', 'x',  'c', 'v',
    'b',        'n', ',',        ';',        ':', '!',  0,   0,
    0,          ' '};
const char scancode_map_fr_shift[] = {
    0,          0,   '1', '2',  '3', '4',        '5', '6', '7',
    '8',        '9', '0', '\0', '+', 0,          0,   'A', 'Z',
    'E',        'R', 'T', 'Y',  'U', 'I',        'O', 'P', (char)0xA8,
    (char)0xA3, 0,   0,   'Q',  'S', 'D',        'F', 'G', 'H',
    'J',        'K', 'L', 'M',  '%', (char)0xB5, 0,   '|', 'W',
    'X',        'C', 'V', 'B',  'N', '?',        '.', '/', (char)0xA7,
    0,          0,   0,   ' '};

const char *current_scancode_map = scancode_map_us;
const char *current_scancode_map_shift = scancode_map_us_shift;

char scancode_to_ascii(uint8_t scancode, bool shift) {
  if (scancode < 58) {
    return shift ? current_scancode_map_shift[scancode]
                 : current_scancode_map[scancode];
  }
  return 0;
}

// Forward declarations
void milla_ide(const char *filename);
void doc_editor(const char *filename);
void text_editor(const char *filename);
extern "C" void start_graphical_shell();
extern "C" void start_cli();

// ============================================================================
// SHELL FILESYSTEM WRAPPERS (extern C for shell.cpp)
// ============================================================================
extern "C" int get_shell_file_count() { return file_count; }

extern "C" void get_shell_file_name(int index, char *out) {
  if (index >= 0 && index < file_count) {
    string_copy(out, file_cache[index].name);
  } else {
    out[0] = '\0';
  }
}

extern "C" uint32_t get_shell_file_size(int index) {
  if (index >= 0 && index < file_count)
    return file_cache[index].size;
  return 0;
}

extern "C" bool get_shell_file_is_dir(int index) {
  if (index >= 0 && index < file_count)
    return file_cache[index].is_directory;
  return false;
}

extern "C" void shell_refresh_files() {
  if (fs_mounted && active_disk) {
    read_directory(active_disk, current_dir_cluster);
  }
}

extern "C" bool shell_is_fs_mounted() { return fs_mounted; }

extern "C" char shell_scancode_to_ascii(uint8_t scancode, bool shift) {
  return scancode_to_ascii(scancode, shift);
}

extern "C" void shell_set_language(int lang) {
  if (lang == 1) {
    current_scancode_map = scancode_map_de;
    current_scancode_map_shift = scancode_map_de_shift;
  } else if (lang == 2) {
    current_scancode_map = scancode_map_fr;
    current_scancode_map_shift = scancode_map_fr_shift;
  } else {
    current_scancode_map = scancode_map_us;
    current_scancode_map_shift = scancode_map_us_shift;
  }
}

extern "C" bool shell_read_file(const char *filename, char *buffer,
                                uint32_t max_size) {
  int file_idx = find_file(filename);
  if (file_idx != -1 && fs_mounted && active_disk) {
    return read_file(active_disk, file_cache[file_idx].first_cluster, buffer,
                     max_size);
  }
  return false;
}

extern "C" bool shell_write_file(const char *filename, const char *data,
                                 uint32_t size) {
  if (fs_mounted && active_disk) {
    bool res = write_file(active_disk, filename, data, size);
    if (res)
      read_directory(active_disk, current_dir_cluster);
    return res;
  }
  return false;
}

extern "C" bool shell_format_disk(int disk_id) {
  ATADevice *disk = disk_id == 1 ? &ramdisk_device
                                 : (hdd_device.present ? &hdd_device : nullptr);
  if (disk) {
    return format_fat16(disk, 0, disk->size_sectors);
  }
  return false;
}

extern "C" bool shell_mount_disk(int disk_id) {
  ATADevice *disk = disk_id == 1 ? &ramdisk_device
                                 : (hdd_device.present ? &hdd_device : nullptr);
  if (disk) {
    if (mount_fat16(disk, 0)) {
      active_disk = disk;
      current_dir_cluster = 0;
      string_copy(current_dir_path, "/");
      read_directory(active_disk, current_dir_cluster);
      if (disk == &hdd_device) {
        create_mou_file_if_needed(disk);
      }
      return true;
    }
    if (disk == &hdd_device && ata_read_sector(disk, 0, sector_buffer)) {
      MBR *mbr = (MBR *)sector_buffer;
      for (int i = 0; i < 4; i++) {
        if (mbr->partitions[i].total_sectors > 0) {
          if (mount_fat16(disk, mbr->partitions[i].start_lba)) {
            active_disk = disk;
            current_dir_cluster = 0;
            string_copy(current_dir_path, "/");
            read_directory(active_disk, current_dir_cluster);
            create_mou_file_if_needed(disk);
            return true;
          }
        }
      }
    }
  }
  return false;
}

extern "C" void shell_unmount_disk() {
  fs_mounted = false;
  file_count = 0;
  current_dir_cluster = 0;
  string_copy(current_dir_path, "/");
}

extern "C" int shell_get_active_disk() {
  if (active_disk == &ramdisk_device)
    return 1;
  if (active_disk == &hdd_device)
    return 2;
  return 0;
}

extern "C" bool shell_is_hdd_present() { return hdd_device.present; }

bool delete_file(ATADevice *dev, const char *filename) {
  if (!dev || !fs_mounted || !filename)
    return false;

  char target_name[11];
  filename_to_fat83(filename, target_name);

  DirSectorIterator it;
  dir_iter_init(&it, dev, current_dir_cluster);

  bool deleted = false;
  uint32_t cur_lba = 0;

  while (dir_iter_next_sector(&it, &cur_lba)) {
    if (!ata_read_sector(dev, cur_lba, sector_buffer))
      break;

    DirEntry *entries = (DirEntry *)sector_buffer;
    bool sec_modified = false;
    bool end_of_dir = false;

    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00) {
        end_of_dir = true;
        break;
      }
      if (entries[i].filename[0] == 0xE5 || entries[i].attributes == 0x0F)
        continue;

      bool match = true;
      for (int k = 0; k < 11; k++) {
        if (entries[i].filename[k] != target_name[k]) {
          match = false;
          break;
        }
      }

      if (match) {
        if ((entries[i].attributes & 0x10) != 0) {
          if (target_name[0] == '.') return false;
          uint32_t sub_c = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
          if (sub_c >= 2) {
            DirSectorIterator sit;
            dir_iter_init(&sit, dev, sub_c);
            uint32_t slba = 0;
            uint8_t sbuf[512];
            bool empty = true;
            while (dir_iter_next_sector(&sit, &slba)) {
              if (ata_read_sector(dev, slba, sbuf)) {
                DirEntry *se = (DirEntry *)sbuf;
                for (int s = 0; s < (SECTOR_SIZE / sizeof(DirEntry)); s++) {
                  if (se[s].filename[0] == 0x00) break;
                  if (se[s].filename[0] == 0xE5 || se[s].attributes == 0x0F || se[s].filename[0] == '.') continue;
                  empty = false;
                  break;
                }
              }
              if (!empty) break;
            }
            if (!empty) return false;
          }
        }

        uint32_t cluster = ((uint32_t)entries[i].first_cluster_high << 16) |
                           entries[i].first_cluster_low;
        while (cluster >= 2 && cluster < 0xFFF8) {
          uint32_t next = get_fat_entry(dev, cluster);
          set_fat_entry(dev, cluster, 0x0000);
          cluster = next;
        }

        entries[i].filename[0] = 0xE5;
        sec_modified = true;
        deleted = true;
      }
    }

    if (sec_modified) {
      ata_write_sector(dev, cur_lba, sector_buffer);
    }
    if (end_of_dir)
      break;
  }

  if (deleted) {
    read_directory(dev, current_dir_cluster);
  }
  return deleted;
}

extern "C" bool shell_delete_file(const char *filename) {
  if (fs_mounted && active_disk) {
    return delete_file(active_disk, filename);
  }
  return false;
}

extern "C" bool shell_mkdir(const char *name) {
  if (fs_mounted && active_disk) {
    return create_directory(active_disk, current_dir_cluster, name);
  }
  return false;
}

extern "C" bool shell_rmdir(const char *name) {
  if (fs_mounted && active_disk) {
    return remove_directory(active_disk, current_dir_cluster, name);
  }
  return false;
}

extern "C" bool shell_move_file(const char *src, const char *dest) {
  if (fs_mounted && active_disk) {
    return move_file(active_disk, src, dest);
  }
  return false;
}

extern "C" bool shell_change_dir(const char *path) {
  if (!fs_mounted || !active_disk || !path)
    return false;

  if (path[0] == '/' && path[1] == '\0') {
    current_dir_cluster = 0;
    string_copy(current_dir_path, "/");
    read_directory(active_disk, current_dir_cluster);
    return true;
  }

  if (path[0] == '.' && path[1] == '\0') {
    return true;
  }

  if (path[0] == '.' && path[1] == '.' && path[2] == '\0') {
    if (current_dir_cluster == 0) {
      return true; // Already at root
    }
    for (int i = 0; i < file_count; i++) {
      if (file_cache[i].is_directory && file_cache[i].name[0] == '.' && file_cache[i].name[1] == '.') {
        current_dir_cluster = file_cache[i].first_cluster;
        int len = string_length(current_dir_path);
        if (len > 1) {
          if (current_dir_path[len - 1] == '/') len--;
          while (len > 0 && current_dir_path[len - 1] != '/') len--;
          if (len == 0) len = 1;
          current_dir_path[len] = '\0';
        }
        read_directory(active_disk, current_dir_cluster);
        return true;
      }
    }
    current_dir_cluster = 0;
    string_copy(current_dir_path, "/");
    read_directory(active_disk, current_dir_cluster);
    return true;
  }

  int idx = find_file(path);
  if (idx != -1 && file_cache[idx].is_directory) {
    current_dir_cluster = file_cache[idx].first_cluster;
    int plen = string_length(current_dir_path);
    if (plen > 0 && current_dir_path[plen - 1] != '/') {
      current_dir_path[plen++] = '/';
      current_dir_path[plen] = '\0';
    }
    int nlen = string_length(file_cache[idx].name);
    for (int i = 0; i < nlen && plen < 120; i++) {
      current_dir_path[plen++] = file_cache[idx].name[i];
    }
    current_dir_path[plen++] = '/';
    current_dir_path[plen] = '\0';

    read_directory(active_disk, current_dir_cluster);
    return true;
  }

  return false;
}

extern "C" const char *shell_get_current_path() {
  return current_dir_path;
}

extern "C" uint32_t shell_get_current_cluster() {
  return current_dir_cluster;
}


// ============================================================================
// KERNEL MAIN
// ============================================================================

extern "C" void kernel_main(uint32_t magic, multiboot_info *info) {
  // Initialize mouse early
  init_mouse();

  // Initialize graphics if available
  screen.active = false;

  if (magic == 0x2BADB002) {
    // Priority 1: Modern Framebuffer Tag (Bit 12)
    if (info->flags & (1 << 12)) {
      screen.framebuffer = (uint32_t *)(uintptr_t)info->framebuffer_addr;
      screen.width = info->framebuffer_width;
      screen.height = info->framebuffer_height;
      screen.pitch = info->framebuffer_pitch;
      screen.active = true;
    }
    // Priority 2: VBE Tag (Bit 11)
    else if (info->flags & (1 << 11)) {
      vbe_mode_info *vbe = (vbe_mode_info *)(uintptr_t)info->vbe_mode_info;
      if (vbe->framebuffer != 0) {
        screen.framebuffer = (uint32_t *)(uintptr_t)vbe->framebuffer;
        screen.width = vbe->x_res;
        screen.height = vbe->y_res;
        screen.pitch = vbe->bytes_per_scanline;
        screen.active = true;
      }
    }
  }

  // Calculate RAM size from multiboot info
  if (magic == 0x2BADB002) {
    if (info->flags & 1) {
      // mem_upper is KB above 1MB
      system_ram_mb = (info->mem_upper + 1024) / 1024;
    }
  }
  if (system_ram_mb == 0)
    system_ram_mb = 128; // Fallback

  if (screen.active) {
    if (screen.framebuffer) {
      uint32_t total_pixels = screen.width * screen.height;
      for (uint32_t i = 0; i < total_pixels; i++) {
        screen.framebuffer[i] = 0x1A1A1A;
      }
    }
    init_filesystem();
    while (1) {
      start_graphical_shell();
      start_cli();
    }
  } else {
    init_filesystem();
    start_cli();
  }
}

// ***ENDE CODE***
