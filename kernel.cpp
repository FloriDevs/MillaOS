#include <stddef.h>
#include <stdint.h>

extern "C" {
    void* malloc(size_t size);
    void free(void* ptr);

    // C-String und Speicherfunktionen
    int string_length(const char* str);
    void string_copy(char* dest, const char* src);
    bool string_compare(const char* s1, const char* s2);
    void memset(void* ptr, uint8_t value, uint32_t size);
    void memcpy(void* dest, const void* src, uint32_t size);
}

// Minimal heap implementation (for example only)
static uint8_t kernel_heap[1024 * 1024]; // 1 MB heap
static size_t heap_top = 0;

extern "C" void* malloc(size_t size) {
    if (heap_top + size >= sizeof(kernel_heap)) return nullptr;
    void* ptr = &kernel_heap[heap_top];
    heap_top += size;
    return ptr;
}

extern "C" void free(void*) {
    // no-op for now
}

// C++ operators
void* operator new(size_t size) { return malloc(size); }
void* operator new[](size_t size) { return malloc(size); }
void operator delete(void* p) noexcept { free(p); }
void operator delete[](void* p) noexcept { free(p); }


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

extern "C" void insl(uint16_t port, void* addr, uint32_t count) {
    asm volatile("cld; rep insl" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
}

extern "C" void outsl(uint16_t port, const void* addr, uint32_t count) {
    asm volatile("cld; rep outsl" : "+S"(addr), "+c"(count) : "d"(port) : "memory");
}

// Verbesserte Delay-Funktion (wichtig!)
void delay(uint32_t count) {
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
    if (row < 0 || row >= 25 || col < 0 || col >= 80) return;
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

// ============================================================================
// C-STRING UND SPEICHER FUNKTIONEN (JETZT EXTERN C)
// ============================================================================
extern "C" {
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

    void memset(void* ptr, uint8_t value, uint32_t size) {
        uint8_t* p = (uint8_t*)ptr;
        for (uint32_t i = 0; i < size; i++) {
            p[i] = value;
        }
    }

    void memcpy(void* dest, const void* src, uint32_t size) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        for (uint32_t i = 0; i < size; i++) {
            d[i] = s[i];
        }
    }
} // Ende extern "C"

const char* get_filename_ext(const char *filename) {
    const char *dot = nullptr;
    while (*filename) {
        if (*filename == '.') dot = filename;
        filename++;
    }
    return dot ? dot + 1 : "";
}


// ============================================================================
// VIRTUELLER (RAM-DISK) DISK DRIVER
// ============================================================================

// Dummy-Struktur, um FAT-Treiber-Signatur anzupassen
struct ATADevice {
    uint16_t io_base;
    uint16_t control_base;
    uint8_t drive; 
    bool present;
    uint32_t size_sectors;
};

// Es gibt nur noch die RAM-Disk
ATADevice* active_disk = nullptr; // Zeigt auf die RAM-Disk

// +++ BEGINN RAM-DISK IMPLEMENTIERUNG +++
const size_t RAMDISK_SIZE_BYTES = 800 * 1024; // 800KB
const size_t RAMDISK_SIZE_SECTORS = RAMDISK_SIZE_BYTES / 512;
uint8_t* ramdisk_storage = nullptr; // Zeiger auf den Speicher der RAM-Disk
ATADevice ramdisk_device; // Ein virtuelles ATADevice für die RAM-Disk
#define RAMDISK_MAGIC_IO 0xDEAD // Eindeutige ID statt I/O-Port
#define SECTOR_SIZE 512 // Definiert hier, da es global genutzt wird
// +++ ENDE RAM-DISK IMPLEMENTIERUNG +++


bool ata_read_sector(ATADevice* dev, uint32_t lba, uint8_t* buffer) {
    // +++ RAM-DISK LESE-LOGIK +++
    if (dev->io_base == RAMDISK_MAGIC_IO) {
        if (!dev->present || lba >= dev->size_sectors) return false;
        
        uint32_t offset = lba * SECTOR_SIZE;
        memcpy(buffer, &ramdisk_storage[offset], SECTOR_SIZE);
        return true;
    }
    // +++ ENDE RAM-DISK +++

    // Kein Hardware-Support mehr
    return false;
}

bool ata_write_sector(ATADevice* dev, uint32_t lba, const uint8_t* buffer) {
    // +++ RAM-DISK SCHREIB-LOGIK +++
    if (dev->io_base == RAMDISK_MAGIC_IO) {
        if (!dev->present || lba >= dev->size_sectors) return false;
        
        uint32_t offset = lba * SECTOR_SIZE;
        memcpy(&ramdisk_storage[offset], buffer, SECTOR_SIZE);
        return true;
    }
    // +++ ENDE RAM-DISK +++

    // Kein Hardware-Support mehr
    return false;
}

// ============================================================================
// FAT16 DATEISYSTEM
// ============================================================================

#define MAX_FILES 64
#define MAX_FILENAME 12

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

uint32_t fat_begin_lba = 0;
uint32_t cluster_begin_lba = 0;
uint32_t sectors_per_cluster = 0;
uint32_t root_dir_lba = 0; 
uint32_t root_dir_sectors = 0; 
uint32_t root_dir_first_cluster = 0; 

bool format_fat16(ATADevice* dev) {
    if (!dev->present) return false;
    
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
    boot_sector.hidden_sectors = 0;

    // Setze Sektorgrößen
    uint32_t total_sectors = dev->size_sectors;
    if (total_sectors < 0x10000) {
        boot_sector.total_sectors_16 = (uint16_t)total_sectors;
        boot_sector.total_sectors_32 = 0;
    } else {
        boot_sector.total_sectors_16 = 0;
        boot_sector.total_sectors_32 = total_sectors;
    }

    // Berechne Root-Verzeichnis-Größe
    root_dir_sectors = (boot_sector.root_entry_count * sizeof(DirEntry) + boot_sector.bytes_per_sector - 1) / boot_sector.bytes_per_sector;
    
    // Berechne FAT-Größe
    uint32_t data_sectors = total_sectors - boot_sector.reserved_sectors - root_dir_sectors;
    uint32_t cluster_count = data_sectors / boot_sector.sectors_per_cluster;
    uint32_t fat_size_sectors = (cluster_count * 2 + boot_sector.bytes_per_sector - 1) / boot_sector.bytes_per_sector;
    
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
    
    if (!ata_write_sector(dev, 0, sector_buffer)) return false;
    
    // Initialisiere FAT (beide Kopien)
    memset(sector_buffer, 0, SECTOR_SIZE);
    ((uint16_t*)sector_buffer)[0] = 0xFFF8; 
    ((uint16_t*)sector_buffer)[1] = 0xFFFF; 
    
    uint32_t fat1_lba = boot_sector.reserved_sectors;
    uint32_t fat2_lba = fat1_lba + boot_sector.sectors_per_fat_16;
    
    if (!ata_write_sector(dev, fat1_lba, sector_buffer)) return false;
    if (!ata_write_sector(dev, fat2_lba, sector_buffer)) return false;
    
    // Lösche restliche FAT Sektoren
    memset(sector_buffer, 0, SECTOR_SIZE);
    for (uint32_t i = 1; i < boot_sector.sectors_per_fat_16; i++) {
        ata_write_sector(dev, fat1_lba + i, sector_buffer);
        ata_write_sector(dev, fat2_lba + i, sector_buffer);
    }
    
    // Initialisiere Root Directory (fester Ort bei FAT16)
    uint32_t root_lba = fat1_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);
    
    memset(sector_buffer, 0, SECTOR_SIZE);
    for (uint32_t i = 0; i < root_dir_sectors; i++) {
        if (!ata_write_sector(dev, root_lba + i, sector_buffer)) return false;
    }
    
    return true;
}

bool mount_fat16(ATADevice* dev) {
    if (!dev->present) return false;
    
    if (!ata_read_sector(dev, 0, sector_buffer)) return false;
    
    // Überprüfe die Magische Zahl
    if (sector_buffer[510] != 0x55 || sector_buffer[511] != 0xAA) return false;

    memcpy(&boot_sector, sector_buffer, sizeof(BootSector));
    
    if (boot_sector.bytes_per_sector != 512) return false;
    if (boot_sector.fat_count == 0) return false;
    
    fat_begin_lba = boot_sector.reserved_sectors;
    
    // Berechne Positionen für FAT16
    root_dir_sectors = (boot_sector.root_entry_count * sizeof(DirEntry) + boot_sector.bytes_per_sector - 1) / boot_sector.bytes_per_sector;
    root_dir_lba = fat_begin_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);
    cluster_begin_lba = root_dir_lba + root_dir_sectors;
    
    sectors_per_cluster = boot_sector.sectors_per_cluster;
    root_dir_first_cluster = 0; 
    
    fs_mounted = true;
    return true;
}

uint32_t cluster_to_lba(uint32_t cluster) {
    return cluster_begin_lba + (cluster - 2) * sectors_per_cluster;
}

uint32_t get_fat_entry(ATADevice* dev, uint32_t cluster) {
    uint32_t fat_offset = cluster * 2; 
    uint32_t fat_sector = fat_begin_lba + (fat_offset / SECTOR_SIZE);
    uint32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    if (!ata_read_sector(dev, fat_sector, sector_buffer)) return 0xFFFF; 
    
    return *((uint16_t*)&sector_buffer[entry_offset]);
}

void set_fat_entry(ATADevice* dev, uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 2; 
    uint32_t fat_sector = fat_begin_lba + (fat_offset / SECTOR_SIZE);
    uint32_t entry_offset = fat_offset % SECTOR_SIZE;
    
    ata_read_sector(dev, fat_sector, sector_buffer);
    *((uint16_t*)&sector_buffer[entry_offset]) = value & 0xFFFF; 
    ata_write_sector(dev, fat_sector, sector_buffer);
    
    // Update second FAT copy
    uint32_t fat2_sector = fat_sector + boot_sector.sectors_per_fat_16;
    ata_read_sector(dev, fat2_sector, sector_buffer);
    *((uint16_t*)&sector_buffer[entry_offset]) = value & 0xFFFF; 
    ata_write_sector(dev, fat2_sector, sector_buffer);
}

uint32_t allocate_cluster(ATADevice* dev) {
    for (uint32_t cluster = 2; cluster < 0xFFF0; cluster++) {
        uint32_t entry = get_fat_entry(dev, cluster);
        if (entry == 0) {
            set_fat_entry(dev, cluster, 0xFFFF); // FAT16 EOF
            return cluster;
        }
    }
    return 0;
}

bool read_directory(ATADevice* dev, uint32_t cluster) {
    file_count = 0;
    
    if (cluster == 0) { 
        for (uint32_t sec = 0; sec < root_dir_sectors; sec++) {
            if (!ata_read_sector(dev, root_dir_lba + sec, sector_buffer)) return false;
            
            DirEntry* entries = (DirEntry*)sector_buffer;
            
            for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
                if (entries[i].filename[0] == 0x00) return true; 
                if (entries[i].filename[0] == 0xE5) continue; 
                if (entries[i].attributes == 0x0F) continue; 
                
                if (file_count >= MAX_FILES) return true;
                
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
                file_cache[file_count].is_directory = (entries[i].attributes & 0x10) != 0;
                file_cache[file_count].first_cluster = ((uint32_t)entries[i].first_cluster_high << 16) | 
                                                        entries[i].first_cluster_low;
                file_count++;
            }
        }
    } else { 
        while (cluster < 0xFFF8) { 
            uint32_t lba = cluster_to_lba(cluster);
            
            for (uint8_t sec = 0; sec < sectors_per_cluster; sec++) {
                if (!ata_read_sector(dev, lba + sec, sector_buffer)) return false;
                
                DirEntry* entries = (DirEntry*)sector_buffer;
                
                for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
                    if (entries[i].filename[0] == 0x00) return true;
                    if (entries[i].filename[0] == 0xE5) continue;
                    if (entries[i].attributes == 0x0F) continue;
                    
                    if (file_count >= MAX_FILES) return true;
                    
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
                    file_cache[file_count].is_directory = (entries[i].attributes & 0x10) != 0;
                    file_cache[file_count].first_cluster = ((uint32_t)entries[i].first_cluster_high << 16) | entries[i].first_cluster_low;
                    file_count++;
                }
            }
            cluster = get_fat_entry(dev, cluster);
        }
    }
    return true;
}

int find_file(const char* name) {
    for (int i = 0; i < file_count; i++) {
        if (string_compare(file_cache[i].name, name)) {
            return i;
        }
    }
    return -1;
}

bool read_file(ATADevice* dev, uint32_t cluster, char* buffer, uint32_t max_size) {
    uint32_t pos = 0;
    
    while (cluster < 0xFFF8 && pos < max_size) { 
        uint32_t lba = cluster_to_lba(cluster);
        
        for (uint8_t sec = 0; sec < sectors_per_cluster && pos < max_size; sec++) {
            if (!ata_read_sector(dev, lba + sec, sector_buffer)) return false;
            
            uint32_t to_copy = (max_size - pos < SECTOR_SIZE) ? (max_size - pos) : SECTOR_SIZE;
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
        buffer[max_size - 1] = '\0'; // Erzwinge Nullterminierung, falls max_size erreicht wurde
    }
    
    return true;
}

bool write_file(ATADevice* dev, const char* filename, const char* data, uint32_t size) {
    // Finde leeren Verzeichniseintrag (nur im Root-Verzeichnis)
    uint32_t dir_lba = root_dir_lba;
    
    int empty_entry = -1;
    uint32_t entry_lba = 0; 
    
    // TODO: Diese Funktion sollte prüfen, ob die Datei bereits existiert.
    // Wenn ja, sollte sie die alte Cluster-Kette finden, alle Cluster
    // in der FAT als 'frei' (0) markieren und den Verzeichniseintrag
    // wiederverwenden, anstatt einen neuen zu suchen.
    // Die aktuelle Implementierung kann Dateien NICHT überschreiben.
    
    for (uint32_t sec = 0; sec < root_dir_sectors; sec++) {
        if (!ata_read_sector(dev, dir_lba + sec, sector_buffer)) return false;
        
        DirEntry* entries = (DirEntry*)sector_buffer;
        for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
            if (entries[i].filename[0] == 0x00 || entries[i].filename[0] == 0xE5) {
                empty_entry = i;
                entry_lba = dir_lba + sec;
                break;
            }
        }
        if (empty_entry != -1) break;
    }
    
    if (empty_entry == -1) return false; // Kein Platz im Root-Verzeichnis
    
    // Alloziere Cluster für Dateidaten
    uint32_t file_cluster = allocate_cluster(dev);
    if (file_cluster == 0) return false; // Kein Speicherplatz (Cluster)
    
    // Schreibe Dateidaten
    uint32_t written = 0;
    uint32_t current_cluster = file_cluster;
    
    while (written < size) {
        uint32_t file_lba = cluster_to_lba(current_cluster);
        
        for (uint8_t sec = 0; sec < sectors_per_cluster && written < size; sec++) {
            memset(sector_buffer, 0, SECTOR_SIZE);
            uint32_t to_write = (size - written < SECTOR_SIZE) ? (size - written) : SECTOR_SIZE;
            memcpy(sector_buffer, data + written, to_write);
            
            if (!ata_write_sector(dev, file_lba + sec, sector_buffer)) return false;
            written += to_write;
        }
        
        if (written < size) {
            uint32_t next_cluster = allocate_cluster(dev);
            if (next_cluster == 0) return false; // Kein Speicherplatz mehr
            set_fat_entry(dev, current_cluster, next_cluster);
            current_cluster = next_cluster;
        }
    }
    
    // Erstelle Verzeichniseintrag
    ata_read_sector(dev, entry_lba, sector_buffer); 
    DirEntry* entries = (DirEntry*)sector_buffer;
    DirEntry* entry = &entries[empty_entry];
    
    memset(entry, 0, sizeof(DirEntry));
    
    // KORREKTUR: Parse Dateiname (8.3 Format, Großbuchstaben, Padding)
    memset(entry->filename, ' ', 11); // Mit Leerzeichen füllen
    
    int name_pos = 0;
    int ext_pos = 8;
    bool found_dot = false;
    
    for (int i = 0; filename[i] != '\0'; i++) {
        char c = filename[i];
        
        if (c == '.') {
            found_dot = true;
            continue;
        }
        
        // Konvertiere zu Großbuchstaben
        if (c >= 'a' && c <= 'z') c -= 32; 
        
        if (found_dot) {
            if (ext_pos < 11) {
                entry->filename[ext_pos++] = c;
            }
        } else {
            if (name_pos < 8) {
                entry->filename[name_pos++] = c;
            }
        }
    }
    
    entry->attributes = 0x20; // Archive
    entry->first_cluster_high = (file_cluster >> 16) & 0xFFFF;
    entry->first_cluster_low = file_cluster & 0xFFFF;
    entry->file_size = size;
    
    return ata_write_sector(dev, entry_lba, sector_buffer);
}

// NUR NOCH RAM-DISK INIT
void init_filesystem() {
    
    // +++ ERSTELLE RAM-DISK +++
    print_string(21, 10, "Creating RAM disk...", 0x0E);
    
    // Speicher allozieren (MUSS VOR ANDEREN MALLOCS PASSIEREN)
    ramdisk_storage = (uint8_t*)malloc(RAMDISK_SIZE_BYTES);
    
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
    
    
    if (active_disk) {
        if (!mount_fat16(active_disk)) {
            // Formatiere wenn Mount fehlschlägt
            print_string(23, 10, "Formatting RAM disk...    ", 0x0E);
            if(format_fat16(active_disk)) {
                mount_fat16(active_disk);
                print_string(23, 10, "Format complete.          ", 0x0A);
            } else {
                print_string(23, 10, "Format failed!            ", 0x0C);
            }
        }
        read_directory(active_disk, root_dir_first_cluster);
    }
    delay(1); // Kurze Pause
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
    if (title_len > 0) {
        int title_start = (width - title_len - 2) / 2;
        print_char(start_row, start_col + title_start, 185, border_color);
        print_string(start_row, start_col + title_start + 1, title, 0x0E);
        print_char(start_row, start_col + title_start + title_len + 1, 204, border_color);
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

    print_string_centered(14, "(Micro Integrated Low-Level Application OS)", 0x0A);
    print_string_centered(15, "An Free an open source OS.", 0x0A);
    print_string_centered(16, "by", 0x0A);
    print_string_centered(19, "FloriDevs", 0x0F); 
}

uint8_t get_keyboard_input() {
    while ((inb(0x64) & 0x01) == 0);
    return inb(0x60);
}

// Tastaturlayouts
const char scancode_map_us[] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0, 0,
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0, 0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, 0, 0, ' '
};
const char scancode_map_us_shift[] = {
    0, 0, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0, 0,
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 0, 0,
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|',
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, 0, 0, ' '
};
const char scancode_map_de[] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '\'', '=', 0, 0,
    'q', 'w', 'e', 'r', 't', 'z', 'u', 'i', 'o', 'p', 'u', '+', 0, 0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'o', 'a', '^', 0, '#',
    'y', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '-', 0, 0, 0, ' '
};
const char scancode_map_de_shift[] = {
    0, 0, '!', '"', '\xA7', '$', '%', '^', '&', '/', '(', ')', '=', '?', '`', 0, 0,
    'Q', 'W', 'E', 'R', 'T', 'Z', 'U', 'I', 'O', 'P', 'U', '*', 0, 0,
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'O', 'A', ' ', 0, '\'',
    'Y', 'X', 'C', 'V', 'B', 'N', 'M', ';', ':', '_', 0, 0, 0, ' '
};
const char* current_scancode_map = scancode_map_de;
const char* current_scancode_map_shift = scancode_map_de_shift;

char scancode_to_ascii(uint8_t scancode, bool shift) {
    if (scancode < 58) {
        return shift ? current_scancode_map_shift[scancode] : current_scancode_map[scancode];
    }
    return 0;
}

void text_editor(const char* filename);

// ============================================================================
// SIMULIERTER C++ PROGRAMM-LADER
// ============================================================================
void run_cpp_program(const char* filename) {
    clear_screen(0x00);
    draw_window(5, 10, 15, 60, " C++ Program Runner ", 0x0A);
    print_string(7, 12, "Executing program: ", 0x70);
    print_string(7, 31, filename, 0x70);

    print_string(9, 12, "---------------------------------------------", 0x70);
    print_string(10, 12, "Output:", 0x70);
    print_string(12, 12, "Hello, C++!", 0x0F);
    print_string(14, 12, "Program finished with exit code 0.", 0x70);
    print_string(16, 12, "---------------------------------------------", 0x70);
    
    print_string_centered(22, "Press any key to continue...", 0x0E);
    get_keyboard_input();
}

// ============================================================================
// DISK MANAGEMENT TOOL (ENTFERNT)
// ============================================================================
// (Funktion gelöscht)

// ============================================================================
// DATEIMANAGER
// ============================================================================

void file_manager() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, "File Manager - FAT16", 0x1E); 
    print_string(0, 50, "ESC=Exit", 0x1F); // Geändert
    
    draw_window(2, 5, 21, 70, " Drives & Files ", 0x0B);
    
    print_string(3, 8, "Active Drive:", 0x70);
    
    // **GEÄNDERT: Nur noch MRD0-Logik**
    char disk_info[50];
    if (active_disk == &ramdisk_device) {
        string_copy(disk_info, "[MRD0] - "); // GEÄNDERT
    } else {
        string_copy(disk_info, "[---] - ");
    }
    
    if (active_disk && fs_mounted) {
        int pos = string_length(disk_info);
        string_copy(disk_info + pos, "FAT16 (");
        pos = string_length(disk_info);
        
        // KORREKTUR: Robuste Größenberechnung (zeigt KB, da < 1 MB)
        uint32_t size_kb = (active_disk->size_sectors * 512) / 1024;
        char temp[20];
        int temp_len = 0;
        if (size_kb == 0) {
            temp[temp_len++] = '0';
        } else {
            uint32_t n = size_kb;
            // Zahlen rückwärts in temp speichern
            while (n > 0 && temp_len < 19) {
                temp[temp_len++] = '0' + (n % 10);
                n /= 10;
            }
        }
        // Zahlen in korrekter Reihenfolge in disk_info schreiben
        for (int i = temp_len - 1; i >= 0; i--) {
            disk_info[pos++] = temp[i];
        }
        
        disk_info[pos++] = ' ';
        disk_info[pos++] = 'K'; // Geändert auf KB
        disk_info[pos++] = 'B';
        disk_info[pos++] = ')';
        disk_info[pos] = '\0';
        
    } else if (active_disk) {
         string_copy(disk_info + string_length(disk_info), "Disk present, not mounted");
    } else {
        string_copy(disk_info + string_length(disk_info), "No disk active");
    }
    print_string(4, 8, disk_info, 0x70);

    print_string(7, 8, "Filename", 0x70);
    print_string(7, 30, "Size", 0x70);
    print_string(7, 45, "Type", 0x70);
    for (int i = 0; i < 68; i++) print_char(8, 6 + i, 196, 0x70);
    
    int selected = 0;
    bool running = true;
    
    while (running) {
        // Leere den Dateibereich, bevor er neu gezeichnet wird
        for (int i = 0; i < 12; i++) {
            print_string(9 + i, 8, "                                                  ", 0x70);
        }

        if (fs_mounted) {
            for (int i = 0; i < file_count && i < 12; i++) {
                uint16_t color = (i == selected) ? 0x07 : 0x70;
                
                print_string(9 + i, 8, file_cache[i].name, color);
                
                char size_str[10] = "        ";
                int size = file_cache[i].size;
                int pos = 7;
                if (size == 0) {
                    size_str[pos--] = '0';
                } else {
                    while (size > 0 && pos >= 0) {
                        size_str[pos--] = '0' + (size % 10);
                        size /= 10;
                    }
                }
                print_string(9 + i, 30, size_str, color);
                print_string(9 + i, 45, file_cache[i].is_directory ? "DIR" : "FILE", color);
            }
        } else {
             print_string(10, 8, "No filesystem mounted.", 0x70);
        }
        
        for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
        print_string(24, 2, "UP/DOWN ENTER=Open ESC=Exit", 0x70); // Geändert
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) {
            running = false;
        } else if (scancode == 0x3D) { // F3 - Entfernt
            // Nichts tun
        } else if (scancode == 0x48 && selected > 0) {
            selected--;
        } else if (scancode == 0x50 && selected < file_count - 1) {
            selected++;
        } else if (scancode == 0x1C && file_count > 0 && active_disk && fs_mounted) { // ENTER
            const char* ext = get_filename_ext(file_cache[selected].name);
            if (string_compare(ext, "TXT")) {
                text_editor(file_cache[selected].name);
                running = false;
            } else if (string_compare(ext, "CPP")) {
                run_cpp_program(file_cache[selected].name);
                // Redraw file manager
                clear_screen(0x03);
                for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
                print_string(0, 2, "File Manager - FAT16", 0x1E); 
                print_string(0, 50, "ESC=Exit", 0x1F);
                draw_window(2, 5, 21, 70, " Drives & Files ", 0x0B);
                print_string(3, 8, "Active Drive:", 0x70);
                print_string(4, 8, disk_info, 0x70);
                print_string(7, 8, "Filename", 0x70);
                print_string(7, 30, "Size", 0x70);
                print_string(7, 45, "Type", 0x70);
                for (int i = 0; i < 68; i++) print_char(8, 6 + i, 196, 0x70);
            }
        }
    }
}

// ============================================================================
// TEXTEDITOR
// ============================================================================

#define EDITOR_BUFFER_SIZE 8192

char editor_buffer[EDITOR_BUFFER_SIZE];

void text_editor(const char* filename) {
    
    char title[40] = "Text Editor - ";
    int fn_len = string_length(filename);
    for (int i = 0; i < fn_len && i < 25; i++) {
        title[14 + i] = filename[i];
    }
    title[14 + fn_len] = '\0';
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, title, 0x1E);
    print_string(0, 45, "F1=Save F2=Reload ESC=Exit", 0x1F);
    
    // Buffer leeren (mit Leerzeichen füllen, wie im Original)
    for (int i = 0; i < EDITOR_BUFFER_SIZE; i++) editor_buffer[i] = ' ';
    int buffer_pos = 0;

    int file_idx = find_file(filename);
    if (file_idx != -1 && fs_mounted && active_disk) {
        read_file(active_disk, file_cache[file_idx].first_cluster, editor_buffer, 
                  file_cache[file_idx].size < EDITOR_BUFFER_SIZE ? file_cache[file_idx].size : EDITOR_BUFFER_SIZE);
        buffer_pos = file_cache[file_idx].size;
    } else {
        // Datei existiert nicht (oder ist neu), buffer_pos bleibt 0
        buffer_pos = 0;
    }
    
    // Fülle den Rest des Puffers mit Leerzeichen (read_file nullterminiert,
    // aber der Editor erwartet Leerzeichen zum Rendern)
    for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++) editor_buffer[i] = ' ';
    
    int cursor_row = 1;
    int cursor_col = 0;
    bool shift_pressed = false;
    bool running = true;
    
    while (running) {
        for (int row = 1; row < 24; row++) {
            for (int col = 0; col < 80; col++) {
                int pos = (row - 1) * 80 + col;
                if (pos < EDITOR_BUFFER_SIZE) {
                   print_char(row, col, editor_buffer[pos] == '\n' ? ' ' : editor_buffer[pos], 0x0F);
                }
            }
        }
        
        print_char(cursor_row, cursor_col, 219, 0x0E);
        
        for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
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
        
        if (scancode == 0x01) {
            running = false;
        } else if (scancode == 0x3B) { // F1 - Save
            if (fs_mounted && active_disk) {
                
                // KORREKTUR: Berechne die tatsächliche Größe (ignoriere nachfolgende Leerzeichen/Nulls)
                int actual_size = EDITOR_BUFFER_SIZE - 1;
                while(actual_size >= 0 && (editor_buffer[actual_size] == ' ' || 
                                           editor_buffer[actual_size] == '\0' || 
                                           editor_buffer[actual_size] == '\n')) {
                    actual_size--;
                }
                buffer_pos = actual_size + 1; // Größe ist Index + 1

                // TODO: Datei löschen/überschreiben, falls sie existiert
                // (Aktuelle Implementierung fügt nur hinzu)
                write_file(active_disk, filename, editor_buffer, buffer_pos);
                read_directory(active_disk, root_dir_first_cluster);
                print_string(24, 30, "File saved to disk!", 0x72);
                delay(10);
            }
        } else if (scancode == 0x3C) { // F2 - Reload
            file_idx = find_file(filename); // Index neu finden
            if (file_idx != -1 && fs_mounted && active_disk) {
                for (int i = 0; i < EDITOR_BUFFER_SIZE; i++) editor_buffer[i] = ' ';
                read_file(active_disk, file_cache[file_idx].first_cluster, editor_buffer, 
                         file_cache[file_idx].size < EDITOR_BUFFER_SIZE ? file_cache[file_idx].size : EDITOR_BUFFER_SIZE);
                buffer_pos = file_cache[file_idx].size;
                // Fülle Rest mit Leerzeichen
                for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++) editor_buffer[i] = ' ';
                
                print_string(24, 30, "File reloaded!", 0x72);
                delay(10);
            }
        } else if (scancode == 0x2A || scancode == 0x36) {
            shift_pressed = true;
        } else if (scancode == 0xAA || scancode == 0xB6) {
            shift_pressed = false;
        } else if (scancode == 0x48 && cursor_row > 1) {
            cursor_row--;
        } else if (scancode == 0x50 && cursor_row < 23) {
            cursor_row++;
        } else if (scancode == 0x4B && cursor_col > 0) {
            cursor_col--;
        } else if (scancode == 0x4D && cursor_col < 79) {
            cursor_col++;
        } else if (scancode == 0x0E) { // Backspace
            int pos = (cursor_row - 1) * 80 + cursor_col;
            if (pos > 0) {
                // Bewege Cursor
                if (cursor_col > 0) {
                    cursor_col--;
                } else if (cursor_row > 1) {
                    cursor_row--;
                    cursor_col = 79;
                }
                
                // Aktualisiere Puffer (Zeichen löschen und Rest nachrücken)
                int new_pos = (cursor_row - 1) * 80 + cursor_col;
                for(int i = new_pos; i < EDITOR_BUFFER_SIZE - 1; ++i) {
                     editor_buffer[i] = editor_buffer[i+1];
                }
                editor_buffer[EDITOR_BUFFER_SIZE - 1] = ' '; // Letztes Feld aufräumen
            }
        } else if (scancode == 0x1C) { // Enter
            if (cursor_row < 23) {
                cursor_row++;
                cursor_col = 0;
            }
        } else {
            char ch = scancode_to_ascii(scancode, shift_pressed);
            if (ch != 0) {
                int pos = (cursor_row - 1) * 80 + cursor_col;
                if (pos < EDITOR_BUFFER_SIZE - 1) {
                    editor_buffer[pos] = ch;
                    if (pos >= buffer_pos) buffer_pos = pos + 1;
                
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
    
    
}

// ============================================================================
// TASCHENRECHNER
// ============================================================================

void calculator() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, "Calculator", 0x1E);
    print_string(0, 60, "ESC=Exit", 0x1F);
    
    draw_window(3, 20, 18, 40, " Calculator ", 0x0B);
    
    char display[20] = "0";
    int display_len = 1;
    long num1 = 0;
    long num2 = 0;
    char operation = 0;
    bool new_number = true;
    bool running = true;
    bool shift_pressed = false;

    int cursor_x = 0, cursor_y = 0;
    
    while (running) {
        print_string(5, 22, "                                  ", 0x70);
        print_string(5, 41 - display_len, display, 0x0F);
        
        const char* buttons[16] = {
            "7", "8", "9", "/",
            "4", "5", "6", "*",
            "1", "2", "3", "-",
            "0", "C", "=", "+"
        };
        
        for (int y = 0; y < 4; y++) {
            for (int x = 0; x < 4; x++) {
                int row = 7 + y * 3;
                int col = 23 + x * 8;
                uint16_t color = (x == cursor_x && y == cursor_y) ? 0x07 : 0x70;
                uint16_t text_color = (x == cursor_x && y == cursor_y) ? 0x0E : 0x7E;
                print_char(row, col, '[', color);
                print_string(row, col + 1, buttons[y*4 + x], text_color);
                print_char(row, col + 1 + string_length(buttons[y*4+x]), ']', color);
            }
        }
        
        for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
        print_string(24, 2, "Arrow keys, Enter to select, ESC=Exit", 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        char ch_input = 0;

        if (scancode == 0x01) { running = false; }
        else if (scancode == 0x48 && cursor_y > 0) { cursor_y--; }
        else if (scancode == 0x50 && cursor_y < 3) { cursor_y++; }
        else if (scancode == 0x4B && cursor_x > 0) { cursor_x--; }
        else if (scancode == 0x4D && cursor_x < 3) { cursor_x++; }
        else if (scancode == 0x1C) {
             ch_input = buttons[cursor_y * 4 + cursor_x][0];
        } else if (scancode == 0x2A || scancode == 0x36) {
            shift_pressed = true;
        } else if (scancode == 0xAA || scancode == 0xB6) {
            shift_pressed = false;
        } else {
            ch_input = scancode_to_ascii(scancode, shift_pressed);
        }

        if (ch_input >= '0' && ch_input <= '9') {
            if (new_number) {
                display[0] = ch_input; display[1] = '\0'; display_len = 1;
                new_number = false;
            } else if (display_len < 15) {
                display[display_len++] = ch_input; display[display_len] = '\0';
            }
        } else if (ch_input == '+' || ch_input == '-' || ch_input == '*' || ch_input == '/') {
            num1 = 0; for (int i=0; i<display_len; ++i) num1 = num1 * 10 + (display[i] - '0');
            operation = ch_input; new_number = true;
        } else if (ch_input == '=') {
            num2 = 0; for (int i=0; i<display_len; ++i) num2 = num2 * 10 + (display[i] - '0');
            long result = 0;
            if (operation == '+') result = num1 + num2;
            else if (operation == '-') result = num1 - num2;
            else if (operation == '*') result = num1 * num2;
            else if (operation == '/' && num2 != 0) result = num1 / num2;
            else if (operation == '/' && num2 == 0) { 
                string_copy(display, "DIV BY ZERO"); display_len = 11; 
                operation = 0; new_number = true; 
                continue; 
            }
            else result = num2;
            
            display_len = 0;
            if (result == 0) {
                display[0] = '0'; display_len = 1;
            } else {
                char temp[20]; int temp_len = 0; long r = result;
                bool negative = false; if (r < 0) { negative = true; r = -r; }
                while (r > 0) { temp[temp_len++] = '0' + (r % 10); r /= 10; }
                if (negative) display[display_len++] = '-';
                for (int i = temp_len - 1; i >= 0; i--) display[display_len++] = temp[i];
            }
            display[display_len] = '\0'; operation = 0; new_number = true;
        } else if (ch_input == 'C') {
            display[0] = '0'; display[1] = '\0'; display_len = 1;
            num1 = 0; num2 = 0; operation = 0; new_number = true;
        }
    }
}

// ============================================================================
// EINSTELLUNGEN
// ============================================================================

void settings() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, "Settings", 0x1E);
    
    draw_window(5, 25, 10, 30, " Keyboard Layout ", 0x0B);
    
    const char* layouts[] = { "German (QWERTZ)", "US (QWERTY)" };
    int selected = (current_scancode_map == scancode_map_de) ? 0 : 1;
    bool running = true;

    while(running) {
        for(int i = 0; i < 2; ++i) {
            uint16_t color = (i == selected) ? 0x07 : 0x70;
            print_string(7 + i * 2, 28, "                       ", color);
            print_string(7 + i * 2, 28, layouts[i], color);
        }

        print_string_centered(24, "UP/DOWN=Select, ENTER=Apply, ESC=Back", 0x70);

        uint8_t scancode = get_keyboard_input();

        if (scancode == 0x01) {
            running = false;
        } else if (scancode == 0x48 && selected > 0) {
            selected--;
        } else if (scancode == 0x50 && selected < 1) {
            selected++;
        } else if (scancode == 0x1C) {
            if (selected == 0) {
                current_scancode_map = scancode_map_de;
                current_scancode_map_shift = scancode_map_de_shift;
            } else {
                current_scancode_map = scancode_map_us;
                current_scancode_map_shift = scancode_map_us_shift;
            }
            print_string(13, 33, "Layout applied!", 0x72);
            delay(10);
            running = false;
        }
    }
}

// ============================================================================
// HILFSFUNKTION FÜR TEXTEINGABE (NEU)
// ============================================================================
void get_string_input(int row, int col, int width, const char* prompt, char* buffer, int max_len) {
    // Zeichne Prompt und Box
    draw_window(row, col, 3, width, prompt, 0x0E);
    
    int pos = string_length(buffer);
    bool running = true;
    bool shift_pressed = false;

    while (running) {
        // Zeichne aktuellen Buffer-Inhalt neu
        for (int i = 0; i < width - 2; i++) {
            char c = (i < pos) ? buffer[i] : ' ';
            print_char(row + 1, col + 1 + i, c, 0x70);
        }
        // Zeichne Cursor
        print_char(row + 1, col + 1 + pos, 219, 0x0F); 

        uint8_t scancode = get_keyboard_input();

        // Verstecke Cursor
        print_char(row + 1, col + 1 + pos, (pos < string_length(buffer)) ? buffer[pos] : ' ', 0x70);

        if (scancode == 0x01) { // ESC
            buffer[0] = '\0'; // Eingabe abbrechen
            running = false;
        } else if (scancode == 0x1C) { // ENTER
            running = false;
        } else if (scancode == 0x0E) { // Backspace
            if (pos > 0) {
                pos--;
                buffer[pos] = '\0';
            }
        } else if (scancode == 0x2A || scancode == 0x36) {
            shift_pressed = true;
        } else if (scancode == 0xAA || scancode == 0xB6) {
            shift_pressed = false;
        } else {
            char ch = scancode_to_ascii(scancode, shift_pressed);
            // Erlaube nur gültige Dateinamenzeichen (grobe Prüfung)
            bool valid_char = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                              (ch >= '0' && ch <= '9') || ch == '.' || ch == '_';

            if (ch != 0 && valid_char && pos < max_len && pos < width - 3) {
                // Konvertiere zu Großbuchstaben (FAT16-Standard)
                if (ch >= 'a' && ch <= 'z') ch -= 32; 
                
                buffer[pos] = ch;
                pos++;
                buffer[pos] = '\0';
            }
        }
    }
    
    // Bereinige den Eingabebereich (stelle Menühintergrund wieder her)
    // (Wird durch das Neuzeichnen des Menüs in main_menu erledigt)
}


// ============================================================================
// HAUPTMENÜ
// ============================================================================

void main_menu() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, "Milla OS 0.53 - Start Menu", 0x1E); 
    
    draw_window(5, 25, 14, 30, " Menu ", 0x0B); // Höhe angepasst
    
    // **GEÄNDERT: Menüpunkte**
    const char* menu_items[] = {
        "1. File Manager",
        "2. Text Editor",
        "3. Calculator",
        "4. Settings",
        "5. Exit to MTop"
    };
    
    int selected = 0;
    bool running = true;
    
    while (running) {
        // Menü neu zeichnen (wichtig nach get_string_input)
        draw_window(5, 25, 14, 30, " Menu ", 0x0B);
        for (int i = 0; i < 5; i++) { // Angepasst auf 5
            uint16_t color = (i == selected) ? 0x07 : 0x70;
            print_string(7 + i * 2, 28, "                        ", color);
            print_string(7 + i * 2, 28, menu_items[i], color);
        }
        
        for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
        print_string(24, 2, "UP/DOWN=Select ENTER=Open ESC=MTop", 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        if (scancode == 0x01) { running = false; }
        else if (scancode == 0x48 && selected > 0) { selected--; }
        else if (scancode == 0x50 && selected < 4) { selected++; } // Angepasst auf 4
        else if (scancode == 0x1C) {
            switch(selected) {
                case 0: file_manager(); break;
                case 1: // NEUE EDITOR-LOGIK
                    {
                        char filename_buffer[MAX_FILENAME + 1];
                        memset(filename_buffer, 0, sizeof(filename_buffer));
                        
                        // Rufe Eingabefunktion auf (überlagert Menü temporär)
                        get_string_input(10, 20, 40, " Enter Filename ", filename_buffer, MAX_FILENAME);
                        
                        if (string_length(filename_buffer) == 0) {
                            string_copy(filename_buffer, "UNTITLED.TXT");
                        } else {
                            // Füge .TXT hinzu, wenn keine Erweiterung vorhanden ist
                            const char* ext = get_filename_ext(filename_buffer);
                            if (string_length(ext) == 0) {
                                int len = string_length(filename_buffer);
                                if (len < MAX_FILENAME - 4) { // Platz für ".TXT"
                                    filename_buffer[len] = '.';
                                    filename_buffer[len+1] = 'T';
                                    filename_buffer[len+2] = 'X';
                                    filename_buffer[len+3] = 'T';
                                    filename_buffer[len+4] = '\0';
                                }
                            }
                        }
                        text_editor(filename_buffer);
                    }
                    break;
                case 2: calculator(); break;
                case 3: settings(); break;
                case 4: running = false; break; // Geändert
            }
            // Zeichne Menü-Hintergrund neu, falls von App überschrieben
            clear_screen(0x03);
            for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
            print_string(0, 2, "Milla OS 0.53 - Start menu", 0x1E); 
            // Das Menüfenster selbst wird am Anfang der nächsten Schleife neu gezeichnet
        }
    }
}

// ============================================================================
// MTop
// ============================================================================

void MTop() {
    clear_screen(0x03);
    
    for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
    print_string(0, 2, "Milla OS 0.53", 0x1E); 
    print_string(0, 60, "[F1=STARTMENU]", 0x4F);
    
    draw_window(3, 10, 12, 60, " MTOP ", 0x0B);
    print_string(5, 15, "Welcome to Milla OS!", 0x70);
   // print_string(6, "(Micro Integrated Low-Level Application OS)", 0x70);

    print_string(8, 15, "A FOSS Operating System", 0x78);
    print_string(9, 15, "by FloriDevs", 0x78);
    print_string(11, 15, "Press F1 for Menu", 0x70);
    
    for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
    
    char status[50] = "Ready - Active Disk: ";
    // **GEÄNDERT: Nur noch MRD0**
    if (active_disk == &ramdisk_device) {
        string_copy(status + 21, "MRD0 (");
    } else {
        string_copy(status + 21, "None (");
    }

    if (active_disk) {
        if (fs_mounted) {
            string_copy(status + string_length(status), "Mounted)");
            print_string(11, 15, "Ramdisk filesystem ready", 0x70);
        } else {
            string_copy(status + string_length(status), "Unformatted)");
            print_string(11, 15, "Disk found. Format needed.", 0x70);
        }
    } else {
        string_copy(status + 21, "Not found");
        print_string(11, 15, "No disk found.", 0x70);
    }
    print_string(24, 2, status, 0x70);
    
    int cursor_row = 12;
    int cursor_col = 40;
    
    while (1) {
        print_char(cursor_row, cursor_col, 219, 0x0E);
        
        char cursor_status[30] = "Cursor: [  ,  ]";
        cursor_status[9] = '0' + (cursor_row / 10);
        cursor_status[10] = '0' + (cursor_row % 10);
        cursor_status[12] = '0' + (cursor_col / 10);
        cursor_status[13] = '0' + (cursor_col % 10);
        print_string(24, 60, cursor_status, 0x70);
        
        uint8_t scancode = get_keyboard_input();
        
        print_char(cursor_row, cursor_col, ' ', 0x03);
        
        if (scancode == 0x3B) { // F1
            main_menu();
            // MTop neu zeichnen
            clear_screen(0x03);
            for (int i = 0; i < 80; i++) print_char(0, i, ' ', 0x1F);
            print_string(0, 2, "Milla OS 0.53", 0x1E); 
            print_string(0, 60, "[F1=MENU]", 0x4F);
            draw_window(3, 10, 12, 60, " Welcome ", 0x0B);
            print_string(5, 15, "Welcome to Milla OS!", 0x70);
            print_string(7, 15, "A FOSS Operating System", 0x78);
            print_string(8, 15, "by FloriDevs", 0x78);
            print_string(10, 15, "Press F1 for Menu", 0x70);
            
            for (int i = 0; i < 80; i++) print_char(24, i, ' ', 0x70);
            
            // Status neu setzen
            char status2[50] = "Ready - Active Disk: ";
            // **GEÄNDERT: Nur noch MRD0**
            if (active_disk == &ramdisk_device) {
                string_copy(status2 + 21, "MRD0 (");
            } else {
                string_copy(status2 + 21, "None (");
            }
            if (active_disk) {
                if (fs_mounted) {
                    string_copy(status2 + string_length(status2), "Mounted)");
                    print_string(11, 15, "FAT16 filesystem ready", 0x70);
                } else {
                    string_copy(status2 + string_length(status2), "Unformatted)");
                    print_string(11, 15, "Disk found. Format needed.", 0x70);
                }
            } else {
                string_copy(status2 + 21, "Not found");
                print_string(11, 15, "No disk found.", 0x70);
            }
            print_string(24, 2, status2, 0x70);

        } else if (scancode == 0x4B && cursor_col > 0) { cursor_col--; }
        else if (scancode == 0x4D && cursor_col < 79) { cursor_col++; }
        else if (scancode == 0x48 && cursor_row > 1) { cursor_row--; }
        else if (scancode == 0x50 && cursor_row < 23) { cursor_row++; }
    }
}

// ============================================================================
// KERNEL MAIN
// ============================================================================

extern "C" void kernel_main() {
    draw_flower();
    init_filesystem();
    MTop();
}

// ***ENDE CODE***