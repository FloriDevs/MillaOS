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

// Minimal heap implementation (for example only)
// Increased heap size for safety
static uint8_t kernel_heap[4 * 1024 * 1024]; // 4 MB heap
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
};

const uint32_t MULTIBOOT_MAGIC = 0x1BADB002;
const uint32_t MULTIBOOT_FLAGS = 0x00000003;
const uint32_t MULTIBOOT_CHECKSUM = -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS);

__attribute__((section(".multiboot_header"))) struct multiboot_header header = {
    .magic = MULTIBOOT_MAGIC,
    .flags = MULTIBOOT_FLAGS,
    .checksum = MULTIBOOT_CHECKSUM};

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
  if (row < 0 || row >= 25 || col < 0 || col >= 80)
    return;
  uint16_t *video_memory = (uint16_t *)0xb8000;
  int offset = row * 80 + col;
  video_memory[offset] = (color << 8) | character;
}

void print_string(int row, int col, const char *str, uint16_t color);

// Debug Helper
void network_debug_print(const char *msg, int col) {
  print_string(24, col, "               ", 0x70); // Clear
  print_string(24, col, msg, 0x74);               // Red on Grey
}

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

// Forward declaration
void network_debug_print(const char *msg, int col);

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
    mouse_x += dx / 2; // Sensitivity div 2
    mouse_y -= dy / 2; // Invert Y

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

void draw_wallpaper() {
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
// NETWORK UTILS & ENDIANNESS
// ============================================================================

uint16_t htons(uint16_t v) { return (v << 8) | (v >> 8); }
uint16_t ntohs(uint16_t v) { return htons(v); }

uint32_t htonl(uint32_t v) {
  return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) |
         ((v >> 24) & 0xFF);
}
uint32_t ntohl(uint32_t v) { return htonl(v); }

// ============================================================================
// NETWORK PROTOCOL HEADERS
// ============================================================================

struct MacAddress {
  uint8_t addr[6];
};

struct EthernetHeader {
  uint8_t dest[6];
  uint8_t src[6];
  uint16_t type;
} __attribute__((packed));

struct ARPHeader {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_addr_len;
  uint8_t protocol_addr_len;
  uint16_t opcode;
  uint8_t src_mac[6];
  uint32_t src_ip;
  uint8_t dest_mac[6];
  uint32_t dest_ip;
} __attribute__((packed));

struct IPv4Header {
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t tos;
  uint16_t length;
  uint16_t id;
  uint16_t frag_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dest_ip;
} __attribute__((packed));

struct UDPHeader {
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} __attribute__((packed));

struct TCPHeader {
  uint16_t src_port;
  uint16_t dest_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t reserved : 4;
  uint8_t data_offset : 4;
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_ptr;
} __attribute__((packed));

struct DNSHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t q_count;
  uint16_t ans_count;
  uint16_t auth_count;
  uint16_t add_count;
} __attribute__((packed));

// Pseudo Header for Checksum calculation
struct PseudoHeader {
  uint32_t src_ip;
  uint32_t dest_ip;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_udp_length;
} __attribute__((packed));

// ============================================================================
// PCI & RTL8139 DRIVER
// ============================================================================

uint32_t pci_read_config(uint8_t bus, uint8_t slot, uint8_t func,
                         uint8_t offset) {
  uint32_t address;
  uint32_t lbus = (uint32_t)bus;
  uint32_t lslot = (uint32_t)slot;
  uint32_t lfunc = (uint32_t)func;
  uint32_t tmp = 0;

  address = (uint32_t)((lbus << 16) | (lslot << 11) | (lfunc << 8) |
                       (offset & 0xfc) | ((uint32_t)0x80000000));

  outl(0xCF8, address);
  tmp = (uint32_t)(inl(0xCFC));
  return tmp;
}

void pci_write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset,
                      uint32_t value) {
  uint32_t address;
  uint32_t lbus = (uint32_t)bus;
  uint32_t lslot = (uint32_t)slot;
  uint32_t lfunc = (uint32_t)func;

  address = (uint32_t)((lbus << 16) | (lslot << 11) | (lfunc << 8) |
                       (offset & 0xfc) | ((uint32_t)0x80000000));

  outl(0xCF8, address);
  outl(0xCFC, value);
}

// RTL8139 Constants
#define RTL8139_VENDOR_ID 0x10EC
#define RTL8139_DEVICE_ID 0x8139

uint16_t rtl8139_io_base = 0;
uint8_t rtl8139_mac[6];
uint8_t *rtl8139_rx_buffer = nullptr;
uint32_t rx_buffer_offset = 0;
uint32_t packet_counter = 0;
uint32_t total_packets_sent = 0;

// TX Buffers
uint8_t *rtl8139_tx_buffers[4];
uint8_t tx_cur = 0;

void find_rtl8139() {
  for (uint32_t bus = 0; bus < 256; bus++) {
    for (uint32_t slot = 0; slot < 32; slot++) {
      uint32_t vendor_device = pci_read_config(bus, slot, 0, 0);
      if ((vendor_device & 0xFFFF) != 0xFFFF) {
        uint16_t vendor = vendor_device & 0xFFFF;
        uint16_t device = (vendor_device >> 16) & 0xFFFF;

        if (vendor == RTL8139_VENDOR_ID && device == RTL8139_DEVICE_ID) {
          // Found it! Get IO Base (BAR0)
          uint32_t bar0 = pci_read_config(bus, slot, 0, 0x10);
          rtl8139_io_base = bar0 & (~0x3);

          // Enable Bus Mastering (Command Register offset 0x04)
          uint32_t command = pci_read_config(bus, slot, 0, 0x04);
          if (!(command & 0x04)) {
            pci_write_config(bus, slot, 0, 0x04, command | 0x04);
            print_string(24, 0, "RTL8139: Bus Mastering Enabled", 0x70);
          } else {
            print_string(24, 0, "RTL8139: Bus Mastering Already On", 0x70);
          }
        }
      }
    }
  }
}

void rtl8139_send_packet(const void *data, uint32_t len) {
  if (rtl8139_io_base == 0)
    return;

  // Use current TX buffer
  memcpy(rtl8139_tx_buffers[tx_cur], data, len);

  // Pad if smaller than 60 bytes (Ethernet min)
  if (len < 60) {
    memset(rtl8139_tx_buffers[tx_cur] + len, 0, 60 - len);
    len = 60;
  }

  // Write Status (Size) | OWN bit gets cleared by controller later
  // TSD0-3 are at 0x10, 0x14, 0x18, 0x1C
  outl(rtl8139_io_base + 0x10 + (tx_cur * 4), len); // Write len triggers TX
  network_debug_print("TX PKT", 40);

  tx_cur = (tx_cur + 1) % 4;
  total_packets_sent++;
}

namespace Network {
bool connected = false;
char status_msg[50] = "Searching...";

void init() {
  find_rtl8139();

  if (rtl8139_io_base != 0) {
    connected = true;
    string_copy(status_msg, "RTL8139 Init OK");

    // Software Reset
    outb(rtl8139_io_base + 0x37, 0x10);
    while ((inb(rtl8139_io_base + 0x37) & 0x10) != 0) {
      asm volatile("nop");
    }

    // Init RX Buffer
    rtl8139_rx_buffer = (uint8_t *)malloc(8192 + 16 + 1500);
    outl(rtl8139_io_base + 0x30, (uint32_t)rtl8139_rx_buffer); // RBSTART

    // Init TX Buffers
    for (int i = 0; i < 4; i++) {
      rtl8139_tx_buffers[i] = (uint8_t *)malloc(1536); // Max MTU + padding
      outl(rtl8139_io_base + 0x20 + (i * 4),
           (uint32_t)rtl8139_tx_buffers[i]); // TSAD0-3
    }

    // Set IMR + ISR (Enable interrupts - though we poll for now)
    outw(rtl8139_io_base + 0x3C, 0x0005); // TOK + ROK
    outw(rtl8139_io_base + 0x44, 0x000F); // AB + AM + APM + AAP (Promiscuous)

    // Enable RX/TX
    outb(rtl8139_io_base + 0x37, 0x0C); // RE + TE

    // Read MAC
    for (int i = 0; i < 6; i++) {
      rtl8139_mac[i] = inb(rtl8139_io_base + i);
    }

  } else {
    string_copy(status_msg, "No NIC Found");
  }
}

// ----------------------------------------------------------------------------
// ETHERNET & ARP LAYER
// ----------------------------------------------------------------------------

const uint16_t ETHERTYPE_IPv4 = 0x0800;
const uint16_t ETHERTYPE_ARP = 0x0806;

// Quick IP helper (10.0.2.15)
uint32_t my_ip =
    0x0F02000A; // Little Endian representation of 10.0.2.15 (Reverse bytes)
// Actually, let's stick to Network Byte Order for structs: 10.0.2.15 ->
// 0x0A00020F BUT, x86 is Little Endian. If I write 0x0A00020F to memory, it
// becomes 0F 02 00 0A. So:
uint32_t ip_addr_host = 0x0A00020F; // 10.0.2.15
uint32_t gateway_ip = 0x0A000202;   // 10.0.2.2 (QEMU default gateway)

// We need a way to set our IP if it's not hardcoded, but static is fine for
// now.

// ARP Cache
struct ArpEntry {
  uint32_t ip;
  uint8_t mac[6];
  bool valid;
};
ArpEntry arp_cache[4];

void arp_update(uint32_t ip, const uint8_t *mac) {
  for (int i = 0; i < 4; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      memcpy(arp_cache[i].mac, mac, 6);
      return;
    }
  }
  // Add new
  for (int i = 0; i < 4; i++) {
    if (!arp_cache[i].valid) {
      arp_cache[i].ip = ip;
      memcpy(arp_cache[i].mac, mac, 6);
      arp_cache[i].valid = true;
      return;
    }
  }
  // Overwrite first
  arp_cache[0].ip = ip;
  memcpy(arp_cache[0].mac, mac, 6);
  arp_cache[0].valid = true;
}

uint8_t *arp_resolve(uint32_t ip) {
  for (int i = 0; i < 4; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip)
      return arp_cache[i].mac;
  }
  return nullptr;
}

void send_ethernet(const uint8_t *dest_mac, uint16_t type, const void *payload,
                   uint32_t len) {
  uint32_t total_len = sizeof(EthernetHeader) + len;
  uint8_t *buffer = (uint8_t *)malloc(total_len);
  if (!buffer)
    return;

  EthernetHeader *eth = (EthernetHeader *)buffer;
  memcpy(eth->dest, dest_mac, 6);
  memcpy(eth->src, rtl8139_mac, 6);
  eth->type = htons(type);
  memcpy(buffer + sizeof(EthernetHeader), payload, len);

  rtl8139_send_packet(buffer, total_len);
  free(buffer);
}

void send_arp_request(uint32_t target_ip) {
  ARPHeader arp;
  arp.hardware_type = htons(1); // Ethernet
  arp.protocol_type = htons(ETHERTYPE_IPv4);
  arp.hardware_addr_len = 6;
  arp.protocol_addr_len = 4;
  arp.opcode = htons(1); // Request
  memcpy(arp.src_mac, rtl8139_mac, 6);
  arp.src_ip = htonl(ip_addr_host); // My IP
  memset(arp.dest_mac, 0,
         6); // Target MAC unknown (0) or Broadcast (FF)? ARP Request dest MAC
             // in header is Broadcast, here is ignored/0.
  arp.dest_ip = htonl(target_ip);

  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  network_debug_print("TX ARP", 40);
  send_ethernet(broadcast, ETHERTYPE_ARP, &arp, sizeof(ARPHeader));
}

void handle_arp(const uint8_t *data, uint32_t len) {
  if (len < sizeof(ARPHeader))
    return;
  ARPHeader *arp = (ARPHeader *)data;

  if (ntohs(arp->hardware_type) != 1 ||
      ntohs(arp->protocol_type) != ETHERTYPE_IPv4)
    return;

  // Cache the sender
  uint32_t sender_ip = ntohl(arp->src_ip);
  arp_update(sender_ip, arp->src_mac);
  network_debug_print("RX ARP", 60);

  if (ntohs(arp->opcode) == 1 && ntohl(arp->dest_ip) == ip_addr_host) {
    // ARP Request for me -> Reply
    ARPHeader reply;
    reply.hardware_type = htons(1);
    reply.protocol_type = htons(ETHERTYPE_IPv4);
    reply.hardware_addr_len = 6;
    reply.protocol_addr_len = 4;
    reply.opcode = htons(2); // Reply

    memcpy(reply.src_mac, rtl8139_mac, 6);
    reply.src_ip = arp->dest_ip;

    memcpy(reply.dest_mac, arp->src_mac, 6);
    reply.dest_ip = arp->src_ip;

    send_ethernet(arp->src_mac, ETHERTYPE_ARP, &reply, sizeof(ARPHeader));
  }
}

// Forward declarations
void poll(); // From Network namespace (later in file)
void handle_tcp(const uint8_t *data, uint32_t len, uint32_t src_ip,
                uint32_t dest_ip);

// Enum for TCP State
enum TcpState { TCP_CLOSED, TCP_SYN_SENT, TCP_ESTABLISHED };
TcpState tcp_state = TCP_CLOSED;
uint32_t tcp_seq_num = 0;
uint32_t tcp_ack_num = 0;
uint32_t tcp_dest_ip = 0;
uint16_t tcp_dest_port = 0;
uint16_t tcp_src_port = 50000; // Static source port for now

// TCP RX Buffer
#define TCP_RX_BUFFER_SIZE 16384
uint8_t tcp_rx_buffer[TCP_RX_BUFFER_SIZE];
uint32_t tcp_rx_pos = 0;

uint16_t calculate_checksum(const void *data, uint32_t len) {
  const uint16_t *ptr = (const uint16_t *)data;
  uint32_t sum = 0;
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }
  if (len) {
    sum += *(const uint8_t *)ptr;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

void send_ipv4(uint32_t dest_ip, uint8_t protocol, const void *payload,
               uint32_t len) {
  uint32_t total_len = sizeof(IPv4Header) + len;
  uint8_t *buffer = (uint8_t *)malloc(total_len);
  if (!buffer)
    return;

  IPv4Header *ip = (IPv4Header *)buffer;
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->length = htons(total_len);
  ip->id = htons(0);               // TODO: Increment ID
  ip->frag_offset = htons(0x4000); // Don't fragment
  ip->ttl = 64;
  ip->protocol = protocol;
  ip->src_ip = htonl(ip_addr_host);
  ip->dest_ip = htonl(dest_ip);
  ip->checksum = 0;
  ip->checksum = calculate_checksum(ip, sizeof(IPv4Header));

  memcpy(buffer + sizeof(IPv4Header), payload, len);

  // ARP Resolve
  uint8_t *dest_mac = arp_resolve(dest_ip);
  if (!dest_mac) {
    send_arp_request(dest_ip);
    free(buffer);
    return;
  }

  send_ethernet(dest_mac, ETHERTYPE_IPv4, buffer, total_len);
  free(buffer);
}

void tcp_send_packet(uint32_t dest_ip, uint16_t dest_port, uint8_t flags,
                     const uint8_t *payload, uint32_t len) {
  uint32_t total_len = sizeof(TCPHeader) + len;
  uint8_t *buffer = (uint8_t *)malloc(total_len);
  if (!buffer)
    return;

  TCPHeader *tcp = (TCPHeader *)buffer;
  tcp->src_port = htons(tcp_src_port);
  tcp->dest_port = htons(dest_port);
  tcp->seq_num = htonl(tcp_seq_num);
  tcp->ack_num = htonl(tcp_ack_num);
  tcp->reserved = 0;
  tcp->data_offset = 5; // 5 * 32-bit words = 20 bytes
  tcp->flags = flags;
  tcp->window_size = htons(8192);
  tcp->checksum = 0;
  tcp->urgent_ptr = 0;

  if (len > 0) {
    memcpy(buffer + sizeof(TCPHeader), payload, len);
  }

  // Pseudo Header Checksum
  PseudoHeader ph;
  ph.src_ip = htonl(ip_addr_host);
  ph.dest_ip = htonl(dest_ip);
  ph.reserved = 0;
  ph.protocol = 6; // TCP
  ph.tcp_udp_length = htons(total_len);

  uint32_t sum = 0;
  // Manual sum of PseudoHeader to avoid packed pointer alignment issues
  sum += (ph.src_ip & 0xFFFF);
  sum += (ph.src_ip >> 16);
  sum += (ph.dest_ip & 0xFFFF);
  sum += (ph.dest_ip >> 16);
  sum += htons(ph.protocol); // Protocol is 8-bit but in 16-bit word 0006
  sum += ph.tcp_udp_length;

  uint16_t *ptr = (uint16_t *)buffer;
  for (int i = 0; i < total_len / 2; i++) {
    sum += ptr[i];
  }
  if (total_len & 1) {
    sum += buffer[total_len - 1] & 0xFF;
  }
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  tcp->checksum = ~sum;

  send_ipv4(dest_ip, 6, buffer, total_len);
  free(buffer);

  // Increment Sequence Number if SYN or FIN or Data
  if ((flags & 0x02) || (flags & 0x01) || len > 0) { // SYN or FIN or payload
    tcp_seq_num += (len > 0 ? len : 1);
  }
}

void handle_tcp(const uint8_t *data, uint32_t len, uint32_t src_ip,
                uint32_t dest_ip) {
  if (len < sizeof(TCPHeader))
    return;
  TCPHeader *tcp = (TCPHeader *)data;

  // Very basic check logic
  if (ntohs(tcp->dest_port) != tcp_src_port) {
    network_debug_print("TCP PORT DROP", 60);
    return;
  }

  uint32_t seq = ntohl(tcp->seq_num);
  uint32_t ack = ntohl(tcp->ack_num);
  uint8_t flags = tcp->flags;

  // Calculate Payload
  uint8_t offset = tcp->data_offset * 4;
  uint32_t payload_len = len - offset;
  const uint8_t *payload = data + offset;

  if (tcp_state == TCP_SYN_SENT) {
    if ((flags & 0x12) == 0x12) { // SYN + ACK
      network_debug_print("RX SYN-ACK", 60);
      tcp_ack_num = seq + 1;
      tcp_seq_num = ack; // Server ACKed our SYN
      tcp_state = TCP_ESTABLISHED;

      // Send ACK
      tcp_send_packet(src_ip, ntohs(tcp->src_port), 0x10, nullptr, 0); // ACK
    }
  } else if (tcp_state == TCP_ESTABLISHED) {
    // Handle PUSH/DATA
    if (payload_len > 0) {
      // Store data
      if (tcp_rx_pos + payload_len < TCP_RX_BUFFER_SIZE) {
        memcpy(tcp_rx_buffer + tcp_rx_pos, payload, payload_len);
        tcp_rx_pos += payload_len;
      }

      tcp_ack_num = seq + payload_len;
      // Send ACK (Ack the data)
      tcp_send_packet(src_ip, ntohs(tcp->src_port), 0x10, nullptr, 0); // ACK

      // If PSH flag is set, maybe we should notify app?
      // For now blocking poll handles it.
    }

    // Handle FIN
    if (flags & 0x01) { // FIN
      tcp_ack_num = seq + 1;
      tcp_send_packet(src_ip, ntohs(tcp->src_port), 0x11, nullptr,
                      0); // FIN + ACK
      tcp_state = TCP_CLOSED;
    }
  }
}

bool http_get(const char *url_str, char *output_buffer, int max_len) {
  // 1. URL Parsing
  // Defaults
  uint32_t ip = 0;
  tcp_dest_port = 80;
  char path[128];
  string_copy(path, "/");
  char host[128];
  memset(host, 0, 128);

  const char *work_str = url_str;
  // Skip protocol if present
  if (string_compare(work_str, "http://") ||
      (work_str[0] == 'h' && work_str[1] == 't' && work_str[2] == 't' &&
       work_str[3] == 'p' && work_str[4] == ':' && work_str[5] == '/' &&
       work_str[6] == '/')) {
    work_str += 7;
  }

  // Extract Host
  int h = 0;
  int i = 0;
  while (work_str[i] != '\0' && work_str[i] != ':' && work_str[i] != '/') {
    if (h < 127)
      host[h++] = work_str[i];
    i++;
  }
  host[h] = '\0';

  // Parse IP or Localhost
  bool is_localhost = false;
  // Simple check for "localhost"
  if (work_str[0] == 'l' && work_str[1] == 'o' && work_str[2] == 'c' &&
      work_str[3] == 'a' && work_str[4] == 'l' && work_str[5] == 'h' &&
      work_str[6] == 'o' && work_str[7] == 's' && work_str[8] == 't') {
    is_localhost = true;
  }

  if (is_localhost) {
    ip = 0x0A000202; // 10.0.2.2 (QEMU Host)
  } else {
    // Basic IP Parsing (X.X.X.X)
    int part = 0;
    int shift = 24;
    for (int k = 0; host[k] != '\0'; k++) {
      if (host[k] == '.') {
        ip |= (part << shift);
        shift -= 8;
        part = 0;
      } else {
        part = part * 10 + (host[k] - '0');
      }
    }
    ip |= part;
  }

  // Parse Port
  if (work_str[i] == ':') {
    i++;
    int p = 0;
    while (work_str[i] >= '0' && work_str[i] <= '9') {
      p = p * 10 + (work_str[i] - '0');
      i++;
    }
    if (p > 0)
      tcp_dest_port = p;
  }

  // Parse Path
  if (work_str[i] == '/') {
    int p_i = 0;
    while (work_str[i] != '\0' && p_i < 127) {
      path[p_i++] = work_str[i++];
    }
    path[p_i] = '\0';
  }

  tcp_dest_ip = ip;
  tcp_state = TCP_CLOSED;
  tcp_seq_num = 1000;
  tcp_ack_num = 0;
  tcp_rx_pos = 0;
  tcp_src_port++;

  // 2. Handshake
  char status[50];
  string_copy(status, "Connecting...");

  tcp_send_packet(tcp_dest_ip, tcp_dest_port, 0x02, nullptr, 0); // SYN
  tcp_state = TCP_SYN_SENT;

  // Timeout - 30 Seconds
  Time start_time = get_time();
  int start_sec =
      start_time.hour * 3600 + start_time.minute * 60 + start_time.second;
  int last_retry_sec = start_sec;
  int polls = 0;

  while (tcp_state != TCP_ESTABLISHED) {
    poll();
    polls++;
    // Check time every ~10000 polls
    if ((polls % 10000) == 0) {
      Time now = get_time();
      int now_sec = now.hour * 3600 + now.minute * 60 + now.second;
      if (now_sec < start_sec)
        now_sec += 24 * 3600; // Day wrap

      if ((now_sec - start_sec) >= 30)
        break;

      // Retry SYN every 1 second
      if ((now_sec - last_retry_sec) >= 1) {
        if (tcp_state == TCP_SYN_SENT) {
          // Reuse same sequence number (undo increment from previous send)
          tcp_seq_num--;
          tcp_send_packet(tcp_dest_ip, tcp_dest_port, 0x02, nullptr, 0); // SYN
          network_debug_print("RETRY SYN", 40);
          last_retry_sec = now_sec;
        }
      }
    }
  }

  if (tcp_state != TCP_ESTABLISHED) {
    string_copy(output_buffer, "Connection Timeout (30s).");
    return false;
  }

  // 3. Send HTTP GET
  char request[256];
  // Simple memset
  for (int k = 0; k < 256; k++)
    request[k] = 0;

  // Construct Request: GET [path] HTTP/1.0\r\nHost: [host]\r\n\r\n
  // Note: We don't have sprintf, so manual construction
  string_copy(request, "GET ");

  // Append Path
  int len = string_length(request);
  for (int k = 0; path[k] != '\0'; k++)
    request[len++] = path[k];

  // Append HTTP/1.0...
  const char *mid = " HTTP/1.0\r\nHost: ";
  for (int k = 0; mid[k] != '\0'; k++)
    request[len++] = mid[k];

  // Append Host
  for (int k = 0; host[k] != '\0'; k++)
    request[len++] = host[k];

  // Append End
  request[len++] = '\r';
  request[len++] = '\n';
  request[len++] = '\r';
  request[len++] = '\n';
  request[len] = '\0';

  tcp_send_packet(tcp_dest_ip, tcp_dest_port, 0x18, (uint8_t *)request, len);

  // 4. Wait for Data
  // Also 30s timeout for data? Or keep large loop? User asked for "connection
  // timeout". But let's be generous with data too.
  int data_timeout_loops =
      50000000; // Just a very large number for safety alongside time check
  Time data_start = get_time();
  int data_start_sec =
      data_start.hour * 3600 + data_start.minute * 60 + data_start.second;

  int last_len = 0;
  int same_len_ticks = 0;

  while (tcp_state == TCP_ESTABLISHED) {
    poll();
    data_timeout_loops--;

    if ((data_timeout_loops % 10000) == 0) {
      Time now = get_time();
      int now_sec = now.hour * 3600 + now.minute * 60 + now.second;
      if (now_sec < data_start_sec)
        now_sec += 24 * 3600;
      if ((now_sec - data_start_sec) >= 30)
        break;
    }

    if (tcp_rx_pos > 0) {
      if (tcp_rx_pos == last_len) {
        same_len_ticks++;
        if (same_len_ticks > 200000) // Stabilized
          break;
      } else {
        same_len_ticks = 0;
        last_len = tcp_rx_pos;
      }
    }

    // Safety break on loop counter to prevent infinite hang if time breaks
    if (data_timeout_loops <= 0)
      break;
  }

  // Copy result
  if (tcp_rx_pos > 0) {
    if (tcp_rx_pos >= max_len)
      tcp_rx_pos = max_len - 1;
    memcpy(output_buffer, tcp_rx_buffer, tcp_rx_pos);
    output_buffer[tcp_rx_pos] = '\0';
  } else {
    string_copy(output_buffer, "No Data Received / Empty");
  }

  // Close
  tcp_send_packet(tcp_dest_ip, tcp_dest_port, 0x11, nullptr, 0); // FIN+ACK
  tcp_state = TCP_CLOSED;

  return true;
}

void handle_ipv4(const uint8_t *data, uint32_t len) {
  if (len < sizeof(IPv4Header))
    return;
  IPv4Header *ip = (IPv4Header *)data;

  if (ip->version != 4)
    return;
  // Check Dest IP
  if (ntohl(ip->dest_ip) != ip_addr_host) {
    network_debug_print("IP DROP", 60);
    // debug hex?
    // we can't easily print hex args here without sprintf
    return; // Not for us
  }

  uint16_t header_len = ip->ihl * 4;
  uint16_t total_len = ntohs(ip->length);

  if (total_len > len)
    return; // Fragmented or cut off?

  uint8_t protocol = ip->protocol;
  uint32_t src_ip = ntohl(ip->src_ip);
  // uint32_t dest_ip = ntohl(ip->dest_ip);

  // Payload
  const uint8_t *payload = data + header_len;
  uint32_t payload_len = total_len - header_len;

  if (protocol == 6) { // TCP
    handle_tcp(payload, payload_len, src_ip, ip_addr_host);
  } // else if (protocol == 1) { handle_icmp... }
}

void handle_packet(const uint8_t *data, uint32_t len) {
  if (len < sizeof(EthernetHeader))
    return;
  EthernetHeader *eth = (EthernetHeader *)data;

  uint16_t type = ntohs(eth->type);

  if (type == ETHERTYPE_ARP) {
    handle_arp(data + sizeof(EthernetHeader), len - sizeof(EthernetHeader));
  } else if (type == ETHERTYPE_IPv4) {
    handle_ipv4(data + sizeof(EthernetHeader), len - sizeof(EthernetHeader));
  }
}

// Poll for new packets
void poll() {
  if (!connected)
    return;

  uint8_t cmd = inb(rtl8139_io_base + 0x37);
  if ((cmd & 0x01) == 0)
    return; // Buffer empty

  network_debug_print("RX EVENT", 60);

  // Simple ring buffer check (very basic)
  // Check Interrupt Status Register
  // Trust Command Register Buffer Empty bit (Bit 0)
  // If bit 0 is 0, buffer is empty.

  while ((inb(rtl8139_io_base + 0x37) & 0x01) == 0) { // Buffer NOT empty
    uint8_t *packet = rtl8139_rx_buffer + rx_buffer_offset;
    uint16_t status = *(uint16_t *)(packet);
    uint16_t len = *(uint16_t *)(packet + 2);

    // Basic Status Check
    if (status & 1) { // ROK
      // Data starts at offset 4
      // Exclude CRC (4 bytes) from length? Typically len includes header(4) +
      // packet + crc(4). RTL8139 Packet: [Header 4 bytes] [Packet Data (len -
      // 4)] [CRC 4 bytes] Actually the length in the header is the length of
      // the packet including CRC. We pass start of Packet Data.
      if (len > 4 && len < 2000) { // Sanity check
        // Inspect EtherType
        uint8_t *p_data = packet + 4;
        uint16_t eth_type = (p_data[12] << 8) | p_data[13];
        if (eth_type == 0x0806)
          network_debug_print("RX ARP PKT", 60);
        else if (eth_type == 0x0800)
          network_debug_print("RX IP PKT", 60);
        else
          network_debug_print("RX UNK", 60);

        handle_packet(packet + 4, len - 4);
      }
    }

    rx_buffer_offset = (rx_buffer_offset + len + 4 + 3) & ~3;
    if (rx_buffer_offset >= 8192)
      rx_buffer_offset = 0; // Wrap around (simplified)

    outw(rtl8139_io_base + 0x38, rx_buffer_offset - 16); // CAPR
  }
  // Acknowledge all interrupts purely for safety
  outw(rtl8139_io_base + 0x3E, 0xFFFF);
}

const char *fetch(const char *url) {
  poll();
  // Return stats instead of content for now
  static char buf[200];
  string_copy(buf, "Network Statistics:\n");
  // Add Packet count
  int len = string_length(buf);
  buf[len++] = 'P';
  buf[len++] = 'k';
  buf[len++] = 't';
  buf[len++] = 's';
  buf[len++] = ':';
  buf[len++] = ' ';
  // Simple itoa
  if (packet_counter == 0)
    buf[len++] = '0';
  else {
    int tmp = packet_counter;
    // Quick hack for single digit (or more roughly)
    if (tmp >= 100)
      buf[len++] = '9'; // cap visual
    else if (tmp >= 10)
      buf[len++] = '0' + (tmp / 10);
    buf[len++] = '0' + (tmp % 10);
  }
  buf[len++] = '\n';
  buf[len++] = 'M';
  buf[len++] = 'A';
  buf[len++] = 'C';
  buf[len++] = ':';
  buf[len++] = ' ';

  for (int i = 0; i < 6; i++) {
    uint8_t val = rtl8139_mac[i];
    uint8_t h = (val >> 4) & 0xF;
    uint8_t l = val & 0xF;
    buf[len++] = (h < 10) ? '0' + h : 'A' + (h - 10);
    buf[len++] = (l < 10) ? '0' + l : 'A' + (l - 10);
    if (i < 5)
      buf[len++] = ':';
  }

  buf[len] = '\0';
  return buf;
}
} // namespace Network

// Dummy-Struktur, um FAT-Treiber-Signatur anzupassen
struct ATADevice {
  uint16_t io_base;
  uint16_t control_base;
  uint8_t drive;
  bool present;
  uint32_t size_sectors;
};

// Es gibt nur noch die RAM-Disk
ATADevice *active_disk = nullptr; // Zeigt auf die RAM-Disk

// +++ BEGINN RAM-DISK IMPLEMENTIERUNG +++
const size_t RAMDISK_SIZE_BYTES = 800 * 1024; // 800KB
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

bool format_fat16(ATADevice *dev) {
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

  if (!ata_write_sector(dev, 0, sector_buffer))
    return false;

  // Initialisiere FAT (beide Kopien)
  memset(sector_buffer, 0, SECTOR_SIZE);
  ((uint16_t *)sector_buffer)[0] = 0xFFF8;
  ((uint16_t *)sector_buffer)[1] = 0xFFFF;

  uint32_t fat1_lba = boot_sector.reserved_sectors;
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

  // Initialisiere Root Directory (fester Ort bei FAT16)
  uint32_t root_lba =
      fat1_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);

  memset(sector_buffer, 0, SECTOR_SIZE);
  for (uint32_t i = 0; i < root_dir_sectors; i++) {
    if (!ata_write_sector(dev, root_lba + i, sector_buffer))
      return false;
  }

  return true;
}

bool mount_fat16(ATADevice *dev) {
  if (!dev->present)
    return false;

  if (!ata_read_sector(dev, 0, sector_buffer))
    return false;

  // Überprüfe die Magische Zahl
  if (sector_buffer[510] != 0x55 || sector_buffer[511] != 0xAA)
    return false;

  memcpy(&boot_sector, sector_buffer, sizeof(BootSector));

  if (boot_sector.bytes_per_sector != 512)
    return false;
  if (boot_sector.fat_count == 0)
    return false;

  fat_begin_lba = boot_sector.reserved_sectors;

  // Berechne Positionen für FAT16
  root_dir_sectors = (boot_sector.root_entry_count * sizeof(DirEntry) +
                      boot_sector.bytes_per_sector - 1) /
                     boot_sector.bytes_per_sector;
  root_dir_lba =
      fat_begin_lba + (boot_sector.fat_count * boot_sector.sectors_per_fat_16);
  cluster_begin_lba = root_dir_lba + root_dir_sectors;

  sectors_per_cluster = boot_sector.sectors_per_cluster;
  root_dir_first_cluster = 0;

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
    if (string_compare(file_cache[i].name, name)) {
      return i;
    }
  }
  return -1;
}

bool read_file(ATADevice *dev, uint32_t cluster, char *buffer,
               uint32_t max_size) {
  uint32_t pos = 0;

  while (cluster < 0xFFF8 && pos < max_size) {
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
    if (!ata_read_sector(dev, dir_lba + sec, sector_buffer))
      return false;

    DirEntry *entries = (DirEntry *)sector_buffer;
    for (int i = 0; i < (SECTOR_SIZE / sizeof(DirEntry)); i++) {
      if (entries[i].filename[0] == 0x00 || entries[i].filename[0] == 0xE5) {
        empty_entry = i;
        entry_lba = dir_lba + sec;
        break;
      }
    }
    if (empty_entry != -1)
      break;
  }

  if (empty_entry == -1)
    return false; // Kein Platz im Root-Verzeichnis

  // Alloziere Cluster für Dateidaten
  uint32_t file_cluster = allocate_cluster(dev);
  if (file_cluster == 0)
    return false; // Kein Speicherplatz (Cluster)

  // Schreibe Dateidaten
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
        return false; // Kein Speicherplatz mehr
      set_fat_entry(dev, current_cluster, next_cluster);
      current_cluster = next_cluster;
    }
  }

  // Erstelle Verzeichniseintrag
  ata_read_sector(dev, entry_lba, sector_buffer);
  DirEntry *entries = (DirEntry *)sector_buffer;
  DirEntry *entry = &entries[empty_entry];

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
    if (c >= 'a' && c <= 'z')
      c -= 32;

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

// Initialisierung
ATADevice hdd_device;

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

  // Mount RAM Disk by default
  if (active_disk) {
    if (!mount_fat16(active_disk)) {
      // Formatiere wenn Mount fehlschlägt
      print_string(23, 10, "Formatting RAM disk...    ", 0x0E);
      if (format_fat16(active_disk)) {
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
uint8_t get_keyboard_input() {
  while (true) {
    uint8_t status = inb(0x64);
    if (status & 0x01) {
      uint8_t data = inb(0x60);
      if (status & 0x20) {
        handle_mouse_byte(data);
        return 0; // Return 0 for mouse update
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
const char *current_scancode_map = scancode_map_de;
const char *current_scancode_map_shift = scancode_map_de_shift;

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

// ============================================================================
// SIMULIERTER C++ PROGRAMM-LADER
// ============================================================================
void run_cpp_program(const char *filename) {
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

  for (int i = 0; i < 80; i++)
    print_char(0, i, ' ', 0x1F);
  print_string(0, 2, "File Manager - FAT16", 0x1E);
  print_string(0, 50, "F3=Switch Drive ESC=Exit", 0x1F); // Geändert

  draw_window(2, 5, 21, 70, " Drives & Files ", 0x0B);

  print_string(3, 8, "Active Drive:", 0x70);

  // **GEÄNDERT: Nur noch MRD0-Logik**
  char disk_info[50];
  if (active_disk == &ramdisk_device) {
    string_copy(disk_info, "[MRD0] RAM Disk - ");
  } else if (active_disk == &hdd_device) {
    string_copy(disk_info, "[HDD0] Hard Disk - ");
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
    string_copy(disk_info + string_length(disk_info),
                "Disk present, not mounted");
  } else {
    string_copy(disk_info + string_length(disk_info), "No disk active");
  }
  print_string(4, 8, disk_info, 0x70);

  print_string(7, 8, "Filename", 0x70);
  print_string(7, 30, "Size", 0x70);
  print_string(7, 45, "Type", 0x70);
  for (int i = 0; i < 68; i++)
    print_char(8, 6 + i, 196, 0x70);

  int selected = 0;
  bool running = true;

  while (running) {
    // Leere den Dateibereich, bevor er neu gezeichnet wird
    for (int i = 0; i < 12; i++) {
      print_string(9 + i, 8,
                   "                                                  ", 0x70);
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
        print_string(9 + i, 45, file_cache[i].is_directory ? "DIR" : "FILE",
                     color);
      }
    } else {
      print_string(10, 8, "No filesystem mounted.", 0x70);
    }

    for (int i = 0; i < 80; i++)
      print_char(24, i, ' ', 0x70);
    print_string(24, 2, "UP/DOWN ENTER=Open ESC=Exit", 0x70); // Geändert

    uint8_t scancode = get_keyboard_input();

    if (scancode == 0x01) {
      running = false;
    } else if (scancode == 0x3D) { // F3 - Switch Drive
      if (active_disk == &ramdisk_device && hdd_device.present) {
        active_disk = &hdd_device;
        // Auto-mount if needed
        if (!mount_fat16(active_disk)) {
          // DON'T FORMAT HDD AUTOMATICALLY! Just warn.
          // But wait, user wants create.sh to format it. So it should be
          // mounted. If create.sh failed or wasn't run, this might fail.
        }
      } else if (active_disk == &hdd_device) {
        active_disk = &ramdisk_device;
        mount_fat16(active_disk); // Re-mount RAM disk just in case
      }
      // Reload Dir
      if (active_disk)
        read_directory(active_disk, root_dir_first_cluster);
      selected = 0; // Reset scroll

      // Redraw Header
      clear_screen(0x03);
      for (int i = 0; i < 80; i++)
        print_char(0, i, ' ', 0x1F);
      print_string(0, 2, "File Manager - FAT16", 0x1E);
      print_string(0, 50, "F3=Switch Drive ESC=Exit", 0x1F);
      draw_window(2, 5, 21, 70, " Drives & Files ", 0x0B);
      print_string(3, 8, "Active Drive:", 0x70);

      // Update Disk Info String
      if (active_disk == &ramdisk_device) {
        string_copy(disk_info, "[MRD0] RAM Disk - ");
      } else if (active_disk == &hdd_device) {
        string_copy(disk_info, "[HDD0] Hard Disk - ");
      } else {
        string_copy(disk_info, "[---] - ");
      }
      if (active_disk && fs_mounted) {
        int pos = string_length(disk_info);
        string_copy(disk_info + pos, "FAT16 (");
        pos = string_length(disk_info);
        uint32_t size_kb = (active_disk->size_sectors * 512) / 1024;
        // ... (Simple size append reused or simplified just print "Ready")
        string_copy(disk_info + pos, "Ready)");
      } else {
        string_copy(disk_info + string_length(disk_info), "No FS / Error");
      }
      print_string(4, 8, disk_info, 0x70);

      print_string(7, 8, "Filename", 0x70);
      print_string(7, 30, "Size", 0x70);
      print_string(7, 45, "Type", 0x70);
      for (int i = 0; i < 68; i++)
        print_char(8, 6 + i, 196, 0x70);

    } else if (scancode == 0x48 && selected > 0) {
      selected--;
    } else if (scancode == 0x50 && selected < file_count - 1) {
      selected++;
    } else if (scancode == 0x1C && file_count > 0 && active_disk &&
               fs_mounted) { // ENTER
      const char *ext = get_filename_ext(file_cache[selected].name);
      if (string_compare(ext, "TXT")) {
        text_editor(file_cache[selected].name);
        running = false;
      } else if (string_compare(ext, "MD")) {
        doc_editor(file_cache[selected].name);
        running = false;
      } else if (string_compare(ext, "MC")) {
        milla_ide(file_cache[selected].name);
        running = false;
      } else if (string_compare(ext, "CPP")) {
        run_cpp_program(file_cache[selected].name);
        // Redraw file manager
        clear_screen(0x03);
        for (int i = 0; i < 80; i++)
          print_char(0, i, ' ', 0x1F);
        print_string(0, 2, "File Manager - FAT16", 0x1E);
        print_string(0, 50, "ESC=Exit", 0x1F);
        draw_window(2, 5, 21, 70, " Drives & Files ", 0x0B);
        print_string(3, 8, "Active Drive:", 0x70);
        print_string(4, 8, disk_info, 0x70);
        print_string(7, 8, "Filename", 0x70);
        print_string(7, 30, "Size", 0x70);
        print_string(7, 45, "Type", 0x70);
        for (int i = 0; i < 68; i++)
          print_char(8, 6 + i, 196, 0x70);
      }
    }
  }
}

// ============================================================================
// TEXTEDITOR
// ============================================================================

#define EDITOR_BUFFER_SIZE 8192

char editor_buffer[EDITOR_BUFFER_SIZE];

void text_editor(const char *filename) {

  char title[40] = "Text Editor - ";
  int fn_len = string_length(filename);
  for (int i = 0; i < fn_len && i < 25; i++) {
    title[14 + i] = filename[i];
  }
  title[14 + fn_len] = '\0';

  for (int i = 0; i < 80; i++)
    print_char(0, i, ' ', 0x1F);
  print_string(0, 2, title, 0x1E);
  print_string(0, 45, "F1=Save F2=Reload ESC=Exit", 0x1F);

  // Buffer leeren (mit Leerzeichen füllen, wie im Original)
  for (int i = 0; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';
  int buffer_pos = 0;

  int file_idx = find_file(filename);
  if (file_idx != -1 && fs_mounted && active_disk) {
    read_file(active_disk, file_cache[file_idx].first_cluster, editor_buffer,
              file_cache[file_idx].size < EDITOR_BUFFER_SIZE
                  ? file_cache[file_idx].size
                  : EDITOR_BUFFER_SIZE);
    buffer_pos = file_cache[file_idx].size;
  } else {
    // Datei existiert nicht (oder ist neu), buffer_pos bleibt 0
    buffer_pos = 0;
  }

  // Fülle den Rest des Puffers mit Leerzeichen (read_file nullterminiert,
  // aber der Editor erwartet Leerzeichen zum Rendern)
  for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';

  int cursor_row = 1;
  int cursor_col = 0;
  bool shift_pressed = false;
  bool running = true;

  while (running) {
    for (int row = 1; row < 24; row++) {
      for (int col = 0; col < 80; col++) {
        int pos = (row - 1) * 80 + col;
        if (pos < EDITOR_BUFFER_SIZE) {
          print_char(row, col,
                     editor_buffer[pos] == '\n' ? ' ' : editor_buffer[pos],
                     0x0F);
        }
      }
    }

    print_char(cursor_row, cursor_col, 219, 0x0E);

    for (int i = 0; i < 80; i++)
      print_char(24, i, ' ', 0x70);
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

        // KORREKTUR: Berechne die tatsächliche Größe (ignoriere nachfolgende
        // Leerzeichen/Nulls)
        int actual_size = EDITOR_BUFFER_SIZE - 1;
        while (actual_size >= 0 && (editor_buffer[actual_size] == ' ' ||
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
    } else if (scancode == 0x3C) {    // F2 - Reload
      file_idx = find_file(filename); // Index neu finden
      if (file_idx != -1 && fs_mounted && active_disk) {
        for (int i = 0; i < EDITOR_BUFFER_SIZE; i++)
          editor_buffer[i] = ' ';
        read_file(active_disk, file_cache[file_idx].first_cluster,
                  editor_buffer,
                  file_cache[file_idx].size < EDITOR_BUFFER_SIZE
                      ? file_cache[file_idx].size
                      : EDITOR_BUFFER_SIZE);
        buffer_pos = file_cache[file_idx].size;
        // Fülle Rest mit Leerzeichen
        for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++)
          editor_buffer[i] = ' ';

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
        for (int i = new_pos; i < EDITOR_BUFFER_SIZE - 1; ++i) {
          editor_buffer[i] = editor_buffer[i + 1];
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
          if (pos >= buffer_pos)
            buffer_pos = pos + 1;

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

  for (int i = 0; i < 80; i++)
    print_char(0, i, ' ', 0x1F);
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

    const char *buttons[16] = {"7", "8", "9", "/", "4", "5", "6", "*",
                               "1", "2", "3", "-", "0", "C", "=", "+"};

    for (int y = 0; y < 4; y++) {
      for (int x = 0; x < 4; x++) {
        int row = 7 + y * 3;
        int col = 23 + x * 8;
        uint16_t color = (x == cursor_x && y == cursor_y) ? 0x07 : 0x70;
        uint16_t text_color = (x == cursor_x && y == cursor_y) ? 0x0E : 0x7E;
        print_char(row, col, '[', color);
        print_string(row, col + 1, buttons[y * 4 + x], text_color);
        print_char(row, col + 1 + string_length(buttons[y * 4 + x]), ']',
                   color);
      }
    }

    for (int i = 0; i < 80; i++)
      print_char(24, i, ' ', 0x70);
    print_string(24, 2, "Arrow keys, Enter to select, ESC=Exit", 0x70);

    uint8_t scancode = get_keyboard_input();

    char ch_input = 0;

    if (scancode == 0x01) {
      running = false;
    } else if (scancode == 0x48 && cursor_y > 0) {
      cursor_y--;
    } else if (scancode == 0x50 && cursor_y < 3) {
      cursor_y++;
    } else if (scancode == 0x4B && cursor_x > 0) {
      cursor_x--;
    } else if (scancode == 0x4D && cursor_x < 3) {
      cursor_x++;
    } else if (scancode == 0x1C) {
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
        display[0] = ch_input;
        display[1] = '\0';
        display_len = 1;
        new_number = false;
      } else if (display_len < 15) {
        display[display_len++] = ch_input;
        display[display_len] = '\0';
      }
    } else if (ch_input == '+' || ch_input == '-' || ch_input == '*' ||
               ch_input == '/') {
      num1 = 0;
      for (int i = 0; i < display_len; ++i)
        num1 = num1 * 10 + (display[i] - '0');
      operation = ch_input;
      new_number = true;
    } else if (ch_input == '=') {
      num2 = 0;
      for (int i = 0; i < display_len; ++i)
        num2 = num2 * 10 + (display[i] - '0');
      long result = 0;
      if (operation == '+')
        result = num1 + num2;
      else if (operation == '-')
        result = num1 - num2;
      else if (operation == '*')
        result = num1 * num2;
      else if (operation == '/' && num2 != 0)
        result = num1 / num2;
      else if (operation == '/' && num2 == 0) {
        string_copy(display, "DIV BY ZERO");
        display_len = 11;
        operation = 0;
        new_number = true;
        continue;
      } else
        result = num2;

      display_len = 0;
      if (result == 0) {
        display[0] = '0';
        display_len = 1;
      } else {
        char temp[20];
        int temp_len = 0;
        long r = result;
        bool negative = false;
        if (r < 0) {
          negative = true;
          r = -r;
        }
        while (r > 0) {
          temp[temp_len++] = '0' + (r % 10);
          r /= 10;
        }
        if (negative)
          display[display_len++] = '-';
        for (int i = temp_len - 1; i >= 0; i--)
          display[display_len++] = temp[i];
      }
      display[display_len] = '\0';
      operation = 0;
      new_number = true;
    } else if (ch_input == 'C') {
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

// ============================================================================
// EINSTELLUNGEN
// ============================================================================

void network_status_page() {
  clear_screen(0x03);
  draw_window(5, 15, 14, 50, " Network Status ", 0x0B);

  print_string(7, 18, "Status: ", 0x70);
  print_string(7, 30, Network::connected ? "Online" : "Offline",
               Network::connected ? 0x0A : 0x0C);

  char buf[50];

  // MAC
  print_string(9, 18, "MAC Address:", 0x70);
  char mac_str[20];
  // Format MAC
  int pos = 0;
  for (int i = 0; i < 6; i++) {
    uint8_t val = rtl8139_mac[i];
    uint8_t h = (val >> 4) & 0xF;
    uint8_t l = val & 0xF;
    mac_str[pos++] = (h < 10) ? '0' + h : 'A' + (h - 10);
    mac_str[pos++] = (l < 10) ? '0' + l : 'A' + (l - 10);
    if (i < 5)
      mac_str[pos++] = ':';
  }
  mac_str[pos] = '\0';
  print_string(10, 18, mac_str, 0x0F);

  // IP
  print_string(12, 18, "IP Address:", 0x70);
  // manual ip to string (Host Byte Order: 0A 00 02 0F -> 10.0.2.15)
  // My ip_addr_host is 0x0A00020F (Big Endian stored in u32? No I defined it as
  // hex literal 0x0A00020F) 0x0A = 10.
  // So shift logic:
  pos = 0;
  uint32_t ip = Network::ip_addr_host;

  for (int i = 0; i < 4; i++) {
    int octet = (ip >> (24 - i * 8)) & 0xFF;
    // itoa
    if (octet >= 100) {
      mac_str[pos++] = '0' + (octet / 100);
      octet %= 100;
      if (octet < 10)
        mac_str[pos++] = '0';
    }
    if (octet >= 10) {
      mac_str[pos++] = '0' + (octet / 10);
      octet %= 10;
    }
    mac_str[pos++] = '0' + octet;
    if (i < 3)
      mac_str[pos++] = '.';
  }
  mac_str[pos] = '\0';
  print_string(13, 18, mac_str, 0x0F);

  // Packets
  print_string(15, 18, "Packets RX: ", 0x70);
  // Simple int to str
  int n = packet_counter;
  mac_str[0] = '0' + (n / 1000) % 10;
  mac_str[1] = '0' + (n / 100) % 10;
  mac_str[2] = '0' + (n / 10) % 10;
  mac_str[3] = '0' + n % 10;
  mac_str[4] = '\0';
  print_string(15, 30, mac_str, 0x0E);

  print_string(16, 18, "Packets TX: ", 0x70);
  n = total_packets_sent;
  mac_str[0] = '0' + (n / 1000) % 10;
  mac_str[1] = '0' + (n / 100) % 10;
  mac_str[2] = '0' + (n / 10) % 10;
  mac_str[3] = '0' + n % 10;
  mac_str[4] = '\0';
  print_string(16, 30, mac_str, 0x0E);

  print_string_centered(24, "Press ESC to Back", 0x70);

  while (1) {
    if (get_keyboard_input() == 0x01)
      break;
  }
}

// Solitaire helpers
void solitaire_draw_cursor() {
  print_char(mouse_y, mouse_x, (char)219, 0x0E); // Cursor
}

bool check_mouse_click() {
  static bool old_left = false;
  bool clicked = (mouse_left && !old_left);
  old_left = mouse_left;
  return clicked;
}

void settings() {
  bool running = true;
  int selected = 0;

  // MERGED SETTINGS MENU
  while (running) {
    // Redraw Background
    if (show_wallpaper) {
      // Redraw underlying if transparent...
      draw_wallpaper(); // Simple redraw
    } else {
      clear_screen(0x03);
    }

    // Draw Window
    draw_window(5, 20, 16, 40, " Settings ", 0x0D);

    const char *opts[] = {"1. Toggle Wallpaper", "2. Keyboard Layout",
                          "3. Network Status", "4. Exit"};

    // Draw Options
    for (int i = 0; i < 4; i++) {
      uint16_t col = (selected == i) ? 0x0F : 0x07;
      print_string(8 + i * 2, 22, opts[i], col);

      // Value next to option
      if (i == 0) {
        if (show_wallpaper)
          print_string(8, 50, "[ON] ", 0x0A);
        else
          print_string(8, 50, "[OFF]", 0x0C);
      } else if (i == 1) {
        if (current_scancode_map == scancode_map_de)
          print_string(10, 50, "[DE]", 0x0E);
        else
          print_string(10, 50, "[US]", 0x0E);
      } else if (i == 2) {
        if (Network::connected)
          print_string(12, 50, "[OK]", 0x0A);
        else
          print_string(12, 50, "[NO]", 0x0C);
      }
    }

    // MOUSE CURSOR
    print_char(mouse_y, mouse_x, (char)219, 0x0E);

    uint8_t sc = get_keyboard_input();

    // Erase Cursor (if moved)
    // Actually, loop redraws everything so erasing specifically is redundant
    // but safe if partial redraw

    if (sc == 0)
      continue;

    if (sc == 0x01) { // ESC
      running = false;
    } else if (sc == 0x1C) { // ENTER
      if (selected == 0) {
        show_wallpaper = !show_wallpaper;
      } else if (selected == 1) {
        if (current_scancode_map == scancode_map_de) {
          current_scancode_map = scancode_map_us;
          current_scancode_map_shift = scancode_map_us_shift;
        } else {
          current_scancode_map = scancode_map_de;
          current_scancode_map_shift = scancode_map_de_shift;
        }
      } else if (selected == 2) {
        // Network Info Popup
        draw_window(8, 15, 12, 50, " Network Info ", 0x09);
        print_string(10, 18, "MAC: ", 0x0F);
        // print_string(10, 23, Network::get_mac_address_str(), 0x0F); // Helper
        // missing sometimes
        char mac_buf[20];
        // Re-implement simplified MAC str if needed or use existing
        // Assuming existing helper is available or we skip detailed MAC for
        // now.

        if (Network::connected)
          print_string(12, 18, "Status: Connected", 0x0A);
        else
          print_string(12, 18, "Status: Disconnected", 0x0C);

        print_string(16, 18, "Press any key...", 0x07);
        get_keyboard_input();
      } else if (selected == 3) {
        running = false;
      }
    } else if (sc == 0x48) { // Up
      if (selected > 0)
        selected--;
    } else if (sc == 0x50) { // Down
      if (selected < 3)
        selected++;
    }
  }
}

// ============================================================================
// HILFSFUNKTION FÜR TEXTEINGABE (NEU)
// ============================================================================
void get_string_input(int row, int col, int width, const char *prompt,
                      char *buffer, int max_len) {
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
    print_char(row + 1, col + 1 + pos,
               (pos < string_length(buffer)) ? buffer[pos] : ' ', 0x70);

    if (scancode == 0x01) { // ESC
      buffer[0] = '\0';     // Eingabe abbrechen
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
        // Konvertiere zu Großbuchstaben (FAT16-Standard NICHT ERZWINGEN hier
        // für URL) if (ch >= 'a' && ch <= 'z') ch -= 32;

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
// BROWSER APPLICATION
// ============================================================================

// Browser Content Buffer
char browser_content[80 * 20 + 1024]; // Small buffer for rendering

void browser() {
  clear_screen(0x1F);

  draw_window(0, 0, 3, 80, " Milla Browser v1.1 ", 0x1E);
  print_string(1, 2, "URL/IP:", 0x1E);

  char url_buffer[128];
  memset(url_buffer, 0, 128);
  string_copy(url_buffer, "localhost:8000/index.txt");

  // Address bar styling
  for (int i = 0; i < 60; i++)
    print_char(1, 10 + i, ' ', 0x70);
  print_string(1, 10, url_buffer, 0x70);

  // Content area
  for (int i = 3; i < 24; i++) {
    for (int j = 0; j < 80; j++)
      print_char(i, j, ' ', 0x0F);
  }

  print_string(24, 0, " F1: Go/Load  F2: Edit IP  ESC: Exit ", 0x70);

  bool running = true;
  bool needs_redraw = false;

  while (running) {
    if (needs_redraw) {
      // Clear content area
      for (int i = 3; i < 24; i++) {
        for (int j = 0; j < 80; j++)
          print_char(i, j, ' ', 0x0F);
      }
      // Render text in browser_content
      int row = 4;
      int col = 2;
      for (int i = 0; browser_content[i] != '\0' && row < 23; i++) {
        char c = browser_content[i];
        if (c == '\n') {
          row++;
          col = 2;
        } else if (c == '\r') {
        } else {
          print_char(row, col, c, 0x0F);
          col++;
          if (col > 78) {
            row++;
            col = 2;
          }
        }
      }
      needs_redraw = false;
    }

    uint8_t input = get_keyboard_input();

    if (input == 0x01) { // ESC
      running = false;
    } else if (input == 0x3B) { // F1 (Go)
      print_string(1, 72, "Loading", 0x4E);

      if (Network::http_get(url_buffer, browser_content,
                            sizeof(browser_content))) {
        print_string(1, 72, "Done   ", 0x2A);
      } else {
        print_string(1, 72, "Error  ", 0x4C);
      }
      needs_redraw = true;

    } else if (input == 0x3C) { // F2 (Addr Bar)
      get_string_input(1, 10, 60, "", url_buffer, 128);
      print_string(1, 10, url_buffer, 0x70);
    }

    // Background poll for incoming packets (packet counter etc)
    Network::poll();

    // Update Stats in corner
    // char stats[10];
    // stats[0] = 'R'; stats[1] = ':';
    // int n = Network::packet_counter % 10;
    // stats[2] = '0'+n;
    // ...
  }
}

// ============================================================================
// MILLA LANG
// ============================================================================

struct MillaVar {
  char name[32];
  char value[64];
  bool in_use;
};

MillaVar milla_vars[20];
char milla_log[20][80]; // Console history
int milla_log_count = 0;

// Random Number Generator (LCG)
unsigned long milla_rand_seed = 123456789;
int milla_rand(int min, int max) {
  milla_rand_seed = milla_rand_seed * 1103515245 + 12345;
  unsigned int r = (unsigned int)(milla_rand_seed / 65536) % 32768;
  if (min > max) {
    int t = min;
    min = max;
    max = t;
  }
  return min + (r % (max - min + 1));
}

// Helper: Parse integer
int milla_atoi(const char *s) {
  int res = 0;
  int sign = 1;
  int i = 0;
  if (s[0] == '-') {
    sign = -1;
    i++;
  }
  for (; s[i] != '\0'; ++i) {
    if (s[i] >= '0' && s[i] <= '9')
      res = res * 10 + s[i] - '0';
  }
  return sign * res;
}

// Helper: Int to String
void milla_itoa(int n, char *s) {
  int i = 0, sign = n;
  if (n < 0)
    n = -n;
  do {
    s[i++] = n % 10 + '0';
  } while ((n /= 10) > 0);
  if (sign < 0)
    s[i++] = '-';
  s[i] = '\0';
  // Reverse
  for (int j = 0, k = i - 1; j < k; j++, k--) {
    char t = s[j];
    s[j] = s[k];
    s[k] = t;
  }
}

// Add line to log
void milla_print(const char *msg) {
  if (milla_log_count < 20) {
    string_copy(milla_log[milla_log_count], msg);
    milla_log_count++;
  } else {
    // Shift up
    for (int i = 0; i < 19; i++)
      string_copy(milla_log[i], milla_log[i + 1]);
    string_copy(milla_log[19], msg);
  }
}

// Evaluate command
void milla_eval(const char *cmd) {
  char buffer[80];
  string_copy(buffer, cmd);

  // Tokenize (simple space split)
  char arg1[32] = "";
  char arg2[32] = "";
  char arg3[32] = ""; // Extra arg
  char command[32] = "";

  int space1 = -1, space2 = -1, space3 = -1;
  int len = string_length(buffer);

  // Find spaces
  for (int i = 0; i < len; i++) {
    if (buffer[i] == ' ') {
      if (space1 == -1)
        space1 = i;
      else if (space2 == -1)
        space2 = i;
      else if (space3 == -1)
        space3 = i;
    }
  }

  // Extract command
  int cmd_len = (space1 == -1) ? len : space1;
  for (int i = 0; i < cmd_len && i < 31; i++)
    command[i] = buffer[i];
  command[cmd_len] = '\0';

  // Extract Arg1
  if (space1 != -1) {
    int start = space1 + 1;
    int end = (space2 == -1) ? len : space2;
    int k = 0;
    for (int i = start; i < end && k < 31; i++)
      arg1[k++] = buffer[i];
    arg1[k] = '\0';
  }

  // Extract Arg2
  if (space2 != -1) {
    int start = space2 + 1;
    int end = (space3 == -1) ? len : space3;
    int k = 0;
    for (int i = start; i < end && k < 31; i++)
      arg2[k++] = buffer[i];
    arg2[k] = '\0';
  }

  // Extract Arg3
  if (space3 != -1) {
    int start = space3 + 1;
    int end = len;
    int k = 0;
    for (int i = start; i < end && k < 31; i++)
      arg3[k++] = buffer[i];
    arg3[k] = '\0';
  }

  // --- COMMANDS ---

  if (string_compare(command, "PRINT")) {
    if (arg1[0] == '"') {
      // String literal: Remove quotes (simple)
      char output[64];
      int k = 0;
      for (int i = 1; arg1[i] != '\0' && arg1[i] != '"'; i++)
        output[k++] = arg1[i];
      output[k] = '\0';
      milla_print(output);
    } else {
      // Variable lookup
      bool found = false;
      for (int i = 0; i < 20; i++) {
        if (milla_vars[i].in_use && string_compare(milla_vars[i].name, arg1)) {
          milla_print(milla_vars[i].value);
          found = true;
          break;
        }
      }
      if (!found)
        milla_print("Error: Var not found");
    }

  } else if (string_compare(command, "VAR")) {
    // VAR x = val
    if (string_compare(arg2, "=")) {
      // Save variable
      bool found = false;
      // Update existing
      for (int i = 0; i < 20; i++) {
        if (milla_vars[i].in_use && string_compare(milla_vars[i].name, arg1)) {
          string_copy(milla_vars[i].value, arg3);
          found = true;
          milla_print("Var updated.");
          break;
        }
      }
      // Create new
      if (!found) {
        for (int i = 0; i < 20; i++) {
          if (!milla_vars[i].in_use) {
            string_copy(milla_vars[i].name, arg1);
            string_copy(milla_vars[i].value, arg3);
            milla_vars[i].in_use = true;
            milla_print("Var set.");
            break;
          }
        }
      }
    } else {
      milla_print("Syntax: VAR name = value");
    }

  } else if (string_compare(command, "RANDOM")) {
    // RANDOM min max
    int min = milla_atoi(arg1);
    int max = milla_atoi(arg2);
    int r = milla_rand(min, max);
    char r_str[32];
    milla_itoa(r, r_str);
    char msg[60] = "Random: ";
    int l = 8;
    for (int i = 0; r_str[i] != 0; i++)
      msg[l++] = r_str[i];
    msg[l] = '\0';
    milla_print(msg);

  } else if (string_compare(command, "CALC")) {
    // CALC 1 + 1 (arg1 op arg2)
    int v1 = 0, v2 = 0;

    // Parse v1
    if (arg1[0] >= '0' && arg1[0] <= '9')
      v1 = milla_atoi(arg1);
    else {
      for (int i = 0; i < 20; i++)
        if (milla_vars[i].in_use && string_compare(milla_vars[i].name, arg1))
          v1 = milla_atoi(milla_vars[i].value);
    }

    char op = arg2[0];
    if (arg3[0] >= '0' && arg3[0] <= '9')
      v2 = milla_atoi(arg3);
    else {
      for (int i = 0; i < 20; i++)
        if (milla_vars[i].in_use && string_compare(milla_vars[i].name, arg3))
          v2 = milla_atoi(milla_vars[i].value);
    }

    int res = 0;
    if (op == '+')
      res = v1 + v2;
    else if (op == '-')
      res = v1 - v2;
    else if (op == '*')
      res = v1 * v2;
    else if (op == '/') {
      if (v2 != 0)
        res = v1 / v2;
    }

    char r_str[32];
    milla_itoa(res, r_str);
    char msg[60] = "Result: ";
    int l = 8;
    for (int i = 0; r_str[i] != 0; i++)
      msg[l++] = r_str[i];
    msg[l] = '\0';
    milla_print(msg);

  } else if (string_compare(command, "CLS")) {
    milla_log_count = 0;
    milla_print("Cleared.");
  } else if (string_compare(command, "HELP")) {
    milla_print("Cmds: PRINT, VAR, RANDOM, CALC");
  } else {
    if (string_length(command) > 0)
      milla_print("Unknown Command");
  }
}

// Run a full script buffer
void milla_run_script(const char *script) {
  milla_print("--- Running Script ---");
  char line_buffer[80];
  int line_pos = 0;

  for (int i = 0; script[i] != '\0'; i++) {
    char c = script[i];
    if (c == '\n') {
      line_buffer[line_pos] = '\0';
      if (line_pos > 0)
        milla_eval(line_buffer);
      line_pos = 0;
    } else {
      if (line_pos < 79)
        line_buffer[line_pos++] = c;
    }
  }
  // Last line
  if (line_pos > 0) {
    line_buffer[line_pos] = '\0';
    milla_eval(line_buffer);
  }
  milla_print("--- Finished ---");
}

void milla_lang() {
  clear_screen(0x0F);
  milla_log_count = 0; // Reset log on start
  milla_print("Welcome to Milla Lang v1.0");
  milla_print("Type HELP for commands. ESC to exit.");

  char input[80] = "";
  int input_len = 0;
  bool running = true;
  bool shift = false;

  while (running) {
    // Draw Interface
    draw_window(0, 0, 2, 80, " Milla Lang REPL ", 0x0B);

    // Draw Log
    for (int i = 0; i < 20; i++) {
      // Clear line
      for (int x = 0; x < 80; x++)
        print_char(3 + i, x, ' ', 0x0F);
      // Print log
      if (i < milla_log_count)
        print_string(3 + i, 2, milla_log[i], 0x0F);
    }

    // Draw Input Line
    for (int x = 0; x < 80; x++)
      print_char(24, x, ' ', 0x1F);
    print_string(24, 0, "> ", 0x1E);
    print_string(24, 2, input, 0x1F);
    print_char(24, 2 + input_len, 219, 0x1E); // Cursor

    // Input Handling
    uint8_t sc = get_keyboard_input();

    if (sc == 0x01) { // ESC
      running = false;
    } else if (sc == 0x1C) { // ENTER
      milla_print(input);    // Echo input
      milla_eval(input);
      input[0] = '\0';
      input_len = 0;
    } else if (sc == 0x0E) { // Backspace
      if (input_len > 0) {
        input_len--;
        input[input_len] = '\0';
      }
    } else if (sc == 0x2A || sc == 0x36) {
      shift = true;
    } else if (sc == 0xAA || sc == 0xB6) {
      shift = false;
    } else {
      char c = scancode_to_ascii(sc, shift);
      if (c != 0 && input_len < 75) {
        input[input_len++] = c;
        input[input_len] = '\0';
      }
    }
  }
}

// IDE for MillaCode
void milla_ide(const char *filename) {
  // Reusing Editor Buffer logic
  // Clear buffer first
  for (int i = 0; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';

  int file_idx = find_file(filename);
  int buffer_pos = 0;

  if (file_idx != -1 && fs_mounted && active_disk) {
    read_file(active_disk, file_cache[file_idx].first_cluster, editor_buffer,
              file_cache[file_idx].size < EDITOR_BUFFER_SIZE
                  ? file_cache[file_idx].size
                  : EDITOR_BUFFER_SIZE);
    buffer_pos = file_cache[file_idx].size;
  }

  // Fill rest with spaces
  for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';

  int cursor_row = 1;
  int cursor_col = 0;
  bool shift = false;
  bool running = true;
  bool show_help = false;

  while (running) {
    // Draw Header
    draw_window(0, 0, 2, 80, " MillaCode IDE ", 0x09);
    print_string(0, 60, "F1:Help F5:Run TAB:Auto", 0x0F);
    print_string(0, 2, filename, 0x0E);

    // Draw Content (Syntax Highlighting)
    for (int row = 1; row < 24; row++) {
      for (int col = 0; col < 80; col++) {
        int pos = (row - 1) * 80 + col;
        if (pos < EDITOR_BUFFER_SIZE) {
          char c = editor_buffer[pos];
          if (c == '\n')
            c = ' ';

          uint16_t color = 0x0F;
          // Very Basic Keyword Highlighting check (slow but works for small
          // screen) Check if we are at start of a keyword? To keep it simple,
          // just highlight Uppercase words?
          if (c >= 'A' && c <= 'Z')
            color = 0x0B; // Cyan for commands

          print_char(row, col, c, color);
        }
      }
    }

    // Draw Help Overlay if active
    if (show_help) {
      draw_window(5, 10, 15, 60, " MillaCode Help ", 0x4F);
      print_string(7, 12, "PRINT \"Text\" : Show text", 0x4F);
      print_string(8, 12, "VAR x = val  : Set variable", 0x4F);
      print_string(9, 12, "CALC 1 + 1   : Calculate", 0x4F);
      print_string(10, 12, "RANDOM 1 10  : Random Num", 0x4F);
      print_string(18, 12, "Press F1 to Close", 0x4F);
    }

    // Draw Cursor
    if (!show_help)
      print_char(cursor_row, cursor_col, 219, 0x0E);

    uint8_t sc = get_keyboard_input();

    if (sc == 0x01) { // ESC
      running = false;
    } else if (sc == 0x3B) { // F1 Help
      show_help = !show_help;
      // Force redraw
      clear_screen(0x00);
    } else if (sc == 0x3F) { // F5 Run
      // Save first (auto-save for run)
      // Calculate size
      int actual_size = EDITOR_BUFFER_SIZE - 1;
      while (actual_size >= 0 && (editor_buffer[actual_size] == ' ' ||
                                  editor_buffer[actual_size] == '\0' ||
                                  editor_buffer[actual_size] == '\n')) {
        actual_size--;
      }
      write_file(active_disk, filename, editor_buffer, actual_size + 1);

      // EXECUTE
      milla_lang(); // Switch to REPL context
      milla_print("--- IDE RUN ---");

      // Need a temp buffer copy for run script because REPL uses its own loops?
      // Actually milla_run_script parses buffers
      // Create a null-terminated copy of editor buffer (run time copy)
      // Warning: Stack size.
      // We'll just pass editor_buffer directly assuming it's safeish (might
      // have spaces at end)
      char *run_buf = (char *)malloc(actual_size + 2);
      if (run_buf) {
        for (int i = 0; i <= actual_size; i++)
          run_buf[i] = editor_buffer[i];
        run_buf[actual_size + 1] = '\0';
        milla_run_script(run_buf);
        free(run_buf);
      }

      // Wait for key
      print_string(24, 0, "Press Any Key...", 0x8E);
      get_keyboard_input();
      clear_screen(0x00);                  // Clear back for IDE
    } else if (sc == 0x0F && !show_help) { // TAB - Autocomplete
      // Find word before cursor
      int p = (cursor_row - 1) * 80 + cursor_col;
      if (p > 0) {
        char prefix[10];
        int len = 0;
        int start = p - 1;
        while (start >= 0 && editor_buffer[start] != ' ' &&
               editor_buffer[start] != '\n' && len < 8) {
          start--;
        }
        start++; // Move back to first char
        // Copy prefix
        for (int i = start; i < p; i++) {
          char c = editor_buffer[i];
          if (c >= 'a' && c <= 'z')
            c -= 32; // To upper
          prefix[len++] = c;
        }
        prefix[len] = '\0';

        const char *prediction = nullptr;
        if (string_compare(prefix, "P") || string_compare(prefix, "PR"))
          prediction = "PRINT ";
        else if (string_compare(prefix, "V") || string_compare(prefix, "VA"))
          prediction = "VAR ";
        else if (string_compare(prefix, "R") || string_compare(prefix, "RA"))
          prediction = "RANDOM ";
        else if (string_compare(prefix, "C") || string_compare(prefix, "CA"))
          prediction = "CALC ";

        if (prediction) {
          // Insert prediction
          // 1. Remove typed prefix
          for (int i = 0; i < len; i++) {
            // Backspace logic locally
            cursor_col--;
            p--;
          }
          // 2. Insert full word
          int pred_len = string_length(prediction);
          for (int i = 0; i < pred_len; i++) {
            if (p < EDITOR_BUFFER_SIZE) {
              editor_buffer[p++] = prediction[i];
              cursor_col++;
            }
          }
        }
      }
    } else if (!show_help) {
      // Standard Editor Logic (Simplified copy)
      if (sc == 0x2A || sc == 0x36)
        shift = true;
      else if (sc == 0xAA || sc == 0xB6)
        shift = false;
      else if (sc == 0x48 && cursor_row > 1)
        cursor_row--;
      else if (sc == 0x50 && cursor_row < 23)
        cursor_row++;
      else if (sc == 0x4B && cursor_col > 0)
        cursor_col--;
      else if (sc == 0x4D && cursor_col < 79)
        cursor_col++;
      else if (sc == 0x0E) { // Backspace
        int pos = (cursor_row - 1) * 80 + cursor_col;
        if (pos > 0) {
          if (cursor_col > 0)
            cursor_col--;
          else if (cursor_row > 1) {
            cursor_row--;
            cursor_col = 79;
          }
          // Shift buffer
          int new_pos = (cursor_row - 1) * 80 + cursor_col;
          for (int i = new_pos; i < EDITOR_BUFFER_SIZE - 1; i++)
            editor_buffer[i] = editor_buffer[i + 1];
        }
      } else if (sc == 0x1C) { // Enter
        if (cursor_row < 23) {
          cursor_row++;
          cursor_col = 0;
        }
      } else {
        char c = scancode_to_ascii(sc, shift);
        if (c != 0) {
          int pos = (cursor_row - 1) * 80 + cursor_col;
          if (pos < EDITOR_BUFFER_SIZE) {
            editor_buffer[pos] = c;
            if (cursor_col < 79)
              cursor_col++;
            else if (cursor_row < 23) {
              cursor_row++;
              cursor_col = 0;
            }
          }
        }
      }
    }
  }
  // Save on exit? optional.
}

// DOC Editor (Markdown-like)
void doc_editor(const char *filename) {
  // Reusing Editor Buffer logic
  for (int i = 0; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';

  int file_idx = find_file(filename);
  int buffer_pos = 0;

  if (file_idx != -1 && fs_mounted && active_disk) {
    read_file(active_disk, file_cache[file_idx].first_cluster, editor_buffer,
              file_cache[file_idx].size < EDITOR_BUFFER_SIZE
                  ? file_cache[file_idx].size
                  : EDITOR_BUFFER_SIZE);
    buffer_pos = file_cache[file_idx].size;
  }
  for (int i = buffer_pos; i < EDITOR_BUFFER_SIZE; i++)
    editor_buffer[i] = ' ';

  int cursor_row = 1;
  int cursor_col = 0;
  bool shift = false;
  bool running = true;

  while (running) {
    // MD Style Header
    draw_window(0, 0, 2, 80, " MillaWriter (MD) ", 0x0D); // Magenta
    print_string(0, 60, "F1:Save ESC:Exit", 0x1F);
    print_string(0, 2, filename, 0x1E);

    // Render loop with Markdown Syntax Highlighting
    for (int row = 1; row < 24; row++) {
      bool is_header = false;
      // Check start of line for #
      int line_start = (row - 1) * 80;
      if (line_start < EDITOR_BUFFER_SIZE && editor_buffer[line_start] == '#')
        is_header = true;

      for (int col = 0; col < 80; col++) {
        int pos = (row - 1) * 80 + col;
        if (pos < EDITOR_BUFFER_SIZE) {
          char c = editor_buffer[pos];
          if (c == '\n')
            c = ' ';
          uint16_t color = 0x0F;

          if (is_header)
            color = 0x0E; // Yellow for headers
          if (c == '*' || c == '_')
            color = 0x0A; // Green for syntax

          print_char(row, col, c, color);
        }
      }
    }
    print_char(cursor_row, cursor_col, 219, 0x0D);

    uint8_t sc = get_keyboard_input();

    if (sc == 0x01)
      running = false;
    else if (sc == 0x3B) { // F1 Save
      int actual_size = EDITOR_BUFFER_SIZE - 1;
      while (actual_size >= 0 && (editor_buffer[actual_size] == ' ' ||
                                  editor_buffer[actual_size] == '\0' ||
                                  editor_buffer[actual_size] == '\n'))
        actual_size--;
      write_file(active_disk, filename, editor_buffer, actual_size + 1);
      print_string(24, 60, "Saved!", 0x2A);
      delay(10);
    } else {
      // Standard edit logic
      if (sc == 0x2A || sc == 0x36)
        shift = true;
      else if (sc == 0xAA || sc == 0xB6)
        shift = false;
      else if (sc == 0x48 && cursor_row > 1)
        cursor_row--;
      else if (sc == 0x50 && cursor_row < 23)
        cursor_row++;
      else if (sc == 0x4B && cursor_col > 0)
        cursor_col--;
      else if (sc == 0x4D && cursor_col < 79)
        cursor_col++;
      else if (sc == 0x0E) { // Backspace
        int pos = (cursor_row - 1) * 80 + cursor_col;
        if (pos > 0) {
          if (cursor_col > 0)
            cursor_col--;
          else if (cursor_row > 1) {
            cursor_row--;
            cursor_col = 79;
          }
          int new_pos = (cursor_row - 1) * 80 + cursor_col;
          for (int i = new_pos; i < EDITOR_BUFFER_SIZE - 1; i++)
            editor_buffer[i] = editor_buffer[i + 1];
        }
      } else if (sc == 0x1C) { // Enter
        if (cursor_row < 23) {
          cursor_row++;
          cursor_col = 0;
        }
      } else {
        char c = scancode_to_ascii(sc, shift);
        if (c != 0) {
          int pos = (cursor_row - 1) * 80 + cursor_col;
          if (pos < EDITOR_BUFFER_SIZE) {
            editor_buffer[pos] = c;
            if (cursor_col < 79)
              cursor_col++;
            else if (cursor_row < 23) {
              cursor_row++;
              cursor_col = 0;
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// SOLITAIRE GAME
// ============================================================================

struct Card {
  uint8_t rank; // 0=A, 1=2, ... 9=10, 10=J, 11=Q, 12=K
  uint8_t suit; // 0=HEARTS, 1=DIAMONDS, 2=CLUBS, 3=SPADES
  bool face_up;
};

// Game State
Card piles[13][52]; // 0-6: Tableau, 7-10: Foundation, 11: Stock, 12: Waste
int pile_counts[13];

// Random need seed from time or user interaction
void shuffle_deck(Card *deck, int count) {
  for (int i = 0; i < count; i++) {
    int r = milla_rand(0, count - 1);
    Card temp = deck[i];
    deck[i] = deck[r];
    deck[r] = temp;
  }
}

void init_solitaire() {
  Card full_deck[52];
  int idx = 0;
  for (int s = 0; s < 4; s++) {
    for (int r = 0; r < 13; r++) {
      full_deck[idx].rank = r;
      full_deck[idx].suit = s;
      full_deck[idx].face_up = false;
      idx++;
    }
  }
  shuffle_deck(full_deck, 52);

  int card_idx = 0;
  for (int i = 0; i < 7; i++) {
    pile_counts[i] = i + 1;
    for (int j = 0; j < i + 1; j++) {
      piles[i][j] = full_deck[card_idx++];
      if (j == i)
        piles[i][j].face_up = true;
    }
  }

  pile_counts[11] = 0;
  while (card_idx < 52) {
    piles[11][pile_counts[11]] = full_deck[card_idx++];
    piles[11][pile_counts[11]].face_up = false;
    pile_counts[11]++;
  }

  for (int i = 7; i <= 10; i++)
    pile_counts[i] = 0;
  pile_counts[12] = 0;
}

void draw_card(int row, int col, Card c, bool selected) {
  uint16_t bg = selected ? 0x20 : 0x70;
  if (!c.face_up) {
    print_string(row, col, "[##]", 0x1F | (selected ? 0x20 : 0x00));
    return;
  }

  uint16_t color = (c.suit < 2) ? 0x0C : 0x00;
  color |= bg;

  char face[5];
  face[0] = '[';
  int pos = 1;
  if (c.rank == 0)
    face[pos++] = 'A';
  else if (c.rank >= 1 && c.rank <= 8)
    face[pos++] = '1' + c.rank;
  else if (c.rank == 9) {
    face[pos++] = '1';
    face[pos++] = '0';
  } else if (c.rank == 10)
    face[pos++] = 'J';
  else if (c.rank == 11)
    face[pos++] = 'Q';
  else if (c.rank == 12)
    face[pos++] = 'K';

  face[pos++] = 3 + c.suit;
  face[pos++] = ']';
  face[pos] = '\0';

  print_string(row, col, face, color);
}

void draw_placeholder(int row, int col, bool selected) {
  uint16_t color = selected ? 0x2F : 0x70;
  print_string(row, col, "[  ]", color);
}

void solitaire() {
  init_solitaire();

  int cur_pile = 0;
  int src_pile = -1;
  bool running = true;
  bool redraw = true;
  for (int i = 0; i < (get_keyboard_input() % 10); i++)
    milla_rand(0, 10);

  while (running) {
    if (redraw) {
      clear_screen(0x03);
      print_string(0, 0, " MillaSolitaire ", 0x3F);
      print_string(0, 60, "Arrows=Move SPC=Sel Q=Quit", 0x3F);

      if (pile_counts[11] > 0)
        draw_card(2, 2, piles[11][pile_counts[11] - 1], cur_pile == 11);
      else
        draw_placeholder(2, 2, cur_pile == 11);
      if (cur_pile == 11 && pile_counts[11] == 0)
        print_string(3, 2, "R", 0x30);

      if (pile_counts[12] > 0)
        draw_card(2, 8, piles[12][pile_counts[12] - 1], cur_pile == 12);
      else
        draw_placeholder(2, 8, cur_pile == 12);

      for (int i = 0; i < 4; i++) {
        int pid = 7 + i;
        int col = 30 + i * 6;
        if (pile_counts[pid] > 0)
          draw_card(2, col, piles[pid][pile_counts[pid] - 1], cur_pile == pid);
        else {
          draw_placeholder(2, col, cur_pile == pid);
          char s[2] = {(char)(3 + i), 0};
          print_string(2, col + 1, s, (i < 2 ? 0x0C : 0x00) | 0x70);
        }
      }

      for (int i = 0; i < 7; i++) {
        int col = 2 + i * 8;
        if (pile_counts[i] == 0) {
          draw_placeholder(6, col, cur_pile == i && src_pile != i);
        } else {
          for (int j = 0; j < pile_counts[i]; j++) {
            int row = 6 + j;
            if (row > 23)
              row = 23;
            bool is_top = (j == pile_counts[i] - 1);
            bool selected = (cur_pile == i && is_top);
            if (src_pile == i && is_top)
              selected = true;

            draw_card(row, col, piles[i][j], selected);
          }
        }
        if (pile_counts[i] == 0 && cur_pile == i) {
          draw_placeholder(6, col, true);
        }
      }

      if (src_pile != -1) {
        char status[30];
        string_copy(status, "Selected: ");
        if (src_pile == 11)
          string_copy(status + 10, "Stock");
        else if (src_pile == 12)
          string_copy(status + 10, "Waste");
        else if (src_pile < 7) {
          string_copy(status + 10, "Col");
          status[13] = '1' + src_pile;
          status[14] = 0;
        }
        print_string(24, 2, status, 0x1E);
      }
      redraw = false;
    }

    uint8_t sc = get_keyboard_input();

    if (sc == 0x01 || sc == 0x10) {
      running = false;
    } else if (sc == 0x4B) {
      if (cur_pile == 7)
        cur_pile = 12;
      else if (cur_pile == 12)
        cur_pile = 11;
      else if (cur_pile > 0 && cur_pile < 7)
        cur_pile--;
      else if (cur_pile > 7)
        cur_pile--;
      else if (cur_pile == 0)
        cur_pile = 6;
      redraw = true;
    } else if (sc == 0x4D) {
      if (cur_pile == 11)
        cur_pile = 12;
      else if (cur_pile == 12)
        cur_pile = 7;
      else if (cur_pile < 6)
        cur_pile++;
      else if (cur_pile >= 7 && cur_pile < 10)
        cur_pile++;
      else if (cur_pile == 10)
        cur_pile = 0;
      redraw = true;
    } else if (sc == 0x48) {
      if (cur_pile < 7) {
        if (cur_pile < 2)
          cur_pile = 11 + cur_pile;
        else
          cur_pile = 7 + (cur_pile - 3);
        if (cur_pile > 10)
          cur_pile = 10;
      }
      redraw = true;
    } else if (sc == 0x50) {
      if (cur_pile >= 7) {
        cur_pile = (cur_pile - 7) * 2;
        if (cur_pile > 6)
          cur_pile = 6;
      }
      redraw = true;
    } else if (sc == 0x39 || sc == 0x1C) {
      if (cur_pile == 11) {
        if (pile_counts[11] > 0) {
          Card c = piles[11][pile_counts[11] - 1];
          pile_counts[11]--;
          c.face_up = true;
          piles[12][pile_counts[12]] = c;
          pile_counts[12]++;
        } else {
          if (pile_counts[12] > 0) {
            for (int i = pile_counts[12] - 1; i >= 0; i--) {
              Card c = piles[12][i];
              c.face_up = false;
              piles[11][pile_counts[11]] = c;
              pile_counts[11]++;
            }
            pile_counts[12] = 0;
          }
        }
        if (src_pile == 11)
          src_pile = -1;
        redraw = true;
      } else {
        if (src_pile == -1) {
          if (pile_counts[cur_pile] > 0) {
            src_pile = cur_pile;
            redraw = true;
          }
        } else {
          if (src_pile == cur_pile) {
            src_pile = -1;
            redraw = true;
          } else {
            Card src = piles[src_pile][pile_counts[src_pile] - 1];
            bool valid = false;

            if (cur_pile >= 7 && cur_pile <= 10) {
              if (pile_counts[cur_pile] == 0) {
                if (src.rank == 0)
                  valid = true;
              } else {
                Card top = piles[cur_pile][pile_counts[cur_pile] - 1];
                if (top.suit == src.suit && src.rank == top.rank + 1)
                  valid = true;
              }
            } else if (cur_pile < 7) {
              if (pile_counts[cur_pile] == 0) {
                if (src.rank == 12)
                  valid = true;
              } else {
                Card top = piles[cur_pile][pile_counts[cur_pile] - 1];
                bool src_red = (src.suit < 2);
                bool top_red = (top.suit < 2);
                if (src_red != top_red && src.rank == top.rank - 1)
                  valid = true;
              }
            }

            if (valid) {
              piles[cur_pile][pile_counts[cur_pile]++] = src;
              pile_counts[src_pile]--;
              if (src_pile < 7 && pile_counts[src_pile] > 0) {
                piles[src_pile][pile_counts[src_pile] - 1].face_up = true;
              }
              src_pile = -1;
              redraw = true;
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// HAUPTMENÜ
// ============================================================================

void main_menu() {
  clear_screen(0x03);

  int win_height = 20;
  int win_width = 40;
  int win_y = 3;
  int win_x = 20;

  for (int i = 0; i < 80; i++)
    print_char(0, i, ' ', 0x1F);
  print_string(0, 2, "Milla OS 1.0 - Start Menu", 0x1E);

  draw_window(win_y, win_x, win_height, win_width, " Main Menu ", 0x0B);

  // **GEÄNDERT: Menüpunkte**
  const char *menu_items[] = {
      "1. File Manager",     "2. Doc Writer", "3. Calculator",
      "4. Internet Browser", "5. Milla Lang", "6. Milla IDE",
      "7. Solitaire",        "8. Settings",   "9. Exit to MTop"};

  const int NUM_ITEMS = 9;

  int selected = 0;
  bool running = true;

  while (running) {
    // Menü neu zeichnen (wichtig nach get_string_input)
    draw_window(win_y, win_x, win_height, win_width, " Main Menu ", 0x0B);

    // Draw Background
    for (int r = win_y + 1; r < win_y + win_height - 1; r++) {
      for (int c = win_x + 1; c < win_x + win_width - 1; c++)
        print_char(r, c, ' ', 0x0F);
    }

    for (int i = 0; i < NUM_ITEMS; i++) {
      int item_y = win_y + 2 + (i * 2);
      uint16_t color = (i == selected) ? 0x4E : 0x0F;
      if (i == selected) {
        for (int k = 0; k < win_width - 2; k++)
          print_char(item_y, win_x + 1 + k, ' ', 0x4F);
      }
      print_string(item_y, win_x + 3, menu_items[i], color);
    }

    for (int i = 0; i < 80; i++)
      print_char(24, i, ' ', 0x70);
    print_string(24, 2, "UP/DOWN=Select ENTER=Open ESC=MTop", 0x70);

    uint8_t scancode = get_keyboard_input();

    if (scancode == 0x01) {
      running = false;
    } else if (scancode == 0x48 && selected > 0) {
      selected--;
    } else if (scancode == 0x50 && selected < NUM_ITEMS - 1) {
      selected++;
    } else if (scancode == 0x1C) {
      switch (selected) {
      case 0:
        file_manager();
        break;
      case 1: // DOC EDITOR / TEXT Editor
      {
        // Ask filename etc.
        char filename_buffer[MAX_FILENAME + 1];
        memset(filename_buffer, 0, sizeof(filename_buffer));
        get_string_input(10, 20, 40, " Enter Filename ", filename_buffer,
                         MAX_FILENAME);
        if (string_length(filename_buffer) == 0)
          string_copy(filename_buffer, "NEW.MD");

        // Auto extension
        // If not .MC and not .TXT, assume .MD for this menu item?
        // Let's just launch doc_editor
        const char *ext = get_filename_ext(filename_buffer);
        if (string_length(ext) == 0) {
          // Append .MD by default for Doc Writer
          int len = string_length(filename_buffer);
          if (len < MAX_FILENAME - 3) {
            filename_buffer[len] = '.';
            filename_buffer[len + 1] = 'M';
            filename_buffer[len + 2] = 'D';
            filename_buffer[len + 3] = '\0';
          }
        }

        doc_editor(filename_buffer);
      } break;
      case 2:
        calculator();
        break;
      case 3:
        browser();
        break;
      case 4:
        milla_lang();
        break;
      case 5:
        // IDE Launch from menu (already handled above in full logic but
        // previous chunk missed case 5 label in this snippet) Wait, I need to
        // match properly.
        {
          char filename_buffer[MAX_FILENAME + 1];
          memset(filename_buffer, 0, sizeof(filename_buffer));
          get_string_input(10, 20, 40, " Enter MC File ", filename_buffer,
                           MAX_FILENAME);
          if (string_length(filename_buffer) == 0)
            string_copy(filename_buffer, "SCRIPT.MC");

          const char *ext = get_filename_ext(filename_buffer);
          if (string_length(ext) == 0) {
            int len = string_length(filename_buffer);
            if (len < MAX_FILENAME - 3) {
              filename_buffer[len] = '.';
              filename_buffer[len + 1] = 'M';
              filename_buffer[len + 2] = 'C';
              filename_buffer[len + 3] = '\0';
            }
          }
          milla_ide(filename_buffer);
        }
        break;
      case 6:
        solitaire();
        break;
      case 7:
        settings();
        break;
      case 8:
        running = false;
        break;
      }

      clear_screen(0x03);
      for (int i = 0; i < 80; i++)
        print_char(0, i, ' ', 0x1F);
      print_string(0, 2, "Milla OS 1.0 - Start Menu", 0x1E);
      draw_window(win_y, win_x, win_height, win_width, " Main Menu ", 0x0B);
    }
  }
}

// ============================================================================
// MTop
// ============================================================================

void MTop() {
  clear_screen(0x03);

  for (int i = 0; i < 80; i++)
    print_char(0, i, ' ', 0x1F);
  print_string(0, 2, "Milla OS 1.0", 0x1E);
  print_string(0, 60, "[F1=STARTMENU]", 0x4F);

  // WIDGET: Clock
  Time t = get_time();
  char time_str[9] = "00:00:00";
  time_str[0] = '0' + (t.hour / 10);
  time_str[1] = '0' + (t.hour % 10);
  time_str[3] = '0' + (t.minute / 10);
  time_str[4] = '0' + (t.minute % 10);
  time_str[6] = '0' + (t.second / 10);
  time_str[7] = '0' + (t.second % 10);
  print_string(0, 45, time_str, 0x1E);

  // WIDGET: Stats
  print_string(0, 30, "RAM: 1MB", 0x1E);
  char net_str[20];

  string_copy(net_str, Network::connected ? "NET: ON " : "NET: OFF");
  if (Network::connected) {
    // Show last byte of MAC as indicator
    int len = string_length(net_str);
    net_str[len - 1] = ' '; // clear space
    uint8_t val = rtl8139_mac[5];
    net_str[len++] = ' ';
    net_str[len++] = (val < 10) ? '0' + val : 'A' + (val - 10);
    net_str[len] = '\0';
  }
  print_string(0, 20, net_str, Network::connected ? 0x1A : 0x1C);

  draw_window(3, 10, 12, 60, " MTOP ", 0x0B);
  print_string(5, 15, "Welcome to Milla OS!", 0x70);
  // print_string(6, "(Micro Integrated Low-Level Application OS)", 0x70);

  print_string(8, 15, "A FOSS Operating System", 0x78);
  print_string(9, 15, "by FloriDevs", 0x78);
  print_string(11, 15, "Press F1 for Menu", 0x70);

  for (int i = 0; i < 80; i++)
    print_char(24, i, ' ', 0x70);

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
    // UPDATE CLOCK WIDGET loop
    Time t = get_time();
    char time_str[9] = "00:00:00";
    time_str[0] = '0' + (t.hour / 10);
    time_str[1] = '0' + (t.hour % 10);
    time_str[3] = '0' + (t.minute / 10);
    time_str[4] = '0' + (t.minute % 10);
    time_str[6] = '0' + (t.second / 10);
    time_str[7] = '0' + (t.second % 10);
    print_string(0, 45, time_str, 0x1E);

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
      for (int i = 0; i < 80; i++)
        print_char(0, i, ' ', 0x1F);
      print_string(0, 2, "Milla OS 1.0", 0x1E);
      print_string(0, 60, "[F1=MENU]", 0x4F);
      draw_window(3, 10, 12, 60, " Welcome ", 0x0B);
      print_string(5, 15, "Welcome to Milla OS!", 0x70);
      print_string(7, 15, "A FOSS Operating System", 0x78);
      print_string(8, 15, "by FloriDevs", 0x78);
      print_string(10, 15, "Press F1 for Menu", 0x70);

      for (int i = 0; i < 80; i++)
        print_char(24, i, ' ', 0x70);

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

    } else if (scancode == 0x4B && cursor_col > 0) {
      cursor_col--;
    } else if (scancode == 0x4D && cursor_col < 79) {
      cursor_col++;
    } else if (scancode == 0x48 && cursor_row > 1) {
      cursor_row--;
    } else if (scancode == 0x50 && cursor_row < 23) {
      cursor_row++;
    }
  }
}

// ============================================================================
// KERNEL MAIN
// ============================================================================

extern "C" void kernel_main() {
  draw_flower();
  init_filesystem();
  Network::init();
  MTop();
}

// ***ENDE CODE***
