#ifndef IMAGE_DECODER_H
#define IMAGE_DECODER_H

#include <stdint.h>
#include <stddef.h>

#define IMG_MAX_W 800
#define IMG_MAX_H 600

// Helper: case-insensitive filename extension comparison
static inline bool img_ends_with_ignore_case(const char *str, const char *suffix) {
    int str_len = 0;
    while (str[str_len]) str_len++;
    int suf_len = 0;
    while (suffix[suf_len]) suf_len++;
    if (suf_len > str_len) return false;
    for (int i = 0; i < suf_len; i++) {
        char c1 = str[str_len - suf_len + i];
        char c2 = suffix[i];
        if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
        if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
        if (c1 != c2) return false;
    }
    return true;
}

// Helper: case-insensitive string equality comparison
static inline bool string_equals_ignore_case(const char *s1, const char *s2) {
    if (!s1 || !s2) return false;
    while (*s1 && *s2) {
        char c1 = *s1++;
        char c2 = *s2++;
        if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
        if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
        if (c1 != c2) return false;
    }
    return (*s1 == '\0' && *s2 == '\0');
}

// Check if file is recognized as an image by filename extension
static inline bool is_image_extension(const char *name) {
    if (!name) return false;
    return img_ends_with_ignore_case(name, ".BMP") ||
           img_ends_with_ignore_case(name, ".RAW") ||
           img_ends_with_ignore_case(name, ".PPM") ||
           img_ends_with_ignore_case(name, ".QOI");
}

// ----------------------------------------------------------------------------
// BMP Decoder (supports 24-bit RGB, 32-bit RGBA, 8-bit indexed)
// ----------------------------------------------------------------------------
static inline bool decode_bmp(const uint8_t *data, uint32_t size, uint32_t *out_pixels,
                              int &out_w, int &out_h, int max_w = IMG_MAX_W, int max_h = IMG_MAX_H) {
    if (size < 54 || !data || !out_pixels) return false;
    if (data[0] != 'B' || data[1] != 'M') return false;

    uint32_t data_offset = *(const uint32_t *)(data + 10);
    uint32_t header_size = *(const uint32_t *)(data + 14);
    int32_t w = *(const int32_t *)(data + 18);
    int32_t h = *(const int32_t *)(data + 22);
    uint16_t planes = *(const uint16_t *)(data + 26);
    uint16_t bpp = *(const uint16_t *)(data + 28);
    uint32_t compression = *(const uint32_t *)(data + 30);

    if (planes != 1 || w <= 0 || w > max_w || h == 0) return false;
    int abs_h = h < 0 ? -h : h;
    if (abs_h > max_h) return false;
    if (compression != 0 && compression != 3) return false; // BI_RGB or BI_BITFIELDS uncompressed

    bool top_down = (h < 0);

    if (bpp == 24) {
        int row_stride = ((w * 3 + 3) / 4) * 4;
        for (int y = 0; y < abs_h; y++) {
            int file_y = top_down ? y : (abs_h - 1 - y);
            uint32_t row_off = data_offset + file_y * row_stride;
            if (row_off + w * 3 > size) return false;
            const uint8_t *row = data + row_off;
            for (int x = 0; x < w; x++) {
                uint8_t b = row[x * 3 + 0];
                uint8_t g = row[x * 3 + 1];
                uint8_t r = row[x * 3 + 2];
                out_pixels[y * w + x] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
            }
        }
        out_w = w;
        out_h = abs_h;
        return true;
    } else if (bpp == 32) {
        int row_stride = w * 4;
        for (int y = 0; y < abs_h; y++) {
            int file_y = top_down ? y : (abs_h - 1 - y);
            uint32_t row_off = data_offset + file_y * row_stride;
            if (row_off + w * 4 > size) return false;
            const uint8_t *row = data + row_off;
            for (int x = 0; x < w; x++) {
                uint8_t b = row[x * 4 + 0];
                uint8_t g = row[x * 4 + 1];
                uint8_t r = row[x * 4 + 2];
                out_pixels[y * w + x] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
            }
        }
        out_w = w;
        out_h = abs_h;
        return true;
    } else if (bpp == 8) {
        // 8-bit indexed palette
        uint32_t pal_offset = 14 + header_size;
        if (pal_offset + 256 * 4 > size) return false;
        const uint8_t *pal = data + pal_offset;
        int row_stride = ((w + 3) / 4) * 4;
        for (int y = 0; y < abs_h; y++) {
            int file_y = top_down ? y : (abs_h - 1 - y);
            uint32_t row_off = data_offset + file_y * row_stride;
            if (row_off + w > size) return false;
            const uint8_t *row = data + row_off;
            for (int x = 0; x < w; x++) {
                uint8_t idx = row[x];
                uint8_t b = pal[idx * 4 + 0];
                uint8_t g = pal[idx * 4 + 1];
                uint8_t r = pal[idx * 4 + 2];
                out_pixels[y * w + x] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
            }
        }
        out_w = w;
        out_h = abs_h;
        return true;
    }

    return false;
}

// ----------------------------------------------------------------------------
// PPM Decoder (supports P6 binary and P3 ASCII)
// ----------------------------------------------------------------------------
static inline bool decode_ppm(const uint8_t *data, uint32_t size, uint32_t *out_pixels,
                              int &out_w, int &out_h, int max_w = IMG_MAX_W, int max_h = IMG_MAX_H) {
    if (size < 10 || !data || !out_pixels) return false;
    if (data[0] != 'P' || (data[1] != '6' && data[1] != '3')) return false;
    bool is_p6 = (data[1] == '6');
    uint32_t pos = 2;

    auto parse_int = [&]() -> int {
        while (pos < size) {
            while (pos < size && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n'))
                pos++;
            if (pos < size && data[pos] == '#') {
                while (pos < size && data[pos] != '\n') pos++;
                continue;
            }
            break;
        }
        if (pos >= size) return -1;
        int val = 0;
        while (pos < size && data[pos] >= '0' && data[pos] <= '9') {
            val = val * 10 + (data[pos++] - '0');
        }
        return val;
    };

    int w = parse_int();
    int h = parse_int();
    int maxval = parse_int();

    if (w <= 0 || w > max_w || h <= 0 || h > max_h || maxval <= 0 || maxval > 255) return false;
    if (pos < size && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n')) pos++;

    if (is_p6) {
        if (pos + (uint32_t)w * h * 3 > size) return false;
        for (int i = 0; i < w * h; i++) {
            uint8_t r = data[pos++];
            uint8_t g = data[pos++];
            uint8_t b = data[pos++];
            out_pixels[i] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        }
    } else {
        for (int i = 0; i < w * h; i++) {
            int r = parse_int();
            int g = parse_int();
            int b = parse_int();
            if (r < 0 || g < 0 || b < 0) return false;
            out_pixels[i] = ((uint32_t)(r & 0xFF) << 16) | ((uint32_t)(g & 0xFF) << 8) | (b & 0xFF);
        }
    }
    out_w = w;
    out_h = h;
    return true;
}

// ----------------------------------------------------------------------------
// QOI Decoder (lossless compressed image format)
// ----------------------------------------------------------------------------
static inline bool decode_qoi(const uint8_t *data, uint32_t size, uint32_t *out_pixels,
                              int &out_w, int &out_h, int max_w = IMG_MAX_W, int max_h = IMG_MAX_H) {
    if (size < 14 || !data || !out_pixels) return false;
    if (data[0] != 'q' || data[1] != 'o' || data[2] != 'i' || data[3] != 'f') return false;

    uint32_t w = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | data[7];
    uint32_t h = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];
    uint8_t channels = data[12];
    if (w <= 0 || w > (uint32_t)max_w || h <= 0 || h > (uint32_t)max_h) return false;
    if (channels != 3 && channels != 4) return false;

    uint32_t index[64] = {0};
    uint8_t r = 0, g = 0, b = 0, a = 255;
    uint32_t total = w * h;
    uint32_t p = 0;
    uint32_t pos = 14;

    while (p < total && pos < size) {
        uint8_t b1 = data[pos++];
        if (b1 == 0xFE) { // QOI_OP_RGB
            if (pos + 3 > size) break;
            r = data[pos++];
            g = data[pos++];
            b = data[pos++];
        } else if (b1 == 0xFF) { // QOI_OP_RGBA
            if (pos + 4 > size) break;
            r = data[pos++];
            g = data[pos++];
            b = data[pos++];
            a = data[pos++];
        } else if ((b1 & 0xC0) == 0x00) { // QOI_OP_INDEX
            uint32_t px = index[b1 & 0x3F];
            r = (px >> 16) & 0xFF;
            g = (px >> 8) & 0xFF;
            b = px & 0xFF;
            a = (px >> 24) & 0xFF;
        } else if ((b1 & 0xC0) == 0x40) { // QOI_OP_DIFF
            r += ((b1 >> 4) & 0x03) - 2;
            g += ((b1 >> 2) & 0x03) - 2;
            b += (b1 & 0x03) - 2;
        } else if ((b1 & 0xC0) == 0x80) { // QOI_OP_LUMA
            if (pos >= size) break;
            uint8_t b2 = data[pos++];
            int dg = (b1 & 0x3F) - 32;
            r += dg - 8 + ((b2 >> 4) & 0x0F);
            g += dg;
            b += dg - 8 + (b2 & 0x0F);
        } else if ((b1 & 0xC0) == 0xC0) { // QOI_OP_RUN
            int run = (b1 & 0x3F) + 1;
            uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
            for (int r_i = 0; r_i < run && p < total; r_i++) {
                out_pixels[p++] = col;
            }
            continue;
        }

        uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        int idx_pos = ((int)r * 3 + (int)g * 5 + (int)b * 7 + (int)a * 11) % 64;
        index[idx_pos] = ((uint32_t)a << 24) | col;
        out_pixels[p++] = col;
    }

    out_w = w;
    out_h = h;
    return (p == total);
}

// ----------------------------------------------------------------------------
// RAW RGBA Decoder (as used by wallpapers and logos in MillaOS)
// ----------------------------------------------------------------------------
static inline bool decode_raw(const uint8_t *data, uint32_t size, uint32_t *out_pixels,
                              int &out_w, int &out_h, int max_w = IMG_MAX_W, int max_h = IMG_MAX_H) {
    if (!data || !out_pixels || size < 4) return false;

    // Detect known dimensions
    if (size == 800 * 600 * 4) {
        out_w = 800;
        out_h = 600;
    } else if (size == 100 * 100 * 4) {
        out_w = 100;
        out_h = 100;
    } else if (size == 80 * 80 * 4) {
        out_w = 80;
        out_h = 80;
    } else if (size == 320 * 240 * 4) {
        out_w = 320;
        out_h = 240;
    } else if (size == 640 * 480 * 4) {
        out_w = 640;
        out_h = 480;
    } else {
        // Fallback: assume 800x600 if size is at least 800*600*4
        if (size >= 800 * 600 * 4) {
            out_w = 800;
            out_h = 600;
        } else {
            return false;
        }
    }

    if (out_w > max_w || out_h > max_h) return false;

    const uint32_t *src = (const uint32_t *)data;
    uint32_t total = out_w * out_h;
    for (uint32_t i = 0; i < total; i++) {
        uint32_t col = src[i];
        uint8_t r = col & 0xFF;
        uint8_t g = (col >> 8) & 0xFF;
        uint8_t b = (col >> 16) & 0xFF;
        out_pixels[i] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    return true;
}

// ----------------------------------------------------------------------------
// Universal Image Decoder: Tries BMP, PPM, QOI, RAW
// ----------------------------------------------------------------------------
static inline bool decode_any_image(const uint8_t *data, uint32_t size, const char *filename,
                                    uint32_t *out_pixels, int &out_w, int &out_h, char *out_format) {
    if (!data || size < 4 || !out_pixels) return false;

    // 1. Try BMP
    if (size >= 54 && data[0] == 'B' && data[1] == 'M') {
        if (decode_bmp(data, size, out_pixels, out_w, out_h)) {
            if (out_format) {
                out_format[0] = 'B'; out_format[1] = 'M'; out_format[2] = 'P'; out_format[3] = '\0';
            }
            return true;
        }
    }

    // 2. Try PPM
    if (size >= 10 && data[0] == 'P' && (data[1] == '6' || data[1] == '3')) {
        if (decode_ppm(data, size, out_pixels, out_w, out_h)) {
            if (out_format) {
                out_format[0] = 'P'; out_format[1] = 'P'; out_format[2] = 'M'; out_format[3] = '\0';
            }
            return true;
        }
    }

    // 3. Try QOI
    if (size >= 14 && data[0] == 'q' && data[1] == 'o' && data[2] == 'i' && data[3] == 'f') {
        if (decode_qoi(data, size, out_pixels, out_w, out_h)) {
            if (out_format) {
                out_format[0] = 'Q'; out_format[1] = 'O'; out_format[2] = 'I'; out_format[3] = '\0';
            }
            return true;
        }
    }

    // 4. Try RAW
    if ((filename && (img_ends_with_ignore_case(filename, ".RAW") ||
                      img_ends_with_ignore_case(filename, ".raw"))) ||
        size == 800 * 600 * 4 || size == 100 * 100 * 4 || size == 80 * 80 * 4) {
        if (decode_raw(data, size, out_pixels, out_w, out_h)) {
            if (out_format) {
                out_format[0] = 'R'; out_format[1] = 'A'; out_format[2] = 'W'; out_format[3] = '\0';
            }
            return true;
        }
    }

    return false;
}

#endif // IMAGE_DECODER_H
