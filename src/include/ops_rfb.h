#ifndef __RFB_H__
#define __RFB_H__

struct rfb_protocol_version_t {
    uint8_t rfb[3];
    uint8_t resv1;
    uint8_t major[3];
    uint8_t resv2;
    uint8_t minor[3];
    uint8_t resv3;
} __attribute__ ((packed));

struct rfb_security_types_t {
    uint8_t count;
} __attribute__ ((packed));

struct rfb_keyevent_t {
    uint8_t type;
    uint8_t down_flag;
    uint16_t padding;
    uint32_t key;
} __attribute__ ((packed));
enum {
    OK = 0,
    FAILED,
    FAILED_ATTEMP,
};

struct client_init_t {
    uint8_t shared_flag;
} __attribute__ ((packed));

struct pixel_format_t {
    uint8_t bit_per_pixel;
    uint8_t depth;
    uint8_t big_endian;
    uint8_t true_color;
    uint16_t red_max;
    uint16_t green_max;
    uint16_t blue_max;
    uint8_t red_shift;
    uint8_t green_shift;
    uint8_t blue_shift;
    uint8_t padding[3];
} __attribute__ ((packed));

#define NAME_LEN        30
struct server_init_t {
    uint16_t fb_width;
    uint16_t fb_height;
    struct pixel_format_t fb_pixel_format;
    uint32_t name_len;
    uint8_t name[NAME_LEN];
} __attribute__ ((packed));

#define MSG_FRAMEBUFFER_UPDATE_REQUEST  3
#define MSG_FRAMEBUFFER_UPDATE          0
#define MSG_RING_BELL                   2
#define MSG_SET_COLOR_MAP_ENTRY         1

struct framebuffer_update_request_t {
    uint8_t msg_type;
    uint8_t incremental;
    uint16_t x_pos;
    uint16_t y_pos;
    uint16_t width;
    uint16_t height;
} __attribute__ ((packed));

struct framebuffer_update_header_t {
    uint8_t padding;
    uint16_t no_rectangle;
} __attribute__ ((packed));

struct framebuffer_update_t {
    uint16_t x_pos;
    uint16_t y_pos;
    uint16_t width;
    uint16_t height;
    uint32_t encoding_type;
} __attribute__ ((packed));

struct color_map_header_t {
    uint8_t padding;
    uint16_t first_color;
    uint16_t no_colors;
} __attribute__ ((packed));

struct color_map_t {
    uint16_t red;
    uint16_t green;
    uint16_t blue;
} __attribute__ ((packed));

struct framebuffer_dev_t {
    uint16_t x_pos;
    uint16_t y_pos;
    uint16_t width;
    uint16_t height;
    uint8_t depth;
    uint8_t bpp;
    uint32_t *fb_ptr;
} __attribute__ ((packed));

#define ENCODING_RAW    0

#define RFB_DRM_EMPTY	0x00
#define RFB_CONN_START	0x01
#define RFB_CONN_STOP	0x02
#define RFB_DRM_TEST	0xFF

struct ops_rfb_t {
    void (*init) (void);
    void (*show_all) (void);
    int (*create_socket)(uint8_t * hostname, int port);
    void (*close_socket)(int fd);
    int (*handshake)(int socket_fd, struct server_init_t *si);
    int (*processor)(int socket_fd, struct server_init_t *si, struct framebuffer_dev_t *fb_dev);
    int (*request_entire_screen)(int socket_fd, struct server_init_t *si);
    int (*request_changed_screen)(int socket_fd, struct server_init_t *si);
    int (*request_keyevent)(int socket, uint8_t down_flag, uint32_t key);
};

struct ops_rfb_t *get_rfb_instance();
void del_rfb_instance();
#endif
