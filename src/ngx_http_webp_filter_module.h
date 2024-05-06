#ifndef __NGX_HTTP_WEBP_FRAME_MODULE__
#define __NGX_HTTP_WEBP_FRAME_MODULE__

// -------------nginx filter module----------------

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <webp/decode.h>
#include <webp/encode.h>
#include <webp/mux.h>
#include <gif_lib.h>
#include <assert.h>

#define READ_IMAGE 1
#define GIF_TO_WEBP 2
#define GET_FRAME 3
#define DONE 4

typedef struct {
  ngx_uint_t frame;
  ngx_flag_t enable;
  ngx_flag_t gif_to_webp;

  ngx_http_complex_value_t* frame_cv;
} ngx_http_webp_filter_conf_t;

typedef struct {
  u_char* image;
  u_char* last;
  size_t length;
  ngx_uint_t frame;
  ngx_uint_t phase;
} ngx_http_webp_filter_ctx_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_webp_filter_init(ngx_conf_t* cf);
static ngx_int_t ngx_http_webp_header_filter(ngx_http_request_t* r);
static ngx_int_t ngx_http_webp_body_filter(ngx_http_request_t* r, ngx_chain_t* in);

// 初始化指定配置结构
static void* ngx_http_webp_filter_create_conf(ngx_conf_t* cf);

// 参数转换函数
static char* ngx_http_webp_filter_frame_parse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static ngx_int_t ngx_http_image_read(ngx_http_request_t* r, ngx_chain_t* in);
static ngx_uint_t ngx_http_webp_filter_get_value(ngx_http_request_t* r, ngx_http_complex_value_t* cv, ngx_uint_t v);
static ngx_uint_t ngx_http_web_filter_value(ngx_str_t* value);

// ------------------gif-to-webp---------------------

#define GIF_INDEX_INVALID (-1)

#define GIF_TRANSPARENT_COLOR 0x00000000u
#define GIF_WHITE_COLOR       0xffffffffu

#define GIF_DISPOSE_SHIFT     2
#define GIF_TRANSPARENT_MASK  0x01
#define GIF_DISPOSE_MASK      0x07

typedef struct {
  int x_offset, y_offset, width, height;
} GIFFrameRect;

typedef enum GIFDisposeMethod {
  GIF_DISPOSE_NONE,
  GIF_DISPOSE_BACKGROUND,
  GIF_DISPOSE_RESTORE_PREVIOUS
} GIFDisposeMethod;

enum {
  METADATA_ICC = (1 << 0),
  METADATA_XMP = (1 << 1),
  METADATA_ALL = METADATA_ICC | METADATA_XMP
};

typedef struct {
  void* buf;
  unsigned int size;
  unsigned int offset;
} MemoryGif;

static int transparent_index = GIF_INDEX_INVALID;

static const char* const kErrorMessages[-WEBP_MUX_NOT_ENOUGH_DATA + 1] = {
  "WEBP_MUX_NOT_FOUND", "WEBP_MUX_INVALID_ARGUMENT", "WEBP_MUX_BAD_DATA",
  "WEBP_MUX_MEMORY_ERROR", "WEBP_MUX_NOT_ENOUGH_DATA"
};

int ReadGifFromMemory(GifFileType* gif, GifByteType* buf, int len);
int GifToWebp(ngx_http_request_t* r, ngx_http_webp_filter_ctx_t* ctx);

extern void WebPCopyPlane(const uint8_t* src, int src_stride, uint8_t* dst, int dst_stride, int width, int height);
extern void WebPCopyPixels(const WebPPicture* const src, WebPPicture* const dst);
const char* ErrorString(WebPMuxError err);
void ClearRectangle(WebPPicture* const picture, int left, int top, int width, int height);
void GIFClearPic(WebPPicture* const pic, const GIFFrameRect* const rect);
int Remap(const GifFileType* const gif, const uint8_t* const src, int len, int transparent_index, uint32_t* dst);
int GIFReadFrame(GifFileType* const gif, int transparent_index, GIFFrameRect* const gif_rect, WebPPicture* const picture);
void GIFGetBackgroundColor(const ColorMapObject* const color_map, int bgcolor_index, int transparent_index, uint32_t* const bgcolor);
void GIFDisposeFrame(GIFDisposeMethod dispose, const GIFFrameRect* const rect, const WebPPicture* const prev_canvas, WebPPicture* const curr_canvas);
int GIFReadGraphicsExtension(const GifByteType* const buf, int* const duration, GIFDisposeMethod* const dispose, int* const transparent_index);
int GIFReadLoopCount(GifFileType* const gif, GifByteType** const buf, int* const loop_count);
int GIFReadMetadata(GifFileType* const gif, GifByteType** const buf, WebPData* const metadata);
void GIFCopyPixels(const WebPPicture* const src, WebPPicture* const dst);
void GIFBlendFrames(const WebPPicture* const src, const GIFFrameRect* const rect, WebPPicture* const dst);

// ------------------webp-get-fram--------------------

void createMux(ngx_http_request_t* r, WebPMux** mux, u_char* image, size_t size);
WebPMuxError getFrame(WebPMux* mux, int index, WebPData* frame_webp_data);
void ngx_http_frame_cleanup(void* data);


#endif // __NGX_HTTP_WEBP_FRAME_MODULE__
