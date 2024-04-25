#ifndef __NGX_HTTP_WEBP_FRAME_MODULE__
#define __NGX_HTTP_WEBP_FRAME_MODULE__

#include <errno.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <webp/decode.h>
#include <webp/mux.h>

#define READ_IMAGE 1
#define GET_FRAME 2
#define GET_FRAME_DONE 3

typedef struct {
  ngx_uint_t frame;
  ngx_flag_t enable;

  ngx_http_complex_value_t* frame_cv;
} ngx_http_webp_filter_conf_t;

typedef struct {
  u_char* image;
  u_char* last;
  size_t length;
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

void createMux(ngx_http_request_t* r, WebPMux** mux, u_char* image, size_t size);
WebPMuxError getFrame(WebPMux* mux, int index, WebPData* frame_webp_data);
void ngx_http_frame_cleanup(void* data);

static ngx_uint_t ngx_http_webp_filter_get_value(ngx_http_request_t *r, ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_web_filter_value(ngx_str_t *value);

#endif // __NGX_HTTP_WEBP_FRAME_MODULE__
