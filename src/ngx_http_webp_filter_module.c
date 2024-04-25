#include "ngx_http_webp_filter_module.h"

// 指令定义
static ngx_command_t ngx_http_webp_filter_commands[] = {
  {
    ngx_string("get_frame"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_http_webp_filter_frame_parse,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_webp_filter_conf_t, frame),
    NULL,
  },
  {
    ngx_string("webp_enable"),
    NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_webp_filter_conf_t, enable),
    NULL,
  },
  ngx_null_command,
};

// 定义 hooks
static ngx_http_module_t ngx_http_webp_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_webp_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_webp_filter_create_conf,      /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_webp_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_webp_filter_module_ctx,      /* module context */
    ngx_http_webp_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

// 配置文件中的参数解析
static char* ngx_http_webp_filter_frame_parse(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
  ngx_http_webp_filter_conf_t* wfcf = conf;
  ngx_http_complex_value_t cv;
  ngx_http_compile_complex_value_t ccv;

  ngx_str_t* value = cf->args->elts;
  ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

  // 配置指针
  ccv.cf = cf;
  // 待解析的值(输入)
  ccv.value = &value[1];
  // 编译后的值(输出)
  ccv.complex_value = &cv;

  if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  if (cv.lengths == NULL) {
    // 非变量值
    wfcf->frame = ngx_http_web_filter_value(&value[1]);
  } else {
    // 变量值
    wfcf->frame_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (wfcf->frame_cv == NULL) {
      return NGX_CONF_ERROR;
    }
    *wfcf->frame_cv = cv;
  }
  return NGX_CONF_OK;
}

// 初始化配置结构
static void* ngx_http_webp_filter_create_conf(ngx_conf_t* cf) {
  ngx_http_webp_filter_conf_t* conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_webp_filter_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }
  conf->frame = NGX_CONF_UNSET_UINT;
  conf->enable = NGX_CONF_UNSET;
  return conf;
}

// 添加过滤器
static ngx_int_t ngx_http_webp_filter_init(ngx_conf_t* cf) {
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_webp_header_filter;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_webp_body_filter;

  return NGX_OK;
}

// header 过滤器
static ngx_int_t ngx_http_webp_header_filter(ngx_http_request_t* r) {
  ngx_http_webp_filter_ctx_t* ctx;
  if (r->headers_out.status != NGX_HTTP_OK) {
    return ngx_http_next_header_filter(r);
  }

  if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
    return ngx_http_next_header_filter(r);
  }

  ngx_http_webp_filter_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_webp_filter_module);
  if (conf->enable == NGX_CONF_UNSET || conf->enable == 0) {
    return ngx_http_next_header_filter(r);
  }

  // 判断上下文是否已存在，防止重复处理
  ctx = ngx_http_get_module_ctx(r, ngx_http_webp_filter_module);
  if (ctx) {
    return ngx_http_next_header_filter(r);
  }

  // 创建上下文
  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_webp_filter_ctx_t));
  if (ctx == NULL) {
    return NGX_ERROR;
  }
  ctx->phase = READ_IMAGE;
  ctx->length = (size_t)r->headers_out.content_length_n + 1;
  ngx_http_set_ctx(r, ctx, ngx_http_webp_filter_module);

  if (r->headers_out.refresh) {
    r->headers_out.refresh->hash = 0;
  }

  // 缺少这一行会导致 body 中无法取到数据
  r->main_filter_need_in_memory = 1;
  r->allow_ranges = 0;

  return NGX_OK;
}

// body 过滤器
static ngx_int_t ngx_http_webp_body_filter(ngx_http_request_t* r, ngx_chain_t* in) {
  ngx_int_t rc;
  ngx_uint_t frame;

  if (in == NULL) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_http_webp_filter_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_webp_filter_module);
  if (conf->enable == NGX_CONF_UNSET || conf->enable == 0) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_http_webp_filter_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_webp_filter_module);
  if (ctx == NULL) {
    return ngx_http_next_body_filter(r, in);
  }
  switch (ctx->phase) {
  case READ_IMAGE:
    rc = ngx_http_image_read(r, in);
    if (rc == NGX_AGAIN) {
      return NGX_OK;
    }
    if (rc == NGX_ERROR) {
      return ngx_http_filter_finalize_request(r, &ngx_http_webp_filter_module, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
    }
    /* fall through */
  case GET_FRAME:
    r->connection->buffered &= ~0x08;
    WebPMux* mux = NULL;
    createMux(r, &mux, ctx->image, ctx->length);

    WebPData* frame_webp_data = ngx_pcalloc(r->pool, sizeof(WebPData));
    frame = ngx_http_webp_filter_get_value(r, conf->frame_cv, conf->frame);
    WebPMuxError err = getFrame(mux, frame, frame_webp_data);
    if (err == WEBP_MUX_NOT_FOUND) {
      err = getFrame(mux, 1, frame_webp_data);
    }
    WebPMuxDelete(mux);
    if (err != WEBP_MUX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get frame error [%d]", err);
      WebPDataClear(frame_webp_data);
      return NGX_ERROR;
    }

    ngx_pfree(r->pool, ctx->image);
    // 添加内存池释放时的回调函数，以便释放自己申请的资源
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
      WebPDataClear(frame_webp_data);
      return NGX_ERROR;
    }

    ngx_buf_t* b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
      WebPDataClear(frame_webp_data);
      return NGX_ERROR;
    }

    cln->handler = ngx_http_frame_cleanup;
    cln->data = frame_webp_data;

    b->pos = (uint8_t*)frame_webp_data->bytes;
    b->last = (uint8_t*)frame_webp_data->bytes + frame_webp_data->size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.content_length_n = frame_webp_data->size;

    if (r->headers_out.content_length) {
      r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
    ngx_http_weak_etag(r);

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    ctx->phase = GET_FRAME_DONE;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
      return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, &out);

    if (ctx->phase == GET_FRAME_DONE) {
      return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;

  case GET_FRAME_DONE:
    return ngx_http_next_body_filter(r, in);
  default:
    return ngx_http_next_body_filter(r, NULL);
    break;
  }
  return (rc == NGX_OK) ? NGX_ERROR : rc;
}

static ngx_uint_t ngx_http_webp_filter_get_value(ngx_http_request_t* r, ngx_http_complex_value_t* cv, ngx_uint_t v) {
  ngx_str_t val;
  if (cv == NULL) {
    return v;
  }
  if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
    return 0;
  }
  return ngx_http_web_filter_value(&val);
}

static ngx_uint_t ngx_http_web_filter_value(ngx_str_t* value) {
  ngx_int_t n = ngx_atoi(value->data, value->len);
  if (n == NGX_ERROR) {
    n = 1;
  }
  return n;
}

static ngx_int_t ngx_http_image_read(ngx_http_request_t* r, ngx_chain_t* in) {
  u_char* p;
  size_t size, rest;
  ngx_buf_t* b;
  ngx_chain_t* cl;
  ngx_http_webp_filter_ctx_t* ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_webp_filter_module);

  if (ctx->image == NULL) {
    ctx->image = ngx_palloc(r->pool, ctx->length);
    if (ctx->image == NULL) {
      return NGX_ERROR;
    }

    ctx->last = ctx->image;
  }

  p = ctx->last;
  for (cl = in; cl; cl = cl->next) {
    b = cl->buf;
    size = b->last - b->pos;

    rest = ctx->image + (ctx->length - 1) - p;

    if (size > rest) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "image filter: too big response");
      return NGX_ERROR;
    }

    p = ngx_cpymem(p, b->pos, size);
    b->pos += size;

    if (b->last_buf) {
      ctx->last = p;
      return NGX_OK;
    }
  }

  ctx->last = p;
  r->connection->buffered |= 0x08;

  // 说明还没有读完请求，将会再次将读事件加入定时器，读事件加入到 epoll 监控事件中，等待下一次被读事件唤醒，或者超时。
  return NGX_AGAIN;
}

void createMux(ngx_http_request_t* r, WebPMux** mux, u_char* image, size_t size) {
  WebPData bitstream;

  image[size - 1] = '\0';
  bitstream.bytes = image;
  bitstream.size = size - 1;

  *mux = WebPMuxCreate(&bitstream, 0);
}

WebPMuxError getFrame(WebPMux* mux, int index, WebPData* frame_webp_data) {
  WebPMuxError err = WEBP_MUX_OK;
  WebPMux* mux_single = NULL;
  WebPChunkId id = WEBP_CHUNK_ANMF;
  WebPMuxFrameInfo info;
  WebPDataInit(&info.bitstream);

  if (index < 0) {
    index = 0;
  }
  err = WebPMuxGetFrame(mux, (uint32_t)index, &info);
  if (err == WEBP_MUX_OK && info.id != id) {
    err = WEBP_MUX_NOT_FOUND;
  }
  if (err != WEBP_MUX_OK) {
    goto ErrGet;
  }
  mux_single = WebPMuxNew();
  if (mux_single == NULL) {
    err = WEBP_MUX_MEMORY_ERROR;
    goto ErrGet;
  }
  err = WebPMuxSetImage(mux_single, &info.bitstream, 0);
  if (err != WEBP_MUX_OK) {
    goto ErrGet;
  }

  err = WebPMuxAssemble(mux_single, frame_webp_data);
  if (err != WEBP_MUX_OK) {
    goto ErrGet;
  }

  goto ErrGet;

ErrGet:
  WebPDataClear(&info.bitstream);
  WebPMuxDelete(mux_single);
  return err;
}

void ngx_http_frame_cleanup(void* data) {
  WebPDataClear(data);
}
