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
  {
    ngx_string("gif_to_webp"),
    NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_webp_filter_conf_t, gif_to_webp),
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

static ngx_str_t gif_content_type = ngx_string("image/gif");

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
  conf->gif_to_webp = NGX_CONF_UNSET;
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
  ctx->phase = DONE;
  ngx_http_set_ctx(r, ctx, ngx_http_webp_filter_module);

  if (conf->enable == NGX_CONF_UNSET || conf->enable == 0) {
    return ngx_http_next_header_filter(r);
  }
  ctx->frame = ngx_http_webp_filter_get_value(r, conf->frame_cv, conf->frame);

  if (ctx->frame != NGX_CONF_UNSET_UINT || (conf->gif_to_webp == 1 && ngx_strncasecmp(r->headers_out.content_type.data, gif_content_type.data, gif_content_type.len) == 0)) {
    ctx->phase = READ_IMAGE;
    ctx->length = (size_t)r->headers_out.content_length_n + 1;
    if (r->headers_out.refresh) {
      r->headers_out.refresh->hash = 0;
    }
    // 缺少这一行会导致 body 中无法取到数据
    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;
    return NGX_OK;
  } else {
    return ngx_http_next_header_filter(r);
  }
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
  case GIF_TO_WEBP:
    if (conf->gif_to_webp == 1 && ngx_strncasecmp(r->headers_out.content_type.data, gif_content_type.data, gif_content_type.len) == 0) {
      GifToWebp(r, ctx);
      ngx_str_set(&r->headers_out.content_type, "image/webp");
      r->headers_out.content_type_lowcase = NULL;
    }
    if (ctx->frame == NGX_CONF_UNSET_UINT) {
      // 添加内存池释放时的回调函数，以便释放自己申请的资源
      ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, 0);
      if (cln == NULL) {
        return NGX_ERROR;
      }
      ngx_buf_t* b = ngx_calloc_buf(r->pool);
      if (b == NULL) {
        return NGX_ERROR;
      }

      cln->data = ctx->image;

      b->pos = (uint8_t*)ctx->image;
      b->last = (uint8_t*)ctx->image + ctx->length;
      b->memory = 1;
      b->last_buf = 1;

      r->headers_out.content_length_n = ctx->length;

      if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
      }

      r->headers_out.content_length = NULL;
      ngx_http_weak_etag(r);

      ngx_chain_t out;
      out.buf = b;
      out.next = NULL;

      ctx->phase = DONE;

      rc = ngx_http_next_header_filter(r);

      if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
      }

      rc = ngx_http_next_body_filter(r, &out);

      return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
    /* fall through */
  case GET_FRAME:
    if (ctx->frame != NGX_CONF_UNSET_UINT) {
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

      ctx->phase = DONE;

      rc = ngx_http_next_header_filter(r);

      if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
      }

      rc = ngx_http_next_body_filter(r, &out);

      return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
    /* fall through */
  case DONE:
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

void ngx_http_frame_cleanup(void* data) {
  WebPDataClear(data);
}

// --------------------gif-to-webp------------------------
int GifToWebp(ngx_http_request_t* r, ngx_http_webp_filter_ctx_t* ctx) {
  WebPMux* mux = NULL;
  WebPData webp_data;
  WebPPicture frame;
  WebPPicture curr_canvas;
  WebPPicture prev_canvas;

  WebPAnimEncoder* enc = NULL;
  WebPAnimEncoderOptions enc_options;
  WebPConfig config;
  WebPData xmp_data;
  WebPData icc_data;
  WebPMuxError err = WEBP_MUX_OK;

  int frame_duration = 0;
  int frame_timestamp = 0;
  int loop_count = 0;
  int stored_loop_count = 0;
  int loop_compatibility = 0;
  int keep_metadata = METADATA_XMP;

  int stored_icc = 0;
  int stored_xmp = 0;

  int ok = 0;
  int done = 0;
  int frame_number = 0;

  GIFDisposeMethod orig_dispose = GIF_DISPOSE_NONE;

  if (
    !WebPConfigInit(&config)
    || !WebPAnimEncoderOptionsInit(&enc_options)
    || !WebPPictureInit(&frame)
    || !WebPPictureInit(&curr_canvas)
    || !WebPPictureInit(&prev_canvas)
    ) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error! Version mismatch!");
    return NGX_ERROR;
  }
  config.lossless = 1;

  WebPDataInit(&webp_data);
  WebPDataInit(&icc_data);
  WebPDataInit(&xmp_data);

  MemoryGif* memoryGif = ngx_pcalloc(r->pool, sizeof(MemoryGif));
  memoryGif->buf = ctx->image;
  memoryGif->size = ctx->length;
  memoryGif->offset = 0;

  int gif_error = GIF_ERROR;
  GifFileType* gif = DGifOpen(memoryGif, ReadGifFromMemory, &gif_error);

  do {
    GifRecordType type;
    if (DGifGetRecordType(gif, &type) == GIF_ERROR) {
      goto End;
    }

    switch (type) {
    case IMAGE_DESC_RECORD_TYPE: {
      GifImageDesc* const image_desc = &gif->Image;

      if (!DGifGetImageDesc(gif)) goto End;

      if (frame_number == 0) {
        if (gif->SWidth == 0 || gif->SHeight == 0) {
          image_desc->Left = 0;
          image_desc->Top = 0;
          gif->SWidth = image_desc->Width;
          gif->SHeight = image_desc->Height;
          if (gif->SWidth <= 0 || gif->SHeight <= 0) {
            goto End;
          }
        }
        frame.width = gif->SWidth;
        frame.height = gif->SHeight;
        frame.use_argb = 1;
        if (!WebPPictureAlloc(&frame)) {
          goto End;
        }
        GIFClearPic(&frame, NULL);
        if (!(WebPPictureCopy(&frame, &curr_canvas) && WebPPictureCopy(&frame, &prev_canvas))) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error allocating canvas.");
          goto End;
        }
        GIFGetBackgroundColor(gif->SColorMap, gif->SBackGroundColor, transparent_index, &enc_options.anim_params.bgcolor);
        enc = WebPAnimEncoderNew(curr_canvas.width, curr_canvas.height, &enc_options);
        if (enc == NULL) {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error! Could not create encoder object. Possibly due to a memory error.");
          goto End;
        }
      }

      if (image_desc->Width == 0 || image_desc->Height == 0) {
        image_desc->Width = gif->SWidth;
        image_desc->Height = gif->SHeight;
      }

      GIFFrameRect gif_rect;
      if (!GIFReadFrame(gif, transparent_index, &gif_rect, &frame)) {
        goto End;
      }
      GIFBlendFrames(&frame, &gif_rect, &curr_canvas);

      if (!WebPAnimEncoderAdd(enc, &curr_canvas, frame_timestamp, &config)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error while adding frame #%d: %s", frame_number, WebPAnimEncoderGetError(enc));
        goto End;
      } else {
        ++frame_number;
      }

      GIFDisposeFrame(orig_dispose, &gif_rect, &prev_canvas, &curr_canvas);
      GIFCopyPixels(&curr_canvas, &prev_canvas);

      if (frame_duration <= 10) {
        frame_duration = 100;
      }

      frame_timestamp += frame_duration;

      orig_dispose = GIF_DISPOSE_NONE;
      frame_duration = 0;
      transparent_index = GIF_INDEX_INVALID;
      break;
    }
    case EXTENSION_RECORD_TYPE: {
      int extension;
      GifByteType* data = NULL;
      if (DGifGetExtension(gif, &extension, &data) == GIF_ERROR) {
        goto End;
      }
      if (data == NULL) {
        continue;
      };

      switch (extension) {
      case COMMENT_EXT_FUNC_CODE: {
        break;
      }
      case GRAPHICS_EXT_FUNC_CODE: {
        if (!GIFReadGraphicsExtension(data, &frame_duration, &orig_dispose, &transparent_index)) {
          goto End;
        }
        break;
      }
      case PLAINTEXT_EXT_FUNC_CODE: {
        break;
      }
      case APPLICATION_EXT_FUNC_CODE: {
        if (data[0] != 11) {
          break;
        }
        if (!memcmp(data + 1, "NETSCAPE2.0", 11) || !memcmp(data + 1, "ANIMEXTS1.0", 11)) {
          if (!GIFReadLoopCount(gif, &data, &loop_count)) {
            goto End;
          }
          stored_loop_count = loop_compatibility ? (loop_count != 0) : 1;
        } else {
          const int is_xmp = (keep_metadata & METADATA_XMP) && !stored_xmp && !memcmp(data + 1, "XMP DataXMP", 11);
          const int is_icc = (keep_metadata & METADATA_ICC) && !stored_icc && !memcmp(data + 1, "ICCRGBG1012", 11);
          if (is_xmp || is_icc) {
            if (!GIFReadMetadata(gif, &data, is_xmp ? &xmp_data : &icc_data)) {
              goto End;
            }
            if (is_icc) {
              stored_icc = 1;
            } else if (is_xmp) {
              stored_xmp = 1;
            }
          }
        }
        break;
      }
      default: {
        break;
      }
      }
      while (data != NULL) {
        if (DGifGetExtensionNext(gif, &data) == GIF_ERROR) goto End;
      }
      break;
    }
    case TERMINATE_RECORD_TYPE: {
      done = 1;
      break;
    }
    default: {
      break;
    }
    }
  } while (!done);

  if (!WebPAnimEncoderAdd(enc, NULL, frame_timestamp, NULL)) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error flushing WebP muxer: %s", WebPAnimEncoderGetError(enc));
  }

  if (!WebPAnimEncoderAssemble(enc, &webp_data)) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error WebPAnimEncoderAssemble: %s", WebPAnimEncoderGetError(enc));
    goto End;
  }
  if (frame_number == 1) {
    loop_count = 0;
  } else if (!loop_compatibility) {
    if (!stored_loop_count) {
      if (frame_number > 1) {
        stored_loop_count = 1;
        loop_count = 1;
      }
    } else if (loop_count > 0 && loop_count < 65535) {
      loop_count += 1;
    }
  }
  if (loop_count == 0) {
    stored_loop_count = 0;
  }

  if (stored_loop_count || stored_icc || stored_xmp) {
    mux = WebPMuxCreate(&webp_data, 1);
    if (mux == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR: Could not re-mux to add loop count/metadata.");
      goto End;
    }
    WebPDataClear(&webp_data);

    if (stored_loop_count) {
      WebPMuxAnimParams new_params;
      err = WebPMuxGetAnimationParams(mux, &new_params);
      if (err != WEBP_MUX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR (%s): Could not fetch loop count", ErrorString(err));
        goto End;
      }
      new_params.loop_count = loop_count;
      err = WebPMuxSetAnimationParams(mux, &new_params);
      if (err != WEBP_MUX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR (%s): Could not update loop count", ErrorString(err));
        goto End;
      }
    }

    if (stored_icc) {
      err = WebPMuxSetChunk(mux, "ICCP", &icc_data, 1);
      if (err != WEBP_MUX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR (%s): Could not set ICC chunk.", ErrorString(err));
        goto End;
      }
    }

    if (stored_xmp) {
      err = WebPMuxSetChunk(mux, "XMP ", &xmp_data, 1);
      if (err != WEBP_MUX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR (%s): Could not set XMP chunk.", ErrorString(err));
        goto End;
      }
    }

    err = WebPMuxAssemble(mux, &webp_data);
    if (err != WEBP_MUX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ERROR (%s): Could not assemble when re-muxing to add loop count/metadata.", ErrorString(err));
      goto End;
    }
  }
  ok = 1;
  gif_error = GIF_OK;
  ngx_pfree(r->pool, ctx->image);
  ctx->image = ngx_palloc(r->pool, webp_data.size + 1);
  if (ctx->image == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(ctx->image, webp_data.bytes, webp_data.size);
  ctx->length = webp_data.size + 1;
End:
  WebPDataClear(&icc_data);
  WebPDataClear(&xmp_data);
  WebPMuxDelete(mux);
  WebPDataClear(&webp_data);
  WebPPictureFree(&frame);
  WebPPictureFree(&curr_canvas);
  WebPPictureFree(&prev_canvas);
  WebPAnimEncoderDelete(enc);

  if (gif_error != GIF_OK) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gif_error");
  }
  if (gif != NULL) {
    DGifCloseFile(gif, &gif_error);
  }
  return !ok;
}

int ReadGifFromMemory(GifFileType* gif, GifByteType* buf, int len) {
  if (len == 0) {
    return 0;
  }
  MemoryGif* memoryGif = (MemoryGif*)gif->UserData;
  int canReadLen = memoryGif->size - memoryGif->offset;
  if (canReadLen < 1) {
    return 0;
  }
  len = canReadLen > len ? len : canReadLen;
  memcpy(buf, (char*)memoryGif->buf + memoryGif->offset, len);
  memoryGif->offset += len;
  return len;
}

const char* ErrorString(WebPMuxError err) {
  assert(err <= WEBP_MUX_NOT_FOUND && err >= WEBP_MUX_NOT_ENOUGH_DATA);
  return kErrorMessages[-err];
}

void ClearRectangle(WebPPicture* const picture, int left, int top, int width, int height) {
  const size_t stride = picture->argb_stride;
  uint32_t* dst = picture->argb + top * stride + left;
  for (int j = 0; j < height; ++j, dst += stride) {
    for (int i = 0; i < width; ++i) dst[i] = GIF_TRANSPARENT_COLOR;
  }
}

void GIFClearPic(WebPPicture* const pic, const GIFFrameRect* const rect) {
  if (rect != NULL) {
    ClearRectangle(pic, rect->x_offset, rect->y_offset, rect->width, rect->height);
  } else {
    ClearRectangle(pic, 0, 0, pic->width, pic->height);
  }
}

int Remap(const GifFileType* const gif, const uint8_t* const src, int len, int transparent_index, uint32_t* dst) {
  const ColorMapObject* const cmap = gif->Image.ColorMap ? gif->Image.ColorMap : gif->SColorMap;
  if (cmap == NULL) {
    return 1;
  }
  if (cmap->Colors == NULL || cmap->ColorCount <= 0) {
    return 0;
  }
  const GifColorType* colors = cmap->Colors;

  for (int i = 0; i < len; ++i) {
    if (src[i] == transparent_index) {
      dst[i] = GIF_TRANSPARENT_COLOR;
    } else if (src[i] < cmap->ColorCount) {
      const GifColorType c = colors[src[i]];
      dst[i] = c.Blue | (c.Green << 8) | (c.Red << 16) | (0xffu << 24);
    } else {
      return 0;
    }
  }
  return 1;
}

int GIFReadFrame(GifFileType* const gif, int transparent_index, GIFFrameRect* const gif_rect, WebPPicture* const picture) {
  const GifImageDesc* const image_desc = &gif->Image;
  const GIFFrameRect rect = {
      image_desc->Left,
      image_desc->Top,
      image_desc->Width,
      image_desc->Height,
  };
  const uint64_t memory_needed = 4 * rect.width * (uint64_t)rect.height;
  int ok = 0;
  *gif_rect = rect;

  if (memory_needed != (size_t)memory_needed || memory_needed > (4ULL << 32)) {
    fprintf(stderr, "Image is too large (%d x %d).", rect.width, rect.height);
    return 0;
  }

  WebPPicture sub_image;
  if (!WebPPictureView(picture, rect.x_offset, rect.y_offset,
    rect.width, rect.height, &sub_image)) {
    fprintf(stderr, "Sub-image %dx%d at position %d,%d is invalid!\n", rect.width, rect.height, rect.x_offset, rect.y_offset);
    return 0;
  }
  uint32_t* dst = sub_image.argb;

  uint8_t* tmp = (uint8_t*)WebPMalloc(rect.width * sizeof(*tmp));
  if (tmp == NULL) goto End;

  if (image_desc->Interlace) {
    const int interlace_offsets[] = { 0, 4, 2, 1 };
    const int interlace_jumps[] = { 8, 8, 4, 2 };
    int pass;
    for (pass = 0; pass < 4; ++pass) {
      const size_t stride = (size_t)sub_image.argb_stride;
      int y = interlace_offsets[pass];
      uint32_t* row = dst + y * stride;
      const size_t jump = interlace_jumps[pass] * stride;
      for (; y < rect.height; y += interlace_jumps[pass], row += jump) {
        if (DGifGetLine(gif, tmp, rect.width) == GIF_ERROR) goto End;
        if (!Remap(gif, tmp, rect.width, transparent_index, row)) goto End;
      }
    }
  } else {
    int y;
    uint32_t* ptr = dst;
    for (y = 0; y < rect.height; ++y, ptr += sub_image.argb_stride) {
      if (DGifGetLine(gif, tmp, rect.width) == GIF_ERROR) goto End;
      if (!Remap(gif, tmp, rect.width, transparent_index, ptr)) goto End;
    }
  }
  ok = 1;

End:
  if (!ok) picture->error_code = sub_image.error_code;
  WebPPictureFree(&sub_image);
  WebPFree(tmp);
  return ok;
}

void GIFGetBackgroundColor(const ColorMapObject* const color_map, int bgcolor_index, int transparent_index, uint32_t* const bgcolor) {
  if (transparent_index != GIF_INDEX_INVALID && bgcolor_index == transparent_index) {
    *bgcolor = GIF_TRANSPARENT_COLOR;  // Special case.
  } else if (color_map == NULL || color_map->Colors == NULL || bgcolor_index >= color_map->ColorCount) {
    *bgcolor = GIF_WHITE_COLOR;
  } else {
    const GifColorType color = color_map->Colors[bgcolor_index];
    *bgcolor = (0xffu << 24)
      | (color.Red << 16)
      | (color.Green << 8)
      | (color.Blue << 0);
  }
}

void GIFDisposeFrame(GIFDisposeMethod dispose, const GIFFrameRect* const rect, const WebPPicture* const prev_canvas, WebPPicture* const curr_canvas) {
  assert(rect != NULL);
  if (dispose == GIF_DISPOSE_BACKGROUND) {
    GIFClearPic(curr_canvas, rect);
  } else if (dispose == GIF_DISPOSE_RESTORE_PREVIOUS) {
    const size_t src_stride = prev_canvas->argb_stride;
    const uint32_t* const src = prev_canvas->argb + rect->x_offset + rect->y_offset * src_stride;
    const size_t dst_stride = curr_canvas->argb_stride;
    uint32_t* const dst = curr_canvas->argb + rect->x_offset + rect->y_offset * dst_stride;
    assert(prev_canvas != NULL);
    WebPCopyPlane(
      (uint8_t*)src,
      (int)(4 * src_stride),
      (uint8_t*)dst,
      (int)(4 * dst_stride),
      4 * rect->width,
      rect->height
    );
  }
}

int GIFReadGraphicsExtension(const GifByteType* const buf, int* const duration, GIFDisposeMethod* const dispose, int* const transparent_index) {
  const int flags = buf[1];
  const int dispose_raw = (flags >> GIF_DISPOSE_SHIFT) & GIF_DISPOSE_MASK;
  const int duration_raw = buf[2] | (buf[3] << 8);
  if (buf[0] != 4) {
    return 0;
  }
  *duration = duration_raw * 10;
  switch (dispose_raw) {
  case 3:
    *dispose = GIF_DISPOSE_RESTORE_PREVIOUS;
    break;
  case 2:
    *dispose = GIF_DISPOSE_BACKGROUND;
    break;
  case 1:
  case 0:
  default:
    *dispose = GIF_DISPOSE_NONE;
    break;
  }
  *transparent_index = (flags & GIF_TRANSPARENT_MASK) ? buf[4] : GIF_INDEX_INVALID;
  return 1;
}

int GIFReadLoopCount(GifFileType* const gif, GifByteType** const buf, int* const loop_count) {
  assert(!memcmp(*buf + 1, "NETSCAPE2.0", 11) || !memcmp(*buf + 1, "ANIMEXTS1.0", 11));
  if (DGifGetExtensionNext(gif, buf) == GIF_ERROR) {
    return 0;
  }
  if (*buf == NULL) {
    return 0;
  }
  if ((*buf)[0] < 3 || (*buf)[1] != 1) {
    return 0;
  }
  *loop_count = (*buf)[2] | ((*buf)[3] << 8);
  return 1;
}

int GIFReadMetadata(GifFileType* const gif, GifByteType** const buf, WebPData* const metadata) {
  const int is_xmp = !memcmp(*buf + 1, "XMP DataXMP", 11);
  const int is_icc = !memcmp(*buf + 1, "ICCRGBG1012", 11);
  assert(is_xmp || is_icc);
  (void)is_icc;
  while (1) {
    WebPData subblock;
    if (DGifGetExtensionNext(gif, buf) == GIF_ERROR) {
      return 0;
    }
    if (*buf == NULL) break;
    subblock.size = is_xmp ? (*buf)[0] + 1 : (*buf)[0];
    assert(subblock.size > 0);
    subblock.bytes = is_xmp ? *buf : *buf + 1;
    const uint8_t* tmp = (uint8_t*)realloc((void*)metadata->bytes, metadata->size + subblock.size);
    if (tmp == NULL) {
      return 0;
    }
    memcpy((void*)(tmp + metadata->size), subblock.bytes, subblock.size);
    metadata->bytes = tmp;
    metadata->size += subblock.size;
  }
  if (is_xmp) {
    const size_t xmp_pading_size = 257;
    if (metadata->size > xmp_pading_size) {
      metadata->size -= xmp_pading_size;
    }
  }
  return 1;
}

void GIFCopyPixels(const WebPPicture* const src, WebPPicture* const dst) {
  WebPCopyPixels(src, dst);
}

void GIFBlendFrames(const WebPPicture* const src, const GIFFrameRect* const rect, WebPPicture* const dst) {
  const size_t src_stride = src->argb_stride;
  const size_t dst_stride = dst->argb_stride;
  assert(src->width == dst->width && src->height == dst->height);
  for (int j = rect->y_offset; j < rect->y_offset + rect->height; ++j) {
    for (int i = rect->x_offset; i < rect->x_offset + rect->width; ++i) {
      const uint32_t src_pixel = src->argb[j * src_stride + i];
      const int src_alpha = src_pixel >> 24;
      if (src_alpha != 0) {
        dst->argb[j * dst_stride + i] = src_pixel;
      }
    }
  }
}

// -------------------webp-get-frame----------------

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
