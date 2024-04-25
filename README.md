#### 

### Install

> require [libwebp](https://github.com/webmproject/libwebp)

```shell
cd /path/nginx-1.22.1

./configure --add-module=/path/libwebp/src
make -j
make install
```

### Usage

edit nginx.conf

```nginx
server {
  listen 8080;
  location ~* /(.+)\.webp@(\d+)$ {
    get_frame $2;
    webp_enable on;
    try_files /$1.webp /usr/share/nginx/html/404.html;
    root /path;
  }
}
```

```shell
nginx -t
nginx -s reload

curl http://localhost:8080/test.webp@1
# return /path/test.webp first frame
```
