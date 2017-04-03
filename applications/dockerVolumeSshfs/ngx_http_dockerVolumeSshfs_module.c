/**
  * Nginx HTTP Application Module
  * Embed Application into Nginx (GET/POST/WebSocket)
  *
  * Author: CUI Wei <ghostplant@qq.com>
  * Copyright (C) 2016.12 - ..
  *
  * The MIT License (MIT)
  */

#include <pty.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>

#include "ngx_http_dockerVolumeSshfs_module.h"

void ngx_websocket_on_open(ngx_http_request_t *r) {
}

void ngx_websocket_on_close(ngx_http_request_t *r) {
}

ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len) {
	return NGX_OK;
}

ngx_int_t ngx_http_output_json(ngx_http_request_t *r, const char *s, ngx_uint_t l) {
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type.len = sizeof("application/json") - 1;
	r->headers_out.content_type.data = (u_char *)"application/json";
	ngx_chain_t *out = (ngx_chain_t*)ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
	ngx_buf_t *b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	out->buf = b;
	out->next = NULL;
	b->pos = (u_char*)s;
	b->last = b->pos + l;
	b->memory = 1;
	b->in_file = 0;
	b->last_buf = 1;
	ngx_http_send_header(r);
	ngx_http_discard_request_body(r);
	return ngx_http_output_filter(r, out);
}

void ngx_http_dockerVolumeSshfs_body_handler(ngx_http_request_t *r) {
	size_t preread = r->header_in->last - r->header_in->pos;
	if (!preread || r->header_in->in_file) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	r->header_in->last[-1] = 0;
	char *name = strstr((char*)r->header_in->pos, "\"Name\":\"");
	if (name) {
		name += 8;
		char *end = strchr(name , '"');
		if (!end)
			name = NULL;
		else
			*end = 0;
	}
	
	if (!ngx_strncmp(r->uri.data, (u_char*)"/VolumeDriver.Mount", sizeof("/VolumeDriver.Mount") - 1)) {
		static char impl[] = "{\"Mountpoint\":\"/mnt\"}";
		ngx_http_output_json(r, impl, sizeof(impl) - 1);
	} else if (!ngx_strncmp(r->uri.data, (u_char*)"/VolumeDriver.Unmount", sizeof("/VolumeDriver.Unmount") - 1)) {
		// default output
	}
	ngx_http_output_json(r, "{}", sizeof("{}") - 1);
}

ngx_int_t ngx_http_dockerVolumeSshfs_normal_handler(ngx_http_request_t *r) {
	printf("["), ngx_print(&r->method_name), printf("] "), ngx_print(&r->unparsed_uri), printf("\n");
	if (!ngx_strncmp(r->uri.data, (u_char*)"/Plugin.Activate", sizeof("/Plugin.Activate") - 1)) {
		static char impl[] = "{\"Implements\": [\"VolumeDriver\"]}";
		return ngx_http_output_json(r, impl, sizeof(impl) - 1);
	}
	++r->count;
	r->headers_in.content_length_n = -1;
	ngx_uint_t rc = ngx_http_read_client_request_body(r, ngx_http_dockerVolumeSshfs_body_handler);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
		return rc;
	return NGX_DONE;
}

