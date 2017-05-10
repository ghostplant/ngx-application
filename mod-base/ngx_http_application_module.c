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

#include "ngx_http_application_module.h"

void ngx_websocket_on_open(ngx_http_request_t *r) {
	puts("WebSocket onopen()");
}

void ngx_websocket_on_close(ngx_http_request_t *r) {
	puts("WebSocket onclose()");
}

ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len) {
	puts("WebSocket onmessage()");
	if (ngx_websocket_do_send(r, message, len) != NGX_OK)
		return NGX_ERROR;
	return NGX_OK;
}

void ngx_http_application_body_handler(ngx_http_request_t *r) {
	if (r->request_body == NULL)
		return;
	// printf("POST-FILE: %d %lx %lx %lx\n", (int)r->count, (long)r->request_body->temp_file, (long)r->request_body->bufs, (long)r->request_body->buf), fflush(stdout);
	// printf("TEMP-FILE: %s\n", (char*)r->request_body->temp_file->file.name.data), fflush(stdout);
	// ngx_chain_t *bufs = r->request_body->bufs;
	// while (bufs && bufs->buf != NULL) {
	//	printf("LL (%ld) (%ld)\n", bufs->buf->last - bufs->buf->pos, bufs->buf->end - bufs->buf->start);
	//	bufs = bufs->next;
	//}
}

ngx_uint_t ngx_http_application_normal_handler(ngx_http_request_t *r) {
	// printf("["), ngx_print(&r->method_name), printf("] "), ngx_print(&r->unparsed_uri), printf("\n");
	if (r->method == NGX_HTTP_POST) {
		++r->count;
		return ngx_http_read_client_request_body(r, ngx_http_application_body_handler);
	}
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type.len = sizeof("text/plain") - 1;
	r->headers_out.content_type.data = (u_char *)"text/plain";
	ngx_chain_t *out = (ngx_chain_t*)ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
	ngx_buf_t *b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	out->buf = b;
	out->next = NULL;
	b->pos = (u_char*)"Not Accesible";
	b->last = b->pos + sizeof("Not Accesible") - 1;
	b->memory = 1;
	b->in_file = 0;
	b->last_buf = 1;
	ngx_http_send_header(r);
	ngx_http_discard_request_body(r);
	return ngx_http_output_filter(r, out);
}
