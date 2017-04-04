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

#include "ngx_http_openAuth_module.h"

void ngx_websocket_on_open(ngx_http_request_t *r) {
}

void ngx_websocket_on_close(ngx_http_request_t *r) {
}

ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len) {
	return NGX_OK;
}

ngx_uint_t ngx_http_openAuth_normal_handler(ngx_http_request_t *r) {
	printf("["), ngx_print(&r->method_name), printf("] "), ngx_print(&r->unparsed_uri), printf("\n");
	
	r->unparsed_uri.data[r->unparsed_uri.len] = 0;
	char *code = strstr((char*)r->unparsed_uri.data, "?code="), *it;
	if (code) {
		code += 6;
		for (it = code; *it; ++it)
			if (!isdigit(*it) && !isalpha(*it)) {
				*it = 0;
				break;
			}
	}
	FILE *fp;
	char path[1024], data[1024];
	snprintf(path, sizeof(path), "curl -sSL 'https://github.com/login/oauth/access_token?client_id=35fec7ac14fb42fc9482&client_secret=4445d011e0079893de9de3860076b27d7d1011f9&code=%s'", code);
	puts(path);
	fp = popen(path, "r");
	if (!~fscanf(fp, "%s", data))
		*data = 0;
	pclose(fp);
	
	snprintf(path, sizeof(path), "curl -sSL 'https://api.github.com/user?%s'", data);
	puts(path);
	fp = popen(path, "r");
	char *username;
	while (fgets(data, sizeof(data), fp)) {
		username = strstr(data, "\"login\": \"");
		if (username) {
			username += 10;
			char *end = strchr(username, '"');
			if (!end)
				username = NULL;
			else
				*end = 0;
			break;
		}
	}
	pclose(fp);
	
	if (username)
		snprintf(path, sizeof(path), "Successfully logged in with username: %s.", username);
	else
		snprintf(path, sizeof(path), "OAuth login failed.");
	
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type.len = sizeof("text/plain") - 1;
	r->headers_out.content_type.data = (u_char *)"text/plain";
	ngx_chain_t *out = (ngx_chain_t*)ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
	ngx_buf_t *b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	out->buf = b;
	out->next = NULL;
	b->pos = (u_char*)path;
	b->last = b->pos + strlen(path);
	b->memory = 1;
	b->in_file = 0;
	b->last_buf = 1;
	ngx_http_send_header(r);
	ngx_http_discard_request_body(r);
	return ngx_http_output_filter(r, out);
}
