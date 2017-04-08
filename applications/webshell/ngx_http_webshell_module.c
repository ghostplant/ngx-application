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

#include "ngx_http_webshell_module.h"

typedef struct {
	ngx_connection_t conn;
	ngx_event_t in, out;
	pid_t pid;
	u_short width, height;
	u_char inbuf[1024];
	
	FILE *upload;
} shell_ctx_t;

typedef struct pid_entry_s {
	pid_t pid;
	ngx_http_request_t *r;
	struct pid_entry_s *next;
} pid_entry_t;

pid_entry_t pids = { };

void ngx_pty_recv(ngx_event_t *ev) {
	ngx_http_request_t *r = ev->data;
	shell_ctx_t *ctx = ngx_get_session(r);
	if (!ctx->in.available)
		return;
	ssize_t n = read(ctx->conn.fd, ctx->inbuf + 1, sizeof(ctx->inbuf) - 1);
	if (n < 0)
		return;
	if (n == 0) {
		ngx_websocket_do_close(r);
		return;
	}
	*ctx->inbuf = 'y';
	if (ngx_websocket_do_send(r, ctx->inbuf, n + 1) != NGX_OK) {
		ngx_websocket_do_close(r);
		return;
	}
	ctx->in.available = 0;
}

void ngx_signal_handler(ngx_event_t *ev) {
	int status;
	volatile pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		for (pid_entry_t *p = &pids, *q; p->next != NULL; p = p->next)
			if (p->next->pid == pid) {
				q = p->next;
				ngx_websocket_do_close(q->r);
				p->next = q->next;
				ngx_free(q);
				--pids.pid;
				break;
			}
	}
}

void signal_hander() {
	ngx_notify(ngx_signal_handler);
}

void ngx_websocket_on_open(ngx_http_request_t *r) {
	shell_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(shell_ctx_t));
	if (ctx == NULL) {
		ngx_websocket_do_close(r);
		return;
	}
	if (!ngx_strncmp(r->uri.data, (u_char*)"/upload", sizeof("/upload") - 1)) {
		ngx_set_session(r, ctx);
		return;
	}
	pid_entry_t *p = ngx_alloc(sizeof(pid_entry_t), ngx_cycle->log);
	if (p == NULL) {
		ngx_websocket_do_close(r);
		return;
	}
	signal(SIGCHLD, signal_hander);
	
	ctx->conn.read = &ctx->in;
	ctx->conn.write = &ctx->out;
	ctx->conn.log = r->pool->log;
	
	ctx->in.handler = ngx_pty_recv;
	ctx->out.handler = ngx_empty_event_handler;
	ctx->in.data = ctx->out.data = r;
	ctx->in.log = ctx->out.log  = r->pool->log;
	ctx->in.available = ctx->out.available = 1;
	
	ctx->pid = forkpty(&ctx->conn.fd, NULL, NULL, NULL);
	if (ctx->pid < 0) {
		ngx_websocket_do_close(r);
		return;
	}
	if (!ctx->pid) {
		char *sh[] = {"/bin/sh", "-c", "if [ $(whoami) = \"root\" ]; then export HOME=/root; else export HOME=/home/$(whoami); fi; cd ~; export TERM=xterm; . /etc/default/locale 2>/dev/null; if which bash >/dev/null; then SHELL=$(which bash) exec bash; else SHELL=$(which sh) exec sh; fi", NULL};
		execvp(*sh, sh);
		exit(1);
	}
	if (ctx->conn.fd < 0) {
		ngx_websocket_do_close(r);
		return;
	}
	p->pid = ctx->pid;
	p->r = r;
	p->next = pids.next;
	pids.next = p;
	++pids.pid;
	
	struct termios tios;
	tcgetattr(ctx->conn.fd, &tios);
	// tios.c_lflag &= ~(ECHO | ECHONL);
	tcsetattr(ctx->conn.fd, TCSAFLUSH, &tios);
	
	fcntl(ctx->conn.fd, F_SETFL, fcntl(ctx->conn.fd, F_GETFL, 0) | O_NONBLOCK);
	//ngx_add_event(&ctx->conn, NGX_READ_EVENT, 0);
	ngx_add_conn(&ctx->conn);
	ngx_set_session(r, ctx);
}

void ngx_websocket_on_close(ngx_http_request_t *r) {
	shell_ctx_t *ctx = ngx_get_session(r);
	if (ctx->upload != NULL) {
		fclose(ctx->upload);
		ctx->upload = NULL;
		return;
	}
	ngx_del_conn(&ctx->conn, 0);
	if (ctx->pid > 0) {
		kill(ctx->pid, SIGKILL);
		ctx->pid = 0;
	}
	if (ctx->conn.fd > 0) {
		close(ctx->conn.fd);
		ctx->conn.fd = 0;
	}
}

ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len) {
	shell_ctx_t *ctx = ngx_get_session(r);
	if (ctx->upload != NULL) {
		fwrite(message, 1, len, ctx->upload);
		if (ngx_websocket_do_send(r, message, 1) != NGX_OK)
			return NGX_ERROR;
	} else if (*message == 'd') {
		if (ctx->conn.fd == 0)
			return NGX_ERROR;
		ssize_t n = write(ctx->conn.fd, message + 1, len - 1);
		if (len > 1 && n <= 0)
			return NGX_ERROR;
		if (!ctx->in.available) {
			ctx->in.available = 1;
			ngx_pty_recv(&ctx->in);
		}
		// FIXME: buffering again message
	} else if (*message == 's') {
		if (ctx->conn.fd == 0)
			return NGX_ERROR;
		char *p = strchr((char*)message, ',');
		if (!p)
			return NGX_ERROR;
		*p = 0;
		if (!ctx->in.available) {
			ctx->in.available = 1;
			ngx_pty_recv(&ctx->in);
		}
		u_short layout[4] = {atoi((char*)message + 1), atoi(p + 1), 0, 0};
		if (layout[0] != ctx->height || layout[1] != ctx->width) {
			ctx->height = layout[0], ctx->width = layout[1];
			ioctl(ctx->conn.fd, TIOCSWINSZ, layout);
		}
	} else if (*message == 'o') {
		if (ctx->upload != NULL || message[1] != '/')
			return NGX_ERROR;
		ctx->upload = fopen((char*)(message + 1), "wb");
		if (!ctx->upload)
			ngx_websocket_do_close(r);
		if (ngx_websocket_do_send(r, message, 1) != NGX_OK)
			return NGX_ERROR;
	} else
			return NGX_ERROR;
	return NGX_OK;
}

