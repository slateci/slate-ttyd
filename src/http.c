#include <string.h>
#include <libwebsockets.h>

#include "server.h"
#include "html.h"

enum {
    AUTH_OK, AUTH_FAIL, AUTH_ERROR
};

int
encode_auth(const char* credential){
	const static char marker[]="TTY_AUTH_TOKEN";
	char* insert_ptr = strstr((char*)index_html, marker);
	if (!insert_ptr) { //if unable to find an insert point, nothing to do
		printf("Did not find credential insertion point\n");
		return 0;
	}
	printf("Found insertion point\n");
	size_t len_written=0;
	if (credential) {
		size_t len = strlen(credential);
		if (len>64u) //credential too long; would overflow
			return 1;
		*insert_ptr++='\'';
		memcpy((void*)insert_ptr,(void*)credential,len);
		insert_ptr+=len;
		*insert_ptr++='\'';
		len_written=len+2;
	}
	else {
		len_written=6;
		memcpy((void*)insert_ptr,(void*)"null",len_written);
		insert_ptr+=len_written;
	}
	if (len_written<sizeof(marker))
		memset(insert_ptr,0x20,sizeof(marker)-len_written);
	return 0;
}

int
check_auth(struct lws *wsi, struct pss_http *pss) {
    if (server->credential == NULL)
        return AUTH_OK;

	char buf[LWS_PRE + 256];
	const char* value = lws_get_urlarg_by_name(wsi, "auth", buf, sizeof(buf));
	if (!value){
		printf("parameter missing\n");
		return AUTH_FAIL;
	}
	if(*value=='=')
		value++;
	printf("Got parameter: %s\n",value);
	if (strcmp(value,server->credential)){
		printf("token does not match\n");
		return AUTH_FAIL;
	}
	printf("token matches\n");
	return AUTH_OK;
}

void access_log(struct lws *wsi, const char *path) {
    char name[100], rip[50];
#if LWS_LIBRARY_VERSION_MAJOR >=2 && LWS_LIBRARY_VERSION_MINOR >=4
    struct lws *n_wsi = lws_get_network_wsi(wsi);
#else
    struct lws *n_wsi = wsi;
#endif
    lws_get_peer_addresses(wsi, lws_get_socket_fd(n_wsi), name, sizeof(name), rip, sizeof(rip));
    lwsl_notice("HTTP %s - %s (%s)\n", path, rip, name);
}

int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct pss_http *pss = (struct pss_http *) user;
    unsigned char buffer[4096 + LWS_PRE], *p, *end;
    char buf[256];
    bool done = false;

    switch (reason) {
        case LWS_CALLBACK_HTTP:
            access_log(wsi, (const char *) in);
            snprintf(pss->path, sizeof(pss->path), "%s", (const char *) in);
            switch (check_auth(wsi, pss)) {
                case AUTH_OK:
                    break;
                case AUTH_FAIL:
                    return 0;
                case AUTH_ERROR:
                default:
                    return 1;
            }

            p = buffer + LWS_PRE;
            end = p + sizeof(buffer) - LWS_PRE;

            if (strncmp(pss->path, "/auth_token.js", 14) == 0) {
                const char *credential = server->credential != NULL ? server->credential : "";
                size_t n = sprintf(buf, "var tty_auth_token = '%s';\n", credential);
                if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
                    return 1;
                if (lws_add_http_header_by_token(wsi,
                                                 WSI_TOKEN_HTTP_CONTENT_TYPE,
                                                 (unsigned char *) "application/javascript",
                                                 22, &p, end))
                    return 1;
                if (lws_add_http_header_content_length(wsi, (unsigned long) n, &p, end))
                    return 1;
                if (lws_finalize_http_header(wsi, &p, end))
                    return 1;
                if (lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
                    return 1;
                pss->buffer = pss->ptr = strdup(buf);
                pss->len = n;
                lws_callback_on_writable(wsi);
                break;
            }

            if (strcmp(pss->path, "/") != 0) {
                lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
                goto try_to_reuse;
            }

            const char* content_type = "text/html";
            if (server->index != NULL) {
                int n = lws_serve_http_file(wsi, server->index, content_type, NULL, 0);
                if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi)))
                    return 1;
            } else {
                if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
                    return 1;
                if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *) content_type, 9, &p, end))
                    return 1;
                if (lws_add_http_header_content_length(wsi, (unsigned long) index_html_len, &p, end))
                    return 1;
                if (lws_finalize_http_header(wsi, &p, end))
                    return 1;
                if (lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
                    return 1;
#if LWS_LIBRARY_VERSION_MAJOR < 2
                if (lws_write_http(wsi, index_html, index_html_len) < 0)
                    return 1;
                goto try_to_reuse;
#else
                pss->buffer = pss->ptr = (char *) index_html;
                pss->len = index_html_len;
                lws_callback_on_writable(wsi);
#endif
            }
            break;

        case LWS_CALLBACK_HTTP_WRITEABLE:
            if (!pss->buffer || pss->len <= 0) {
                goto try_to_reuse;
            }

            do {
                int n = sizeof(buffer) - LWS_PRE;
                int m = lws_get_peer_write_allowance(wsi);
                if (m == 0) {
                    lws_callback_on_writable(wsi);
                    return 0;
                } else if (m != -1 && m < n) {
                    n = m;
                }
                if (pss->ptr + n > pss->buffer + pss->len) {
                    n = (int) (pss->len - (pss->ptr - pss->buffer));
                    done = true;
                }
                memcpy(buffer + LWS_PRE, pss->ptr, n);
                pss->ptr += n;
                if (lws_write_http(wsi, buffer + LWS_PRE, (size_t) n) < n) {
                    if (pss->buffer != (char *) index_html) free(pss->buffer);
                    return -1;
                }
            } while (!lws_send_pipe_choked(wsi) && !done);

            if (!done && pss->ptr < pss->buffer + pss->len) {
                lws_callback_on_writable(wsi);
                break;
            }

            if (pss->buffer != (char *) index_html) {
                free(pss->buffer);
            }
            goto try_to_reuse;

        case LWS_CALLBACK_HTTP_FILE_COMPLETION:
            goto try_to_reuse;

        case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
            if (!len || (SSL_get_verify_result((SSL *) in) != X509_V_OK)) {
                int err = X509_STORE_CTX_get_error((X509_STORE_CTX *) user);
                int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *) user);
                const char *msg = X509_verify_cert_error_string(err);
                lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
                return 1;
            }
            break;
        default:
            break;
    }

    return 0;

    /* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
    if (lws_http_transaction_completed(wsi))
        return -1;

    return 0;
}
