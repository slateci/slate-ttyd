#include <string.h>
#include <libwebsockets.h>

#include "server.h"
#include "html.h"

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
check_auth(struct lws *wsi) {
    if (server->credential == NULL)
        return 0;

	char buf[LWS_PRE + 256];
	const char* value = lws_get_urlarg_by_name(wsi, "auth", buf, sizeof(buf));
	if (!value){
		printf("parameter missing\n");
		return 1;
	}
	if(*value=='=')
		value++;
	printf("Got parameter: %s\n",value);
	if (strcmp(value,server->credential)){
		printf("token does not match\n");
		return 1;
	}
	printf("token matches\n");
	return 0;
}

int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct pss_http *pss = (struct pss_http *) user;
    unsigned char buffer[4096 + LWS_PRE], *p, *end;
    char buf[256], name[100], rip[50];

    switch (reason) {
        case LWS_CALLBACK_HTTP:
            // only GET method is allowed
            if (/*!lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) ||*/ len < 1) {
                lwsl_notice("Request which is not a GET or has len<1\n"
                            "reason: %i  len: %zu  path: %s\n", reason, len, in);
                lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
                goto try_to_reuse;
            }

            snprintf(pss->path, sizeof(pss->path), "%s", (const char *)in);
            lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, sizeof(name), rip, sizeof(rip));
            lwsl_notice("HTTP %s - %s (%s)\n", (char *) in, rip, name);

            switch (check_auth(wsi)) {
                case 0:
                    break;
                case -1:
                    goto try_to_reuse;
                case 1:
                default:
                    return 1;
            }

            p = buffer + LWS_PRE;
            end = p + sizeof(buffer) - LWS_PRE;

            if (strncmp(pss->path, "/auth_token.js", 14) == 0) {
                size_t n = server->credential != NULL ? sprintf(buf, "var tty_auth_token = '%s';", server->credential) : 0;

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
#if LWS_LIBRARY_VERSION_MAJOR < 3
                if (n > 0 && lws_write_http(wsi, buf, n) < 0)
                    return 1;
                goto try_to_reuse;
#else
                if (n > 0) {
                    pss->buffer = pss->ptr = strdup(buf);
                    pss->len = n;
                    lws_callback_on_writable(wsi);
                }
                return 0;
#endif
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
#if LWS_LIBRARY_VERSION_MAJOR < 3
                if (lws_write_http(wsi, index_html, index_html_len) < 0)
                    return 1;
                goto try_to_reuse;
#else
                pss->buffer = pss->ptr = (char *) index_html;
                pss->len = index_html_len;
                lws_callback_on_writable(wsi);
                return 0;
#endif
            }
            break;

        case LWS_CALLBACK_HTTP_WRITEABLE:
            if (pss->len <= 0)
                goto try_to_reuse;

            if (pss ->ptr - pss->buffer == pss->len) {
                if (pss->buffer != (char *) index_html) free(pss->buffer);
                goto try_to_reuse;
            }

            int n = sizeof(buffer) - LWS_PRE;
            if (pss->ptr - pss->buffer + n > pss->len)
                n = (int) (pss->len - (pss->ptr - pss->buffer));
            memcpy(buffer + LWS_PRE, pss->ptr, n);
            pss->ptr += n;
            if (lws_write_http(wsi, buffer + LWS_PRE, (size_t) n) < n) {
                if (pss->buffer != (char *) index_html) free(pss->buffer);
                return -1;
            }

            lws_callback_on_writable(wsi);
            break;

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
