/*-
 * Copyright (c) 2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "vsa.h"
#include "vcl.h"
#include "vrt.h"
#include "vdef.h"
#include "vsb.h"
#include "vtim.h"
#include "vqueue.h"
#include "cache/cache.h"
#include "cache/cache_director.h"
#include "cache/cache_filter.h"

#include "vcc_if.h"

#include "vtree.h"

#define FSB_EXT_MAX			15

#define E200_OK				200
#define E400_BAD_REQUEST		400
#define E403_FORBIDDEN			403
#define E404_NOT_FOUND			404
#define E414_URI_TOO_LONG		414
#define E500_SERVER_ERROR		500

struct fsb_header {
	unsigned			magic;
#define FSB_HEADER_MAGIC		0x6ae00a29

	VTAILQ_ENTRY(fsb_header)	list;
	char				*hdrstr;
};

struct fsb_mimetype {
	unsigned			magic;
#define FSB_MIMETYPE_MAGIC		0x1b9b464c

	char				ext[FSB_EXT_MAX + 1];
	char				*type;
	VRB_ENTRY(fsb_mimetype)		entry;
};

VRB_HEAD(mimedb, fsb_mimetype);

struct vmod_fsbackend_root {
	unsigned			magic;
#define VMOD_FSBACKEND_ROOT_MAGIC	0xd6ad5238

	struct mimedb			mimedb;

	char				*root;

	VTAILQ_HEAD(,fsb_header)	headers;

	struct director			dir[1];
};

struct fsb_conn {
	unsigned			magic;
#define FSB_CONN_MAGIC			0x38596f4d

	const struct vmod_fsbackend_root	*root;

	int				fd;
	struct vsb			*synth;
};

static inline int
cmp_mimetype(const struct fsb_mimetype *a, const struct fsb_mimetype *b)
{
	return (strcasecmp(a->ext, b->ext));
}

VRB_PROTOTYPE_STATIC(mimedb, fsb_mimetype, entry, cmp_mimetype);
VRB_GENERATE_STATIC(mimedb, fsb_mimetype, entry, cmp_mimetype);

static int
fromhex(int c)
{
	c = tolower(c);
	if (c <= '9')
		return (c - '0');
	return (10 + (c - 'a'));
}

static int
penc_decode(char *d, txt s, size_t n)
{
	int c;
	ssize_t l;

	AN(s.b);
	AN(d);
	if (n == 0)
		return (0);
	l = 0;
	while (s.b < s.e && l < (n - 1)) {
		if (s.b[0] == '%') {
			if (s.e - s.b >= 3 &&
			    isxdigit(s.b[1]) && isxdigit(s.b[2])) {
				c = fromhex(s.b[1]);
				c *= 0x10;
				c += fromhex(s.b[2]);
				d[l++] = c;
				s.b += 3;
			} else if (s.e - s.b >= 2 && s.b[1] == '%') {
				d[l++] = '%';
				s.b += 2;
			} else
				return (0);
		} else if (s.b[0] == '+') {
			d[l++] = ' ';
			s.b++;
		} else {
			d[l++] = s.b[0];
			s.b++;
		}
	}
	if (s.b < s.e)
		return (0);
	d[l++] = '\0';
	return (1);
}

static void
fsb_mime_readdb(struct vmod_fsbackend_root *root, const char *mimedb)
{
	FILE *in;
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t l;
	char *b, *p;
	const char *type;
	const char *ext;
	struct fsb_mimetype *entry, tmpentry;

	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);
	AN(mimedb);

	in = fopen(mimedb, "r");
	if (in == NULL)
		return;

	INIT_OBJ(&tmpentry, FSB_MIMETYPE_MAGIC);

	while (1) {
		l = getline(&buf, &buflen, in);
		if (l < 0)
			break;
		l = strlen(buf);
		b = buf;

		while (*b && isspace(*b))
			b++;
		if (*b == '#')
			continue; /* Comment */

		/* Mime type */
		p = b;
		while (*p && !isspace(*p))
			p++;
		if (p == b)
			continue; /* Empty line */
		*p++ = '\0';
		type = b;
		b = p;

		/* Extensions */
		while (*b) {
			p = b;
			while (*p && isspace(*p))
				p++;
			b = p;
			while (*p && !isspace(*p))
				p++;
			if (p == b)
				break;
			*p++ = '\0';
			ext = b;
			b = p;

			if (strlen(ext) > FSB_EXT_MAX)
				continue; /* Too large, ignore */

			strncpy(tmpentry.ext, ext, FSB_EXT_MAX);
			entry = VRB_FIND(mimedb, &root->mimedb, &tmpentry);
			if (entry != NULL) {
				/* Already exists. Later entries overwrite
				   previous */
				CHECK_OBJ_NOTNULL(entry, FSB_MIMETYPE_MAGIC);
				AN(entry->type);
				free(entry->type);
				entry->type = strdup(type);
				AN(entry->type);
				continue;
			}

			ALLOC_OBJ(entry, FSB_MIMETYPE_MAGIC);
			AN(entry);
			strncpy(entry->ext, ext, FSB_EXT_MAX);
			entry->type = strdup(type);
			AN(entry->type);
			AZ(VRB_INSERT(mimedb, &root->mimedb, entry));
		}
	}
	free(buf);
	fclose(in);
}

static const char *
fsb_mime_lookup(const struct vmod_fsbackend_root *root, const char *filename)
{
	const char *ext;
	struct fsb_mimetype *entry, tmpentry;

	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);
	AN(filename);

	ext = strrchr(filename, '.');
	if (ext == NULL)
		return (NULL);
	ext++;
	if (!*ext)
		return (NULL);
	if (strlen(ext) > FSB_EXT_MAX)
		return (NULL);

	INIT_OBJ(&tmpentry, FSB_MIMETYPE_MAGIC);
	strncpy(tmpentry.ext, ext, FSB_EXT_MAX);

	entry = VRB_FIND(mimedb, &root->mimedb, &tmpentry);
	CHECK_OBJ_ORNULL(entry, FSB_MIMETYPE_MAGIC);
	if (entry == NULL)
		return (NULL);
	return (entry->type);
}

static void
fsb_mime_cleanup(struct vmod_fsbackend_root *root)
{
	struct fsb_mimetype *e, *e2;

	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);

	VRB_FOREACH_SAFE(e, mimedb, &root->mimedb, e2) {
		AN(VRB_REMOVE(mimedb, &root->mimedb, e));
		CHECK_OBJ_NOTNULL(e, FSB_MIMETYPE_MAGIC);
		AN(e->type);
		free(e->type);
		FREE_OBJ(e);
	}
}

static int
fsb_synth(struct busyobj *bo, unsigned status)
{
	struct fsb_conn *conn;
	const char *reason;
	struct vsb *vsb;

	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);

	CHECK_OBJ_NOTNULL(bo->htc, HTTP_CONN_MAGIC);
	CAST_OBJ_NOTNULL(conn, bo->htc->priv, FSB_CONN_MAGIC);
	AZ(conn->synth);

	reason = http_Status2Reason(status);
	AN(reason);

	vsb = VSB_new_auto();
	if (vsb == NULL)
		return (-1);

	(void)VSB_printf(vsb, "<html>\n");
	(void)VSB_printf(vsb, "<head>\n");
	(void)VSB_printf(vsb, "<title>%s</title>\n", reason);
	(void)VSB_printf(vsb, "</head>\n");
	(void)VSB_printf(vsb, "<body>\n");
	(void)VSB_printf(vsb, "<h1>%s</h1>\n", reason);
	(void)VSB_printf(vsb, "</body>\n");
	(void)VSB_printf(vsb, "</html>\n");
	(void)VSB_finish(vsb);

	http_PutResponse(bo->beresp, "HTTP/1.1", status, NULL);
	http_PrintfHeader(bo->beresp, "Content-Type: text/html");
	http_PrintfHeader(bo->beresp, "Content-Length: %ju", VSB_len(vsb));
	bo->htc->content_length = VSB_len(vsb);
	bo->htc->body_status = BS_LENGTH;

	conn->synth = vsb;
	return (0);
}

static int __match_proto__(vdi_gethdrs_f)
fsb_gethdrs(const struct director *dir, struct worker *wrk, struct busyobj *bo)
{
	struct vmod_fsbackend_root *root;
	struct fsb_conn *conn;
	int i;
	char buf1[PATH_MAX], buf2[PATH_MAX];
	const char *mimetype;
	txt url;
	char *p;
	struct stat st, fst;
	const struct fsb_header *hdr;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->bereq, HTTP_MAGIC);
	CHECK_OBJ_NOTNULL(bo->beresp, HTTP_MAGIC);

	CAST_OBJ_NOTNULL(root, dir->priv, VMOD_FSBACKEND_ROOT_MAGIC);

	conn = WS_Alloc(bo->ws, sizeof *conn);
	if (conn == NULL)
		return (-1);
	INIT_OBJ(conn, FSB_CONN_MAGIC);
	conn->root = root;
	conn->fd = -1;

	AZ(bo->htc);
	bo->htc = WS_Alloc(bo->ws, sizeof *bo->htc);
	if (bo->htc == NULL)
		return (-1);
	INIT_OBJ(bo->htc, HTTP_CONN_MAGIC);
	bo->htc->priv = conn;

	url = bo->bereq->hd[HTTP_HDR_URL];
	if (url.b == NULL)
		return (fsb_synth(bo, E500_SERVER_ERROR));
	AN(url.e);
	AZ(*url.e);		/* Null terminated */

	while (*url.b == '/')
		url.b++;
	p = strchr(url.b, '?');
	if (p)
		url.e = p;

	if (!penc_decode(buf1, url, sizeof buf1))
		return (fsb_synth(bo, E400_BAD_REQUEST));

	mimetype = fsb_mime_lookup(root, buf1);

	i = snprintf(buf2, sizeof buf2, "%s/%s", root->root, buf1);
	if (i >= sizeof buf2)
		return (fsb_synth(bo, E414_URI_TOO_LONG));

	if (stat(buf2, &st) || !realpath(buf2, buf1)) {
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, E403_FORBIDDEN));
		case ENAMETOOLONG:
			return (fsb_synth(bo, E414_URI_TOO_LONG));
		case ENOENT:
		case ENOTDIR:
			return (fsb_synth(bo, E404_NOT_FOUND));
		default:
			return (fsb_synth(bo, E500_SERVER_ERROR));
		}
	}

	if (strncmp(buf1, root->root, strlen(root->root)))
		return (fsb_synth(bo, E403_FORBIDDEN));

	conn->fd = open(buf1, O_RDONLY);
	if (conn->fd < 0) {
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, E403_FORBIDDEN));
		case ENAMETOOLONG:
			return (fsb_synth(bo, E414_URI_TOO_LONG));
		default:
			return (fsb_synth(bo, E500_SERVER_ERROR));
		}
	}

	if (fstat(conn->fd, &fst)) {
		close(conn->fd);
		conn->fd = -1;
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, E403_FORBIDDEN));
		default:
			return (fsb_synth(bo, E500_SERVER_ERROR));
		}
	}

	if (st.st_dev != fst.st_dev || st.st_ino != fst.st_ino) {
		close(conn->fd);
		conn->fd = -1;
		return (fsb_synth(bo, E500_SERVER_ERROR));
	}

	if (!S_ISREG(fst.st_mode)) {
		close(conn->fd);
		conn->fd = -1;
		return (fsb_synth(bo, E403_FORBIDDEN));
	}

	http_PutResponse(bo->beresp, "HTTP/1.1", E200_OK, NULL);

	http_PrintfHeader(bo->beresp, "Content-Length: %jd", fst.st_size);

	assert(sizeof buf1 >= VTIM_FORMAT_SIZE);
	VTIM_format(fst.st_mtim.tv_sec, buf1);
	http_PrintfHeader(bo->beresp, "Last-Modified: %s", buf1);

	VTAILQ_FOREACH(hdr, &root->headers, list) {
		CHECK_OBJ_NOTNULL(hdr, FSB_HEADER_MAGIC);
		http_SetHeader(bo->beresp, hdr->hdrstr);
	}

	if (mimetype)
		http_PrintfHeader(bo->beresp, "Content-Type: %s", mimetype);

	bo->htc->body_status = BS_LENGTH;
	bo->htc->content_length = fst.st_size;

	return (0);
}

static enum vfp_status __match_proto__(vfp_pull_f)
fsb_pull_vsb(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp)
{
	struct vsb *vsb;
	ssize_t l;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	AN(p);
	AN(lp);

	CAST_OBJ_NOTNULL(vsb, vfe->priv1, VSB_MAGIC);

	l = VSB_len(vsb);
	assert(vfe->priv2 <= l);
	l -= vfe->priv2;
	if (l > *lp)
		l = *lp;
	memcpy(p, VSB_data(vsb) + vfe->priv2, l);
	*lp = l;
	vfe->priv2 += l;

	if (vfe->priv2 == VSB_len(vsb))
		return (VFP_END);
	return (VFP_OK);
}

static const struct vfp fsb_vfp_vsb = {
	.name = "FSB_VFP_VSB",
	.pull = fsb_pull_vsb,
};

static enum vfp_status __match_proto__(vfp_pull_f)
fsb_pull_file(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp)
{
	struct http_conn *htc;
	struct fsb_conn *conn;
	ssize_t l;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	AN(p);
	AN(lp);

	CAST_OBJ_NOTNULL(htc, vfe->priv1, HTTP_CONN_MAGIC);
	CAST_OBJ_NOTNULL(conn, htc->priv, FSB_CONN_MAGIC);
	assert(conn->fd >= 0);

	assert(vfe->priv2 <= htc->content_length);
	if (vfe->priv2 == htc->content_length)
		return (VFP_END);
	l = htc->content_length - vfe->priv2;
	if (l > *lp)
		l = *lp;
	l = read(conn->fd, p, l);
	if (l <= 0)
		return (VFP_ERROR);
	*lp = l;
	vfe->priv2 += l;
	if (vfe->priv2 == htc->content_length)
		return (VFP_END);
	return (VFP_OK);
}

static const struct vfp fsb_vfp_file = {
	.name = "FSB_VFP_FILE",
	.pull = fsb_pull_file,
};

static int __match_proto__(vdi_getbody_f)
fsb_getbody(const struct director *dir, struct worker *wrk, struct busyobj *bo)
{
	struct fsb_conn *conn;
	struct vfp_entry *vfe;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->vfc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(bo->htc, HTTP_CONN_MAGIC);

	CAST_OBJ_NOTNULL(conn, bo->htc->priv, FSB_CONN_MAGIC);

	if (conn->synth != NULL) {
		assert(conn->fd < 0);
		vfe = VFP_Push(bo->vfc, &fsb_vfp_vsb, 0);
		CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
		vfe->priv1 = conn->synth;
		vfe->priv2 = 0;
	} else {
		assert(conn->fd >= 0);
		vfe = VFP_Push(bo->vfc, &fsb_vfp_file, 0);
		CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
		vfe->priv1 = bo->htc;
		vfe->priv2 = 0;
	}

	return (0);
}

static void __match_proto__(vdi_finish_f)
fsb_finish(const struct director *dir, struct worker *wrk, struct busyobj *bo)
{
	struct fsb_conn *conn;

	(void)dir;
	(void)wrk;
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	CHECK_OBJ_NOTNULL(bo->htc, HTTP_CONN_MAGIC);
	CAST_OBJ_NOTNULL(conn, bo->htc->priv, FSB_CONN_MAGIC);

	if (conn->synth != NULL)
		VSB_delete(conn->synth);
	conn->synth = NULL;
	if (conn->fd >= 0)
		close(conn->fd);
	conn->fd = -1;

	conn->magic = 0;
	bo->htc->priv = NULL;
	bo->htc->magic = 0;
	bo->htc = NULL;
}

static void __match_proto__(vdi_panic_f)
fsb_panic(const struct director *dir, struct vsb *vsb)
{
	(void)dir;
	(void)vsb;
}

VCL_VOID
vmod_root__init(VRT_CTX, struct vmod_fsbackend_root **p_root,
    const char *vcl_name, VCL_STRING rootdir, VCL_STRING mimedb)
{
	struct vmod_fsbackend_root *root;
	char buf[PATH_MAX];
	struct stat st;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(ctx->msg);
	AN(p_root);
	AZ(*p_root);
	AN(vcl_name);

	ALLOC_OBJ(root, VMOD_FSBACKEND_ROOT_MAGIC);
	AN(root);

	VRB_INIT(&root->mimedb);

	if (rootdir == NULL || strlen(rootdir) == 0) {
		VSB_printf(ctx->msg, "No root directory specified.\n");
		goto error;
	}
	if (rootdir[0] != '/') {
		VSB_printf(ctx->msg, "'%s' is not an absolute path.\n",
		    rootdir);
		goto error;
	}
	if (!realpath(rootdir, buf)) {
		VSB_printf(ctx->msg, "Can't resolve path '%s': %s.\n",
		    rootdir, strerror(errno));
		goto error;
	}
	if (stat(buf, &st)) {
		VSB_printf(ctx->msg, "Can't stat '%s': %s.\n",
		    buf, strerror(errno));
		goto error;
	}
	if (!S_ISDIR(st.st_mode)) {
		VSB_printf(ctx->msg, "'%s' is not a directory.\n", buf);
		goto error;
	}
	REPLACE(root->root, buf);

	VTAILQ_INIT(&root->headers);

	INIT_OBJ(root->dir, DIRECTOR_MAGIC);
	root->dir->name = root->root;
	REPLACE(root->dir->vcl_name, vcl_name);
	root->dir->priv = root;
	root->dir->gethdrs = fsb_gethdrs;
	root->dir->getbody = fsb_getbody;
	root->dir->finish = fsb_finish;
	root->dir->panic = fsb_panic;

	if (mimedb)
		fsb_mime_readdb(root, mimedb);

	*p_root = root;
	return;

 error:
	AZ(*p_root);
	VRT_handling(ctx, VCL_RET_FAIL);
	if (root == NULL)
		return;
	free(root->root);
	free(root->dir->vcl_name);
	FREE_OBJ(root);
}

VCL_VOID
vmod_root__fini(struct vmod_fsbackend_root **p_root)
{
	struct vmod_fsbackend_root *root;
	struct fsb_header *hdr;

	AN(p_root);
	root = *p_root;
	if (root == NULL)
		return;
	*p_root = NULL;
	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);

	free(root->root);
	free(root->dir->vcl_name);
	while (!VTAILQ_EMPTY(&root->headers)) {
		hdr = VTAILQ_FIRST(&root->headers);
		CHECK_OBJ_NOTNULL(hdr, FSB_HEADER_MAGIC);
		VTAILQ_REMOVE(&root->headers, hdr, list);
		free(hdr->hdrstr);
		FREE_OBJ(hdr);
	}
	fsb_mime_cleanup(root);
	FREE_OBJ(root);
}

VCL_VOID
vmod_root_add_header(VRT_CTX, struct vmod_fsbackend_root *root,
    VCL_STRING hdrstr)
{
	struct fsb_header *hdr;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);

	if (hdrstr == NULL || *hdrstr == '\0')
		return;

	ALLOC_OBJ(hdr, FSB_HEADER_MAGIC);
	AN(hdr);
	REPLACE(hdr->hdrstr, hdrstr);
	VTAILQ_INSERT_TAIL(&root->headers, hdr, list);
}

VCL_BACKEND
vmod_root_backend(VRT_CTX, struct vmod_fsbackend_root *root)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);
	return (root->dir);
}

int __match_proto__(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{

	(void)priv;
	(void)e;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (0);
}
