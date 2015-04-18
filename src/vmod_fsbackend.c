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
#include "cache/cache.h"
#include "cache/cache_director.h"
#include "cache/cache_filter.h"

#include "vcc_if.h"

struct vmod_fsbackend_root {
	unsigned			magic;
#define VMOD_FSBACKEND_ROOT_MAGIC	0xd6ad5238

	char				*root;

	struct director			dir[1];
};

struct fsb_conn {
	unsigned			magic;
#define FSB_CONN_MAGIC			0x38596f4d

	const struct vmod_fsbackend_root	*root;

	int				fd;
	struct vsb			*synth;
};

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
	char buf[PATH_MAX], path[PATH_MAX];
	txt url;
	char *p;
	struct stat stat;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
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
	HTC_InitObj(bo->htc, &conn->fd, NULL);
	bo->htc->priv = conn;

	url = bo->bereq->hd[HTTP_HDR_URL];
	if (url.b == NULL)
		return (fsb_synth(bo, 500));
	AN(url.e);
	AZ(*url.e);		/* Null terminated */

	VSLb(bo->vsl, SLT_Debug, "url: '%s'", url.b);

	while (*url.b == '/')
		url.b++;

	p = strchr(url.b, '?');
	if (p)
		url.e = p;

	i = snprintf(buf, sizeof buf, "%s/%.*s",
	    root->root, (int)(url.e - url.b), url.b);
	VSLb(bo->vsl, SLT_Debug, "buf: '%s'", buf);
	if (i >= sizeof buf)
		return (fsb_synth(bo, 414));

	if (!realpath(buf, path)) {
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, 403));
		case ENAMETOOLONG:
			return (fsb_synth(bo, 414));
		case ENOENT:
		case ENOTDIR:
			return (fsb_synth(bo, 404));
		default:
			return (fsb_synth(bo, 500));
		}
	}

	VSLb(bo->vsl, SLT_Debug, "path: '%s'", path);
	VSLb(bo->vsl, SLT_Debug, "root: '%s'", root->root);

	if (strncmp(path, root->root, strlen(root->root)))
		return (fsb_synth(bo, 403));

	VSLb(bo->vsl, SLT_Debug, "buf: '%s'", buf);

	conn->fd = open(buf, O_RDONLY);
	if (conn->fd < 0) {
		VSLb(bo->vsl, SLT_Debug, "open failed");
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, 403));
		case ENAMETOOLONG:
			return (fsb_synth(bo, 414));
		default:
			return (fsb_synth(bo, 500));
		}
	}

	if (fstat(conn->fd, &stat)) {
		VSLb(bo->vsl, SLT_Debug, "stat failed");
		close(conn->fd);
		conn->fd = -1;
		switch (errno) {
		case EACCES:
			return (fsb_synth(bo, 403));
		default:
			return (fsb_synth(bo, 500));
		}
	}

	if ((stat.st_mode & S_IFMT) != S_IFREG) {
		VSLb(bo->vsl, SLT_Debug, "not a file: 0x%x",
		    stat.st_mode & S_IFMT);
		close(conn->fd);
		conn->fd = -1;
		return (fsb_synth(bo, 403));
	}

	bo->htc->content_length = stat.st_size;
	http_PutResponse(bo->beresp, "HTTP/1.1", 200, NULL);
	http_PrintfHeader(bo->beresp, "Content-Length: %jd",
	    bo->htc->content_length);
	bo->htc->body_status = BS_LENGTH;

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
    const char *vcl_name, VCL_STRING rootdir)
{
	struct vmod_fsbackend_root *root;
	char buf[PATH_MAX];

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(ctx->msg);
	AN(p_root);
	AZ(*p_root);
	AN(vcl_name);

	ALLOC_OBJ(root, VMOD_FSBACKEND_ROOT_MAGIC);
	AN(root);

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
		VSB_printf(ctx->msg, "Bad path: %s.\n", strerror(errno));
		goto error;
	}
	REPLACE(root->root, buf);

	INIT_OBJ(root->dir, DIRECTOR_MAGIC);
	root->dir->name = root->root;
	REPLACE(root->dir->vcl_name, vcl_name);
	root->dir->priv = root;
	root->dir->gethdrs = fsb_gethdrs;
	root->dir->getbody = fsb_getbody;
	root->dir->finish = fsb_finish;
	root->dir->panic = fsb_panic;

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

	AN(p_root);
	root = *p_root;
	if (root == NULL)
		return;
	*p_root = NULL;
	CHECK_OBJ_NOTNULL(root, VMOD_FSBACKEND_ROOT_MAGIC);

	free(root->root);
	free(root->dir->vcl_name);
	FREE_OBJ(root);
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
