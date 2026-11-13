// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * GStreamer elements around the secvid TA, for secure media pipelines whose
 * buffers live in the TEE protected heap:
 *
 * secvidsrc: reads a stream whose units (access units or raw frames) were
 *   each encrypted on their own (location, sizes in index, one per line).
 *   mode=tee: the TA decrypts each unit into a fresh protected-heap DMA-buf.
 *   mode=clear: the file holds the plaintext XORed with 0xa5 (a reference
 *   run; the plaintext never sits in a file), restored into a DMA-buf from
 *   heap (default the system heap). Pushes DMA-buf memory with the caps
 *   given in the caps property. Every unit gets a fresh DMA-buf of at
 *   least buffer-size bytes (a V4L2 queue may need buffers as large as its
 *   sizeimage). Buffers are not recycled: vb2 keeps a DMA-buf mapped in its
 *   V4L2 slot until another buffer replaces it, and with protected memory
 *   the hypervisor refuses to map pages into a second slot while they are
 *   still mapped for another, which a recycling pool smaller than the
 *   queue causes.
 *
 * secviddigestsink: writes one SHA-256 per buffer to location, "<n> <hex>"
 *   per line. mode=tee: the TA hashes the protected DMA-buf; mode=host: the
 *   CPU maps the DMA-buf and hashes it (reference runs only). Never maps a
 *   buffer in tee mode.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/dma-buf.h>

#include <gst/gst.h>
#include <gst/base/gstbasesink.h>
#include <gst/base/gstpushsrc.h>
#include <gst/allocators/gstdmabuf.h>

#include "../secvid_tee.h"

#define SYSTEM_HEAP	"/dev/dma_heap/system"
#define XOR_BYTE	0xa5

GST_DEBUG_CATEGORY_STATIC (secvid_debug);
#define GST_CAT_DEFAULT secvid_debug

typedef enum {
	SECVID_MODE_TEE,
	SECVID_MODE_CLEAR,
} SecvidSrcMode;

typedef enum {
	SECVID_SINK_TEE,
	SECVID_SINK_HOST,
} SecvidSinkMode;

static GType secvid_src_mode_get_type(void)
{
	static const GEnumValue values[] = {
		{ SECVID_MODE_TEE, "The TA decrypts into protected memory", "tee" },
		{ SECVID_MODE_CLEAR, "XOR-stored plaintext (reference runs)", "clear" },
		{ 0, NULL, NULL },
	};
	static GType type;

	if (g_once_init_enter(&type))
		g_once_init_leave(&type, g_enum_register_static("SecvidSrcMode",
								 values));
	return type;
}

static GType secvid_sink_mode_get_type(void)
{
	static const GEnumValue values[] = {
		{ SECVID_SINK_TEE, "The TA hashes protected memory", "tee" },
		{ SECVID_SINK_HOST, "The CPU hashes (reference runs)", "host" },
		{ 0, NULL, NULL },
	};
	static GType type;

	if (g_once_init_enter(&type))
		g_once_init_leave(&type, g_enum_register_static("SecvidSinkMode",
								 values));
	return type;
}

static gboolean dmabuf_sync(int fd, guint64 flags)
{
	struct dma_buf_sync sync = { .flags = flags };

	return !ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync);
}

/* secvidsrc */

#define SECVID_TYPE_SRC (secvid_src_get_type())
G_DECLARE_FINAL_TYPE(SecvidSrc, secvid_src, SECVID, SRC, GstPushSrc)

struct _SecvidSrc {
	GstPushSrc parent;
	gchar *location;
	gchar *index;
	gchar *heap;
	SecvidSrcMode mode;
	GstCaps *caps;
	guint buffer_size;

	FILE *f;
	FILE *idx;
	guint64 n;
	GstAllocator *allocator;
	struct secvid tee;
	gboolean tee_open;
};

enum {
	PROP_SRC_0,
	PROP_SRC_LOCATION,
	PROP_SRC_INDEX,
	PROP_SRC_MODE,
	PROP_SRC_HEAP,
	PROP_SRC_CAPS,
	PROP_SRC_BUFFER_SIZE,
};

G_DEFINE_TYPE(SecvidSrc, secvid_src, GST_TYPE_PUSH_SRC)

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE("src",
	GST_PAD_SRC, GST_PAD_ALWAYS, GST_STATIC_CAPS_ANY);

static void secvid_src_set_property(GObject *object, guint id,
				    const GValue *value, GParamSpec *pspec)
{
	SecvidSrc *self = SECVID_SRC(object);

	switch (id) {
	case PROP_SRC_LOCATION:
		g_free(self->location);
		self->location = g_value_dup_string(value);
		break;
	case PROP_SRC_INDEX:
		g_free(self->index);
		self->index = g_value_dup_string(value);
		break;
	case PROP_SRC_MODE:
		self->mode = g_value_get_enum(value);
		break;
	case PROP_SRC_HEAP:
		g_free(self->heap);
		self->heap = g_value_dup_string(value);
		break;
	case PROP_SRC_CAPS:
		gst_caps_replace(&self->caps, (GstCaps *)gst_value_get_caps(value));
		break;
	case PROP_SRC_BUFFER_SIZE:
		self->buffer_size = g_value_get_uint(value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
	}
}

static void secvid_src_get_property(GObject *object, guint id, GValue *value,
				    GParamSpec *pspec)
{
	SecvidSrc *self = SECVID_SRC(object);

	switch (id) {
	case PROP_SRC_LOCATION:
		g_value_set_string(value, self->location);
		break;
	case PROP_SRC_INDEX:
		g_value_set_string(value, self->index);
		break;
	case PROP_SRC_MODE:
		g_value_set_enum(value, self->mode);
		break;
	case PROP_SRC_HEAP:
		g_value_set_string(value, self->heap);
		break;
	case PROP_SRC_CAPS:
		gst_value_set_caps(value, self->caps);
		break;
	case PROP_SRC_BUFFER_SIZE:
		g_value_set_uint(value, self->buffer_size);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
	}
}

static const gchar *secvid_src_heap(SecvidSrc *self)
{
	if (self->heap)
		return self->heap;
	return self->mode == SECVID_MODE_TEE ? SECVID_PROTECTED_HEAP :
					       SYSTEM_HEAP;
}

static gboolean secvid_src_stop(GstBaseSrc *bsrc);

static gboolean secvid_src_start(GstBaseSrc *bsrc)
{
	SecvidSrc *self = SECVID_SRC(bsrc);
	TEEC_Result res;

	if (!self->location || !self->index) {
		GST_ELEMENT_ERROR(self, RESOURCE, NOT_FOUND, (NULL),
				  ("location and index must be set"));
		return FALSE;
	}
	self->f = fopen(self->location, "rb");
	if (self->f)
		self->idx = fopen(self->index, "r");
	if (!self->f || !self->idx) {
		GST_ELEMENT_ERROR(self, RESOURCE, OPEN_READ, (NULL),
				  ("%s: %s", self->f ? self->index : self->location,
				   g_strerror(errno)));
		goto err;
	}
	if (self->mode == SECVID_MODE_TEE) {
		res = secvid_open(&self->tee);
		if (res != TEEC_SUCCESS) {
			GST_ELEMENT_ERROR(self, RESOURCE, OPEN_READ, (NULL),
					  ("secvid TA session: 0x%x", res));
			goto err;
		}
		self->tee_open = TRUE;
	}
	self->allocator = gst_dmabuf_allocator_new();
	self->n = 0;
	return TRUE;

err:
	secvid_src_stop(bsrc);
	return FALSE;
}

static gboolean secvid_src_stop(GstBaseSrc *bsrc)
{
	SecvidSrc *self = SECVID_SRC(bsrc);

	if (self->tee_open)
		secvid_close(&self->tee);
	self->tee_open = FALSE;
	g_clear_pointer(&self->f, fclose);
	g_clear_pointer(&self->idx, fclose);
	gst_clear_object(&self->allocator);
	return TRUE;
}

static GstCaps *secvid_src_get_caps(GstBaseSrc *bsrc, GstCaps *filter)
{
	SecvidSrc *self = SECVID_SRC(bsrc);
	GstCaps *caps = self->caps ? gst_caps_ref(self->caps) :
				     gst_caps_new_any();

	if (filter) {
		GstCaps *tmp = gst_caps_intersect_full(filter, caps,
						       GST_CAPS_INTERSECT_FIRST);

		gst_caps_unref(caps);
		caps = tmp;
	}
	return caps;
}

/* Restore the XOR-stored plaintext into the DMA-buf (reference runs). */
static gboolean secvid_src_fill_clear(int fd, const guint8 *data, gsize len)
{
	guint8 *map = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);

	if (map == MAP_FAILED)
		return FALSE;
	dmabuf_sync(fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_WRITE);
	for (gsize i = 0; i < len; i++)
		map[i] = data[i] ^ XOR_BYTE;
	dmabuf_sync(fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE);
	munmap(map, len);
	return TRUE;
}

/* A fresh DMA-buf of at least len and buffer-size bytes. */
static GstFlowReturn secvid_src_buffer(SecvidSrc *self, gsize len,
				       GstBuffer **buf)
{
	gsize size = MAX(len, self->buffer_size);
	GstMemory *mem;
	int fd;

	fd = secvid_heap_alloc(secvid_src_heap(self), size);
	if (fd < 0) {
		GST_ELEMENT_ERROR(self, RESOURCE, NO_SPACE_LEFT, (NULL),
				  ("%s: %s", secvid_src_heap(self),
				   g_strerror(errno)));
		return GST_FLOW_ERROR;
	}
	mem = gst_dmabuf_allocator_alloc(self->allocator, fd, size);
	if (!mem) {
		close(fd);
		return GST_FLOW_ERROR;
	}
	*buf = gst_buffer_new();
	gst_buffer_append_memory(*buf, mem);
	return GST_FLOW_OK;
}

static GstFlowReturn secvid_src_create(GstPushSrc *psrc, GstBuffer **out)
{
	SecvidSrc *self = SECVID_SRC(psrc);
	guint8 digest[SECVID_DIGEST_LEN];
	GstBuffer *buf = NULL;
	GstFlowReturn ret;
	gboolean ok = FALSE;
	guint8 *data;
	gsize len;
	int fd;

	if (fscanf(self->idx, "%zu", &len) != 1)
		return GST_FLOW_EOS;
	data = g_malloc(len);
	if (fread(data, 1, len, self->f) != len) {
		g_free(data);
		GST_ELEMENT_ERROR(self, RESOURCE, READ, (NULL),
				  ("short read at unit %" G_GUINT64_FORMAT,
				   self->n));
		return GST_FLOW_ERROR;
	}

	ret = secvid_src_buffer(self, len, &buf);
	if (ret != GST_FLOW_OK) {
		g_free(data);
		return ret;
	}
	fd = gst_dmabuf_memory_get_fd(gst_buffer_peek_memory(buf, 0));
	if (self->mode == SECVID_MODE_TEE)
		ok = secvid_decrypt(&self->tee, data, len, fd, digest) ==
		     TEEC_SUCCESS;
	else
		ok = secvid_src_fill_clear(fd, data, len);
	g_free(data);
	if (!ok) {
		gst_buffer_unref(buf);
		GST_ELEMENT_ERROR(self, RESOURCE, WRITE, (NULL),
				  ("filling unit %" G_GUINT64_FORMAT " failed",
				   self->n));
		return GST_FLOW_ERROR;
	}

	gst_buffer_resize(buf, 0, len);
	GST_BUFFER_OFFSET(buf) = self->n++;
	*out = buf;
	return GST_FLOW_OK;
}

static void secvid_src_finalize(GObject *object)
{
	SecvidSrc *self = SECVID_SRC(object);

	g_free(self->location);
	g_free(self->index);
	g_free(self->heap);
	gst_clear_caps(&self->caps);
	G_OBJECT_CLASS(secvid_src_parent_class)->finalize(object);
}

static void secvid_src_class_init(SecvidSrcClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	GstElementClass *element_class = GST_ELEMENT_CLASS(klass);
	GstBaseSrcClass *bsrc_class = GST_BASE_SRC_CLASS(klass);
	GstPushSrcClass *psrc_class = GST_PUSH_SRC_CLASS(klass);

	object_class->set_property = secvid_src_set_property;
	object_class->get_property = secvid_src_get_property;
	object_class->finalize = secvid_src_finalize;

	g_object_class_install_property(object_class, PROP_SRC_LOCATION,
		g_param_spec_string("location", "Location",
				    "Stream file (units encrypted each on its own)",
				    NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SRC_INDEX,
		g_param_spec_string("index", "Index",
				    "Unit sizes, one per line", NULL,
				    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SRC_MODE,
		g_param_spec_enum("mode", "Mode", "Who restores the plaintext",
				  secvid_src_mode_get_type(), SECVID_MODE_TEE,
				  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SRC_HEAP,
		g_param_spec_string("heap", "Heap",
				    "DMA heap path (default: protected heap in "
				    "tee mode, system heap in clear mode)", NULL,
				    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SRC_CAPS,
		g_param_spec_boxed("caps", "Caps", "Caps of the stream",
				   GST_TYPE_CAPS,
				   G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SRC_BUFFER_SIZE,
		g_param_spec_uint("buffer-size", "Buffer size",
				  "Minimum bytes per buffer (0: the unit's size)",
				  0, G_MAXUINT, 0,
				  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	gst_element_class_add_static_pad_template(element_class, &src_template);
	gst_element_class_set_static_metadata(element_class,
		"Secure video source", "Source/Video",
		"Pushes units the secvid TA decrypted into protected memory",
		"Tyler Baker <tyler.baker@oss.qualcomm.com>");

	bsrc_class->start = secvid_src_start;
	bsrc_class->stop = secvid_src_stop;
	bsrc_class->get_caps = secvid_src_get_caps;
	psrc_class->create = secvid_src_create;
}

static void secvid_src_init(SecvidSrc *self)
{
	self->mode = SECVID_MODE_TEE;
}

/* secviddigestsink */

#define SECVID_TYPE_DIGEST_SINK (secvid_digest_sink_get_type())
G_DECLARE_FINAL_TYPE(SecvidDigestSink, secvid_digest_sink, SECVID, DIGEST_SINK,
		     GstBaseSink)

struct _SecvidDigestSink {
	GstBaseSink parent;
	gchar *location;
	SecvidSinkMode mode;

	FILE *out;
	guint64 n;
	struct secvid tee;
	gboolean tee_open;
};

enum {
	PROP_SINK_0,
	PROP_SINK_LOCATION,
	PROP_SINK_MODE,
};

G_DEFINE_TYPE(SecvidDigestSink, secvid_digest_sink, GST_TYPE_BASE_SINK)

static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE("sink",
	GST_PAD_SINK, GST_PAD_ALWAYS, GST_STATIC_CAPS_ANY);

static void secvid_digest_sink_set_property(GObject *object, guint id,
					    const GValue *value,
					    GParamSpec *pspec)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(object);

	switch (id) {
	case PROP_SINK_LOCATION:
		g_free(self->location);
		self->location = g_value_dup_string(value);
		break;
	case PROP_SINK_MODE:
		self->mode = g_value_get_enum(value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
	}
}

static void secvid_digest_sink_get_property(GObject *object, guint id,
					    GValue *value, GParamSpec *pspec)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(object);

	switch (id) {
	case PROP_SINK_LOCATION:
		g_value_set_string(value, self->location);
		break;
	case PROP_SINK_MODE:
		g_value_set_enum(value, self->mode);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
	}
}

static gboolean secvid_digest_sink_stop(GstBaseSink *bsink);

static gboolean secvid_digest_sink_start(GstBaseSink *bsink)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(bsink);
	TEEC_Result res;

	if (!self->location) {
		GST_ELEMENT_ERROR(self, RESOURCE, NOT_FOUND, (NULL),
				  ("location must be set"));
		return FALSE;
	}
	self->out = fopen(self->location, "w");
	if (!self->out) {
		GST_ELEMENT_ERROR(self, RESOURCE, OPEN_WRITE, (NULL),
				  ("%s: %s", self->location, g_strerror(errno)));
		return FALSE;
	}
	if (self->mode == SECVID_SINK_TEE) {
		res = secvid_open(&self->tee);
		if (res != TEEC_SUCCESS) {
			GST_ELEMENT_ERROR(self, RESOURCE, OPEN_READ, (NULL),
					  ("secvid TA session: 0x%x", res));
			secvid_digest_sink_stop(bsink);
			return FALSE;
		}
		self->tee_open = TRUE;
	}
	self->n = 0;
	return TRUE;
}

static gboolean secvid_digest_sink_stop(GstBaseSink *bsink)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(bsink);

	if (self->tee_open)
		secvid_close(&self->tee);
	self->tee_open = FALSE;
	g_clear_pointer(&self->out, fclose);
	return TRUE;
}

static gboolean host_digest(int fd, gsize offset, gsize len,
			    guint8 digest[SECVID_DIGEST_LEN])
{
	GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
	gsize dlen = SECVID_DIGEST_LEN;
	guint8 *map = mmap(NULL, offset + len, PROT_READ, MAP_SHARED, fd, 0);

	if (map == MAP_FAILED) {
		g_checksum_free(sum);
		return FALSE;
	}
	dmabuf_sync(fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ);
	g_checksum_update(sum, map + offset, len);
	dmabuf_sync(fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ);
	munmap(map, offset + len);
	g_checksum_get_digest(sum, digest, &dlen);
	g_checksum_free(sum);
	return TRUE;
}

static GstFlowReturn secvid_digest_sink_render(GstBaseSink *bsink,
					       GstBuffer *buf)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(bsink);
	guint8 digest[SECVID_DIGEST_LEN];
	GstMemory *mem;
	gboolean ok;
	int fd;

	if (gst_buffer_n_memory(buf) != 1 ||
	    !gst_is_dmabuf_memory(mem = gst_buffer_peek_memory(buf, 0))) {
		GST_ELEMENT_ERROR(self, STREAM, WRONG_TYPE, (NULL),
				  ("buffer %" G_GUINT64_FORMAT " is not a single "
				   "DMA-buf", self->n));
		return GST_FLOW_ERROR;
	}
	fd = gst_dmabuf_memory_get_fd(mem);
	if (self->mode == SECVID_SINK_TEE)
		ok = secvid_digest(&self->tee, fd, mem->offset, mem->size,
				   digest) == TEEC_SUCCESS;
	else
		ok = host_digest(fd, mem->offset, mem->size, digest);
	if (!ok) {
		GST_ELEMENT_ERROR(self, RESOURCE, READ, (NULL),
				  ("hashing buffer %" G_GUINT64_FORMAT " failed",
				   self->n));
		return GST_FLOW_ERROR;
	}

	fprintf(self->out, "%" G_GUINT64_FORMAT " ", self->n++);
	for (int i = 0; i < SECVID_DIGEST_LEN; i++)
		fprintf(self->out, "%02x", digest[i]);
	fprintf(self->out, "\n");
	return GST_FLOW_OK;
}

static void secvid_digest_sink_finalize(GObject *object)
{
	SecvidDigestSink *self = SECVID_DIGEST_SINK(object);

	g_free(self->location);
	G_OBJECT_CLASS(secvid_digest_sink_parent_class)->finalize(object);
}

static void secvid_digest_sink_class_init(SecvidDigestSinkClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	GstElementClass *element_class = GST_ELEMENT_CLASS(klass);
	GstBaseSinkClass *bsink_class = GST_BASE_SINK_CLASS(klass);

	object_class->set_property = secvid_digest_sink_set_property;
	object_class->get_property = secvid_digest_sink_get_property;
	object_class->finalize = secvid_digest_sink_finalize;

	g_object_class_install_property(object_class, PROP_SINK_LOCATION,
		g_param_spec_string("location", "Location",
				    "Digest file, \"<n> <sha256>\" per line", NULL,
				    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(object_class, PROP_SINK_MODE,
		g_param_spec_enum("mode", "Mode", "Who hashes the buffers",
				  secvid_sink_mode_get_type(), SECVID_SINK_TEE,
				  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	gst_element_class_add_static_pad_template(element_class, &sink_template);
	gst_element_class_set_static_metadata(element_class,
		"Secure video digest sink", "Sink/Video",
		"Has the secvid TA hash protected buffers",
		"Tyler Baker <tyler.baker@oss.qualcomm.com>");

	bsink_class->start = secvid_digest_sink_start;
	bsink_class->stop = secvid_digest_sink_stop;
	bsink_class->render = secvid_digest_sink_render;
}

static void secvid_digest_sink_init(SecvidDigestSink *self)
{
	self->mode = SECVID_SINK_TEE;
	gst_base_sink_set_sync(GST_BASE_SINK(self), FALSE);
}

static gboolean plugin_init(GstPlugin *plugin)
{
	GST_DEBUG_CATEGORY_INIT(secvid_debug, "secvid", 0, "secvid elements");
	return gst_element_register(plugin, "secvidsrc", GST_RANK_NONE,
				    SECVID_TYPE_SRC) &&
	       gst_element_register(plugin, "secviddigestsink", GST_RANK_NONE,
				    SECVID_TYPE_DIGEST_SINK);
}

#define PACKAGE "optee_examples"
GST_PLUGIN_DEFINE(GST_VERSION_MAJOR, GST_VERSION_MINOR, secvid,
		  "OP-TEE secvid TA elements", plugin_init, "1.0", "BSD",
		  "optee_examples", "https://github.com/linaro-swg/optee_examples")
