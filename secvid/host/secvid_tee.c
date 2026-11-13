// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/dma-heap.h>

#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

#include <secvid_ta.h>
#include "secvid_tee.h"

TEEC_Result secvid_open(struct secvid *s)
{
	TEEC_UUID uuid = SECVID_TA_UUID;
	uint32_t origin = 0;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &s->ctx);
	if (res != TEEC_SUCCESS)
		return res;
	res = TEEC_OpenSession(&s->ctx, &s->sess, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		TEEC_FinalizeContext(&s->ctx);
	return res;
}

void secvid_close(struct secvid *s)
{
	TEEC_CloseSession(&s->sess);
	TEEC_FinalizeContext(&s->ctx);
}

int secvid_heap_alloc(const char *heap, size_t len)
{
	struct dma_heap_allocation_data d = {
		.len = len,
		.fd_flags = O_RDWR | O_CLOEXEC,
	};
	int hfd = open(heap, O_RDONLY | O_CLOEXEC);
	int ret = -1;

	if (hfd < 0)
		return -1;
	if (!ioctl(hfd, DMA_HEAP_IOCTL_ALLOC, &d))
		ret = d.fd;
	close(hfd);
	return ret;
}

TEEC_Result secvid_decrypt(struct secvid *s, const void *ct, size_t len,
			   int fd, uint8_t digest[SECVID_DIGEST_LEN])
{
	TEEC_SharedMemory shm = { .flags = TEEC_MEM_OUTPUT };
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	TEEC_Result res;

	res = TEEC_RegisterSharedMemoryFileDescriptor(&s->ctx, &shm, fd);
	if (res != TEEC_SUCCESS)
		return res;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)ct;
	op.params[0].tmpref.size = len;
	op.params[1].memref.parent = &shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = len;
	op.params[2].tmpref.buffer = digest;
	op.params[2].tmpref.size = SECVID_DIGEST_LEN;
	res = TEEC_InvokeCommand(&s->sess, SECVID_CMD_DECRYPT, &op, &origin);
	TEEC_ReleaseSharedMemory(&shm);
	return res;
}

TEEC_Result secvid_digest(struct secvid *s, int fd, size_t offset,
			  size_t len, uint8_t digest[SECVID_DIGEST_LEN])
{
	TEEC_SharedMemory shm = { .flags = TEEC_MEM_INPUT };
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	TEEC_Result res;

	res = TEEC_RegisterSharedMemoryFileDescriptor(&s->ctx, &shm, fd);
	if (res != TEEC_SUCCESS)
		return res;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);
	op.params[0].memref.parent = &shm;
	op.params[0].memref.offset = offset;
	op.params[0].memref.size = len;
	op.params[1].tmpref.buffer = digest;
	op.params[1].tmpref.size = SECVID_DIGEST_LEN;
	res = TEEC_InvokeCommand(&s->sess, SECVID_CMD_DIGEST, &op, &origin);
	TEEC_ReleaseSharedMemory(&shm);
	return res;
}
