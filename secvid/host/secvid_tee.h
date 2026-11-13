/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef SECVID_TEE_H
#define SECVID_TEE_H

#include <stddef.h>
#include <stdint.h>
#include <tee_client_api.h>

#define SECVID_DIGEST_LEN	32

/* The Linux TEE protected-memory heap for secure video. */
#define SECVID_PROTECTED_HEAP	"/dev/dma_heap/protected,secure-video"

struct secvid {
	TEEC_Context ctx;
	TEEC_Session sess;
};

TEEC_Result secvid_open(struct secvid *s);
void secvid_close(struct secvid *s);

/* A DMA-buf of at least @len bytes from the DMA heap @heap, or -1. */
int secvid_heap_alloc(const char *heap, size_t len);

/*
 * The TA decrypts @len bytes of @ct (one frame or access unit, encrypted
 * on its own) into the DMA-buf @fd, which must be protected memory, and
 * returns the SHA-256 of the plaintext in @digest.
 */
TEEC_Result secvid_decrypt(struct secvid *s, const void *ct, size_t len,
			   int fd, uint8_t digest[SECVID_DIGEST_LEN]);

/* The TA's SHA-256 of @len bytes at @offset of the protected DMA-buf @fd. */
TEEC_Result secvid_digest(struct secvid *s, int fd, size_t offset,
			  size_t len, uint8_t digest[SECVID_DIGEST_LEN]);

#endif
