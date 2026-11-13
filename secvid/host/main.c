// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * optee_example_secvid <stream.enc> <stream.idx>: decrypts each access unit
 * of an encrypted stream (one ciphertext per unit, sizes in stream.idx, one
 * per line) into its own buffer from the TEE protected heap and prints the
 * SHA-256 the TA computed of each plaintext. Checks first that the TA
 * refuses to decrypt into non-secure memory (ordinary host memory) with
 * TEEC_ERROR_SECURITY.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <tee_client_api.h>

#include <secvid_ta.h>
#include "secvid_tee.h"

/* DECRYPT into ordinary host memory, which the TA must refuse. */
static TEEC_Result decrypt_to_host(struct secvid *s, void *ct, size_t len)
{
	uint8_t digest[SECVID_DIGEST_LEN];
	TEEC_Operation op = { 0 };
	uint32_t origin = 0;
	TEEC_Result res;
	void *out = malloc(len);

	if (!out)
		err(1, "malloc");
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = ct;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = len;
	op.params[2].tmpref.buffer = digest;
	op.params[2].tmpref.size = sizeof(digest);
	res = TEEC_InvokeCommand(&s->sess, SECVID_CMD_DECRYPT, &op, &origin);
	free(out);
	return res;
}

static void print_digest(unsigned int n, const uint8_t *d)
{
	printf("%u ", n);
	for (int i = 0; i < SECVID_DIGEST_LEN; i++)
		printf("%02x", d[i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	uint8_t digest[SECVID_DIGEST_LEN];
	FILE *enc = NULL, *idx = NULL;
	struct secvid s = { 0 };
	unsigned int n = 0;
	size_t len = 0;
	TEEC_Result res;
	void *ct = NULL;
	int fd;

	if (argc != 3)
		errx(1, "usage: %s <stream.enc> <stream.idx>", argv[0]);
	enc = fopen(argv[1], "rb");
	idx = fopen(argv[2], "r");
	if (!enc || !idx)
		err(1, "open");

	res = secvid_open(&s);
	if (res != TEEC_SUCCESS)
		errx(1, "opening a session with the secvid TA: 0x%x", res);

	while (fscanf(idx, "%zu", &len) == 1) {
		ct = realloc(ct, len);
		if (!ct || fread(ct, 1, len, enc) != len)
			errx(1, "short read at access unit %u", n);

		if (!n) {
			res = decrypt_to_host(&s, ct, len);
			if (res != TEEC_ERROR_SECURITY)
				errx(1, "non-secure output: 0x%x, not TEE_ERROR_SECURITY",
				     res);
			printf("non-secure output refused: 0x%x\n", res);
		}

		fd = secvid_heap_alloc(SECVID_PROTECTED_HEAP, len);
		if (fd < 0)
			err(1, "%s", SECVID_PROTECTED_HEAP);
		res = secvid_decrypt(&s, ct, len, fd, digest);
		close(fd);
		if (res != TEEC_SUCCESS)
			errx(1, "access unit %u: decrypt failed: 0x%x", n, res);
		print_digest(n++, digest);
	}

	free(ct);
	secvid_close(&s);
	fclose(enc);
	fclose(idx);
	return 0;
}
