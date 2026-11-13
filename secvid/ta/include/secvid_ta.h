/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef SECVID_TA_H
#define SECVID_TA_H

#define SECVID_TA_UUID { 0x1b7d45ae, 0x0f97, 0x4ee8, \
	{ 0xbd, 0xeb, 0xf0, 0x5a, 0x85, 0x2d, 0xe1, 0x80 } }

/*
 * Decrypt one unit (AES-128-CTR from the start of the key stream) into a
 * protected (secure) buffer of the same size and return the SHA-256 of
 * the plaintext. Refused with TEE_ERROR_SECURITY when the output is not
 * secure memory.
 *
 * [in]  memref  ciphertext (non-secure)
 * [out] memref  plaintext (secure)
 * [out] memref  32 bytes of SHA-256
 */
#define SECVID_CMD_DECRYPT	0

/*
 * SHA-256 of a range of a secure buffer.
 *
 * [in]  memref  the range (secure)
 * [out] memref  32 bytes of SHA-256
 */
#define SECVID_CMD_DIGEST	1

#endif
