// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * secvid TA: decrypts content into protected (secure) buffers, as a DRM TA
 * feeding a secure decoder would, and hashes protected buffers so that a
 * test can check what a codec produced there.
 *
 * Demo shortcuts, not for a product: the key is built in, every unit is
 * decrypted from the start of the same CTR key stream (one key, one IV),
 * and DECRYPT and DIGEST return hashes of the plaintext (DIGEST of any
 * range of a protected buffer the host asks for), an oracle on it. A real
 * TA gets its keys from a key system, uses a fresh IV per unit and does
 * not expose such commands.
 */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <secvid_ta.h>

static const uint8_t stream_key[16] = {
	0x5d, 0xaa, 0x82, 0x2d, 0x6c, 0x0e, 0xec, 0xd9,
	0xe5, 0x80, 0xab, 0x8b, 0x95, 0xab, 0x3f, 0x80
};

static const uint8_t stream_iv[16] = {
	0x1b, 0x78, 0x2a, 0xd1, 0xe4, 0x5f, 0x0b, 0x5d,
	0xf4, 0xff, 0x9f, 0xde, 0xaa, 0x6a, 0x09, 0xdf
};

#define SHA256_SIZE	32

static TEE_Result digest(const void *buf, size_t len, TEE_Param *out)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t dlen = SHA256_SIZE;

	if (out->memref.size < SHA256_SIZE)
		return TEE_ERROR_SHORT_BUFFER;
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res)
		return res;
	res = TEE_DigestDoFinal(op, buf, len, out->memref.buffer, &dlen);
	TEE_FreeOperation(op);
	out->memref.size = SHA256_SIZE;
	return res;
}

/* Plaintext only ever lives in secure memory. */
static TEE_Result check_secure(TEE_Param *p, uint32_t access)
{
	if (!p->memref.size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (TEE_CheckMemoryAccessRights(access | TEE_MEMORY_ACCESS_SECURE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					p->memref.buffer, p->memref.size))
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}

/*
 * Protected buffers are cacheable in the TA and the codec reads and writes
 * them without snooping: push what the TA wrote to memory, and drop stale
 * lines before reading what a device wrote.
 */
static TEE_Result sync_for_device(void *buf, size_t len)
{
	return TEE_CacheFlush(buf, len);
}

static TEE_Result sync_for_cpu(void *buf, size_t len)
{
	return TEE_CacheInvalidate(buf, len);
}

static TEE_Result cmd_decrypt(uint32_t types, TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_Attribute attr = { };
	TEE_Result res = TEE_SUCCESS;
	size_t len = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	res = check_secure(&p[1], TEE_MEMORY_ACCESS_WRITE);
	if (res)
		return res;
	if (p[0].memref.size != p[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, 128);
	if (res)
		return res;
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key);
	if (res)
		goto out;
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, stream_key,
			     sizeof(stream_key));
	res = TEE_PopulateTransientObject(key, &attr, 1);
	if (res)
		goto out;
	res = TEE_SetOperationKey(op, key);
	if (res)
		goto out;
	TEE_CipherInit(op, stream_iv, sizeof(stream_iv));
	len = p[1].memref.size;
	res = TEE_CipherDoFinal(op, p[0].memref.buffer, p[0].memref.size,
				p[1].memref.buffer, &len);
	if (res)
		goto out;
	res = sync_for_device(p[1].memref.buffer, p[1].memref.size);
	if (res)
		goto out;
	res = digest(p[1].memref.buffer, p[1].memref.size, &p[2]);
out:
	TEE_FreeTransientObject(key);
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_digest(uint32_t types, TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	res = check_secure(&p[0], TEE_MEMORY_ACCESS_READ);
	if (res)
		return res;
	res = sync_for_cpu(p[0].memref.buffer, p[0].memref.size);
	if (res)
		return res;
	return digest(p[0].memref.buffer, p[0].memref.size, &p[1]);
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t types __unused,
				    TEE_Param p[TEE_NUM_PARAMS] __unused,
				    void **ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *ctx __unused, uint32_t cmd,
				      uint32_t types,
				      TEE_Param p[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case SECVID_CMD_DECRYPT:
		return cmd_decrypt(types, p);
	case SECVID_CMD_DIGEST:
		return cmd_digest(types, p);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
