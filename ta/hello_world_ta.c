/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <hello_world_ta.h>

/* AES defines */
#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)
#define AES_BUFFER_SIZE			4096

/* RSA info */
uint32_t rsa_key_size = 1024;

uint8_t server_exp[] = { 0x01, 0x00, 0x01 };
uint32_t server_explen = sizeof(server_exp);

uint8_t server_mod[] = {
	0xad,0xdf,0xa6,0x84,0xb6,0xc2,0xf0,0xf3,0xe4,0x8a,0xfb,0x13,0xd4,0xb9,
	0xe9,0x6c,0x7d,0xa8,0xe2,0x25,0xb1,0x14,0x7d,0xed,0xc7,0x01,0xb0,0x26,0xb7,
	0x05,0x98,0x00,0xb1,0xd4,0xdd,0xdd,0x00,0x10,0x02,0x68,0xa5,0xf4,0x84,0x5e,
	0x4f,0xa3,0x4b,0xec,0x59,0x89,0x8e,0xc2,0x27,0x46,0x0c,0xa9,0xf4,0xde,0x47,
	0xb7,0xfe,0x56,0x9a,0x2d,0x45,0x30,0xb6,0xc5,0x3b,0xa1,0x4a,0x92,0xef,0xe3,
	0xdd,0xe1,0x72,0x6a,0xcc,0xbb,0x6f,0xe7,0xf4,0x71,0xe4,0x0a,0x5a,0x80,0xa1,
	0x41,0xea,0x38,0x00,0xb7,0x83,0x01,0xad,0x1b,0x16,0x41,0x98,0x96,0x4e,0x2b,
	0x61,0xd9,0x5b,0x76,0xd4,0x33,0x0e,0x9c,0x0f,0x73,0xb6,0xac,0xb3,0x50,0xf5,
	0x70,0x2c,0x2f,0xc0,0x44,0x98,0xe0,0x21,0xf7
};
uint32_t server_modlen = sizeof(server_mod);

uint8_t server_pvt[] = {
	0x9c,0x04,0xbe,0xd0,0x01,0x8b,0x05,0x59,0x64,0x6f,0x4d,0x82,0xea,0xf4,
	0x73,0xbf,0x75,0x36,0x70,0xce,0xef,0x89,0xfa,0xc1,0xbd,0x3c,0x07,0x8b,0x85,
	0xd9,0x50,0x1e,0xf7,0x73,0x92,0x2d,0xb7,0xdb,0xa5,0xbd,0xaf,0x84,0xac,0xae,
	0x4f,0xf9,0xb0,0xac,0x01,0x60,0x0c,0xa8,0xad,0x43,0x0f,0x24,0x06,0x64,0xda,
	0xa8,0x00,0x62,0x47,0x6e,0xf1,0xfa,0xe5,0xa1,0x5f,0x54,0x6f,0x68,0x5f,0xa3,
	0x00,0xc3,0x97,0xf2,0x59,0xce,0xcf,0x67,0xfa,0x66,0x5f,0x3c,0xc6,0xba,0x50,
	0xc7,0xbf,0x8e,0x1d,0x73,0x21,0x6c,0x53,0x45,0x68,0xdb,0x1b,0x44,0x5c,0x78,
	0xdc,0x5c,0x43,0xc2,0x5e,0xf8,0x23,0x6e,0x84,0xde,0x86,0x1b,0x98,0xd2,0xb1,
	0xc0,0xec,0xc6,0xf2,0x0a,0x95,0xce,0x47,0x11
};
uint32_t server_pvtlen = sizeof(server_pvt);

uint8_t client_exp[] = { 0x01, 0x00, 0x01 };
uint32_t client_explen = sizeof(client_exp);

uint8_t client_mod[] = {
	0xe9,0x32,0x33,0xe7,0x87,0xdd,0x9c,0x1c,0x1e,0xac,0x3c,0x21,0xe4,0x60,
	0x5a,0xbf,0x55,0x47,0x55,0x00,0xdd,0xd0,0x96,0xb5,0x2a,0xae,0xeb,0x82,0xa1,
	0xea,0x78,0x5e,0x5f,0x0f,0xd4,0x07,0x30,0x68,0x9e,0xe5,0x87,0x63,0x9b,0xe2,
	0x84,0x4f,0x4a,0x1d,0x81,0x42,0x16,0x57,0x96,0xf3,0xf7,0x92,0x4d,0xce,0x20,
	0x82,0x77,0x75,0x06,0xda,0x88,0xb7,0xb9,0x66,0x77,0x7a,0x4c,0x53,0xab,0x27,
	0x0c,0x2f,0x01,0x67,0xff,0xb6,0xe0,0xf0,0x91,0xea,0x87,0xe2,0xc7,0xfe,0x3d,
	0xf9,0xf7,0x39,0xb5,0x1c,0x02,0xb1,0x33,0xca,0xeb,0xda,0x53,0xaa,0xef,0xe1,
	0xe9,0xd7,0x1e,0xce,0x3f,0xfc,0x25,0x80,0x11,0xa8,0x55,0x2f,0x36,0x7e,0x8e,
	0xfb,0xf2,0x49,0xd9,0x50,0x50,0xe7,0x98,0x15
};
uint32_t client_modlen = sizeof(client_mod);

uint8_t client_pvt[] = {
	0x7d,0xc4,0x0e,0x8c,0x33,0x11,0x48,0xcd,0x3d,0x99,0xa4,0x40,0x9f,0x1b,0x7c,
	0x35,0xae,0x77,0x6f,0x17,0xad,0x89,0x7e,0x8e,0x2c,0x7b,0xf4,0x16,0x1a,0xdf,
	0x0a,0x95,0xd2,0xed,0x05,0x6b,0xef,0x26,0xad,0x73,0x9a,0xc6,0x14,0xdf,0x60,
	0x7e,0x26,0xb9,0xac,0xe9,0x88,0x85,0x2a,0xab,0x5e,0xfc,0xef,0xab,0x58,0x8b,
	0x24,0x83,0xdf,0xf2,0x5a,0xb3,0x4e,0x75,0x3b,0x8d,0x98,0x0d,0x1a,0x90,0xb0,
	0x57,0xd3,0x53,0xba,0xc5,0x28,0x26,0xfb,0x69,0x25,0x9c,0x11,0xe0,0x1c,0x06,
	0xbd,0x3b,0x15,0x52,0x6e,0x2f,0x92,0x86,0xf0,0xa1,0x40,0x2f,0xdd,0x27,0xab,
	0xa0,0xab,0x80,0x99,0xd9,0x3b,0x79,0x56,0x87,0x68,0xb4,0x40,0xd5,0x87,0x70,
	0xe6,0xd1,0x7d,0xdd,0x2e,0x22,0xa3,0x0d
};
uint32_t client_pvtlen = sizeof(client_pvt);

/*
 * Ciphering context: each opened session relates to a cipehring operation.
 * - configure the AES flavour from a command.
 * - load key from a command (here the key is provided by the REE)
 * - reset init vector (here IV is provided by the REE)
 * - cipher a buffer frame (here input and output buffers are non-secure)
 */
struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

/* Status info */
char msg[AES_BUFFER_SIZE] = "Number 1: OK!\n";
uint32_t msg_len = AES_BUFFER_SIZE;
char temp[AES_BUFFER_SIZE];
uint32_t temp_size = AES_BUFFER_SIZE;

/* Machine info */
char info[] = "Machine Number: 1";
uint32_t info_len = sizeof(info);

/* AES key info */
char *aes_key;
uint32_t aes_key_size;
char *rsa_ciph;
uint32_t rsa_ciph_size;
char *rsa_plain;
uint32_t rsa_plain_size;

/*
 * Few routines to convert IDs from TA API into IDs from OP-TEE.
 */
static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_AES_ALGO_ECB:
		*algo = TEE_ALG_AES_ECB_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CBC:
		*algo = TEE_ALG_AES_CBC_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CTR:
		*algo = TEE_ALG_AES_CTR;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param) {
	case AES128_KEY_BYTE_SIZE:
	case AES256_KEY_BYTE_SIZE:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param) {
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Process command TA_AES_CMD_PREPARE. API in aes_ta.h
 *
 * Allocate resources required for the ciphering operation.
 * During ciphering operation, when expect client can:
 * - update the key materials (provided by client)
 * - reset the initial vector (provided by client)
 * - cipher an input buffer into an output buffer (provided by client)
 */
static TEE_Result alloc_resources(void *session, uint32_t param_types,
				  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: get ciphering resources", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ta2tee_algo_id(params[0].value.a, &sess->algo);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_key_size(params[1].value.a, &sess->key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_mode_id(params[2].value.a, &sess->mode);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Ready to allocate the resources which are:
	 * - an operation handle, for an AES ciphering of given configuration
	 * - a transient object that will be use to load the key materials
	 *   into the AES ciphering operation.
	 */

	/* Free potential previous operation */
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    sess->mode,
				    sess->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		sess->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free potential previous transient object */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  sess->key_size * 8,
					  &sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		sess->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/*
	 * When loading a key in the cipher session, set_aes_key()
	 * will reset the operation and load a key. But we cannot
	 * reset and operation that has no key yet (GPD TEE Internal
	 * Core API Specification – Public Release v1.1.1, section
	 * 6.2.5 TEE_ResetOperation). In consequence, we will load a
	 * dummy key in the operation so that operation can be reset
	 * when updating the key.
	 */
	key = TEE_Malloc(sess->key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	return res;

err:
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

/* Generate AES random key */
static TEE_Result gen_aes_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: generate key", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	aes_key_size = params[0].value.a;
	aes_key = TEE_Malloc(aes_key_size*sizeof(char), 0);
	TEE_GenerateRandom(aes_key, aes_key_size);
	IMSG("aes_key: %s", aes_key);
	IMSG("aes_key_size = %" PRId32, aes_key_size);

	if (aes_key_size != sess->key_size) {
		EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes",
		     aes_key_size, sess->key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_SET_KEY. API in aes_ta.h
 */
static TEE_Result set_aes_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;

	/* Get ciphering context from session ID */
	DMSG("Session %p: set key", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;


	/*
	 * Load the key material into the configured operation
	 * - create a secret key attribute with the key material
	 *   TEE_InitRefAttribute()
	 * - reset transient object and load attribute data
	 *   TEE_ResetTransientObject()
	 *   TEE_PopulateTransientObject()
	 * - load the key (transient object) into the ciphering operation
	 *   TEE_SetOperationKey()
	 *
	 * TEE_SetOperationKey() requires operation to be in "initial state".
	 * We can use TEE_ResetOperation() to reset the operation but this
	 * API cannot be used on operation with key(s) not yet set. Hence,
	 * when allocating the operation handle, we load a dummy key.
	 * Thus, set_key sequence always reset then set key on operation.
	 */

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, aes_key, aes_key_size);

	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return res;
}

/*
 * Process command TA_AES_CMD_SET_IV. API in aes_ta.h
 */
static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	size_t iv_sz;
	char *iv;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	/*
	 * Init cipher operation with the initialization vector.
	 */
	TEE_CipherInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_CIPHER. API in aes_ta.h
 */
static TEE_Result cipher_buffer(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size < AES_BUFFER_SIZE) {
		EMSG("Bad sizes: %d, Expect: %d", params[0].memref.size, AES_BUFFER_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (sess->op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Process ciphering operation on provided buffers
	 */
	if(sess->mode == 0){
		DMSG("AES Encode");
		return TEE_CipherUpdate(sess->op_handle, msg, msg_len,
				params[0].memref.buffer, &params[0].memref.size);
	}
	else{
		DMSG("AES Decode");
		TEE_Result res;
		res = TEE_CipherUpdate(sess->op_handle,
				params[0].memref.buffer, params[0].memref.size, temp, &temp_size);
		if(temp[0] == 'N'){
			params[0].memref.size = 1;
			int i = 0, pos;
			while(1){
				if(msg[i] == '\n'){
					pos = i+1;
					i = 0;
					break;
				}
				else i++;
			}
			while(1){
				if(temp[i] == '\n'){
					msg[pos] = '\n';
					break;
				}
				else{
					msg[pos] = temp[i];
					i++;
					pos++;
				}
			}
		}
		else params[0].memref.size = 0;
		IMSG("msg: %s", msg);
		TEE_MemFill(temp, 0, AES_BUFFER_SIZE);
		return res;
	}
}

static TEE_Result cmd_hash(void *session, uint32_t pt, TEE_Param params[4])
{
	TEE_Result res;
	char *hash;
	uint32_t hash_len;
	TEE_OperationHandle op;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	hash_len = params[0].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	IMSG("hash_len = %" PRId32, hash_len);
						
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_DIGEST, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_SHA256, 0, res);
		return res;
	}
	
	DMSG("Start TEE_DigestDoFinal!");
	
	res = TEE_DigestDoFinal(op, info, info_len, hash, &hash_len);
	if (res) {
		EMSG("TEE_DigestDoFinal(output size: %" PRId32 "): %#" PRIx32, hash_len, res);
		return res;
	}
	
	DMSG("TEE_DigestDoFinal finish!");
	
	params[0].memref.size = hash_len;
	TEE_MemMove(params[0].memref.buffer, hash, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	TEE_FreeOperation(op);
	
	return res;
}

static TEE_Result cmd_sign(void *session, uint32_t pt, TEE_Param params[4])
{
	TEE_Result res;
	char *hash;
	uint32_t hash_len;
	char *sign;
	uint32_t sign_len;
	TEE_OperationHandle op;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	hash_len = params[0].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	TEE_MemMove(hash, params[0].memref.buffer, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	sign_len = params[1].memref.size;
	sign = TEE_Malloc(sign_len, 0);
	
	IMSG("sign_len = %" PRId32, sign_len);
	
	DMSG("Populate Private Key!");

	TEE_ObjectHandle pvt_key;
	
	IMSG("server_exp: %" PRIu8, server_exp);
	IMSG("server_explen = %" PRId32, server_explen);
	IMSG("server_mod: %" PRIu8, server_mod);
	IMSG("server_modlen = %" PRId32, server_modlen);
	IMSG("server_pvt: %" PRIu8, server_pvt);
	IMSG("server_pvtlen = %" PRId32, server_pvtlen);

	TEE_Attribute pvt_attrs[3];
	TEE_InitRefAttribute(&pvt_attrs[0], TEE_ATTR_RSA_MODULUS, server_mod, server_modlen);
	TEE_InitRefAttribute(&pvt_attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, server_exp, server_explen);
	TEE_InitRefAttribute(&pvt_attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, server_pvt, server_pvtlen);

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, rsa_key_size, &pvt_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_TYPE_RSA_KEYPAIR, rsa_key_size, res);
		return res;
	}

	res = TEE_PopulateTransientObject(pvt_key, pvt_attrs, 3);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}

	DMSG("Private Key succeed!");
		
	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
					TEE_MODE_SIGN, rsa_key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_SIGN, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, 0, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pvt_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}
	
	DMSG("Start TEE_AsymmetricSignDigest!");
	
	res = TEE_AsymmetricSignDigest(op, NULL, 0, hash, hash_len, sign, &sign_len);
	if (res) {
		EMSG("TEE_AsymmetricSignDigest(sign size = %" PRId32 "): %#" PRIx32, sign_len, res);
		return res;
	}
	
	DMSG("TEE_AsymmetricSignDigest finish!");
	
	IMSG("sign: %s size = %" PRId32, sign, sign_len);
	
	params[1].memref.size = sign_len;
	TEE_MemMove(params[1].memref.buffer, sign, sign_len);

out:
	TEE_Free(hash);
	TEE_Free(sign);
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_verify(void *session, uint32_t pt, TEE_Param params[4])
{
	TEE_Result res;
	char *sign;
	uint32_t sign_len;
	char *hash;
	uint32_t hash_len;
	TEE_OperationHandle op;
	TEE_ObjectHandle pub_key;
	const uint32_t key_type = TEE_TYPE_RSA_PUBLIC_KEY;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	hash_len = params[0].memref.size;
	hash = TEE_Malloc(hash_len, 0);
	TEE_MemMove(hash, params[0].memref.buffer, hash_len);
	
	IMSG("hash: %s size = %" PRId32, hash, hash_len);
	
	sign_len = params[1].memref.size;
	sign = TEE_Malloc(sign_len, 0);
	TEE_MemMove(sign, params[1].memref.buffer, sign_len);
	
	IMSG("sign: %s size = %" PRId32, sign, sign_len);
	
	DMSG("Populate Public Key!");
	
	TEE_Attribute attrs[2];
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, server_mod, server_modlen);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, server_exp, server_explen);
	
	res = TEE_AllocateTransientObject(key_type, rsa_key_size, &pub_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, rsa_key_size, res);
		return res;
	}
	
	res = TEE_PopulateTransientObject(pub_key, attrs, 2);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}
	
	DMSG("Public Key Succeed!");
	
	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
					TEE_MODE_VERIFY, rsa_key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_VERIFY, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, 0, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pub_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}
	
	DMSG("Start TEE_AsymmetricVerifyDigest!");
	
	res = TEE_AsymmetricVerifyDigest(op, NULL, 0, hash, hash_len, sign, sign_len);
	if (res) {
		EMSG("TEE_AsymmetricSVerifyDigest(): %#" PRIx32, res);
		return res;
	} else { DMSG("TEE_AsymmetricSVerifyDigest Succeed!"); }
		
	
	DMSG("TEE_AsymmetricVerifyDigest finish!");

out:
	TEE_Free(hash);
	TEE_Free(sign);
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_enc(void *session, uint32_t pt, TEE_Param params[4])
{
	TEE_Result res;
	TEE_OperationHandle op;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	
	const uint32_t key_type = TEE_TYPE_RSA_PUBLIC_KEY;
	
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	IMSG("plain: %s", aes_key);
	IMSG("size = %" PRIu32, aes_key_size);

	/* === Public Key === */
	
	DMSG("Populate Public Key!");
	
	TEE_ObjectHandle pub_key;
	
	TEE_Attribute attrs[2];
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, client_mod, client_modlen);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, client_exp, client_explen);
	
	res = TEE_AllocateTransientObject(key_type, rsa_key_size, &pub_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, rsa_key_size, res);
		return res;
	}
	
	res = TEE_PopulateTransientObject(pub_key, attrs, 2);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}
	
	DMSG("Public Key Succeed!");
	
	/* === Public Key Operations Finish Line === */
	
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    rsa_key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, rsa_key_size, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pub_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

encrypt:
	res = TEE_AsymmetricEncrypt(op, NULL, 0, aes_key, aes_key_size, rsa_ciph,
				    &rsa_ciph_size);
	if (res) {
		EMSG("TEE_AsymmetricEncrypt(size = %" PRId32 "): %#" PRIx32, rsa_ciph_size, res);
		rsa_ciph = TEE_Malloc(rsa_ciph_size, 0);
		goto encrypt;
	}

out:
	IMSG("cipher: %s", rsa_ciph);
	IMSG("size = %" PRIu32, rsa_ciph_size);
	params[0].memref.size = rsa_ciph_size;
	TEE_MemMove(params[0].memref.buffer, rsa_ciph, rsa_ciph_size);
	IMSG("buffer: %s", params[0].memref.buffer);
	IMSG("size = %" PRIu32, params[0].memref.size);
	TEE_FreeOperation(op);
	return res;

}

static TEE_Result cmd_dec(void *session, uint32_t pt, TEE_Param params[4])
{
	TEE_Result res;
	TEE_OperationHandle op;
	const uint32_t key_type = TEE_TYPE_RSA_PUBLIC_KEY;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	char *inbuf;
	uint32_t inbuf_size = params[0].memref.size;
	inbuf = TEE_Malloc(inbuf_size, 0);
	TEE_MemMove(inbuf, params[0].memref.buffer, inbuf_size);
	
	IMSG("cipher: %s", inbuf);
	IMSG("size = %" PRIu32, inbuf_size);
	
	DMSG("Populate Private Key!");

	TEE_ObjectHandle pvt_key;

	TEE_Attribute pvt_attrs[3];
	TEE_InitRefAttribute(&pvt_attrs[0], TEE_ATTR_RSA_MODULUS, client_mod, client_modlen);
	TEE_InitRefAttribute(&pvt_attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, client_exp, client_explen);
	TEE_InitRefAttribute(&pvt_attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, client_pvt, client_pvtlen);

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, rsa_key_size, &pvt_key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, TEE_TYPE_RSA_KEYPAIR, rsa_key_size, res);
		return res;
	}

	res = TEE_PopulateTransientObject(pvt_key, pvt_attrs, 3);
	if (res) {
		EMSG("TEE_PopulateTransientObject: %#" PRIx32, res);
		return res;
	}

	DMSG("Private Key succeed!");
	
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_DECRYPT,
				    rsa_key_size);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_DECRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, rsa_key_size, res);
		return res;
	}
	
	res = TEE_SetOperationKey(op, pvt_key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

decrypt:
	res = TEE_AsymmetricDecrypt(op, NULL, 0, inbuf, inbuf_size, rsa_plain,
				    &rsa_plain_size);
	if (res) {
		EMSG("TEE_AsymmetricDecrypt(size = %" PRId32 "): %#" PRIx32, rsa_plain_size, res);
		rsa_plain = TEE_Malloc(rsa_plain_size, 0);
		goto decrypt;
	}

out:
	IMSG("plain: %s", rsa_plain);
	IMSG("size = %" PRIu32, rsa_plain_size);
	aes_key = TEE_Malloc(rsa_plain_size, 0);
	TEE_MemMove(aes_key, rsa_plain, rsa_plain_size);
	aes_key_size = rsa_plain_size;
	TEE_Free(inbuf);
	TEE_FreeOperation(op);
	return res;

}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{
	struct aes_cipher *sess;

	/*
	 * Allocate and init ciphering materials for the session.
	 * The address of the structure is used as session ID for
	 * the client.
	 */
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct aes_cipher *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4])
{
	switch (cmd) {
	case TA_AES_CMD_PREPARE:
		return alloc_resources(session, param_types, params);
	case TA_AES_CMD_GEN_KEY:
		return gen_aes_key(session, param_types, params);
	case TA_AES_CMD_SET_KEY:
		return set_aes_key(session, param_types, params);
	case TA_AES_CMD_SET_IV:
		return reset_aes_iv(session, param_types, params);
	case TA_AES_CMD_CIPHER:
		return cipher_buffer(session, param_types, params);
	case TA_RSA_CMD_HASH:
		return cmd_hash(session, param_types, params);
	case TA_RSA_CMD_SIGN:
		return cmd_sign(session, param_types, params);
	case TA_RSA_CMD_VERIFY:
		return cmd_verify(session, param_types, params);
	case TA_RSA_CMD_ENCRYPT:
		return cmd_enc(session, param_types, params);
	case TA_RSA_CMD_DECRYPT:
		return cmd_dec(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
