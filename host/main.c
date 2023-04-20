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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hello_world_ta.h>

/* For Socket */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* For AES */
#define AES_TEST_BUFFER_SIZE	4096
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

/* TEE Prepare and Close */
void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

/* AES functions */
void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void gen_key(struct test_ctx *ctx, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_GEN_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *buf, size_t sz, int *result)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	
	*result = op.params[0].tmpref.size;
}

void create_sign(struct test_ctx *ctx, char *hash, uint32_t *hash_len,
						char *sign, uint32_t *sign_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = *hash_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_HASH,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(HASH) failed 0x%x origin 0x%x",
			res, origin);
	
	*hash_len = op.params[0].tmpref.size;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = *hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = *sign_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_SIGN,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SIGN) failed 0x%x origin 0x%x",
			res, origin);
	else printf("Signature Created!\n");
	
	*sign_len = op.params[1].tmpref.size;
}

void verify_sign(struct test_ctx *ctx, char *hash, uint32_t hash_len, char *sign, uint32_t sign_len, int *result)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = sign_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_VERIFY,
				 &op, &origin);
	if (res != TEEC_SUCCESS){
		printf("Verify Failed!\n");
		*result = 0;
	}
	else{
		printf("Verify Succeed!\n");
		*result = 1;
	}
}

void rsa_encrypt(struct test_ctx *ctx, char *ciph, uint32_t *ciph_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = ciph;
	op.params[0].tmpref.size = *ciph_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_ENCRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(ENCRYPT) failed 0x%x origin 0x%x",
			res, origin);
			
	*ciph_len = op.params[0].tmpref.size;
}

void rsa_decrypt(struct test_ctx *ctx, char *ciph, uint32_t ciph_len, int *result)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.size = ciph_len;
	op.params[0].tmpref.buffer = malloc(ciph_len);
	memmove(op.params[0].tmpref.buffer, ciph, ciph_len);
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_DECRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS){
		*result = 0;
	} else {
		*result = 1;
	}
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	char iv[AES_BLOCK_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	
	char hash[64];
	uint32_t hash_len = sizeof(hash);
	char hash_size[3];
	char sign[256];
	uint32_t sign_len = sizeof(sign);
	char sign_size[3];
	char rsa_ciph[256];
	uint32_t rsa_ciph_size = sizeof(rsa_ciph);
	char size[3];
	
	int tmp, result;
	
	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);
	
	/* Receive Signature and AES Key */
	
	printf("Client: Receive Signature and AES Key\n");
	
	printf("Creating Socket...\n");
	int sockfd = 0, forServerSockfd = 0;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1){
		printf("Fail to create a socket.\n");
	} else printf("Socket created.\n");

	struct sockaddr_in serverInfo, clientInfo;
	socklen_t addrlen = sizeof(serverInfo);
	bzero(&clientInfo, sizeof(clientInfo));
	clientInfo.sin_family = PF_INET;
	clientInfo.sin_addr.s_addr = INADDR_ANY;
	clientInfo.sin_port = htons(8700);
	bind(sockfd, (struct sockaddr*)&clientInfo, sizeof(clientInfo));
	listen(sockfd, 5);
	
	char success[] = {"Signature Received. Verification Approved.\n"};
	char fail[] = {"Verification failed.\n"};
	char good[] = {"AES Key received.\n"};
	char bad[] = {"AES Key failed.\n"};
	
	while(1){
		printf("Server Linking...\n");
		forServerSockfd = accept(sockfd, (struct sockaddr*)&serverInfo, &addrlen);
		printf("Receive Signature\n");
		recv(forServerSockfd, sign, sizeof(sign), 0);
		printf("Sign: %s\n", sign);
		recv(forServerSockfd, sign_size, sizeof(sign_size), 0);
		printf("size = %s\n", sign_size);
		tmp = 0;
		tmp = (sign_size[0]-'0')*100+(sign_size[1]-'0')*10+(sign_size[2]-'0');
		sign_len = tmp;
		printf("Receive Hash\n");
		recv(forServerSockfd, hash, sizeof(hash), 0);
		printf("Hash: %s\n", hash);
		recv(forServerSockfd, hash_size, sizeof(hash_size), 0);
		printf("size = %s\n", hash_size);
		tmp = 0;
		tmp = (hash_size[0]-'0')*100+(hash_size[1]-'0')*10+(hash_size[2]-'0');
		hash_len = tmp;
		
		/* Verify Signature */
		
		printf("Verify Signature\n");
		verify_sign(&ctx, hash, hash_len, sign, sign_len, &result);
		if(result == 0){
			send(forServerSockfd, fail, sizeof(fail), 0);
			break;
		}
		else{
			send(forServerSockfd, success, sizeof(success), 0);
		}
		
		/* Receive AES Key */
recv_aes:		
		printf("Receive AES Key\n");
		recv(forServerSockfd, rsa_ciph, sizeof(rsa_ciph), 0);
		printf("Encrypted AES Key: %s\n", rsa_ciph);
		recv(forServerSockfd, size, sizeof(size), 0);
		printf("Encrypted AES Key Size = %s\n", size);
		tmp = 0;
		tmp = (size[0]-'0')*100+(size[1]-'0')*10+(size[2]-'0');
		rsa_ciph_size = tmp;
		printf("Receive Initial Vector\n");
		recv(forServerSockfd, iv, sizeof(iv), 0);
		printf("iv: %s\n", iv);
		
		printf("RSA Decrypt AES Key\n");
		rsa_decrypt(&ctx, rsa_ciph, rsa_ciph_size, &result);
		if(result == 0){
			send(forServerSockfd, bad, sizeof(bad), 0);
			goto recv_aes;
		}
		else{
			send(forServerSockfd, good, sizeof(good), 0);
			break;
		}
	}
	
	/* Encrypt Status */
	
	printf("Prepare encode operation\n");
	prepare_aes(&ctx, ENCODE);

	printf("Set key in TA\n");
	set_key(&ctx);
	
	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	set_iv(&ctx, iv, AES_BLOCK_SIZE);
	
	printf("Encode buffer from TA\n");
	cipher_buffer(&ctx, ciph, AES_TEST_BUFFER_SIZE, &result);
	
	printf("ciph: %s\n", ciph);
	
	/* Send Status */
	
	printf("Client: Send Status\n");
	
	char message[AES_TEST_BUFFER_SIZE] = {};
	char receiveMessage[] = {"Data received.\n"};
	char failMessage[] = {"Incorrect Data.\n"};
	
	while(1){
		send(forServerSockfd, ciph, sizeof(ciph), 0);
		recv(forServerSockfd, message, sizeof(message), 0);
		printf("From Server: %s", message);
		if(strcmp(message, receiveMessage) == 0) break;
		else if(strcmp(message, failMessage) == 0){
			printf("Prepare to send data again...\n");
		}
		else{
			printf("Server Error.\n");
			break;
		}
	}
	
	close(sockfd);
	
	terminate_tee_session(&ctx);

	return 0;
}
