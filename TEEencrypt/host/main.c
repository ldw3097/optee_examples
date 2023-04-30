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
#include <getopt.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* const* argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[128] = {0,};		// buffer for plaintext input from file
	char TEEoutput[128] = {0,};		// buffer for storing TEEoutput
	int key;	// variable for storing key

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	
	// op has two shared buffer
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);		
	// initialize shared buffer
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = 128;
	op.params[1].tmpref.buffer = &key;
	op.params[1].tmpref.size = 4;

	int opt = getopt(argc, argv, "e:w:d:r:");		// get program option
	char file_name[64] = {0,};		// buffer for file name
	memcpy(file_name, optarg, 64);	// get file name
	printf("file name: %s\n", file_name);
	FILE* open_file;	// file descriptor of current open file
	char user_input[128];	// buffer for user input
	char file_c[128];	// buffer for file content
	char encrypt[128];		// buffer for encrypted text
	switch(opt) {
		// encrypt file
		case 'e':
			open_file = fopen(file_name, "r");
			// no file exception handling
			if(open_file == NULL){
				printf("no such file");
				return 1;
			}
			// get content from file
			fgets(plaintext, 128, open_file);
			// TEE invoke for encrypt command
			memcpy(op.params[0].tmpref.buffer, plaintext, 128);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS){
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
				return 2;
			} 
			// write TEE output to buffer
			memcpy(encrypt, op.params[0].tmpref.buffer, 128);
			memcpy(&key, op.params[1].tmpref.buffer, 4);
			// combine encrypt text and key
			sprintf(TEEoutput, "%s %d", encrypt, key);
			printf("TEEoutput : %s\nwritten at encrypt.txt\n", TEEoutput);
			fclose(open_file);
			// write cipher text and key to file
			open_file = fopen("encrypt.txt", "w");	
			fprintf(open_file, TEEoutput);		// write to "encrypt.txt" file
			fclose(open_file);
			return 0;
		// write user input to file
		case 'w':
			open_file = fopen(file_name, "w");
			printf("write text file: \n");
			scanf("%s", user_input);		// save user input to buffer
			fprintf(open_file, user_input);		// write buffer to file
			fclose(open_file);
			return 0;
		// read file and print out
		case 'r':
			open_file = fopen(file_name, "r");
			fgets(file_c, 128, open_file);		// save file content to buffer
			printf("text content:\n%s\n", file_c);	// print buffer
			fclose(open_file);
			return 0;
		// decrypt file
		case 'd':
			// open file and save it to buffers
			open_file = fopen(file_name, "r");
			fgets(file_c, 128, open_file);
			printf("text content:\n%s\n", file_c);
			char* encrypted_text = strtok(file_c, " ");
			char* string_of_key = strtok(NULL, " ");
			int encrypted_key = atoi(string_of_key);
			
			
			// TEE invoke for decrypt command
			memcpy(op.params[0].tmpref.buffer, encrypted_text, 128);
			memcpy(op.params[1].tmpref.buffer, &encrypted_key, 4);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS){
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
					res, err_origin);
				return 2;
			} 
			// copy TEEoutput
			memcpy(TEEoutput, op.params[0].tmpref.buffer, 128);
			printf("Decrypted text : %s\nwritten at decrypt.txt\n", TEEoutput);
			fclose(open_file);
			// write decrypted text to "decrypt.txt" file
			open_file = fopen("decrypt.txt", "w");
			fprintf(open_file, TEEoutput);
			fclose(open_file);
			return 0;					
		default:
			return 1;
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
