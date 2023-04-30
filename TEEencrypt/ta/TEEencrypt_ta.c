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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

// rootkey is 7
int rootkey = 7;


/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Caesar cipher\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

// Caesar encrypt function
static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	// declare pointers to shared buffers
	char * in = (char *)params[0].memref.buffer;
	int* keyout = (int*)params[1].memref.buffer;
	
	// declare buffer for output
	char encrypted [128]={0,};
	strcpy(encrypted, in);
	int text_len = strlen (encrypted);
	// random key generation
	int key = 0;
	TEE_GenerateRandom(&key, 4);
	key = key %25;		// key is -24 ~ 24
	if(key<0) key = -key;	// key is 0 ~ 24
	key++;	// key is 1 ~ 25
	
	DMSG("text_len: %d", text_len);
	DMSG("key: %d", key);
	DMSG ("Plaintext :  %s", encrypted);

	// encrypt to Caesar password 
	for(int i=0; i<text_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG ("Ciphertext :  %s", encrypted);
	// encrypt key with rootkey
	key += rootkey;

	// put output to shared buffer
	memcpy(in, encrypted, 128);
	memcpy(keyout, &key, 4);

	return TEE_SUCCESS;
}

// Caesar decrypt function
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	// pointers to shared buffers
	char * encrypted_text = (char *)params[0].memref.buffer;
	int* encrypted_key = (int*)params[1].memref.buffer;
	// extract encrypted string
	char decrypted [128]={0,};  // buffer for output
	strcpy(decrypted, encrypted_text);
	int text_len = strlen(decrypted);
	// decrypt key
	int key = *encrypted_key - rootkey;

	DMSG("text_len: %d", text_len);
	DMSG("key: %d", key);
	DMSG ("Cypher text :  %s", decrypted);
	//decrypt from Caesar password
	for(int i=0; i<text_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			// Caesar decryption
			decrypted[i] -= key;
			if(decrypted[i]<'a') decrypted[i] += 26;
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= key;
			if(decrypted[i]<'A') decrypted[i] += 26;	
		}
	}

	DMSG ("Plaintext :  %s", decrypted);
	// save decrypted string to shared buffer
	memcpy(encrypted_text, decrypted, 128);		
	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	IMSG("initializing");
	(void)&sess_ctx; /* Unused parameter */
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:  // encryption command
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:		// decryption command
		return dec_value(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
