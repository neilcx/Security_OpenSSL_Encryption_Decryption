#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fscrypt.h"


/************************************************************************
Definition from blowfish.h

void BF_set_key(BF_KEY *key, int len, const unsigned char *data);

void BF_encrypt(BF_LONG *data,const BF_KEY *key);
void BF_decrypt(BF_LONG *data,const BF_KEY *key);

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const BF_KEY *key, int enc);

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
	const BF_KEY *schedule, unsigned char *ivec, int enc);

*******************************************************************************/


void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	
	int i;
	int pad_size;
	int result_size;
	int size = bufsize;
	
	BF_KEY *key_str;
	
	unsigned char *plain_text=(unsigned char *) plaintext;

	unsigned char init_vec[]="00000000";

	unsigned char * result, *unit, *unit_res;


	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));

	BF_set_key(key_str, strlen(keystr), (const unsigned char *)keystr);

	if (bufsize % BLOCKSIZE == 0){
		result_size = bufsize;
	}
	
	else {
		result_size = bufsize + (bufsize % BLOCKSIZE);		
	}
	

	result = (unsigned char *)malloc(sizeof(unsigned char) * result_size);
	unit= (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	unit_res= (unsigned char *)malloc(sizeof(unsigned char) * result_size);


	for(i=0;i< bufsize;i++){
		
		result[i]='0';
		unit_res[i] = '0';

	}

	for (i = 0; i < BLOCKSIZE; i++){
		unit[i] = init_vec[i];
		
	}

	while(size >= BLOCKSIZE){
		for(i = 0; i < BLOCKSIZE; i++){
			unit_res[bufsize - size + i] = (unsigned char)(plain_text[bufsize - size+ i]);
		}
		size = size - BLOCKSIZE;
	}

	
	pad_size = BLOCKSIZE - size;
	*resultlen = bufsize - size;

	if(size > 0){
		for(i = 0; i < BLOCKSIZE; i++){
			if(size != 0){
				unit_res[bufsize - size] = (unsigned char)plain_text[bufsize - size];
				size--;
			}
		}

		*resultlen = *resultlen + BLOCKSIZE;
		for(i = 0; i < pad_size; i++){
			unit_res[bufsize + i] = (int)(pad_size & 0xFF);
		}
	}

	BF_cbc_encrypt(unit_res, result, (long)*resultlen, key_str, init_vec, BF_ENCRYPT);

	free(key_str);
	free(unit);
	free(unit_res);
	return (void *)result;
	
}
	




void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){


	int i;
	int count=0;
	int pad_size;
	int result_size;
	int size = bufsize;
	BF_KEY *key_str;

	unsigned char init_vec[]="00000000";

	unsigned char *cipher_text=(unsigned char *) ciphertext;


	unsigned char * result, *unit, *unit_res, *pre_unit; 
	
	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));
	
	BF_set_key(key_str, strlen(keystr), (const unsigned char *)keystr);

	result = (unsigned char *)malloc(sizeof(unsigned char) * (bufsize));

	for(i=0;i< bufsize;i++){
		
		result[i]='0';

	}

	BF_cbc_encrypt(cipher_text, result, (long)bufsize, key_str, init_vec, BF_DECRYPT);

	
	for (i = bufsize - 1; i > bufsize - BLOCKSIZE + 1; i--){
	
		if(result[bufsize - 1] == result[i - 1]){
			count ++;
		}
		else{
			break;
		}
	}
	
	if((count+1) >= (int)(result[bufsize - 1])){
		*resultlen = bufsize - (int)(result[bufsize - 1]);
	}
	else{
		return NULL;
	}

	free(key_str);
	return (void *)result;
}
	
