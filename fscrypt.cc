#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fscrypt.h"


/************************************************************************


void BF_set_key(BF_KEY *key, int len, const unsigned char *data);

void BF_encrypt(BF_LONG *data,const BF_KEY *key);
void BF_decrypt(BF_LONG *data,const BF_KEY *key);

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const BF_KEY *key, int enc);

void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
	const BF_KEY *schedule, unsigned char *ivec, int enc);

*******************************************************************************/


unsigned char init_vec[]="00000000";


void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){

	
	int i;
	int pad_size;
	int result_size;
	int size=bufsize;
	BF_KEY *key_str;

	unsigned char * result, *unit, *unit_res; 
	unsigned char *plain_text=(unsigned char *) plaintext;

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
	unit_res= (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);


	for(i=0;i< bufsize;i++){
		
		result[i]='0';

	}

	for (i = 0; i < BLOCKSIZE; i++){
		unit[i] = init_vec[i];
		unit_res[i] = '0';
	}
	

	while( size >= BLOCKSIZE){
		for(i = 0; i < BLOCKSIZE; i++){
			unit[i]=unit[i] ^ (unsigned char)(plain_text[bufsize - size + i]);

		}//do XOR for each byte
		
		BF_ecb_encrypt(unit, unit_res, key_str, BF_ENCRYPT);

		for(i = 0; i < BLOCKSIZE; i++){
			unit[i] = unit_res[i];
			result[bufsize - size + i] = unit_res[i];
		}
		
		size = size - BLOCKSIZE;
	}



	pad_size = BLOCKSIZE - size ;

	*resultlen = bufsize - size ;

	if(size > 0){
		for(i = 0; i < BLOCKSIZE; i++){

			if(size != 0){
				unit[i]= unit[i] ^ (unsigned char)plain_text[bufsize - size ];
				size --;
			}
			else{
				unit[i]= unit[i] ^ (unsigned char)(pad_size & 0xFF);	
			}
			
		}

		BF_ecb_encrypt(unit, unit_res, key_str, BF_ENCRYPT);

		for(i = 0; i < BLOCKSIZE; i++){
			
			result[bufsize - BLOCKSIZE + pad_size + i] = unit_res[i];
					}
		*resultlen += BLOCKSIZE;
		
	}

	free(key_str);
	free(unit);
	free(unit_res);
	return (void *) result;
	
}


void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	
	
	int i;
	int count=0;
	int pad_size;
	int result_size;
	int size = bufsize;
	BF_KEY *key_str;

	unsigned char *cipher_text=(unsigned char *) ciphertext;


	unsigned char * result, *unit, *unit_res, *pre_unit; 
	
	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));

	BF_set_key(key_str, strlen(keystr), (const unsigned char *)keystr);



	result = (unsigned char *)malloc(sizeof(unsigned char) * (bufsize));

	unit = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	unit_res = (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	pre_unit= (unsigned char *)malloc(sizeof(unsigned char) * BLOCKSIZE);
	
	for(i=0;i< bufsize;i++){
		
		result[i]='0';

	}
	for (i = 0; i < BLOCKSIZE; i++){
		unit[i] = '0';
		unit_res[i] = '0';
		pre_unit[i] = init_vec[i];
		
	}

	while(size  >= BLOCKSIZE){
		for(i = 0; i < BLOCKSIZE; i++){
			unit[i] = (unsigned char)cipher_text[bufsize - size + i];			
		}
		
		BF_ecb_encrypt(unit, unit_res, key_str, BF_DECRYPT);

		for(i = 0; i < BLOCKSIZE; i++){
			unit_res[i]= unit_res[i] ^ pre_unit[i];
			pre_unit[i] = unit[i];
			result[bufsize - size + i] = unit_res[i];
		}		
		size =size - BLOCKSIZE;
	}


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
	free(unit);
	free(pre_unit);
	free(unit_res);
	return (void *)result;
}
	





