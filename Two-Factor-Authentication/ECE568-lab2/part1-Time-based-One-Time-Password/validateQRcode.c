#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include "lib/sha1.h"

#define T0 0
#define X 30

int stringToUint8(const char* str, uint8_t* array, int arraySize);

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	uint8_t keya[11];
	memset(keya,0x00,sizeof(keya));
    int arrayValidLen=stringToUint8(secret_hex, keya, 10);

	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	memset(k_ipad,0x00,sizeof(k_ipad));
	memset(k_opad,0x00,sizeof(k_ipad));
	memcpy(k_ipad,keya,sizeof(keya));
	memcpy(k_opad,keya,sizeof(keya));

	for (int i=0; i<64; i++) {
 	k_ipad[i] ^= 0x36;
 	k_opad[i] ^= 0x5c;
	}

	time_t t = floor((time(NULL) - T0) / X);
	uint8_t T[8];
	for (int i=7;i>=0;i--){
		T[i]=t;
		t>>=8;
	}

	SHA1_INFO ctx;
	uint8_t sha_1[SHA1_DIGEST_LENGTH]; 
	uint8_t sha[SHA1_DIGEST_LENGTH]; //20
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, 64);
	sha1_update(&ctx, T, 8);
	sha1_final(&ctx, sha_1);

	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, 64);
	sha1_update(&ctx, sha_1, 20);
	sha1_final(&ctx, sha);

	int offset = sha[SHA1_DIGEST_LENGTH-1] & 0xf;
	int binary;
	binary = (sha[offset] & 0x7f) << 24;
	binary = binary | ((sha[offset+1] & 0xff)<<16);
	binary = binary | ((sha[offset+2] & 0xff)<<8);
	binary = binary | (sha[offset+3] & 0xff);
	int totp=binary % (1000000);

	if (atoi(TOTP_string) == totp) return 1;

	return (0);

}

int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}

int stringToUint8(const char* str, uint8_t* array, int arraySize)
{
    int arrayValidLen = 0;
    for (int arrayElement = 0; arrayValidLen < arraySize && str[arrayValidLen * 2] != '\0'; arrayValidLen++)
    {
        sscanf(&str[arrayValidLen * 2], "%2x", &arrayElement);
        array[arrayValidLen] = arrayElement;
    }
    return arrayValidLen;
}