#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "lib/encoding.h"

// void hex_2_uint8(const char* source, size_t length, uint8_t* target, size_t n);

int stringToUint8(const char* str, uint8_t* array, int arraySize);

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}


	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	uint8_t result[16];

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

    // uint8_t res[10] = {0};
    // hex_2_uint8(secret_hex, 20, res, 10);

	uint8_t key[11];
	memset(key,0x00,sizeof(key));
    int arrayValidLen=stringToUint8(secret_hex, key, 10);
    // for (int i = 0; i < arrayValidLen; i++)
    //     printf("%#x\t", keya[i]);
	// printf("\n");

	int count=base32_encode(key,10,result,16);

    int bufSize=42+strlen(urlEncode(accountName))+strlen(urlEncode(issuer))+strlen(result);
	char buf[bufSize]; 
	snprintf(buf,sizeof(buf),"otpauth://totp/%s?issuer=%s&secret=%s&period=30",urlEncode(accountName),urlEncode(issuer),result);
	
	displayQRcode(buf);
	

	return (0);
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

// void hex_2_uint8(const char* source, size_t length, uint8_t* target, size_t n) {
//     n = 0;
//     for (int i = 0; i < length; i += 2) {
//         if (source[i] >= 'A' && source[i] <= 'F') {
//             target[n] = source[i] - 'A' + 10;
//         }
//         else {
//             target[n] = source[i] - '0';
//         }
//         if (source[i + 1] >= 'A' && source[i + 1] <= 'F') {
//             target[n] = (target[n] << 4) | (source[i + 1] - 'A' + 10);
//         }
//         else {
//             target[n] = (target[n] << 4) | (source[i + 1] - '0');
//         }
//         ++n;
//     }
// }