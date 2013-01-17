#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <string>
#include <vector>
#include <map>

#include "tinyxml.h"
#include "srvlookup.h"

#include "base64.h"

typedef unsigned char uint8_t;

static char str2b64[256];
static char b64tostr[65]={
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

void base64init()
{
    int i, idx;
    memset(str2b64, 0xFF, sizeof(str2b64));
    for (i=0; i<64; i++) {
		idx = b64tostr[i];
		str2b64[idx] = i;
    }
    str2b64[int('=')] = 0;
}

size_t base64dec(const char ** inptr, void *buffer, size_t bufsz)
{
    size_t bitbuf=0, bitcnt=0;
    const char *ptext = *inptr;
    char *pbuff = (char*)buffer;
	
    while (*ptext != 0) {
		size_t bitval = *ptext++;
		assert(bitval < 256);
		if (str2b64[bitval]==-1)
			continue;
		
		bitbuf = (bitbuf<<6)|str2b64[bitval];
		bitcnt += 6;
		
		while (bitcnt >= 8) {
			if (bufsz == 0) {
				*inptr = ptext;
				return pbuff-(char*)buffer;
			}
			bufsz --;
			bitcnt -= 8;
			*pbuff++ = bitbuf>>bitcnt;
		}
		
		if (bitval == '=') {
			break;
		}
    }
    *inptr = ptext;
    return pbuff-(char*)buffer;
}

appstr bin2B64str(const char *mem, size_t count)
{
    int i;
    int out = 0;
    char buff[8192];
	
    size_t bitcnt = 0;
    size_t bitvalues = 0;
	
    uint8_t *text = (uint8_t*)mem;
    for (i=0; i<int(count); i++){
        bitvalues <<= 8;
        bitvalues |= text[i];
        bitcnt += 8;
		
        while (bitcnt>6){
            int ch = 0x3F&(bitvalues>>(bitcnt-6));
            buff[out++] = b64tostr[ch];
            bitcnt -= 6;
        }
    }
	
    if (bitcnt > 0){
        int ch = 0x3F&(bitvalues<<(6-bitcnt));
        buff[out++] = b64tostr[ch];
        bitcnt -= 6;
    }
	
    while (out&0x3){
        buff[out] = '=';
        out++;
    }
    buff[out] = 0;
    return buff;
}

