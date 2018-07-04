// (c) 2015 Synopsys, Inc. All rights reserved worldwide.

typedef void symmetric_LRW;
// lrw_start initializes "symmetric_LRW *lrw" to be used using the key. 
// Vulnerable argument: "const unsigned char *key and const unsigned char *tweak" are the vulnerable arguments
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int lrw_start(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *tweak, int num_rounds, symmetric_LRW *lrw)
{
	unsigned char ch,ch1;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;
	
	/* 2. Reads "tweak" */
	ch1 = *tweak;

	/* 3. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use
	
	/* 4. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(tweak); //#event#crypto_use

	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 6. Sinks if len is negative */
	__coverity_negative_sink__(num_rounds);
	
	/* 7. only when function returns 0, then lrw->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup lrw data structure with the key from the key argument. Also tweak is copied to lrw->tweak directly
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/lrw/lrw_start.c on line 62 and 68 respectively*/
	if (!ret_code)
		((unsigned char*)lrw)[0] = ch;
		((unsigned char*)lrw)[1] = ch1;
	return ret_code;
}


void test_lrw_start(char *passw,char *tweak2) {

		char pass[] = "Hardcoded";	
		char IV1[] = "dsssdsdsddsdsd";	
		char tweak1[] = "ssdsdsdsdkey";
		symmetric_LRW *lrw1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

	
		
		ret = lrw_start(1, IV1, pass, pass_len, tweak1, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto //#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}