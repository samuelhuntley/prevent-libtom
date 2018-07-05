/* Copyright (c) 2018 Synopsys, Inc. All rights reserved worldwide. */
/*{
  ANALYSIS_OPTS+=["-en";"HARDCODED_CREDENTIALS"];
}*/


typedef void symmetric_key;
typedef void symmetric_CTR;
typedef void symmetric_CBC;
typedef void symmetric_OFB;
typedef void symmetric_CFB;
typedef void symmetric_ECB;
typedef void symmetric_LRW;
typedef void symmetric_xts;
typedef void symmetric_F8;
typedef void eax_state;
typedef void ocb_state;
typedef void gcm_state;
typedef void ccm_state;
typedef void hmac_state;
typedef void omac_state;
typedef void pmac_state;
typedef void pelican_state;
typedef void xcbc_state;
typedef void f9_state;
#define NULL 0
typedef unsigned size_t;

/*
############################################################ PBKDF2 ALGO TEST CASES #####################################################################
*/

/* Test cases */
void test_pkcs_5_alg1() {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		char salt[] = "123344";
		int itr_cnt = 1000;
		int h_idx = 1;
		unsigned char out1[200];
		unsigned long out1_len = 200;
		int ret;

		ret = pkcs_5_alg1(pass, pass_len, salt, itr_cnt, h_idx, out1, out1_len);//#defect#HARDCODED_CREDENTIALS

}


void test_pkcs_5_alg2(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		char salt[] = "123344";
		unsigned long salt_len = 6;
		int itr_cnt = 1000;
		int h_idx = 1;
		unsigned char out1[200];
		unsigned long out1_len = 200;
		int ret,ret1;

		ret = pkcs_5_alg2(pass, pass_len, salt, salt_len, itr_cnt, h_idx, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		ret1 = pkcs_5_alg2(passw, pass_len, salt, salt_len, itr_cnt, h_idx, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}

/*
############################################################ SYMMETRIC ALGO TEST CASES #####################################################################
*/

void test_rijndael_setup() {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = rijndael_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS

}


void test_safer_sk64_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = safer_sk64_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = safer_sk64_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_safer_sk128_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = safer_sk128_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = safer_sk128_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_twofish_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = twofish_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = twofish_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_anubis_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = anubis_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = anubis_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_blowfish_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = blowfish_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = blowfish_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_camellia_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = camellia_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = camellia_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_cast5_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = cast5_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = cast5_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_des_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = des_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = des_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_des3_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = des3_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = des3_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_idea_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = idea_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = idea_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}


void test_kasumi_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = kasumi_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = kasumi_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_khazad_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = khazad_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = khazad_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}




void test_kseed_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = kseed_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = kseed_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_multi2_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = multi2_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = multi2_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_noekeon_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = noekeon_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = noekeon_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_rc2_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = rc2_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = rc2_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_rc5_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = rc5_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = rc5_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_rc6_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = rc6_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = rc6_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_serpent_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = serpent_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = serpent_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_skipjack_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = skipjack_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = skipjack_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}




void test_xtea_setup(char *passw) {

		char pass[] = "Hardcoded";
		unsigned long pass_len = sizeof(pass);
		symmetric_key *skey1 = "";
		int ret;

		ret = xtea_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS
		
		ret = xtea_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS

}




void test_ctr_start(char *passw) {

		char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
		unsigned long pass_len = sizeof(pass);
		symmetric_CTR *ctr1 = "";
		int ret;

		ret = ctr_start(1, IV1, pass, pass_len, 0, 0, ctr1);//#defect#HARDCODED_CREDENTIALS
		
		ret = ctr_start(1, IV1, passw, pass_len, 0, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_cbc_start(char *passw) {

		char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
		unsigned long pass_len = sizeof(pass);
		symmetric_CBC *ctr1 = "";
		int ret;

		ret = cbc_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS
		
		ret = cbc_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_cfb_start(char *passw) {

		char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
		unsigned long pass_len = sizeof(pass);
		symmetric_CFB *ctr1 = "";
		int ret;

		ret = cfb_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS
		
		ret = cfb_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_ofb_start(char *passw) {

		char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
		unsigned long pass_len = sizeof(pass);
		symmetric_OFB *ctr1 = "";
		int ret;

		ret = ofb_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS
		
		ret = ofb_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS

}



void test_ecb_start(char *passw) {

		char pass[] = "Hardcoded";		
		unsigned long pass_len = sizeof(pass);
		symmetric_ECB *ctr1 = "";
		int ret;

		ret = ecb_start(1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS
		
		ret = ecb_start(1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS

}


//int lrw_start( int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *tweak, int num_rounds, symmetric_LRW *lrw)

void test_lrw_start(char *passw,char *tweak2) {

		char pass[] = "Hardcoded";	
		char IV1[] = "dsssdsdsddsdsd";	
		char tweak1[] = "ssdsdsdsdkey";
		symmetric_LRW *lrw1 = "sdsdsdsdsdsdsdsdsdsdsdsdsdsdsddsdsdsdsdsdsd";		
		unsigned long pass_len = sizeof(pass);
		int ret;

		
		
		ret = lrw_start(1, IV1, passw, pass_len, tweak1, 0, lrw1);//#defect#HARDCODED_CREDENTIALS
		
		ret = lrw_start(1, IV1, passw, pass_len, tweak2, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS
		
		

}

//int xts_start( int cipher,const unsigned char *key1, const unsigned char *key2, unsigned long keylen, int num_rounds, symmetric_xts *xts)

void test_xts_start(char *passw,char *tweak2) {

		char key_1[] = "Hardcoded"; 
		char IV1[] = "dsssdsdsddsdsd";	
		char key_2[] = "ssdsdsdsdkey";
		symmetric_xts *lrw1 = "sdsdsdsdsdsdsdsdsdsdsdsdsdsdsddsdsdsdsdsdsd";		
		unsigned long key1_len = sizeof(key_1);
		int ret;

		
		
		ret = xts_start(1, passw, key_2, key1_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS
		
		ret = xts_start(1, passw, tweak2, key1_len, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS
		
		

}


//int f8_start( int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *salt_key, int skeylen, int num_rounds, symmetric_F8 *f8)

void test_f8_start(char *passw,char *tweak2) {

		char key_1[] = "Hardcoded"; 
		char IV1[] = "dsssdsdsddsdsd";	
		char key_2[] = "ssdsdsdsdkey";
		symmetric_F8 *lrw1 = "";			
		unsigned long key1_len = sizeof(key_1);
		unsigned long key2_len = sizeof(key_2);
		int ret;

		
		
		ret = f8_start(1, IV1, passw, key1_len, key_2, key2_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS
		
		ret = f8_start(1, IV1, passw, key1_len, tweak2, key2_len, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS
		
		

}



//int eax_init( eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen)
#define NULL 0

void test_eax_init(char *passw) {

		char pass[] = "Hardcoded";	
		eax_state *eax1 = ""; 
		char nonce1 = "sssssssssss";
		unsigned long pass_len = sizeof(pass);
		unsigned long nonce1_len = sizeof(nonce1);
	   
		int ret;

		ret = eax_init(eax1, 0, pass, pass_len, nonce1,nonce1_len, NULL,0);//#defect#HARDCODED_CREDENTIALS
		
		ret = eax_init(eax1, 0, passw, pass_len, nonce1,nonce1_len, NULL,0);//#nodefect#HARDCODED_CREDENTIALS

}


//int ocb_init( ocb_state *ocb, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
#define NULL 0

void test_ocb_init(char *passw) {

		char pass[] = "Hardcoded";	
		ocb_state *eax1 = ""; 
		char nonce1 = "sssssssssss";
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = ocb_init(eax1, 1, pass, pass_len, nonce1);//#defect#HARDCODED_CREDENTIALS
		
		ret = ocb_init(eax1, 1, passw, pass_len, nonce1);//#nodefect#HARDCODED_CREDENTIALS

}


//int gcm_init(gcm_state *gcm, int cipher, const unsigned char *key, int keylen)
#define NULL 0

void test_gcm_init(char *passw) {

		char pass[] = "Hardcoded";	
		gcm_state *eax1 = ""; 
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = gcm_init(eax1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = gcm_init(eax1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}


//int ccm_init(ccm_state *ccm, int cipher, const unsigned char *key, int keylen, int ptlen, int taglen, int aadlen)
#define NULL 0

void test_ccm_init(char *passw) {

		char pass[] = "Hardcoded";	
		ccm_state *eax1 = ""; 
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = ccm_init(eax1, 1, pass, pass_len, 8, 8, 16);//#defect#HARDCODED_CREDENTIALS
		
		ret = ccm_init(eax1, 1, passw, pass_len, 8, 8, 16);//#nodefect#HARDCODED_CREDENTIALS

}

/*
############################################################ MAC ALGO TEST CASES #####################################################################
*/

//int hmac_init( hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen)


void test_hmac_init(char *passw) {

		char pass[] = "Hardcoded";	
		hmac_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = hmac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = hmac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}


//int omac_init( omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen)

void test_omac_init(char *passw) {

		char pass[] = "Hardcoded";	
		omac_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = omac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = omac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}

//int pmac_init( pmac_state *pmac, int cipher, const unsigned char *key, unsigned long keylen)

void test_pmac_init(char *passw) {

		char pass[] = "Hardcoded";	
		pmac_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = pmac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = pmac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}

//int pelican_init( pelican_state *pelmac, const unsigned char *key, unsigned long keylen)

void test_pelican_init(char *passw) {

		char pass[] = "Hardcoded";	
		pelican_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = pelican_init(hmac1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = pelican_init(hmac1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}


//int xcbc_init( xcbc_state *xcbc, int cipher, const unsigned char *key, unsigned long keylen)

void test_xcbc_init(char *passw) {

		char pass[] = "Hardcoded";	
		xcbc_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = xcbc_init(hmac1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = xcbc_init(hmac1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}

//int f9_init( f9_state *f9, int cipher, const unsigned char *key, unsigned long keylen)

void test_f9_init(char *passw) {

		char pass[] = "Hardcoded";	
		f9_state *hmac1;		
		unsigned long pass_len = sizeof(pass);
		int ret;

		ret = f9_init(hmac1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = f9_init(hmac1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS

}


/*
############################################# File and Memory Encryption/Decryption ALGO TEST CASES #####################################################################
*/


void test_hmac_memory(char *passw) {

		char pass[] = "Hardcoded";	
		char in1[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);
		unsigned long in1_len = sizeof(in1);
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = hmac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = hmac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}

//int hmac_file( int hash, const char *fname, const unsigned char *key,	 unsigned long keylen, unsigned char *out, unsigned long *outlen)


void test_hmac_file(char *passw) {

		char pass[] = "Hardcoded";	
		char filename[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);	
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = hmac_file(1, filename, pass, pass_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = hmac_file(1, filename, passw, pass_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}


void test_omac_memory(char *passw) {

		char pass[] = "Hardcoded";	
		char in1[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);
		unsigned long in1_len = sizeof(in1);
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = omac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = omac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}

// int omac_file(int cipher, const unsigned char *key,	unsigned long keylen, const char *filename, unsigned char *out,	 unsigned long *outlen)

void test_omac_file(char *passw) {

		char pass[] = "Hardcoded";	
		char filename[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);	
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = omac_file(1, pass, pass_len,	filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = omac_file(1, passw, pass_len,	 filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}


void test_pmac_memory(char *passw) {

		char pass[] = "Hardcoded";	
		char in1[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);
		unsigned long in1_len = sizeof(in1);
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = pmac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = pmac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}

// int pmac_file(int cipher, const unsigned char *key,	unsigned long keylen, const char *filename, unsigned char *out,	 unsigned long *outlen)

void test_pmac_file(char *passw) {

		char pass[] = "Hardcoded";	
		char filename[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);	
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = pmac_file(1, pass, pass_len,	filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = pmac_file(1, passw, pass_len,	 filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}



void test_xcbc_memory(char *passw) {

		char pass[] = "Hardcoded";	
		char in1[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);
		unsigned long in1_len = sizeof(in1);
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = xcbc_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = xcbc_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}



void test_xcbc_file(char *passw) {

		char pass[] = "Hardcoded";	
		char filename[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);	
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = xcbc_file(1, pass, pass_len,	filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = xcbc_file(1, passw, pass_len,	 filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}


void test_f9_memory(char *passw) {

		char pass[] = "Hardcoded";	
		char in1[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);
		unsigned long in1_len = sizeof(in1);
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = f9_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = f9_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}



void test_f9_file(char *passw) {

		char pass[] = "Hardcoded";	
		char filename[] = "test";
		char *out1 = ""; 
	
		unsigned long pass_len = sizeof(pass);	
		unsigned long out1_len = sizeof(out1);
		int ret;

		ret = f9_file(1, pass, pass_len,  filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = f9_file(1, passw, pass_len,  filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS

}


/*
int eax_encrypt_authenticate_memory(int cipher,
									const unsigned char *key, 
									unsigned long keylen,
									const unsigned char *nonce, 
									unsigned long noncelen,
									const unsigned char *header, 
									unsigned long headerlen,
									const unsigned char *pt, 
									unsigned long ptlen,
									unsigned char *ct,
									unsigned char *tag, 
									unsigned long *taglen);*/
									
									
void test_eax_encrypt_authenticate_memory(char *passw) {

		char key1[] = "Hardcoded";	
		char pt1[] = "test";
		char nonce1[] = "sssdsdsds";
		char header1[] = "asasasasa";
		char *ct1 = "";
		char *tag1 = "";	
	
		unsigned long key_len = sizeof(key1);
		unsigned long nonce_len = sizeof(nonce1);
		unsigned long header_len = sizeof(header1);
		unsigned long pt_len = sizeof(pt1);
		unsigned long tag_len = sizeof(tag1);
		
		int ret;

		ret = eax_encrypt_authenticate_memory(1, key1, key_len, nonce1, nonce_len, header1, header_len, pt1, pt_len, ct1, tag1, tag_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = eax_encrypt_authenticate_memory(1, passw, key_len, nonce1, nonce_len, header1, header_len, pt1, pt_len, ct1, tag1, tag_len);//#nodefect#HARDCODED_CREDENTIALS

}

/*
int eax_decrypt_verify_memory(int cipher,
									const unsigned char *key, 
									unsigned long keylen,
									const unsigned char *nonce, 
									unsigned long noncelen,
									const unsigned char *header, 
									unsigned long headerlen,
									const unsigned char *ct, 
									unsigned long ctlen,
									unsigned char *pt,
									unsigned char *tag, 
									unsigned long taglen,
									int *res);*/
									
									
									
void test_eax_decrypt_verify_memory(char *passw) {

		char key1[] = "Hardcoded";	
		char ct1[] = "ssddsdmkksujshsgsnhshhstsksksksks+/8www";
		char nonce1[] = "sssdsdsds";
		char header1[] = "asasasasa";
		char tag1[] = "sssdsdsdsd";
		char *pt1 = "";	
	
		unsigned long key_len = sizeof(key1);
		unsigned long nonce_len = sizeof(nonce1);
		unsigned long header_len = sizeof(header1);
		unsigned long tag_len = sizeof(tag1);
		unsigned long ct_len = sizeof(ct1);
		
		int ret, res1;

		ret = eax_decrypt_verify_memory(1, key1, key_len, nonce1, nonce_len, header1, header_len, ct1, ct_len, pt1, tag1, tag_len, res1);//#defect#HARDCODED_CREDENTIALS
		
		ret = eax_decrypt_verify_memory(1, passw, key_len, nonce1, nonce_len, header1, header_len, ct1, ct_len, pt1, tag1, tag_len, res1);//#nodefect#HARDCODED_CREDENTIALS

}


/*
int ocb_encrypt_authenticate_memory(int cipher,
									const unsigned char *key, 
									unsigned long keylen,
									const unsigned char *nonce,
									const unsigned char *pt, 
									unsigned long ptlen,
									unsigned char *ct,
									unsigned char *tag, 
									unsigned long *taglen);*/
									
void test_ocb_encrypt_authenticate_memory(char *passw) {

		char key1[] = "Hardcoded";	
		char pt1[] = "test";
		char nonce1[] = "sssdsdsds";		
		char *ct1 = "";
		char *tag1 = "";	
	
		unsigned long key_len = sizeof(key1);		
		unsigned long pt_len = sizeof(pt1);
		unsigned long tag_len = sizeof(tag1);
		
		int ret;

		ret = ocb_encrypt_authenticate_memory(1, key1, key_len, nonce1, pt1, pt_len, ct1, tag1, tag_len);//#defect#HARDCODED_CREDENTIALS
		
		ret = ocb_encrypt_authenticate_memory(1, passw, key_len, nonce1, pt1, pt_len, ct1, tag1, tag_len);//#nodefect#HARDCODED_CREDENTIALS

}

/*

int ocb_decrypt_verify_memory(int cipher,
									const unsigned char *key,
									unsigned long keylen,
									const unsigned char *nonce,
									const unsigned char *ct, 
									unsigned long ctlen,
									unsigned char *pt,
									const unsigned char *tag, 
									unsigned long taglen,
									int *res)*/
									
									
void test_ocb_decrypt_verify_memory(char *passw) {

		char key1[] = "Hardcoded";	
		char ct1[] = "ssddsdmkksujshsgsnhshhstsksksksks+/8www";
		char nonce1[] = "sssdsdsds";		
		char tag1[] = "sssdsdsdsd";
		char *pt1 = "";	
	
		unsigned long key_len = sizeof(key1);
		unsigned long tag_len = sizeof(tag1);
		unsigned long ct_len = sizeof(ct1);
		
		int ret, res1;

		ret = ocb_decrypt_verify_memory(1, key1, key_len, nonce1, ct1, ct_len, pt1, tag1, tag_len, res1);//#defect#HARDCODED_CREDENTIALS
		
		ret = ocb_decrypt_verify_memory(1, passw, key_len, nonce1, ct1, ct_len, pt1, tag1, tag_len, res1);//#nodefect#HARDCODED_CREDENTIALS

}
