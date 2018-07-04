// (c) 2015 Synopsys, Inc. All rights reserved worldwide.
//Libtomcrypt API starting here



/*

1. Need to verify 

	XXX_Setup function is defined correctly with correct return value


	Is the way to return PBKDF2 APIs and XXX_START APIs correct since out and state params are only filled with value when function returns with 0


	XXX_init APIs also check if the return value is set correctly as when function return with 0 then it is successful
	

2. Also negative len is applicable to every int or only length like params 

*/

/*
############################################################ PBKDF2 ALGO APIs#####################################################################
*/

/*
This is a PBKDF2 algorithm.
password is the user’s password.
The salt is a fixed size 8–byte array which should be random for each user and session.
The iteration count is the delay desired on the password. The hash idx is the index of the hash you wish to use in the descriptor table.
The output of length up to outlen is stored in out.
If outlen is initially larger than the size of the hash functions output it is set to the number of bytes stored. If it is smaller than not all of the hash output is stored in out.
*/
int pkcs_5_alg1(const unsigned char *password, unsigned long password_len, const unsigned char *salt, int iteration_count, int hash_idx, unsigned char *out, unsigned long *outlen)
{

	unsigned char ch;
	int ret_code;
	unsigned char outbuf;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	
	  /* 1. Reads "password" */
	ch = *password;
	
	
	 /* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(password);//#event#crypto_use

	
	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(password_len);

	
	
	/* 4. Sinks if itr_cnt is negative */
	__coverity_negative_sink__(iteration_count);
	


	 /* 5. only when function returns 0 then out is filled with mac_key, cipher_key, cipher_IV */
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; // Need to verify this as actually out is filled with hash value;
	}
	return ret_code;
		
}


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
