/*
  Copyright (c) 2018, Synopsys, Inc. All rights reserved worldwide.
  The information contained in this file is the proprietary and confidential
  information of Synopsys, Inc. and its licensors, and is supplied subject to,
  and may be used only by Synopsys customers in accordance with the terms and
  conditions of a previously executed license agreement between Synopsys and that
  customer.
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
	__coverity_hardcoded_credential_crypto_sink__(password); 

	
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
This is a PBKDF2 algorithm.
password is the user’s password.
The salt is an array of size salt len. It should be random for each user and session
The iteration count is the delay desired on the password. The hash idx is the index of the hash you wish to use in the descriptor table.
The output of length up to outlen is stored in out.
If outlen is initially larger than the size of the hash functions output it is set to the number of bytes stored. If it is smaller than not all of the hash output is stored in out.
*/
int pkcs_5_alg2(const unsigned char *password, unsigned long password_len, const unsigned char *salt, unsigned long salt_len, int iteration_count, int hash_idx, unsigned char *out, unsigned long *outlen)
{
	
	unsigned char ch;
	int ret_code;
	unsigned char outbuf;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	
	  /* 1. Reads "password" */
	ch = *password;
	
	
	 /* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(password); 

	
	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(password_len);

	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(salt_len);
	
	
	
	/* 5. Sinks if ir_cnt  is negative */
	__coverity_negative_sink__(iteration_count);
	

	 /* 6. only when function returns 0 then out is filled with mac_key, cipher_key, cipher_IV */
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; // Need to verify this as actually out is filled with hash value;
	}
	return ret_code;
		
}

/*
############################################################ SYMMETRIC ALGO APIs#####################################################################
*/

typedef void symmetric_key;

// rijndael_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int rijndael_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}



// safer_sk64_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int safer_sk64_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}



// safer_sk128_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int safer_sk128_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// twofish_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int twofish_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// anubis_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int anubis_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}



// blowfish_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int blowfish_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// camellia_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int camellia_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}

// cast5_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int cast5_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// des_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int des_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}



// des3_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int des3_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// idea_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int idea_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// kasumi_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int kasumi_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// khazad_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int khazad_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// kseed_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int kseed_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// multi2_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int multi2_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// noekeon_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int noekeon_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// rc2_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int rc2_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}



// rc5_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int rc5_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// rc6_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int rc6_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// serpent_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int serpent_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// skipjack_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int skipjack_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


// xtea_setup sets up the "symmetric_key skey" using the keylen bytes at key.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// Only when function returns 0 then skey is assigned the key correctly
// headers/tomcrypt_cipher.h
int xtea_setup(const unsigned char *key, int keylen,int rounds, symmetric_key *skey)
{
	unsigned char ch;
	int ret_code;
	
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(rounds);

	/* 5. Reads and writes "skey": only when function returns 0 then skey is assigned the key after some transformation */
	if (!ret_code)
	   ((unsigned char*)skey)[0] = ch;
	return ret_code;

}


typedef void symmetric_CTR;

// ctr_start sets up "const unsigned char *key" and algorithm defined in  "int cipher" to encrypt the data in CTR mode. The final parameter
// is a pointer to the structure you want to hold the information for the mode of operation.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ctr_start(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_CTR *ctr)
{
	unsigned char ch;
	int ret_code;

	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(num_rounds);
	
	
	 /* 5. Sinks if ctr mode is negative */
	__coverity_negative_sink__(ctr_mode);
	
	/* 6. only when function returns 0, then &ctr->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup	ctr data structure with the key from key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/ctr/ctr_start.c on line 58*/

	if (!ret_code)
	   ((unsigned char*)ctr)[0] = ch;
	return ret_code;

}


typedef void symmetric_CBC;

// cbc_start sets up "const unsigned char *key" and algorithm defined in  "int cipher" to encrypt the data in CTR mode.The final parameter
// is a pointer to the structure you want to hold the information for the mode of operation.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, int num_rounds, symmetric_CBC *cbc)
{
	unsigned char ch;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(num_rounds);
		
	/* 5. only when function returns 0, then &cbc->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup	cbc data structure with the key from key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/cbc/cbc_start.c on line 43*/
	if (!ret_code)
	   ((unsigned char*)cbc)[0] = ch;
	return ret_code;
	
}



typedef void symmetric_OFB;

// ofb_start sets up "const unsigned char *key" and algorithm defined in  "int cipher" to encrypt the data in CTR mode.The final parameter
// is a pointer to the structure you want to hold the information for the mode of operation.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ofb_start(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, int num_rounds, symmetric_OFB *ofb)
{
	unsigned char ch;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(num_rounds);
	
	
	/* 5. only when function returns 0, then &ofb->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup ofb data structure with the key from key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/ofb/ofb_start.c on line 51*/
	if (!ret_code)
	   ((unsigned char*)ofb)[0] = ch;
	return ret_code;
}



typedef void symmetric_CFB;

// cfb_start sets up "const unsigned char *key" and algorithm defined in  "int cipher" to encrypt the data in CTR mode.The final parameter
// is a pointer to the structure you want to hold the information for the mode of operation.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int cfb_start(int cipher, const unsigned char *IV, const unsigned char *key, int keylen, int num_rounds, symmetric_CFB *cfb)
{
	unsigned char ch;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(num_rounds);
	
	/* 5. only when function returns 0, then &cfb->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup cfb data structure with the key from key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/cfb/cfb_start.c on line 51*/
	if (!ret_code)
	   ((unsigned char*)cfb)[0] = ch;
	return ret_code;
	

}


typedef void symmetric_ECB;

// ecb_start sets up "const unsigned char *key" and algorithm defined in  "int cipher" to encrypt the data in CTR mode.The final parameter
// is a pointer to the structure you want to hold the information for the mode of operation.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ecb_start(int cipher, const unsigned char *key, int keylen, int num_rounds, symmetric_ECB *ecb)
{
	unsigned char ch;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
	__coverity_negative_sink__(num_rounds);
	
	
	/* 5. only when function returns 0, then &ecb->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup ecb data structure with the key from key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/ecb/ecb_start.c on line 39*/
	if (!ret_code)
	   ((unsigned char*)ecb)[0] = ch;
	return ret_code;

}


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
	__coverity_hardcoded_credential_crypto_sink__(key); 
	
	/* 4. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(tweak); 

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


typedef void symmetric_xts;
// xts_start initializes "symmetric_xts *xts" to be used using the key. 
// Vulnerable argument: "const unsigned char *key1 and const unsigned char *key2" are the vulnerable arguments
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int xts_start( int cipher,const unsigned char *key1, const unsigned char *key2, unsigned long keylen, int num_rounds, symmetric_xts *xts)
{
	unsigned char ch,ch1;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key1" */
	ch = *key1;
	
	/* 2. Reads "key2" */
	ch1 = *key2;

	/* 3. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key1); 
	
	/* 4. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key2); 

	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
   /* 6. Sinks if len is negative */
	__coverity_negative_sink__(num_rounds);
	
	/* 7. only when function returns 0, then xts->key1 and xts->key2 are set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup xts data structure with the key from the key arguments respectively. 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/xts/xts_init.c on line 46 and 49 respectively*/
	if (!ret_code)
		((unsigned char*)xts)[0] = ch;
		((unsigned char*)xts)[1] = ch1;
	return ret_code;
}

typedef void symmetric_F8;
// f8_start initializes "symmetric_F8 *f8" to be used using the key. 
// Vulnerable argument: "const unsigned char *key and const unsigned char *salt_key" are the vulnerable arguments
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int f8_start( int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *salt_key, int skeylen, int num_rounds, symmetric_F8 *f8)
{
	unsigned char ch,ch1;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key1" */
	ch = *key;
	
	/* 2. Reads "key2" */
	ch1 = *salt_key;

	/* 3. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 
	
	/* 4. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(salt_key); 

	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 6. Sinks if len is negative */
	__coverity_negative_sink__(skeylen);
	
   /* 7. Sinks if len is negative */
	__coverity_negative_sink__(num_rounds);
	
	/* 8. only when function returns 0, then f8->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup f8 data structure with the key by xoring the (key ^ salt_key ^ 0x55)  arguments respectively. 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/modes/f8/f8_start.c on lines 60 - 73 respectively*/
	if (!ret_code)
		((unsigned char*)f8)[0] = ch ^ ch1 ^ 0x55;		
	return ret_code;
}


typedef void eax_state;

// eax_init initializes "eax_state *eax" to be used using the key, nonce and header values. The header can be NULL 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int eax_init( eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen)
{
	unsigned char ch,outbuf;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	
	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(noncelen);
	
	
	 /* 5. Sinks if len is negative */
	__coverity_negative_sink__(headerlen);
	
	
	/* 6. only when function returns 0, then eax->headeromac,eax->ctr and eax->ctomac are set up with the key using omac_init and ctr_start functions on lines 96,109,114 respectively. The key argument passed to eax_init is used for setting up these 3 data structures and hence eax context is setup with key value using the key argument.
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/eax/eax_init.c */
	if (!ret_code)
	   ((unsigned char*)eax)[0] = ch;
	return ret_code;
}


typedef void ocb_state;

// ocb_init initializes "ocb_state *ocb" to be used using the key, nonce. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ocb_init( ocb_state *ocb, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
{
	unsigned char ch,outbuf;
	int ret_code;

	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0, then &ocb->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup ocb data structure with the key from the key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/ocb/ocb_init.c on line 75*/
	if (!ret_code)
	   ((unsigned char*)ocb)[0] = ch;
	return ret_code;
}


typedef void gcm_state;

// gcm_init initializes "gcm_state *gcm" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int gcm_init(gcm_state *gcm, int cipher, const unsigned char *key, int keylen)
{
	unsigned char ch,outbuf;
	int ret_code;

	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0, then &gcm->K is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup gcm data structure with the key from the key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/gcm/gcm_init.c on line 53*/
	if (!ret_code)
	   ((unsigned char*)gcm)[0] = ch;
	return ret_code;
}


typedef void ccm_state;

// ccm_init initializes "ccm_state *ccm" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ccm_init(ccm_state *ccm, int cipher, const unsigned char *key, int keylen, int ptlen, int taglen, int aadlen)
{
	unsigned char ch,outbuf;
	int ret_code;

	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();
	
	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(ptlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(taglen);
	
	/* 6. Sinks if len is negative */
	__coverity_negative_sink__(aadlen);
	
	/* 7. only when function returns 0, then &ccm->K is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup gcm data structure with the key from the key argument 
	This is defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/ccm/ccm_init.c on line 57*/
	if (!ret_code)
	   ((unsigned char*)ccm)[0] = ch;
	return ret_code;
}




/*
############################################################ MAC ALGO APIs#####################################################################
*/


typedef void hmac_state;

// hmac_init initializes "hmac_state *hmac" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int hmac_init( hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	
	 /* 4. only when function returns 0 then hmac_state is initialized correctly, 
	hmac->key is filled with value from key if keylen is less than the hash size e.g. md5 is 32 bytes and if keylen is 31, then key is copied in hmac->key and one byte is zeroed out, 
	If keylen is exactly the size of the hash e.g 32 bytes as in md5 then hmac->key = key 
	else key is hashed to bring it to 32 bytes and then added the hash is added to hmac->key 
	to bring it to the size of hash
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/hmac/hmac_init.c and above behavior is defined in line 65 and 70 
	*/		  
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}


typedef void omac_state;

// hmac_init initializes "omac_state *omac" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int omac_init( omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
  /* 4. only when function returns 0 then omac_state is initialized correctly, 
	omac->key is filled with value from key after processing according to the cipher chosen e.g. if aes is chosen, then setup function in aes.c will process key and then basically store that in omac->key in SETUP Function
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/omac/omac_init.c and above behavior is defined in line 56
	*/		  
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}


typedef void pmac_state;

// pmac_init initializes "pmac_state *pmac" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int pmac_init( pmac_state *pmac, int cipher, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0 then pmac_state is initialized correctly, 
	pmac->key is filled with value from key after processing according to the cipher chosen e.g. if aes is chosen, then setup function in aes.c will process key and then basically store that in pmac->key in SETUP Function
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/pmac/pmac_init.c and above behavior is defined in line 79
	*/		  
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}


typedef void pelican_state;

// pelican_init initializes "pelican_state *pelmac" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int pelican_init( pelican_state *pelmac, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0 then pelican_state is initialized correctly, 
	pelmac->key is filled with value from key after processing according to the aes cipher chosen e.g. if aes is chosen, then setup function in aes.c will process key and then basically store that in pelmac->key in SETUP Function
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/pelican/pelican.c and above behavior is defined in line 43
	*/		  
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}


typedef void xcbc_state;

// xcbc_init initializes "xcbc_state *xcbc" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int xcbc_init( xcbc_state *xcbc, int cipher, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0 then pelican_state is initialized correctly, 
	xcbc->key is filled with value from key after processing according to the  cipher chosen and depending on keylen
	The key goes through processing to be made equivalent to cipher requirements and finally it is used to setup a xcbc->K[0,1,2,3] structures which are then encrypted again and finally allow xcbc->key to be setup. 
	In a simplistic way key --> goes after processing to xcbc->key structure 
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/xcbc/xcbc_init.c and above behavior is defined in line 83
	*/		  
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}



typedef void f9_state;

// f9_init initializes "f9_state *f9" to be used using the key. 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int f9_init( f9_state *f9, int cipher, const unsigned char *key, unsigned long keylen)
{
	unsigned char ch;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. only when function returns 0 then f9_state is initialized correctly, 
	f9->key is filled with value from key after processing according to the aes cipher chosen e.g. if aes is chosen, then setup function in aes.c will process key and then basically store that in f9->key in SETUP Function
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/f9/f9_init.c and above behavior is defined in line 43
	*/		
	if (!ret_code)
	   ((unsigned char*)key)[0] = ch;
	return ret_code;
}


/*
############################################## File and Memory Encryption/Decryption Functions APIS #####################################################################
*/

// hmac_memory creates a hmac hash of char *in and dumps it in char * out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int hmac_memory(int hash, const unsigned char *key,	 unsigned long keylen, const unsigned char *in,	 unsigned long inlen, unsigned char *out,  unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(inlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 6. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for  char *in using char *key.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/hmac/hmac_memory.c and above behavior is defined on lines 59-69
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// hmac_file creates a hmac hash of char *fname and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int hmac_file( int hash, const char *fname, const unsigned char *key,  unsigned long keylen, unsigned char *out, unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
		
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 5. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for contents in char *filename using char *key. 
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/hmac/hmac_file.c and above behavior is defined on lines 60-83
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// omac_memory creates a omac hash of char *in and dumps it in char *out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int omac_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,	 unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(inlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 6. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for  char *in using char *key.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/omac/omac_memory.c and above behavior is defined on lines 59-65
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// omac_file creates a omac hash of contents in	 char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int omac_file(int cipher, const unsigned char *key,	 unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
		
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 5. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for contents in char *filename using char *key. 
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/omac/omac_file.c and above behavior is defined on lines 57-80
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// pmac_memory creates a pmac hash of char *in and dumps it in char *out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int pmac_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,	 unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(inlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 6. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for  char *in using char *key.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/pmac/pmac_memory.c and above behavior is defined on lines 48-54
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// pmac_file creates a omac hash of contents in	 char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int pmac_file(int cipher, const unsigned char *key,	 unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
		
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 5. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for contents in char *filename using char *key.   
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/omac/pmac_file.c and above behavior is defined on lines 58-81
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// xcbc_memory creates a xcbc hash of char *in and dumps it in char *out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int xcbc_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,	 unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(inlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 6. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for  char *in using char *key.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/xcbc/xcbc_memory.c and above behavior is defined on lines 51-59
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// xcbc_file creates a omac hash of contents in	 char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int xcbc_file(int cipher, const unsigned char *key,	 unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
		
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 5. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for contents in char *filename using char *key.  
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/xcbc/xcbc_file.c and above behavior is defined on lines 57-80
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// f9_memory creates a f9 hash of char *in and dumps it in char *out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int f9_memory(int cipher, const unsigned char *key,	 unsigned long keylen, const unsigned char *in,	 unsigned long inlen, unsigned char *out,  unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(inlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 6. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for  char *in using char *key.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/f9/f9_memory.c and above behavior is defined on lines 51-59
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


// f9_file creates a omac hash of contents in  char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int f9_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,	unsigned long *outlen)
{
	unsigned char ch,outbuf;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
		
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(outlen);
	
	/* 5. char *out is finally filled with calculated value based on the hash algorithm chosen and is calculated for contents in char *filename using char *key. 
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/mac/f9/f9_file.c and above behavior is defined on lines 57-80
	*/		
	if (!ret_code) {
	   ((unsigned char*)out)[0] = outbuf; 
	}
	return ret_code;
}


/*
############################################################ Authenticate and Verify Memory Functions APIs #####################################################################
*/


// eax_encrypt_authenticate_memory encrypts plaintext data in pt using key and writes it to ct buffer. Also it calculates tag based on header, plaintext, etc. which then it writes to tag.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
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
									unsigned long *taglen)
{
	unsigned char ch,input;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;
	
	 /* 1. Reads "input" */
	input = *pt;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(noncelen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(headerlen);
	
	/* 6. Sinks if len is negative */
	__coverity_negative_sink__(ptlen);
	
	/* 7. Sinks if len is negative */
	__coverity_negative_sink__(taglen);
	
	/* 8. This function basically calls eax_init function on line 53 which sets eax->key structure with key value defined in /src/encauth/eax/eax_init.c on line and then calls eax_encrypt function on line 57 defined in /src/encauth/eax/eax_encrypt.c which calls ctr_encrypt on line 36 defined in /src/modes/ctr/ctr_encrypt.c. The ctr_encrypt function basically performs encryption on data pointed by *pt using *key and writes it to *ct. In simple sense it is ct = pt ^ (key after transformation based on algo)
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/eax/eax_encrypt_authenticate_memory.c
	*/		
	if (!ret_code) {
	   ((unsigned char*)ct)[0] = ch ^ input; 
	}
	return ret_code;
}


// eax_decrypt_verify_memory decrypts ciphertext data in ct using key and writes it to pt buffer. Also it calculates tag based on header, plaintext, etc. and tries to match it to the tag supplied in that tag parameter.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
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
									int *res)
{
	unsigned char ch,ciphertext;
	int ret_code;
	int stat;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;
	
	 /* 1. Reads "ct" */
	ciphertext = *ct;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(noncelen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(headerlen);
	
	/* 6. Sinks if len is negative */
	__coverity_negative_sink__(ctlen);
	
	/* 7. Sinks if len is negative */
	__coverity_negative_sink__(taglen);
	
	/* 8. This function basically calls eax_init function on line 74 which sets eax->key structure with key value defined in /src/encauth/eax/eax_init.c on line and then calls eax_decrypt function on line 78 defined in /src/encauth/eax/eax_decrypt.c which calls ctr_decrypt on line 41 defined in /src/modes/ctr/ctr_decrypt.c. The ctr_decrypt function basically performs decryption on data pointed by *ct using *key and writes it to *pt. In simple sense it is pt = ct ^ (key after transformation based on algo).It also writes a 1 or 0 to res based on whether tag passed in the function matches the calculated tag value.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/eax/eax_decrypt_verify_memory.c
	*/		
	if (!ret_code) {
		((unsigned char*) pt)[0] = ch ^ ciphertext; 
		res = stat;
	}
	return ret_code;
}


// ocb_encrypt_authenticate_memory encrypts plaintext data in pt using key and writes it to ct buffer. Also it calculates tag based on plaintext, etc. which then it writes to tag.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ocb_encrypt_authenticate_memory(int cipher,
									const unsigned char *key, 
									unsigned long keylen,
									const unsigned char *nonce,
									const unsigned char *pt, 
									unsigned long ptlen,
									unsigned char *ct,
									unsigned char *tag, 
									unsigned long *taglen)
{
	unsigned char ch,input;
	int ret_code;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;
	
	 /* 1. Reads "input" */
	input = *pt;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(ptlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(taglen);
	
	/* 6. This function basically calls ocb_init function on line 54 which sets ocb->key structure with key value defined in /src/encauth/ocb/ocb_init.c on line and then calls ocb_encrypt function on line 59 defined in /src/encauth/ocb/ocb_encrypt.c. The ocb_encrypt function basically performs encryption on data pointed by *pt using *key and writes it to *ct. In simple sense it is ct = pt ^ (key after transformation based on algo)
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
	*/		
	if (!ret_code) {
	   ((unsigned char*)ct)[0] = ch ^ input; 
	}
	return ret_code;
}



// ocb_decrypt_verify_memory decrypts ciphertext data in ct using key and writes it to pt buffer. Also it calculates tag based on header, plaintext, etc. and tries to match it to the tag supplied in that tag parameter.
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int ocb_decrypt_verify_memory(int cipher,
								const unsigned char *key,
								unsigned long keylen,
								const unsigned char *nonce,
								const unsigned char *ct, 
								unsigned long ctlen,
								unsigned char *pt,
								const unsigned char *tag, 
								unsigned long taglen,
								int *res)
{
	unsigned char ch,ciphertext;
	int ret_code, stat;
	
	/* Require that the caller always checks the return value. */
	__coverity_always_check_return_internal__();

	/* 1. Reads "key" */
	ch = *key;
	
	 /* 1. Reads "ct" */
	ciphertext = *ct;

	/* 2. data contains sensitive credentials and should not be hardcoded */
	__coverity_hardcoded_credential_crypto_sink__(key); 

	/* 3. Sinks if len is negative */
	__coverity_negative_sink__(keylen);
	
	/* 4. Sinks if len is negative */
	__coverity_negative_sink__(ctlen);
	
	/* 5. Sinks if len is negative */
	__coverity_negative_sink__(taglen);
	
	/* 6. This function basically calls ocb_init function on line 56 which sets ocb->key structure with key value defined in /src/encauth/ocb/ocb_init.c on line and then calls ocb_decrypt function on line 61 defined in /src/encauth/ocb/ocb_derypt.c. The ocb_decrypt function basically performs decryption on data pointed by *ct using *key and writes it to *pt. In simple sense it is pt = ct ^ (key after transformation based on algo). It also writes a 1 or 0 to res based on whether tag passed in the function matches the calculated tag value.
	Main function defined in https://github.com/libtom/libtomcrypt/blob/55fbe256adc4b063108279e5c9c563fa96198dc2/src/encauth/ocb/ocb_decrypt_verify_memory.c
	*/		
	if (!ret_code) {
	   ((unsigned char*) pt)[0] = ch ^ ciphertext; 
	   res = stat;
	}
	return ret_code;
}