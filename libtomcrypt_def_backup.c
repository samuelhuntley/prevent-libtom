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
    __coverity_hardcoded_credential_crypto_sink__(password); //#event#crypto_use

	
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
    __coverity_hardcoded_credential_crypto_sink__(password); //#event#crypto_use

	
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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

    /* 3. Sinks if len is negative */
    __coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
    __coverity_negative_sink__(num_rounds);
	
	
	 /* 5. Sinks if ctr mode is negative */
    __coverity_negative_sink__(ctr_mode);
	
	/* 6. only when function returns 0, then &ctr->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup  ctr data structure with the key from key argument 
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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

    /* 3. Sinks if len is negative */
    __coverity_negative_sink__(keylen);
	
	 /* 4. Sinks if rounds is negative */
    __coverity_negative_sink__(num_rounds);
		
	/* 5. only when function returns 0, then &cbc->key is set up using the cipher specific SETUP function e.g. in aes.c SETUP function would be called if aes is used with the cipher algo and this will setup  cbc data structure with the key from key argument 
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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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

        ret = pkcs_5_alg2(pass, pass_len, salt, salt_len, itr_cnt, h_idx, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        ret1 = pkcs_5_alg2(passw, pass_len, salt, salt_len, itr_cnt, h_idx, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

/*
############################################################ SYMMETRIC ALGO TEST CASES #####################################################################
*/

void test_rijndael_setup() {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = rijndael_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_safer_sk64_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = safer_sk64_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = safer_sk64_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_safer_sk128_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = safer_sk128_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = safer_sk128_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_twofish_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = twofish_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = twofish_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_anubis_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = anubis_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = anubis_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_blowfish_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = blowfish_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = blowfish_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_camellia_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = camellia_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = camellia_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_cast5_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = cast5_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = cast5_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_des_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = des_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = des_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_des3_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = des3_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = des3_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_idea_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = idea_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = idea_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_kasumi_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = kasumi_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = kasumi_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_khazad_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = khazad_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = khazad_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}




void test_kseed_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = kseed_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = kseed_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_multi2_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = multi2_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = multi2_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_noekeon_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = noekeon_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = noekeon_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_rc2_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = rc2_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = rc2_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_rc5_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = rc5_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = rc5_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_rc6_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = rc6_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = rc6_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_serpent_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = serpent_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = serpent_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_skipjack_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = skipjack_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = skipjack_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}




void test_xtea_setup(char *passw) {

        char pass[] = "Hardcoded";
        unsigned long pass_len = sizeof(pass);
        symmetric_key *skey1;
        int ret;

        ret = xtea_setup(pass, pass_len, 0, skey1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = xtea_setup(passw, pass_len, 0, skey1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}




void test_ctr_start(char *passw) {

        char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
        unsigned long pass_len = sizeof(pass);
        symmetric_CTR *ctr1;
        int ret;

        ret = ctr_start(1, IV1, pass, pass_len, 0, 0, ctr1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = ctr_start(1, IV1, passw, pass_len, 0, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_cbc_start(char *passw) {

        char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
        unsigned long pass_len = sizeof(pass);
        symmetric_CBC *ctr1;
        int ret;

        ret = cbc_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = cbc_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_cfb_start(char *passw) {

        char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
        unsigned long pass_len = sizeof(pass);
        symmetric_CFB *ctr1;
        int ret;

        ret = cfb_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = cfb_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_ofb_start(char *passw) {

        char pass[] = "Hardcoded";
		char IV1[]= "sssssssssssssss";
        unsigned long pass_len = sizeof(pass);
        symmetric_OFB *ctr1;
        int ret;

        ret = ofb_start(1, IV1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = ofb_start(1, IV1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_ecb_start(char *passw) {

        char pass[] = "Hardcoded";		
        unsigned long pass_len = sizeof(pass);
        symmetric_ECB *ctr1;
        int ret;

        ret = ecb_start(1, pass, pass_len, 0, ctr1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = ecb_start(1, passw, pass_len, 0, ctr1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}




//int eax_init( eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen, const unsigned char *header, unsigned long headerlen)
#define NULL 0

void test_eax_init(char *passw) {

        char pass[] = "Hardcoded";	
		eax_state *eax1; 
		char nonce1 = "sssssssssss";
        unsigned long pass_len = sizeof(pass);
		unsigned long nonce1_len = sizeof(nonce1);
       
        int ret;

        ret = eax_init(eax1, 0, pass, pass_len, nonce1,nonce1_len, NULL,0);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = eax_init(eax1, 0, passw, pass_len, nonce1,nonce1_len, NULL,0);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int ocb_init( ocb_state *ocb, int cipher, const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
#define NULL 0

void test_ocb_init(char *passw) {

        char pass[] = "Hardcoded";	
		ocb_state *eax1; 
		char nonce1 = "sssssssssss";
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = ocb_init(eax1, 1, pass, pass_len, nonce1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = ocb_init(eax1, 1, passw, pass_len, nonce1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int gcm_init(gcm_state *gcm, int cipher, const unsigned char *key, int keylen)
#define NULL 0

void test_gcm_init(char *passw) {

        char pass[] = "Hardcoded";	
		gcm_state *eax1; 
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = gcm_init(eax1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = gcm_init(eax1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int ccm_init(ccm_state *ccm, int cipher, const unsigned char *key, int keylen, int ptlen, int taglen, int aadlen)
#define NULL 0

void test_ccm_init(char *passw) {

        char pass[] = "Hardcoded";	
		ccm_state *eax1; 
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = ccm_init(eax1, 1, pass, pass_len, 8, 8, 16);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = ccm_init(eax1, 1, passw, pass_len, 8, 8, 16);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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

        ret = hmac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = hmac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int omac_init( omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen)

void test_omac_init(char *passw) {

        char pass[] = "Hardcoded";	
		omac_state *hmac1; 		
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = omac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = omac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

//int pmac_init( pmac_state *pmac, int cipher, const unsigned char *key, unsigned long keylen)

void test_pmac_init(char *passw) {

        char pass[] = "Hardcoded";	
		pmac_state *hmac1; 		
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = pmac_init(hmac1, 0, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = pmac_init(hmac1, 0, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

//int pelican_init( pelican_state *pelmac, const unsigned char *key, unsigned long keylen)

void test_pelican_init(char *passw) {

        char pass[] = "Hardcoded";	
		pelican_state *hmac1; 		
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = pelican_init(hmac1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = pelican_init(hmac1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int xcbc_init( xcbc_state *xcbc, int cipher, const unsigned char *key, unsigned long keylen)

void test_xcbc_init(char *passw) {

        char pass[] = "Hardcoded";	
		xcbc_state *hmac1; 		
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = xcbc_init(hmac1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = xcbc_init(hmac1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

//int f9_init( f9_state *f9, int cipher, const unsigned char *key, unsigned long keylen)

void test_f9_init(char *passw) {

        char pass[] = "Hardcoded";	
		f9_state *hmac1; 		
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = f9_init(hmac1, 1, pass, pass_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
		
		ret = f9_init(hmac1, 1, passw, pass_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}