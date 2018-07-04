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


typedef void symmetric_xts;
// lrw_start initializes "symmetric_xts *xts" to be used using the key. 
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
    __coverity_hardcoded_credential_crypto_sink__(key1); //#event#crypto_use
    
    /* 4. data contains sensitive credentials and should not be hardcoded */
    __coverity_hardcoded_credential_crypto_sink__(key2); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use
    
    /* 4. data contains sensitive credentials and should not be hardcoded */
    __coverity_hardcoded_credential_crypto_sink__(salt_key); //#event#crypto_use

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
############################################## File and Memory Encryption/Decryption Functions APIS #####################################################################
*/

// hmac_memory creates a hmac hash of char *in and dumps it in char * out using the secret *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int hmac_memory(int hash, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,  unsigned long *outlen)
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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
int omac_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,  unsigned long *outlen)
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


// omac_file creates a omac hash of contents in  char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int omac_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
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
int pmac_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,  unsigned long *outlen)
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


// pmac_file creates a omac hash of contents in  char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int pmac_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
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
int xcbc_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,  unsigned long *outlen)
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


// xcbc_file creates a omac hash of contents in  char *filename and dumps it in char *out using the secret char *key 
// Vulnerable argument: "const unsigned char *key" is the vulnerable argument
// that could be hard-coded by the developer
// headers/tomcrypt_cipher.h
int xcbc_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
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
int f9_memory(int cipher, const unsigned char *key,  unsigned long keylen, const unsigned char *in,  unsigned long inlen, unsigned char *out,  unsigned long *outlen)
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
int f9_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)
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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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
    __coverity_hardcoded_credential_crypto_sink__(key); //#event#crypto_use

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


//int lrw_start( int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *tweak, int num_rounds, symmetric_LRW *lrw)

void test_lrw_start(char *passw,char *tweak2) {

        char pass[] = "Hardcoded";  
        char IV1[] = "dsssdsdsddsdsd";  
        char tweak1[] = "ssdsdsdsdkey";
        symmetric_LRW *lrw1;        
        unsigned long pass_len = sizeof(pass);
        int ret;

        ret = lrw_start(1, IV1, pass, pass_len, tweak2, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = lrw_start(1, IV1, passw, pass_len, tweak1, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = lrw_start(1, IV1, passw, pass_len, tweak2, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = lrw_start(1, IV1, pass, pass_len, tweak1, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto //#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

//int xts_start( int cipher,const unsigned char *key1, const unsigned char *key2, unsigned long keylen, int num_rounds, symmetric_xts *xts)

void test_xts_start(char *passw,char *tweak2) {

        char key_1[] = "Hardcoded"; 
        char IV1[] = "dsssdsdsddsdsd";  
        char key_2[] = "ssdsdsdsdkey";
        symmetric_xts *lrw1;        
        unsigned long key1_len = sizeof(key_1);
        int ret;

        ret = xts_start(1, key_1, tweak2, key1_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = xts_start(1, passw, key_2, key1_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = xts_start(1, passw, tweak2, key1_len, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = xts_start(1, key_1, key_2, key1_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto //#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


//int f8_start( int cipher, const unsigned char *IV, const unsigned char *key, int keylen, const unsigned char *salt_key, int skeylen, int num_rounds, symmetric_F8 *f8)

void test_f8_start(char *passw,char *tweak2) {

        char key_1[] = "Hardcoded"; 
        char IV1[] = "dsssdsdsddsdsd";  
        char key_2[] = "ssdsdsdsdkey";
        symmetric_F8 *lrw1;         
        unsigned long key1_len = sizeof(key_1);
        unsigned long key2_len = sizeof(key_2);
        int ret;

        ret = f8_start(1, IV1, key_1, key1_len, tweak2, key2_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = f8_start(1, IV1, passw, key1_len, key_2, key2_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = f8_start(1, IV1, passw, key1_len, tweak2, key2_len, 0, lrw1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = f8_start(1, IV1, key_1, key1_len, key_2, key2_len, 0, lrw1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto //#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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


/*
############################################# File and Memory Encryption/Decryption ALGO TEST CASES #####################################################################
*/


void test_hmac_memory(char *passw) {

        char pass[] = "Hardcoded";  
        char in1[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);
        unsigned long in1_len = sizeof(in1);
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = hmac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = hmac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

//int hmac_file( int hash, const char *fname, const unsigned char *key,  unsigned long keylen, unsigned char *out, unsigned long *outlen)


void test_hmac_file(char *passw) {

        char pass[] = "Hardcoded";  
        char filename[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);  
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = hmac_file(1, filename, pass, pass_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = hmac_file(1, filename, passw, pass_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_omac_memory(char *passw) {

        char pass[] = "Hardcoded";  
        char in1[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);
        unsigned long in1_len = sizeof(in1);
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = omac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = omac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

// int omac_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)

void test_omac_file(char *passw) {

        char pass[] = "Hardcoded";  
        char filename[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);  
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = omac_file(1, pass, pass_len,  filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = omac_file(1, passw, pass_len,  filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_pmac_memory(char *passw) {

        char pass[] = "Hardcoded";  
        char in1[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);
        unsigned long in1_len = sizeof(in1);
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = pmac_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = pmac_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}

// int pmac_file(int cipher, const unsigned char *key,  unsigned long keylen, const char *filename, unsigned char *out,  unsigned long *outlen)

void test_pmac_file(char *passw) {

        char pass[] = "Hardcoded";  
        char filename[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);  
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = pmac_file(1, pass, pass_len,  filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = pmac_file(1, passw, pass_len,  filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_xcbc_memory(char *passw) {

        char pass[] = "Hardcoded";  
        char in1[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);
        unsigned long in1_len = sizeof(in1);
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = xcbc_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = xcbc_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_xcbc_file(char *passw) {

        char pass[] = "Hardcoded";  
        char filename[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);  
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = xcbc_file(1, pass, pass_len,  filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = xcbc_file(1, passw, pass_len,  filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}


void test_f9_memory(char *passw) {

        char pass[] = "Hardcoded";  
        char in1[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);
        unsigned long in1_len = sizeof(in1);
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = f9_memory(1, pass, pass_len, in1, in1_len, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = f9_memory(1, passw, pass_len, in1, in1_len, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}



void test_f9_file(char *passw) {

        char pass[] = "Hardcoded";  
        char filename[] = "test";
        char *out1; 
    
        unsigned long pass_len = sizeof(pass);  
        unsigned long out1_len = sizeof(out1);
        int ret;

        ret = f9_file(1, pass, pass_len,  filename, out1, out1_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = f9_file(1, passw, pass_len,  filename, out1, out1_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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
        char *ct1, *tag1;   
    
        unsigned long key_len = sizeof(key1);
        unsigned long nonce_len = sizeof(nonce1);
        unsigned long header_len = sizeof(header1);
        unsigned long pt_len = sizeof(pt1);
        unsigned long tag_len = sizeof(tag1);
        
        int ret;

        ret = eax_encrypt_authenticate_memory(1, key1, key_len, nonce1, nonce_len, header1, header_len, pt1, pt_len, ct1, tag1, tag_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = eax_encrypt_authenticate_memory(1, passw, key_len, nonce1, nonce_len, header1, header_len, pt1, pt_len, ct1, tag1, tag_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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
        char *pt1;  
    
        unsigned long key_len = sizeof(key1);
        unsigned long nonce_len = sizeof(nonce1);
        unsigned long header_len = sizeof(header1);
        unsigned long tag_len = sizeof(tag1);
        unsigned long ct_len = sizeof(ct1);
        
        int ret, res1;

        ret = eax_decrypt_verify_memory(1, key1, key_len, nonce1, nonce_len, header1, header_len, ct1, ct_len, pt1, tag1, tag_len, res1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = eax_decrypt_verify_memory(1, passw, key_len, nonce1, nonce_len, header1, header_len, ct1, ct_len, pt1, tag1, tag_len, res1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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
        char *ct1, *tag1;   
    
        unsigned long key_len = sizeof(key1);       
        unsigned long pt_len = sizeof(pt1);
        unsigned long tag_len = sizeof(tag1);
        
        int ret;

        ret = ocb_encrypt_authenticate_memory(1, key1, key_len, nonce1, pt1, pt_len, ct1, tag1, tag_len);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = ocb_encrypt_authenticate_memory(1, passw, key_len, nonce1, pt1, pt_len, ct1, tag1, tag_len);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

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
        char *pt1;  
    
        unsigned long key_len = sizeof(key1);
        unsigned long tag_len = sizeof(tag1);
        unsigned long ct_len = sizeof(ct1);
        
        int ret, res1;

        ret = ocb_decrypt_verify_memory(1, key1, key_len, nonce1, ct1, ct_len, pt1, tag1, tag_len, res1);//#defect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto
        
        ret = ocb_decrypt_verify_memory(1, passw, key_len, nonce1, ct1, ct_len, pt1, tag1, tag_len, res1);//#nodefect#HARDCODED_CREDENTIALS#__coverity_hardcoded_credential_crypto_sink__#hardcoded_credential_crypto

}