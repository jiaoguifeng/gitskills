
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/pem.h>   
#include <openssl/evp.h>  

#include "inc/tr_tbox.h"
#include "tbox_crypto.h"

//modify for this
static AES_KEY aec_enc, aec_dec;
static uint8_t aes_key[16];
// aes_iv is fixed
static uint8_t aes_iv[16] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
void tbox_set_aes_key(uint8_t *buf)
{
    memcpy(aes_key, buf, 16);
    AES_set_encrypt_key(buf, 128, &aec_enc);
    AES_set_decrypt_key(buf, 128, &aec_dec);
}

uint8_t *tbox_get_aes_key(void)
{
    return aes_key;
}

static volatile int using_aes_key = 0;
void tbox_set_using_aes_key(void)
{
    using_aes_key = 1;
}

void tbox_reset_using_aes_key(void)
{
    using_aes_key = 0;
}

int tbox_using_aes_key(void)
{
    return using_aes_key;
}

int tbox_aes_decrypt(uint8_t *buf, int len, uint8_t **out_buf)
{
    int i;
    uint8_t iv[16];
    uint8_t *dec_buf;
    int padding_len;
    int out_buf_len;

    dec_buf = malloc(len);
    if (!dec_buf)
	{
		TBOX_LOG_ERROR("malloc error!");
		return -1;
    }

    memcpy(iv, aes_iv, sizeof(aes_iv));
    for (i = 0; (i + 16) <= len; i += 16)
        AES_cbc_encrypt(buf + i, dec_buf + i, 16, &aec_dec, iv, AES_DECRYPT);

    out_buf_len = len;

    // we use the last byte according to PCKS7 padding
    padding_len = dec_buf[len - 1];
    out_buf_len -= padding_len;

    if (out_buf)
		*out_buf = dec_buf;
    return out_buf_len;
}

int tbox_aes_encrypt(uint8_t *buf, int len, uint8_t **out_buf)
{
    int i, out_buf_len;
    uint8_t iv[16];
    uint8_t *enc_buf;
    uint8_t padding_buf[16];
    uint8_t padding_len;


    //PCKS7 padding
    out_buf_len = (len / 16 + 1) * 16;

    padding_len = 16 - len % 16;
    if (padding_len == 0)
		padding_len = 16;

    enc_buf = malloc(out_buf_len);
    if (!enc_buf) 
	{
		TBOX_LOG_ERROR("malloc error!");
		return -1;
    }

    memcpy(iv, aes_iv, sizeof(aes_iv));
    for (i = 0; (i + 16) <= len; i += 16)
        AES_cbc_encrypt(buf + i, enc_buf + i, 16, &aec_enc, iv, AES_ENCRYPT);

    if (len % 16) {
	    memcpy(padding_buf, buf + i, len % 16);
    }
	// padding
    memset(padding_buf + len % 16, padding_len, padding_len);


	AES_cbc_encrypt(padding_buf, enc_buf+i, 16, &aec_enc, iv, AES_ENCRYPT);

    if (out_buf)
		*out_buf = enc_buf;
    return out_buf_len;

}

int tbox_aes_ebc_decrypt(uint8_t *buf, int len, uint8_t **out_buf)
{
    int i;
    uint8_t *dec_buf;
    int padding_len;
    int out_buf_len;

    dec_buf = malloc(len);
    if (!dec_buf)
	{
		TBOX_LOG_ERROR("malloc error!");
		return -1;
    }

    for (i = 0; (i + 16) <= len; i += 16)
        AES_ecb_encrypt(buf + i, dec_buf + i, &aec_dec, AES_DECRYPT);

    out_buf_len = len;

    // we use the last byte according to PCKS7 padding
    padding_len = dec_buf[len - 1];
    out_buf_len -= padding_len;

	TBOX_LOG_DEBUG("out_buf_len :%d, padding_len : %d\n",out_buf_len, padding_len);
    if (out_buf)
		*out_buf = dec_buf;
    return out_buf_len;
}

int tbox_aes_ebc_encrypt(uint8_t *buf, int len, uint8_t **out_buf)
{
    int i, out_buf_len;
    uint8_t *enc_buf;
    uint8_t padding_buf[16];
    uint8_t padding_len;


    //PCKS7 padding
    out_buf_len = (len / 16 + 1) * 16;

    padding_len = 16 - len % 16;
    if (padding_len == 0)
		padding_len = 16;

    enc_buf = malloc(out_buf_len);
    if (!enc_buf) 
	{
		TBOX_LOG_ERROR("malloc error!");
		return -1;
    }

    for (i = 0; (i + 16) <= len; i += 16)
        AES_ecb_encrypt(buf + i, enc_buf + i, &aec_enc, AES_ENCRYPT);

    if (len % 16) 
	{
	    memcpy(padding_buf, buf + i, len % 16);
    }
	// padding
    memset(padding_buf + len % 16, padding_len, padding_len);

	AES_ecb_encrypt(padding_buf, enc_buf+i, &aec_enc, AES_ENCRYPT);

    if (out_buf)
		*out_buf = enc_buf;
    return out_buf_len;

}

static  pthread_mutex_t rsa_mutex = PTHREAD_MUTEX_INITIALIZER;
static RSA *rsa_key = NULL;

//generate public key and private key
int tbox_generate_key_pair()
{
	TBOX_LOG_DEBUG("tbox_generate_key_pair");
	pthread_mutex_lock(&rsa_mutex);
	if (rsa_key)
	{
        RSA_free(rsa_key);
        rsa_key = NULL;
    }

	rsa_key = RSA_generate_key(1024, 65537, NULL, NULL);
	TBOX_LOG_DEBUG("BIGNUM :%s\n",BN_bn2hex(rsa_key->n));

	//generate private key;
	//PEM_write_RSAPrivateKey(stdout, rsa_key, NULL, NULL, 0, NULL, NULL);
	//PEM_write_RSAPublicKey(stdout, rsa_key);

	pthread_mutex_unlock(&rsa_mutex);
	/*
	//generate public key
	unsigned char *n_b = (unsigned char *)calloc(RSA_size(rsa), sizeof(unsigned char));
	unsigned char *e_b = (unsigned char *)calloc(RSA_size(rsa), sizeof(unsigned char));

	int n_size = BN_bn2bin(rsa->n, n_b);
	int b_size = BN_bn2bin(rsa->e, e_b);

	TBOX_LOG_DEBUG("n_size :%d, b_size : %d\n",n_size,b_size);
	RSA *rsa_keys = RSA_new();
	rsa_keys->n = BN_bin2bn(n_b, n_size, NULL);
	rsa_keys->e = BN_bin2bn(e_b, b_size, NULL);
	
	TBOX_LOG_DEBUG("rsa_key->n :%s, rsa_key->e : %s\n",BN_bn2hex(rsa_keys->n),BN_bn2hex(rsa_keys->e));

	pthread_mutex_unlock(&rsa_mutex);
	PEM_write_RSAPublicKey(stdout, rsa_key);
	*/
	return 0;	
}

//
int load_rsa_key(uint8_t *n, int n_len, uint32_t e)
{
    RSA *r;
    BIGNUM *bne, *bnn, *bnd;
    int i;

    pthread_mutex_lock(&rsa_mutex);
    if (rsa_key)
	{
        RSA_free(rsa_key);
        rsa_key = NULL;
    }


    uint8_t *n_hex;
    char tmp[3];

    n_hex = alloca(n_len * 2 + 1);
    if (!n_hex) 
	{
		TBOX_LOG_ERROR("alloca error!");
        return -1;
    }

    for (i = 0; i < n_len; i++)
	{
        // must be Uppercase?
        sprintf(tmp, "%02X", n[i]);
        memcpy(n_hex + i * 2, tmp, 2);
    }
    n_hex[n_len * 2] = '\0'; // null-terminated

    bne = BN_new();
    bnn = BN_new();
    BN_set_word(bne, e);
    BN_hex2bn(&bnn, n_hex);

    r = RSA_new();
    r->e = bne;
    r->n = bnn;
    rsa_key = r;

    pthread_mutex_unlock(&rsa_mutex);

   	//PEM_write_RSAPublicKey(stderr, r);

    return 0;
}

int tbox_has_rsa_key(void)
{
    int ret;

    pthread_mutex_lock(&rsa_mutex);
    ret = rsa_key ? 1 : 0;
    pthread_mutex_unlock(&rsa_mutex);

	return ret;
}

int tbox_get_rsa_public_key(uint8_t **out_buf)
{
	uint8_t *buf = NULL;
	//generate public key
	unsigned char *n_b = (unsigned char *)calloc(RSA_size(rsa_key), sizeof(unsigned char));
	unsigned char *e_b = (unsigned char *)calloc(RSA_size(rsa_key), sizeof(unsigned char));

	int n_size = BN_bn2bin(rsa_key->n, n_b);
	int b_size = BN_bn2bin(rsa_key->e, e_b);

	TBOX_LOG_DEBUG("n_size :%d, b_size : %d\n",n_size,b_size);

	TBOX_LOG_DEBUG("rsa_key->n :%s, rsa_key->e : %s\n",BN_bn2hex(rsa_key->n),BN_bn2hex(rsa_key->e));
	char *public_key = BN_bn2hex(rsa_key->n);
	int pub_key_len = strlen(public_key);

	TBOX_LOG_DEBUG("n_size :%d\n",pub_key_len);
	buf = malloc(pub_key_len+1);

	memset(buf, 0, pub_key_len+1);
	memcpy(buf, public_key, pub_key_len);
	if (out_buf)
      *out_buf = buf;

	return 0;
}

int tbox_rsa_encrypt(uint8_t *in_buf, int in_len, uint8_t **out_buf)
{
    int ret = -1, plen = 0;
    uint8_t *buf = NULL;

    if (!out_buf)
	{
		TBOX_LOG_ERROR("error!");
		return -1;
	}

    pthread_mutex_lock(&rsa_mutex);
    if (rsa_key)
	{
        plen = RSA_size(rsa_key);
        buf = malloc(plen);
		if (!buf)
		{
			TBOX_LOG_ERROR("malloc error!");
		}
		else
		{
            memset(buf, 0, plen);
            ret = RSA_public_encrypt(in_len, in_buf, buf, rsa_key, RSA_PKCS1_PADDING);
		}
    }
    pthread_mutex_unlock(&rsa_mutex);

	TBOX_LOG_DEBUG("tbox_rsa_encrypt ret : %d\n",ret);
    if (ret < 0)
	{
        if (buf)
            free(buf);
        TBOX_LOG_ERROR("RSA_public_encrypt: ret=%d plen=%d", ret, plen);
        return -1;
    }

    if (out_buf)
        *out_buf = buf;

    return ret;
}

int tbox_rsa_decrypt(uint8_t *in_buf, int in_len, uint8_t **out_buf)
{
    int ret = -1, plen = 0;
    uint8_t *buf = NULL;

    if (!out_buf)
	{
		TBOX_LOG_ERROR("error!");
		return -1;
	}

    pthread_mutex_lock(&rsa_mutex);
    if (rsa_key) 
	{
        plen = RSA_size(rsa_key);
        buf = malloc(plen);
		if (!buf)
		{
			TBOX_LOG_ERROR("malloc error!");
		}
		else
		{
            memset(buf, 0, plen);
            ret = RSA_public_decrypt(plen, in_buf, buf, rsa_key, RSA_PKCS1_PADDING);
		}
    }
    pthread_mutex_unlock(&rsa_mutex);

	TBOX_LOG_DEBUG("tbox_rsa_decrypt ret : %d\n",ret);
    if (ret < 0)
	{
        if (buf)
            free(buf);
        TBOX_LOG_ERROR("RSA_public_decrypt: ret=%d plen=%d", ret, plen);
        return -1;
    }

    if (out_buf)
        *out_buf = buf;

    return ret;
}

//MD5 encrypt
int md5_encrypt(uint8_t *in_buf, int in_len, uint8_t *out_buf)
{
	MD5_CTX the_md5;
	
	MD5_Init(&the_md5);
	MD5_Update(&the_md5, in_buf, in_len);
	MD5_Final(out_buf, &the_md5);

	return 0;
}


//base64 encode decode
int base64_encode(char *in_str, int in_len, char *out_str)  
{  
	BIO *b64, *bio;  
    BUF_MEM *bptr = NULL;  
    size_t size = 0;  
      
    if (in_str == NULL || out_str == NULL)  
   		return -1;  
      
    b64 = BIO_new(BIO_f_base64());  
    bio = BIO_new(BIO_s_mem());  
    bio = BIO_push(b64, bio);  
      
    BIO_write(bio, in_str, in_len);  
    BIO_flush(bio);  
      
    BIO_get_mem_ptr(bio, &bptr);  
    memcpy(out_str, bptr->data, bptr->length);  
    out_str[bptr->length] = '\0';  
    size = bptr->length;  
      
    BIO_free_all(bio);  
    return size;  
}  
      
int base64_decode(char *in_str, int in_len, char *out_str)  
{  
	BIO *b64, *bio;  
    BUF_MEM *bptr = NULL;  
    int counts;  
    int size = 0;  
      
    if (in_str == NULL || out_str == NULL)  
    	return -1;  
      
    b64 = BIO_new(BIO_f_base64());  
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
      
    bio = BIO_new_mem_buf(in_str, in_len);  
    bio = BIO_push(b64, bio);  
      
    size = BIO_read(bio, out_str, in_len);  
    out_str[size] = '\0';  
      
    BIO_free_all(bio);  
    return size;  
} 

