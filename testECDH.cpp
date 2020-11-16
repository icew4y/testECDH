// testECDH.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#define ECDH_SIZE 256


EC_KEY* gen_ECDH_pubkey(unsigned char* pubkey, size_t& len) {
    int ret = 0;

    //Generate Public
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp192k1);
    ret = EC_KEY_generate_key(key);

    const EC_POINT *point = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);


//     BIGNUM* x = BN_new();
//     BIGNUM* y = BN_new();
// 
//     ret = EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL);
//     if (ret == 1)
//     {
//         BN_print_fp(stdout, x);
//         putc('\n', stdout);
//         BN_print_fp(stdout, y);
//         putc('\n', stdout);
//     }
// 
//     BN_free(x);
//     BN_free(y);


    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL);
    return key;
}


unsigned char* gen_ECDH_sharedsecret(EC_KEY* ecdh, unsigned char* peerkey, size_t secret_len) {
    int len, ret;
    unsigned char* shared = new unsigned char[ECDH_SIZE];
    memset(shared, 0, ECDH_SIZE);
    const EC_GROUP* group = EC_KEY_get0_group(ecdh);

    //Computekey
    EC_POINT* point_peer = EC_POINT_new(group);
    EC_POINT_oct2point(group, point_peer, peerkey, secret_len, NULL);
    ECDH_compute_key(shared, ECDH_SIZE - 1, point_peer, ecdh, NULL);
    return shared;
}

int main()
{
    std::cout << "Hello World!\n";
	unsigned char* alice_pubkey = (unsigned char*)malloc(ECDH_SIZE);
    memset(alice_pubkey, 0, ECDH_SIZE);
	unsigned char* bob_pubkey = (unsigned char*)malloc(ECDH_SIZE);
    memset(bob_pubkey, 0, ECDH_SIZE);
	size_t len_alice = 0, len_bob = 0;

    //Alice pubkey
    EC_KEY * Alice = gen_ECDH_pubkey(alice_pubkey, len_alice);

    //Bob pubkey
    EC_KEY* Bob = gen_ECDH_pubkey(bob_pubkey, len_bob);


	//Alice need Bob pubkey to generate shared data
	unsigned char* bob_sharedkey = gen_ECDH_sharedsecret(Alice, bob_pubkey, len_bob);
    
    //Bob need Alice pubkey to generate shared data
    unsigned char *alice_sharedkey = gen_ECDH_sharedsecret(Bob, alice_pubkey, len_alice);


    //alice_sharedkey should be equal bob_sharedkey
    if (0 == memcmp(alice_sharedkey, bob_sharedkey, ECDH_SIZE))
    {
        BIGNUM* skey = BN_new();
        BN_bin2bn(alice_sharedkey, 192/8, skey);
        BN_print_fp(stdout, skey);
        BN_free(skey);
    }

    EC_KEY_free(Alice);
    EC_KEY_free(Bob);
    free(alice_pubkey);
    free(bob_pubkey);
	free(alice_sharedkey);
	free(bob_sharedkey);
}

