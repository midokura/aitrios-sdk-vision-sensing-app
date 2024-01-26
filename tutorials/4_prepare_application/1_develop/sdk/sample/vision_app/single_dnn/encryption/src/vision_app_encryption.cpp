/****************************************************************************
 * Copyright 2023 Sony Semiconductor Solutions Corp. All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 ****************************************************************************/

#include <stdio.h>

// random
#include <stdlib.h>

// memcpy
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <monocypher.h>

#include "vision_app_public.h"

/* -------------------------------------------------------- */
/* macro define                                             */
/* -------------------------------------------------------- */
#define ERR_PRINTF(fmt, ...) pthread_mutex_lock(&g_libc_mutex);fprintf(stderr, "E [VisionAPP] ");fprintf(stderr, fmt, ##__VA_ARGS__);fprintf(stderr, "\n");pthread_mutex_unlock(&g_libc_mutex);
#define WARN_PRINTF(fmt, ...) pthread_mutex_lock(&g_libc_mutex);fprintf(stderr, "W [VisionAPP] ");fprintf(stderr, fmt, ##__VA_ARGS__);fprintf(stderr, "\n");pthread_mutex_unlock(&g_libc_mutex);
#define INFO_PRINTF(fmt, ...) pthread_mutex_lock(&g_libc_mutex);fprintf(stdout, "I [VisionAPP] ");fprintf(stdout, fmt, ##__VA_ARGS__);fprintf(stdout, "\n");pthread_mutex_unlock(&g_libc_mutex);
#define DBG_PRINTF(fmt, ...) pthread_mutex_lock(&g_libc_mutex);printf( "D [VisionAPP] "); printf( fmt, ##__VA_ARGS__); printf( "\n");pthread_mutex_unlock(&g_libc_mutex);
#define VER_PRINTF(fmt, ...) pthread_mutex_lock(&g_libc_mutex);printf( "V [VisionAPP] "); printf( fmt, ##__VA_ARGS__); printf( "\n");pthread_mutex_unlock(&g_libc_mutex);

/* -------------------------------------------------------- */
/* static                                                   */
/* -------------------------------------------------------- */

static bool  s_is_evp_exit = false;

#include "operator_public_key.h"

static uint8_t secret_key[32];
static uint8_t public_key[32];
static uint8_t shared_key[32];


/* prevent libc func with multi thread */
pthread_mutex_t g_libc_mutex;

static void *evp_Thread(void *arg);
static void  ConfigurationCallback(const char *topic, const void *config, size_t config_len, void *private_data);

void
append_bytearray_hex_encode(char **output, uint8_t *array, size_t len) {
        for (int i = 0; i < len; i++) {
                pthread_mutex_lock(&g_libc_mutex);
                sprintf((*output) + 2 * i, "%02x", array[i]);
                pthread_mutex_unlock(&g_libc_mutex);
        }
        *output += 2 * len;
}

void
get_shared_key(uint8_t *shared_key, size_t shared_key_len,
               const uint8_t operator_public_key[32])
{
        /* get temporary shared secret */
        uint8_t shared_secret[32];

        fprintf(stderr, "  crypto_x25519(...)\n");
        crypto_x25519(
                shared_secret, secret_key,
                operator_public_key); /* TODO: move this to device agent */
        fprintf(stderr, "  crypto_x25519(...);\n");

        /* derive shared key */
        crypto_blake2b_ctx ctx;
        fprintf(stderr, "  crypto_blake2b_init(...)\n");
        crypto_blake2b_init(&ctx, shared_key_len);
        fprintf(stderr, "  crypto_blake2b_init(...);\n");

        fprintf(stderr, "  crypto_blake2b_update(...)\n");
        crypto_blake2b_update(&ctx, shared_secret, 32);
        fprintf(stderr, "  crypto_blake2b_update(...);\n");

        fprintf(stderr, "  crypto_blake2b_update(...)\n");
        crypto_blake2b_update(&ctx, public_key, 32);
        fprintf(stderr, "  crypto_blake2b_update(...);\n");

        fprintf(stderr, "  crypto_blake2b_update(...)\n");
        crypto_blake2b_update(&ctx, operator_public_key, 32);
        fprintf(stderr, "  crypto_blake2b_update(...);\n");

        fprintf(stderr, "  crypto_blake2b_final(...)\n");
        crypto_blake2b_final(&ctx, shared_key);
        fprintf(stderr, "  crypto_blake2b_final(...);\n");

        fprintf(stderr, "  crypto_wipe(...)\n");
        crypto_wipe(shared_secret, 32);
        fprintf(stderr, "  crypto_wipe(...);\n");
}

void
arc4random_buf(char *buf, size_t n)
{
        /* WARNING: this is just for testing. DO NOT use it for production! */
        while (n) {
                pthread_mutex_lock(&g_libc_mutex);
                int x = random();
                pthread_mutex_unlock(&g_libc_mutex);
                size_t inc = n < sizeof(x) ? n : sizeof(x);
                pthread_mutex_lock(&g_libc_mutex);
                memcpy(buf, (void *)&x, inc);
                pthread_mutex_unlock(&g_libc_mutex);
                buf += inc;
                n -= inc;
        }
}

void
encrypt_text(char *text /* in/out */, uint8_t mac[16] /* out */,
             uint8_t nonce[24] /* out */, uint8_t key[32] /* in */)
{
        /* generate nonce */
        fprintf(stderr, "  arc4random_buf(...)\n");
        arc4random_buf(nonce, 24);
        fprintf(stderr, "  arc4random_buf(...);\n");

        /* encrypt text (and generate mac) */
        fprintf(stderr, "  crypto_aead_lock(...)\n");
        crypto_aead_lock((uint8_t *)text, mac, key, nonce, NULL, 0,
                         (uint8_t *)text, strlen(text));
        fprintf(stderr, "  crypto_aead_lock(...);\n");
}

char *
encrypt_telemetry_value(char *value)
{
        uint8_t mac[16];
        uint8_t nonce[24];
        pthread_mutex_lock(&g_libc_mutex);
        size_t value_len = strlen(value);
        pthread_mutex_unlock(&g_libc_mutex);

        fprintf(stderr, " encrypt_text(...)\n");
        encrypt_text(value, mac, nonce, shared_key);
        fprintf(stderr, " encrypt_text(...);\n");

        pthread_mutex_lock(&g_libc_mutex);
        char *ciphertext = (char *) malloc(1 + 2 * (sizeof(public_key) + sizeof(nonce) + sizeof(mac) + value_len) + 1 + 1);
        pthread_mutex_unlock(&g_libc_mutex);
        char *cursor = ciphertext;

        *cursor++ = '"';
        fprintf(stderr, " append_bytearray_hex_encode(...)\n");
        append_bytearray_hex_encode(&cursor, public_key, sizeof(public_key));
        fprintf(stderr, " append_bytearray_hex_encode(...);\n");
        fprintf(stderr, " append_bytearray_hex_encode(...)\n");
        append_bytearray_hex_encode(&cursor, nonce, sizeof(nonce));
        fprintf(stderr, " append_bytearray_hex_encode(...);\n");
        fprintf(stderr, " append_bytearray_hex_encode(...)\n");
        append_bytearray_hex_encode(&cursor, (uint8_t *) value, value_len);
        fprintf(stderr, " append_bytearray_hex_encode(...);\n");
        fprintf(stderr, " append_bytearray_hex_encode(...)\n");
        append_bytearray_hex_encode(&cursor, mac, sizeof(mac));
        fprintf(stderr, " append_bytearray_hex_encode(...);\n");
        *cursor++ = '"';
        *cursor = '\0';

        return ciphertext;
}


void
prepare_crypto()
{
        fprintf(stderr, " arc4random_buf(...)\n");
        arc4random_buf((char *) secret_key, 32);
        fprintf(stderr, " arc4random_buf(...);\n");

        fprintf(stderr, " crypto_x25519_public_key(...)\n");
        crypto_x25519_public_key(public_key, secret_key);
        fprintf(stderr, " crypto_x25519_public_key(...);\n");

        fprintf(stderr, " get_shared_key(...)\n");
        get_shared_key(shared_key, sizeof(shared_key), operator_public_key);
        fprintf(stderr, " get_shared_key(...);\n");
}

/* -------------------------------------------------------- */
/* public function                                          */
/* -------------------------------------------------------- */
int main(int argc, char *argv[]) {
    pthread_t         evpthread_handle;
    int32_t           ret = -1;

    fprintf(stderr, "START OF MODULE (STDERR)\n");

    if (pthread_mutex_init(&g_libc_mutex, NULL) != 0) {
        printf("pthread_mutex_init failed libc_mutex");
        return -1;
    }

    if (setvbuf(stdout, NULL, _IOFBF, BUFSIZ) != 0) {
        ERR_PRINTF("fail setvbuf");
        return -1;
    }

    INFO_PRINTF("vision app encryption start\n");

    fprintf(stderr, "prepare_crypto()\n");
    prepare_crypto();
    fprintf(stderr, "prepare_crypto();\n");


    ret = pthread_create(&evpthread_handle, NULL, evp_Thread, NULL);
    if (ret != 0) {
        ERR_PRINTF("pthread_create failed for evp_Thread");
        return -1;
    }

    ret = pthread_join(evpthread_handle, NULL);
    if (ret != 0) {
        ERR_PRINTF("pthread_join error");
    }

    pthread_mutex_destroy(&g_libc_mutex);
    return 0;
}

static void *evp_Thread(void *arg) {

    struct EVP_client* handle = EVP_initialize();
    INFO_PRINTF("EVP client handle:%p\n", handle);
    EVP_RESULT evp_ret = EVP_OK;
    evp_ret = EVP_setConfigurationCallback(handle, (EVP_CONFIGURATION_CALLBACK)ConfigurationCallback, NULL);
    INFO_PRINTF("EVP_setConfigurationCallback evp_ret:%d\n", evp_ret);

    while (1) {
        if (s_is_evp_exit == true) {
            ERR_PRINTF("pthread_exit");
            pthread_exit(NULL);
            break;
        }

        int32_t timeout_msec = 1000;
        evp_ret = EVP_processEvent(handle, timeout_msec);
        if (evp_ret == EVP_SHOULDEXIT) {
            INFO_PRINTF("Should exit vision app");
            s_is_evp_exit = true;
            break;
        }
        else if (evp_ret == EVP_TIMEDOUT) {
            /* Do Nothing */
        }
        else if (evp_ret) {
            ERR_PRINTF("Failed to EVP_processEvent:%d\n", evp_ret);
        }
        else {
            /* Do Nothing */
        }

        char value[] = "foo";
        fprintf(stderr, "encrypt_telemetry_value(...)\n");
        char* ciphertext = encrypt_telemetry_value(value);
        fprintf(stderr, "encrypt_telemetry_value(...);\n");

        fprintf(stderr, "ciphertext: '%s'\n", ciphertext);

        pthread_mutex_lock(&g_libc_mutex);
        free(ciphertext);
        pthread_mutex_unlock(&g_libc_mutex);
    }

    return NULL;
}

static void ConfigurationCallback(const char *topic, const void *config, size_t configlen, void *userData) {

    DBG_PRINTF("%s", __func__);

    if ((char *)config == NULL) {
        ERR_PRINTF("Invalid param : config=NULL");
        return;
    }
    INFO_PRINTF("%s topic:%s\nconfig:%s\nconfig_len:%zu\nuserData:%p\n", __func__, topic, (char*)config, configlen, userData);

    pthread_mutex_lock(&g_libc_mutex);
    int str_ret = strcmp((char *)config, "");
    pthread_mutex_unlock(&g_libc_mutex);

    if (str_ret == 0) {
        INFO_PRINTF("ConfigurationCallback: config is empty.");
        return;
    }

    pthread_mutex_lock(&g_libc_mutex);
    char *value = (char *) malloc(configlen+1);
    pthread_mutex_unlock(&g_libc_mutex);

    if (value == NULL) {
        fprintf(stderr, " malloc failed!\n");
    } else {
        pthread_mutex_lock(&g_libc_mutex);
        memcpy(value, config, configlen);
        pthread_mutex_unlock(&g_libc_mutex);
        value[configlen] = '\0';

        fprintf(stderr, " encrypt_telemetry_value(...)\n");
        char* ciphertext = encrypt_telemetry_value(value);
        fprintf(stderr, " encrypt_telemetry_value(...);\n");

        fprintf(stderr, " ciphertext: '%s'\n", ciphertext);

        pthread_mutex_lock(&g_libc_mutex);
        free(ciphertext);
        pthread_mutex_unlock(&g_libc_mutex);
    }
    return;
}
