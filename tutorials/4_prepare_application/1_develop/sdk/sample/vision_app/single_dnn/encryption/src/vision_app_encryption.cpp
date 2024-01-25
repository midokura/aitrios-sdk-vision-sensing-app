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
#include <string.h>
#include <unistd.h>
#include <pthread.h>

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

/* prevent libc func with multi thread */
pthread_mutex_t g_libc_mutex;

static void *evp_Thread(void *arg);
static void  ConfigurationCallback(const char *topic, const void *config, size_t config_len, void *private_data);

/* -------------------------------------------------------- */
/* public function                                          */
/* -------------------------------------------------------- */
int main(int argc, char *argv[]) {
    pthread_t         evpthread_handle;
    int32_t           ret = -1;

    if (pthread_mutex_init(&g_libc_mutex, NULL) != 0) {
        printf("pthread_mutex_init failed libc_mutex");
        return -1;
    }

    if (setvbuf(stdout, NULL, _IOFBF, BUFSIZ) != 0) {
        ERR_PRINTF("fail setvbuf");
        return -1;
    }

    INFO_PRINTF("vision app encryption start\n");

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

    return;
}
