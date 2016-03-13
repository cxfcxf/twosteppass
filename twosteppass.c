/*
   this is a simple pam module of two step auth for sshd.
   it will not send you a pin instead it requires an url
   which contains a pin. the url link can be something like
   http://pleasechangethis.toyourownsite/random, you can
   have a cronjob to generate that page. the page must be
   plaintest with only a random number, the random number
   you have should be inside range of BASH's $RANDOM 0-32767.
   if the url you have can be accessed but does not return a
   number, it will always fail you (known bug).
   author: xuefeng chen
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

struct MemoryStruct {
        char *memory;
        size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
        size_t realsize = size * nmemb;
        struct MemoryStruct *mem = (struct MemoryStruct *)userp;

        mem->memory = realloc(mem->memory, mem->size + realsize + 1);
        if(mem->memory == NULL) {
                printf("not enough memory (realloc returned NULL)\n");
                return 0;
        }

        memcpy(&(mem->memory[mem->size]), contents, realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;

        return realsize;
}

int
curlrand(char *url, char *code)
{
        CURL *curl_handle;
        CURLcode res;

        struct MemoryStruct chunk;
        chunk.memory = malloc(1);
        chunk.size = 0;

        curl_handle = curl_easy_init();

        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl_handle);

        if(res != CURLE_OK) {
                return 1;
        }
        strcpy(code,chunk.memory);
        code[strlen(code)-1] = 0;

        curl_easy_cleanup(curl_handle);
        free(chunk.memory);
        return 0;
}

int
converse(pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response) {
        int retval;
        struct pam_conv *conv;

        retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
        if(retval==PAM_SUCCESS) {
                retval = conv->conv(nargs, (const struct pam_message **) message, response, conv->appdata_ptr);
        }

        return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv) {
        int retval;

        char code[5];
        char *url = "http://pleasechangethis.toyourownsite/random"; /* please change this, if this exists with other value, it will always fail you */

        /* this assume ok to login if libcurl fails */
        if((retval = curlrand(url,code)) != 0) {
                return PAM_SUCCESS;
        }

        char *input;
        struct pam_message msg[1],*pmsg[1];
        struct pam_response *resp;

        pmsg[0] = &msg[0];
        msg[0].msg_style = PAM_PROMPT_ECHO_ON;
        msg[0].msg = "Enter Your Code: ";
        resp = NULL;
        if((retval = converse(pamh, 1, pmsg, &resp))!=PAM_SUCCESS) {
                return retval;
        }

        if(resp) {
                if((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
                        free(resp);
                        return PAM_AUTH_ERR;
                }
                input = resp[0].resp;
                resp[0].resp = NULL;
        } else {
                return PAM_CONV_ERR;
        }

        if (strcmp(input, code) == 0) {
                free(input);
                return PAM_SUCCESS;
        } else {
                free(input);
                return PAM_AUTH_ERR;
        }

        return PAM_AUTH_ERR;
}
