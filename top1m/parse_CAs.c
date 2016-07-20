/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * Author: Hubert Kario - 2014
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/err.h>
#include <json-c/json.h>

#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })

#ifndef X509_V_FLAG_TRUSTED_FIRST
/*
 * OpenSSL implements the same chain building logic as does NSS but it doesn't
 * use it by default, it's also not available in stock 1.0.1 but is backported
 * for example on Fedora
 */
#warning "X509_V_FLAG_TRUSTED_FIRST not available, chain creation will be unreliable"
#define X509_V_FLAG_TRUSTED_FIRST 0
#endif

#define MAX_BUFFER_SIZE 8192

static char* CA_TRUSTED = "./ca_trusted";
static char* CA_ALL = "./ca_files";
static char* CERTS_DIR = "./certs";

/* SSL context that knows only about trust anchors */
SSL_CTX *trusted_only;
/* SSL context that also has access to other CA certs */
SSL_CTX *all_CAs;

// load certificate from file to a OpenSSL object
X509 *load_cert(char *filename)
{
    BIO* f;
    X509 *ret;

    f = BIO_new(BIO_s_file());
    BIO_read_filename(f, filename);

    ret = PEM_read_bio_X509_AUX(f, NULL, 0, NULL);
    if (ret == NULL)
        fprintf(stderr, "Unable to load file %s as X509 certificate\n", filename);

    BIO_free_all(f);

    return ret;
}

// convert sha256 to a file name, if the file exists
// search in "all CAs" dir and "leaf certs" directories
char *hash_to_filename(const char *hash)
{
    char *tmp_f_name;
    size_t n;
    int ret;

    n = strlen(hash) + MAX(MAX(strlen(CA_TRUSTED), strlen(CA_ALL)),
            strlen(CERTS_DIR)) + 1 + // slash in name
            strlen(".pem") + 1;

    tmp_f_name = malloc(n);
    if (!tmp_f_name) {
        fprintf(stderr, "Out of memory (line %i)\n", __LINE__);
        abort();
    }

    /* first check if the file is in directory with regular certs */
    ret = snprintf(tmp_f_name, n, "%s/%s.pem", CERTS_DIR, hash);
    if (ret >= n) {
        fprintf(stderr, "Out of buffer space (line %i)\n", __LINE__);
        abort();
    }
    if (access(tmp_f_name, F_OK) != -1) {
        return tmp_f_name;
    }

    ret = snprintf(tmp_f_name, n, "%s/%s.pem", CA_ALL, hash);
    if (ret >= n) {
        fprintf(stderr, "Out of buffer space (line %i)\n", __LINE__);
        abort();
    }
    if (access(tmp_f_name, F_OK) != -1) {
        return tmp_f_name;
    }

    // file not found
    free(tmp_f_name);
    return NULL;
}

// take certificate hashes, check their validity and output json that
// will indicate which certificate were used for verification, whatever
// the chain was trusted and if all certificates needed for verification
// (with the exception of root CA) were present in hashes
int process_chain(const char **cert_hashes, time_t v_time)
{
    int ret;
    int rc; // return code from function
    char *f_name;

    X509 *cert;
    X509 *x509;

    X509_STORE *store;

    X509_STORE_CTX *csc;
    X509_VERIFY_PARAM *vp;

    STACK_OF(X509) *ustack;
    STACK_OF(X509) *vstack;

    // load certificates to temp structures

    // first the end entity cert
    // (EE cert needs to be passed separately to OpenSSL verification context)
    f_name = hash_to_filename(cert_hashes[0]);
    if (f_name == NULL)
        return 1;

    cert = load_cert(f_name);
    free(f_name);
    if (cert == NULL) {
        printf("can't load certificate!\n");
        return 1;
    }

    // then the intermediate certificates
    ustack = sk_X509_new_null();

    for (int i=1; cert_hashes[i]!=NULL; i++) {
        //printf(".\n");
        f_name = hash_to_filename(cert_hashes[i]);
        if (f_name == NULL) {
            // file not found
            continue;
        }
        x509 = load_cert(f_name);
        if (x509 == NULL) {
            // loading cert failed
            continue;
        }
        sk_X509_push(ustack, x509);
        free(f_name);
    }

    // prepare store parameters
    vp = X509_VERIFY_PARAM_new();
    if (vp == NULL) {
        printf("out of memory\n");
        return 1;
    }
    X509_VERIFY_PARAM_set_time(vp, v_time);

    // first try with just trusted certificates

    store = SSL_CTX_get_cert_store(trusted_only);
    if (store == NULL) {
        fprintf(stderr, "store init failed\n");
        return 1;
    }
    X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST);
    X509_STORE_set1_param(store, vp);

    csc = X509_STORE_CTX_new();

    ret = X509_STORE_CTX_init(csc, store, cert, ustack);
    if (ret != 1) {
        return 1;
    }

    ret = X509_verify_cert(csc);

    if (ret != 1) {
       // printf("%s\n", X509_verify_cert_error_string(csc->error));
    } else {
        // chain is complete, output certificate hashes
        printf("{\"chain\":\"complete\",\"certificates\":[");
        vstack = X509_STORE_CTX_get_chain(csc);
        for(int i=0; i<sk_X509_num(vstack); i++) {
            X509 *c = sk_X509_value(vstack, i);

            const EVP_MD *digest;
            unsigned char md[EVP_MAX_MD_SIZE];
            int n;
            digest = EVP_get_digestbyname("sha256");
            X509_digest(c, digest, md, &n);
            printf("\"");
            for(int i=0; i<n; i++) {
                printf("%02x", md[i]);
            }
            printf("\"");
            if (i+1 < sk_X509_num(vstack)) {
                printf(",");
            }
        }
        printf("]}");
        X509_STORE_CTX_free(csc);
        sk_X509_pop_free(ustack, X509_free);
        X509_free(cert);
        return 0;
    }
    X509_STORE_CTX_free(csc);

    // validation failed with just the trust anchors, retry with all
    // known intermediate certificates

    store = SSL_CTX_get_cert_store(all_CAs);
    if (store == NULL) {
        fprintf(stderr, "store init failed\n");
        return 1;
    }
    X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST);
    X509_STORE_set1_param(store, vp);

    csc = X509_STORE_CTX_new();

    ret = X509_STORE_CTX_init(csc, store, cert, ustack);
    if (ret != 1) {
        return 1;
    }

    ret = X509_verify_cert(csc);
    if (ret != 1) {
        // certificate untrusted
        printf("{\"chain\":\"untrusted\"}");
    } else {
        // chain successfully verified using all certificates,
        // print all the certs used to verify it
        printf("{\"chain\":\"incomplete\",\"certificates\":[");
        vstack = X509_STORE_CTX_get_chain(csc);
        for(int i=0; i<sk_X509_num(vstack); i++) {
            X509 *c = sk_X509_value(vstack, i);

            const EVP_MD *digest;
            unsigned char md[EVP_MAX_MD_SIZE];
            int n;
            digest = EVP_get_digestbyname("sha256");
            X509_digest(c, digest, md, &n);
            printf("\"");
            for(int i=0; i<n; i++) {
                printf("%02x", md[i]);
            }
            printf("\"");
            if (i+1 < sk_X509_num(vstack)) {
                printf(",");
            }
        }
        printf("]}");
    }

    X509_STORE_CTX_free(csc);
    sk_X509_pop_free(ustack, X509_free);
    X509_free(cert);

    return 0;
}

// check if array of strings in json object is the same or not
int string_array_cmp(struct json_object *a, struct json_object *b)
{
    if (json_object_get_type(a) != json_type_array)
        return -1; // wrong type

    if (json_object_get_type(b) != json_type_array)
        return -1; // wrong type

    if (json_object_array_length(a) != json_object_array_length(b))
        return 1;

    for (int i=0; i<json_object_array_length(a); i++) {
        struct json_object *s_a, *s_b;
        const char *str_a, *str_b;

        s_a = json_object_array_get_idx(a, i);
        if (json_object_get_type(s_a) != json_type_string)
            return -1; // wrong type

        s_b = json_object_array_get_idx(b, i);
        if (json_object_get_type(s_b) != json_type_string)
            return -1; // wrong type

        str_a = json_object_get_string(s_a);
        str_b = json_object_get_string(s_b);
        if (str_a == NULL && str_b == NULL)
            continue;

        if (str_a == NULL || str_b == NULL)
            return 1;

        if (strcmp(str_a, str_b) != 0)
            return 1;
    }

    return 0;
}

// add a list of new strings (hashes) to a list of known strings, if they are
// indeed new, don't do anything if they are already in the known set
int register_known_chains(struct json_object ***known, struct json_object *new)
{
    int rc;

    if (*known == NULL) {
        *known = calloc(sizeof(struct json_object**), 2);
        (*known)[0] = new;
        return 0; // it's a new one
    }

    int i;
    for (i=0; (*known)[i] != NULL; i++) {
        rc = string_array_cmp((*known)[i], new);
        if (rc < 0) {
            fprintf(stderr, "error in string_array_cmp\n");
        }
        if (string_array_cmp((*known)[i], new) == 0) {
            return 1; // we've seen it before
        }
    }

    // add it to known objects
    *known = realloc(*known, sizeof(struct json_object **)*(i+2));
    if (!*known) {
        fprintf(stderr, "Out of memory (line %i)\n", __LINE__);
        abort();
    }
    (*known)[i] = new;
    (*known)[i+1] = NULL;
    return 0;
}

struct json_object *read_json_from_file(char *filename)
{
    json_tokener *tok;

    struct json_object *obj = NULL;
    int ret = 0;
    int rc;
    size_t len = MAX_BUFFER_SIZE;
    char buffer[len];
    char *start;
    int i;
    enum json_tokener_error jerr;

    int fd;

    fd = open(filename, 0);
    if (fd < 0) {
        ret = 1;
        goto err;
    }
    // skip garbage at the beginning of file (old `cipherscan` versions
    // sometimes did put `popd` and pushd` output in the json file)
    do {
        rc = read(fd, buffer, 1);
    } while (buffer[0] != '{' || rc < 0);
    if (rc >= 0) {
        lseek(fd, -1, SEEK_CUR);
    }

    // parse the json object from the file
    tok = json_tokener_new();
    do {
        rc = read(fd, buffer, len);
        if (rc < 0)
            break;
        obj = json_tokener_parse_ex(tok, buffer, rc);
    } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);

    if (jerr != json_tokener_success){
        fprintf(stderr, "error in file %s, line: %s\n", filename, buffer);
    }

tok_free:
    json_tokener_free(tok);

close_fd:
    close(fd);

err:
    if (ret) {
        fprintf(stderr, "error while reading file: %i", ret);
    }
    return obj;
}

// process all ciphersuites one by one from a given host results file
int process_host_results(char *filename, time_t v_time)
{
    int fd;
    int ret = 0;
    int rc;
    size_t sz;
    size_t alloc_size = 64 * 1024;
    const char *str;
    struct json_object *root;
    struct json_object *ciphers;
    struct json_object *current;
    struct json_object *certificates;

    struct json_object **known_chains;
    known_chains = malloc(sizeof(struct json_object*) * 1);
    known_chains[0] = NULL;

    struct lh_table *table;
    enum json_type obj_t;
    json_bool j_rc;

    root = read_json_from_file(filename);
    if (root == NULL) {
        ret = 1;
        goto err;
    }

    obj_t = json_object_get_type(root);
    str = json_type_to_name(obj_t);

    j_rc = json_object_object_get_ex(root, "ciphersuite", &ciphers);
    if (j_rc == FALSE) {
        ret = 1;
        goto json_free;
    }

    // ok, we've got the ciphersuite part, we can print the json header for
    // the host file
    printf("{\"host\":\"%s\",\"chains\":[", filename);

    int first_printed=0;
    for(int i=0; i < json_object_array_length(ciphers); i++) {
        current = json_object_array_get_idx(ciphers, i);
#ifdef DEBUG
        printf("\t[%i]:\n", i);
#endif
        j_rc = json_object_object_get_ex(current, "certificates", &certificates);
        if (j_rc == FALSE)
            continue;

        const char** certs;
        certs = calloc(sizeof(const char*), json_object_array_length(certificates) + 1);
        int j;
        for (j=0; j < json_object_array_length(certificates); j++) {
            certs[j] = json_object_get_string(json_object_array_get_idx(certificates, j));
#ifdef DEBUG
            printf("\t\t\t%s\n", certs[j]);
#endif
        }
        rc = register_known_chains(&known_chains, certificates);
#ifdef DEBUG
        printf("\t\t%i\n", rc);
#endif

        if (rc == 0 && j > 0) {
            if (first_printed != 0)
                printf(",");
            if (process_chain(certs, v_time) != 0) {
                fprintf(stderr, "error while processing chains!\n");
            } else {
                first_printed = 1;
            }
        }

#ifdef DEBUG
        // print whole json "object" object
        json_object_object_foreach(current, key, val) {
            str = json_object_to_json_string(val);
            printf("\t\t%s: %s\n", key, str);
        }
#endif

        free(certs);
    }
    printf("]}");

json_free:
    json_object_put(root);

err:
    free(known_chains);
    return ret;
}

int main(int argc, char** argv)
{
    int ret;

    DIR *dirp;
    struct dirent *direntp;
    time_t v_time;

    char buffer[MAX_BUFFER_SIZE] = {};

    if (argc < 2) {
        v_time = time(NULL);
    } else {
        char *endptr;
        v_time = (time_t)strtoul(argv[0], &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "time parameter is not a valid number\n");
            return 1;
        }
    }

    SSL_load_error_strings();
    SSL_library_init();

    /* init trust stores with certificate locations */
    trusted_only = SSL_CTX_new(SSLv23_method());
    if (trusted_only == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    ret = SSL_CTX_load_verify_locations(trusted_only, NULL, CA_TRUSTED);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    all_CAs = SSL_CTX_new(SSLv23_method());
    if (all_CAs == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    ret = SSL_CTX_load_verify_locations(all_CAs, NULL, CA_ALL);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* traverse the result directory, check all files in turn */
    dirp=opendir("results");
    while((direntp=readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0)
            continue;
        if (strcmp(direntp->d_name, "..") == 0)
            continue;

        ret = snprintf(buffer, MAX_BUFFER_SIZE-1, "results/%s", direntp->d_name);
        if (ret >= MAX_BUFFER_SIZE-1) {
            fprintf(stderr, "Out of buffer space (line %i)\n", __LINE__);
            abort();
        }

        ret = process_host_results(buffer, v_time);
        if (ret == 1) {
            fprintf(stderr, "error while processing %s\n", buffer);
        }
        if (ret == 0)
            printf("\n");
    }
    closedir(dirp);

    /* clean up */
    SSL_CTX_free(trusted_only);
    SSL_CTX_free(all_CAs);
    all_CAs = NULL;
    trusted_only = NULL;

    return ret;
}
