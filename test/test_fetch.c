/* test_fetch.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#include "unit.h"

static int test_fetch_alg(int op, const char *name)
{
    int ok = 0;

    if (op == OSSL_OP_DIGEST) {
        EVP_MD *md = EVP_MD_fetch(wpLibCtx, name, "provider=wolfprov");
        ok = (md != NULL);
        EVP_MD_free(md);
    }
    else {
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(wpLibCtx, name,
            "provider=wolfprov");
        ok = (cipher != NULL);
        EVP_CIPHER_free(cipher);
    }

    return ok;
}

/* Every registered digest and cipher must be fetchable through OpenSSL. */
int test_fetch_registered(void *data)
{
    static const int ops[] = { OSSL_OP_DIGEST, OSSL_OP_CIPHER };
    int err = 0;
    size_t i;

    (void)data;

    PRINT_MSG("Testing fetch of every registered digest and cipher");

    for (i = 0; (err == 0) && (i < sizeof(ops) / sizeof(ops[0])); i++) {
        const OSSL_ALGORITHM *algs;
        const OSSL_ALGORITHM *alg;
        int noCache = 0;

        algs = OSSL_PROVIDER_query_operation(wpProv, ops[i], &noCache);
        if (algs == NULL) {
            PRINT_ERR_MSG("No algorithms for operation %d", ops[i]);
            err = 1;
        }
        for (alg = algs; (err == 0) && (alg->algorithm_names != NULL);
                alg++) {
            char name[64];
            size_t len = strcspn(alg->algorithm_names, ":");

            if (len >= sizeof(name)) {
                PRINT_ERR_MSG("Algorithm name too long: %s",
                    alg->algorithm_names);
                err = 1;
            }
            else {
                memcpy(name, alg->algorithm_names, len);
                name[len] = '\0';
                if (!test_fetch_alg(ops[i], name)) {
                    PRINT_ERR_MSG("Failed to fetch registered algorithm: %s",
                        name);
                    err = 1;
                }
            }
        }
        if (algs != NULL) {
            OSSL_PROVIDER_unquery_operation(wpProv, ops[i], algs);
        }
    }

    return err;
}
