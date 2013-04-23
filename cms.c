
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/randombytes.h>

#include "cms.h"

#ifdef __GNUC__
#define unlikely(C) __builtin_expect((C), 0)
#else
#define unlikely(C) (C)
#endif

static size_t
cms_optimal_k_num(size_t items_count, size_t granularity)
{
    size_t  k_num;

    if (granularity >= items_count) {
        granularity = items_count;
    } else if (granularity < (size_t) 1U) {
        granularity = (size_t) 1U;
    }
    k_num = (size_t) (double) ceil(log(items_count) / granularity);
    if (k_num < (size_t) 1U) {
        k_num = (size_t) 1U;
    }
    return k_num;
}

static uint64_t
cms_hash(const CMS * const cms, uint64_t hashes[2],
         const char * const item, const size_t item_len, const size_t k_i)
{
    if (unlikely(k_i < 2U)) {
        crypto_shorthash_siphash24((unsigned char *) &hashes[k_i],
                                   (const unsigned char *) item,
                                   item_len, cms->skeys[k_i]);
        return hashes[k_i];
    } else {
        return hashes[0] + (((uint64_t) k_i * hashes[1]) % 0xffffffffffffffc5);
    }
}

static int
cms_init(CMS * const cms, const size_t vector_size, const size_t items_count)
{
    cms->vector_entries = (size_t) vector_size /
        (size_t) sizeof *cms->vector;
    cms->k_num = cms_optimal_k_num(cms->vector_entries, items_count);
    cms->vector = calloc(sizeof *cms->vector, vector_size);
    if (cms->vector == NULL) {
        return -1;
    }
    randombytes_buf(&cms->skeys[0], sizeof cms->skeys[0]);
    randombytes_buf(&cms->skeys[1], sizeof cms->skeys[1]);

    return 0;
}

CMS *
cms_new(const size_t vector_size, const size_t items_count)
{
    CMS *cms;

    if ((cms = malloc(sizeof *cms)) == NULL) {
        return NULL;
    }
    if (cms_init(cms, vector_size, items_count) != 0) {
        free(cms);
        return NULL;
    }
    return cms;
}

void
cms_free(CMS * const cms)
{
    free(cms->vector);
    cms->vector = NULL;
    free(cms);
}

size_t
cms_compute_vector_size(const size_t items_count, const double fp_p)
{
    return (size_t) llround((double) items_count * log(fp_p)) *
        sizeof(CMSCount);
}

_Bool
cms_incr(const CMS * const cms, const char * const item, const size_t item_len)
{
    uint64_t      hashes[2];
    size_t        k_i = (size_t) 0U;
    size_t        offset;
    _Bool         overflow = 0;

    do {
        offset = (size_t) (cms_hash(cms, hashes,
                                    item, item_len, k_i) % cms->vector_entries);
        if (cms->vector[offset] >= CMSCOUNT_MAX) {
            overflow = 1;
        } else {
            cms->vector[offset]++;
        }
    } while (++k_i < cms->k_num);

    return overflow;
}

CMSCount
cms_count(const CMS * const cms, const char * const item,
          const size_t item_len)
{
    uint64_t      hashes[2];
    size_t        k_i = (size_t) 0U;
    size_t        offset;
    CMSCount      min = 0;
    CMSCount      val;
    _Bool         min_set = 0;

    do {
        offset = (size_t) (cms_hash(cms, hashes,
                                    item, item_len, k_i) % cms->vector_entries);
        val = cms->vector[offset];
        if (min_set == 0 || val < min) {
            min_set = 1;
            min = val;
        }
    } while (++k_i < cms->k_num);

    return min;
}
