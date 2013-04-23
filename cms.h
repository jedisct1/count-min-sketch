
#ifndef __CMS_H__
#define __CMS_H__ 1

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <sodium/crypto_shorthash_siphash24.h>

typedef unsigned long CMSCount;
#define CMSCOUNT_MAX ULONG_MAX

typedef struct CMS_ {
    unsigned char  skeys[2][crypto_shorthash_siphash24_KEYBYTES];
    CMSCount      *vector;
    size_t         vector_entries;
    size_t         k_num;
} CMS;

CMS * cms_new(const size_t vector_size, const size_t items_count);

size_t cms_compute_vector_size(const size_t items_count, const double fp_p);

void cms_free(CMS * const cms);

_Bool cms_incr(const CMS * const cms, const char * const item,
               const size_t item_len);

CMSCount cms_count(const CMS * const cms, const char * const item,
                   const size_t item_len);

#endif
