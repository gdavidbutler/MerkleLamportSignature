#include <stdio.h>
#include <stdlib.h>
#if MLSHASH256
#include "sha256.h"
#else
#include "rmd128.h"
#endif
#include "mls.h"

static void
printHashHex(
  mlsHsh_t *hashContext
 ,unsigned char *hash
){
  char *bf;
  unsigned int bs;

  bs = 1U << (hashContext->h + 1);
#if MLSHASH256
  if ((bf = malloc(bs))) {
    sha256hex(hash, bf);
    printf("%.*s\n", bs, bf);
  }
#else
  if ((bf = malloc(bs))) {
    rmd128hex(hash, bf);
    printf("%.*s\n", bs, bf);
  }
#endif
  free(bf);
}

static void *
hashAllocate(
  void
){
#if MLSHASH256
  return (malloc(sha256tsize()));
#else
  return (malloc(rmd128tsize()));
#endif
}

int
main(
  int argc
 ,char *argv[]
){
  mlsHsh_t hashContext;
  mlsCtx_t mlsContext;
  unsigned char *workArea;
  unsigned char *hash;
  mlsSz_t privateDataSize;
  unsigned int workAreaSize;
  unsigned int signatureSize;
  unsigned int signing;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s 2^signings signing < privateData\n", argv[0]);
    return (1);
  }
  hashContext.a = hashAllocate;
  hashContext.d = free;
#if MLSHASH256
  hashContext.i = (void(*)(void *))sha256init;
  hashContext.u = (void(*)(void *, const unsigned char *, unsigned int))sha256update;
  hashContext.f = (void(*)(void *, unsigned char *))sha256final;
  hashContext.h = 5U; /* 2^5 = 32 bytes = 256 bits */
#else
  hashContext.i = (void(*)(void *))rmd128init;
  hashContext.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  hashContext.f = (void(*)(void *, unsigned char *))rmd128final;
  hashContext.h = 4U; /* 2^4 = 16 bytes = 128 bits */
#endif
  mlsContext.h = &hashContext;
  mlsContext.s = atoi(argv[1]);
  signing = atoi(argv[2]);
  if (!(privateDataSize = mlsPrSz(mlsContext.h->h, mlsContext.s))
   || !(workAreaSize = mlsWaSz(mlsContext.h->h, mlsContext.s))
   || !(signatureSize = mlsSgSz(mlsContext.h->h, mlsContext.s))) {
    fprintf(stderr, "%s: number of signings too large\n", argv[0]);
    return (1);
  }
  printf("signings 2^%u = %u signing %u: privateDataSize %u signatureSize %u workAreaSize %u\n"
        ,mlsContext.s
        ,1U << mlsContext.s
        ,signing
        ,privateDataSize
        ,signatureSize
        ,workAreaSize);
  if (!(mlsContext.r = malloc(privateDataSize))) {
    fprintf(stderr, "%s: malloc\n", argv[0]);
    return (1);
  }
  { /* fill private data till full or EOF on stdin */
    mlsSz_t i;
    size_t j;

    for (i = 0; i < privateDataSize && (j = fread(mlsContext.r + i, 1, privateDataSize - i, stdin)) > 0; i += j);
  }
  if (!(workArea = malloc(workAreaSize))) {
    fprintf(stderr, "%s: malloc\n", argv[0]);
    return (1);
  }
  if (!(hash = mlsHash(&mlsContext, workArea))) {
    fprintf(stderr, "%s: mlsHash\n", argv[0]);
    return (1);
  }
  printHashHex(&hashContext, hash);
  { /* create signature of the signing hash */
    unsigned char *newWorkArea;
    unsigned char *signature;

    if (!(newWorkArea = malloc(workAreaSize))) {
      fprintf(stderr, "%s: malloc\n", argv[0]);
      return (1);
    }
    if (!(signature = malloc(signatureSize))) {
      fprintf(stderr, "%s: malloc\n", argv[0]);
      return (1);
    }
    if (!mlsSign(&mlsContext, newWorkArea, hash, signature, signing)) {
      fprintf(stderr, "%s: mlsSign\n", argv[0]);
      return (1);
    }
    /* verify sizes from signature */
    if (mlsEwSz(mlsContext.h->h, signature, signatureSize) != workAreaSize) {
      fprintf(stderr, "%s: mlsEwSz\n", argv[0]);
      return (1);
    }
    if (mlsEgSz(mlsContext.h->h, signature, signatureSize) != signatureSize) {
      fprintf(stderr, "%s: mlsEgSz\n", argv[0]);
      return (1);
    }
    /* extract signing hash from signature */
    if (!(hash = mlsExtract(mlsContext.h, newWorkArea, hash, signature))) {
      fprintf(stderr, "%s: mlsExtract\n", argv[0]);
      return (1);
    }
    free(signature);
    free(workArea);
    workArea = newWorkArea;
  }
  printHashHex(&hashContext, hash);
  free(workArea);
  free(mlsContext.r);
  return (0);
}
