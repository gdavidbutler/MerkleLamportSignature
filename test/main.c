#include <stdio.h>
#include <stdlib.h>
#if MLSHASH256
#include "sha256.h"
#else
#include "rmd128.h"
#endif
#include "mls.h"

static void *
hshA(
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
  unsigned char *w;
  unsigned char *k;
  mlsSz_t r;
  mlsHsh_t h;
  mlsCtx_t c;
  unsigned int o;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s 2^signings signing < privateData\n", argv[0]);
    return (1);
  }
  h.a = hshA;
  h.d = free;
#if MLSHASH256
  h.i = (void(*)(void *))sha256init;
  h.u = (void(*)(void *, const unsigned char *, unsigned int))sha256update;
  h.f = (void(*)(void *, unsigned char *))sha256final;
  h.h = 5U; /* 2^5 = 32 bytes = 256 bits */
#else
  h.i = (void(*)(void *))rmd128init;
  h.u = (void(*)(void *, const unsigned char *, unsigned int))rmd128update;
  h.f = (void(*)(void *, unsigned char *))rmd128final;
  h.h = 4U; /* 2^4 = 16 bytes = 128 bits */
#endif
  c.h = &h;
  c.s = atoi(argv[1]);
  if (!(r = mlsPrSz(c.h->h, c.s))) {
    fprintf(stderr, "%s: number of signings too large\n", argv[0]);
    return (1);
  }
  o = atoi(argv[2]);
printf("s %u 2^s %u o %u pr %u wa %u sg %u\n", c.s, 1U << c.s, o, r, mlsWaSz(c.h->h, c.s), mlsSgSz(c.h->h, c.s));
  if (!(c.r = malloc(r))) {
    fprintf(stderr, "%s: malloc\n", argv[0]);
    return (1);
  }
  { /* fill private data till full or EOF on stdin */
    mlsSz_t i;
    size_t j;

    for (i = 0; i < r && (j = fread(c.r + i, 1, r - i, stdin)) > 0; i += j);
  }
  if (!(w = malloc(mlsWaSz(c.h->h, c.s)))) {
    fprintf(stderr, "%s: malloc\n", argv[0]);
    return (1);
  }
  if (!(k = mlsHash(&c, w))) {
    fprintf(stderr, "%s: mlsHash\n", argv[0]);
    return (1);
  }
  { /* print signing hash (merkle hash) */
    char *bf;
    unsigned int bs;

    bs = 1U << (h.h + 1);
#if MLSHASH256
    if ((bf = malloc(bs))) {
      sha256hex(k, bf);
      printf("%.*s\n", bs, bf);
    }
#else
    if ((bf = malloc(bs))) {
      rmd128hex(k, bf);
      printf("%.*s\n", bs, bf);
    }
#endif
    free(bf);
  }
  { /* sign the signing hash */
    unsigned char *t;
    unsigned char *g;
    unsigned int s;
    unsigned int r;

    if (!(t = malloc(mlsWaSz(c.h->h, c.s)))) {
      fprintf(stderr, "%s: malloc\n", argv[0]);
      return (1);
    }
    s = mlsSgSz(c.h->h, c.s);
    if (!(g = malloc(s))) {
      fprintf(stderr, "%s: malloc\n", argv[0]);
      return (1);
    }
    if (!mlsSign(&c, t, k, g, o)) {
      fprintf(stderr, "%s: mlsSign\n", argv[0]);
      return (1);
    }
    free(t);
    if (mlsEgSz(c.h->h, g, s) != s) {
      fprintf(stderr, "%s: mlsEgSz\n", argv[0]);
      return (1);
    }
    if (!(r = mlsEwSz(c.h->h, g, s))) {
      fprintf(stderr, "%s: mlsEwSz\n", argv[0]);
      return (1);
    }
    if (!(t = malloc(r))) {
      fprintf(stderr, "%s: malloc\n", argv[0]);
      return (1);
    }
    if (!(k = mlsExtract(c.h, t, k, g))) {
      fprintf(stderr, "%s: mlsExtract\n", argv[0]);
      return (1);
    }
    free(g);
    free(w);
    w = t;
  }
  { /* print signing hash (merkle hash) */
    char *bf;
    unsigned int bs;

    bs = 1U << (h.h + 1);
#if MLSHASH256
    if ((bf = malloc(bs))) {
      sha256hex(k, bf);
      printf("%.*s\n", bs, bf);
    }
#else
    if ((bf = malloc(bs))) {
      rmd128hex(k, bf);
      printf("%.*s\n", bs, bf);
    }
#endif
    free(bf);
  }
  free(w);
  free(c.r);
  return (0);
}
