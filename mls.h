/* Merkle Lamport signature */

/*
 * sizeof (mlsSz_t) * 8 bits per byte must be greater than
 *      h (2^h bytes per hash)
 * plus 3 (2^3 bits per byte)
 * plus 1 (2^1 values per hash bit)
 * plus h (2^h bytes per hash)
 * plus s (2^s number of signings)
 */
typedef unsigned int mlsSz_t; /* largest size, in bytes, of private data */

/* return size, in bytes, of private data, 0 on mlsSz_t overflow */
mlsSz_t
mlsPrSz(
  unsigned char /* (2^h) bytes per hash  */
 ,unsigned char /* (2^s) number of signings */
);

/* hash Context */
typedef struct {
  void *(*a)(void);                                       /* hashContext allocate */
  void (*i)(void *);                                      /* hashContext initialize */
  void (*u)(void *, const unsigned char *, unsigned int); /* hashContext update */
  void (*f)(void *, unsigned char *);                     /* hashContext finalize */
  void (*d)(void *);                                      /* hashContext deallocate */
  unsigned char h;                                        /* (2^h) bytes per hash */
} mlsHsh_t;

/* mls Context */
typedef struct {
  mlsHsh_t *h;      /* hash context */
  unsigned char *r; /* private data (mlsPrSz) */
  unsigned char s;  /* (2^s) number of signings */
} mlsCtx_t;

/* return size, in bytes, of work area, 0 on mlsSz_t overflow */
mlsSz_t
mlsWaSz(
  unsigned char /* (2^h) bytes per hash  */
 ,unsigned char /* (2^s) number of signings */
);

/* return pointer to public hash in work area, 0 on error */
unsigned char *
mlsPublic(
  mlsCtx_t *
 ,unsigned char * /* work area (mlsWaSz) */
);

/* return size, in bytes, of signature data, 0 on mlsSz_t overflow */
mlsSz_t
mlsSgSz(
  unsigned char /* (2^h) bytes per hash  */
 ,unsigned char /* (2^s) number of signings */
);

/* return pointer to byte after signature, 0 on error */
unsigned char *
mlsSign(
  mlsCtx_t *
 ,unsigned char *       /* work area (mlsWaSz) */
 ,const unsigned char * /* hash to sign */
 ,unsigned char *       /* signature (mlsSgSz) */
 ,unsigned int          /* signing offset to use (0 to (1 << mlsCtx_t.s) - 1) */
);

/* return size, in bytes, of recover area, 0 on null s */
mlsSz_t
mlsRcSz(
  unsigned char /* (2^h) bytes per hash  */
 ,const unsigned char * /* signature */
);

/* return pointer to public hash in recover area, 0 on error */
unsigned char *
mlsRecover(
  mlsHsh_t *
 ,unsigned char *       /* recover area (mslRcSz) */
 ,const unsigned char * /* signed hash */
 ,const unsigned char * /* signature */
);
