/*
 * MerkleLamportSignature - a small Merkle signature scheme using Lamport signatures implementation
 * Copyright (C) 2020-2024 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of MerkleLamportSignature
 *
 * MerkleLamportSignature is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MerkleLamportSignature is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __MLS_H__
#define __MLS_H__

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

/* return size, in bytes, of work area */
mlsSz_t
mlsWaSz(
  unsigned char /* (2^h) bytes per hash  */
 ,unsigned char /* (2^s) number of signings */
);

/* return pointer to signing hash in work area, 0 on error */
unsigned char *
mlsHash(
  mlsCtx_t *
 ,unsigned char * /* work area (mlsWaSz) */
);

/* return size, in bytes, of signature data */
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

/* return size, in bytes, of signature data from signature, 0 on error */
mlsSz_t
mlsEgSz(
  unsigned char /* (2^h) bytes per hash  */
 ,const unsigned char * /* signature */
 ,unsigned int          /* signature length */
);

/* return size, in bytes, of work area from signature, 0 on error */
mlsSz_t
mlsEwSz(
  unsigned char /* (2^h) bytes per hash  */
 ,const unsigned char * /* signature */
 ,unsigned int          /* signature length */
);

/* return pointer to signing hash in work area, 0 on error */
unsigned char *
mlsExtract(
  mlsHsh_t *
 ,unsigned char *       /* work area (mlsEwSz) */
 ,const unsigned char * /* signed hash */
 ,const unsigned char * /* signature */
);

#endif /* __MLS_H__ */
