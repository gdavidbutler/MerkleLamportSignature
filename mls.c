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

#include "mls.h"

mlsSz_t
mlsPrSz(
  unsigned char h
 ,unsigned char s
){
  if (h + 3 + 1 + h + s >= sizeof (mlsSz_t) * 8)
    return (0);
  /*
   * private data size in bytes:
   *       (2^h) bytes per hash
   * times (2^3) bits per byte
   * times (2^1) values per hash bit
   * times (2^h) bytes per hash
   * times (2^s) number of signings
   */
  return (1U << (h + 3 + 1 + h + s));
}

mlsSz_t
mlsWaSz(
  unsigned char h
 ,unsigned char s
){
  /*
   * work area size in bytes:
   *  unsigned char array of merkle node level
   *  hash array of merkle hash node at level
   * the number of elements in the arrays are:
   *      (h) power of bytes per hash
   * plus (3) power of bits per byte
   * plus (1) power of values per hash bit
   * plus (s) power of number of signings (leafs)
   * plus max(s-1, 1) power of number of signings (nodes)
   * times:
   *      (1) node level
   * plus (2^h) hash size node
   */
  return ((h + 3 + (s > 1 ? 2 * s : 3)) * (1 + (1U << h)));
}

unsigned char *
mlsHash(
  mlsCtx_t *v
 ,unsigned char *w
){
  unsigned char *wh;
  void *c;
  mlsSz_t s;
  unsigned int b;
  unsigned int b2;
  unsigned int i;
  unsigned int j;

  if (!v || !w
   || !v->h || !v->h->a || !v->h->i || !v->h->u || !v->h->f
   || !v->r
   || !(s = mlsPrSz(v->h->h, v->s))
   || !(c = v->h->a()))
    return (0);
  s >>= v->h->h;
  wh = w + v->h->h + 3 + (v->s > 1 ? 2 * v->s : 3);
  b = 1U << v->h->h;
  b2 = b << 1;
  for (i = j = 0; i < s; ++i, ++j) {
    *(w + j) = 0;
    v->h->i(c);
    v->h->u(c, v->r + i * b, b);
    v->h->f(c, wh + j * b);
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      v->h->i(c);
      v->h->u(c, wh + j * b, b2);
      v->h->f(c, wh + j * b);
    }
  }
  if (v->h->d)
    v->h->d(c);
  return (wh);
}

mlsSz_t
mlsSgSz(
  unsigned char h
 ,unsigned char s
){
  /*
   * signature size in bytes:
   *       (2^0) "left" levels
   *       (2^0) "right" levels
   * plus  (s) levels
   * plus  (s) levels
   * times (2^h) bytes per hash
   * plus  (2^h) bytes per hash
   * times (2^3) bits per byte
   * times (2^1) values per hash bit
   * times (2^h) bytes per hash
   */
  return (1 + 1 + s + (s << h) + (1U << (h + 3 + 1 + h)));
}

unsigned char *
mlsSign(
  mlsCtx_t *v
 ,unsigned char *w
 ,const unsigned char *a
 ,unsigned char *g
 ,unsigned int o
){
  unsigned char *z;
  unsigned char *wh; /* work area hashes */
  void *c;
  mlsSz_t s;
  unsigned int b;
  unsigned int b2;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned int l;
  unsigned int m;
  unsigned int n;
  unsigned char t;

  if (!v || !w || !a || !g || o >= (1U << v->s)
   || !v->h || !v->h->a || !v->h->i || !v->h->u || !v->h->f
   || !v->r
   || !(s = mlsPrSz(v->h->h, v->s))
   || !(c = v->h->a()))
    return (0);
  s >>= v->h->h;
  wh = w + v->h->h + 3 + (v->s > 1 ? 2 * v->s : 3);
  b = 1U << v->h->h;
  b2 = b << 1;
  o <<= v->h->h + 3 + 1;
  for (i = j = 0; i < o; ++i, ++j) {
    *(w + j) = 0;
    v->h->i(c);
    v->h->u(c, v->r + i * b, b);
    v->h->f(c, wh + j * b);
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      v->h->i(c);
      v->h->u(c, wh + j * b, b2);
      v->h->f(c, wh + j * b);
    }
  }
  z = g;
  *g++ = j;
  for (k = 0; k < j; ++k) {
    *g++ = *(w + k);
    for (l = 0; l < b; ++l)
      *g++ = *(wh + k * b + l);
  }
  for (m = v->h->h + 3 + 1, n = j; j && *(w + j - 1) <= m; ++m, --j);
  for (k = 0; k < b; ++k) {
    for (t = 0x80; t; t >>= 1) {
      if (*(a + k) & t) {
        v->h->i(c);
        v->h->u(c, v->r + i * b, b);
        v->h->f(c, g);
        g += b;
        ++i;
        for (l = 0; l < b; ++l)
          *g++ = *(v->r + i * b + l);
      } else {
        for (l = 0; l < b; ++l)
          *g++ = *(v->r + i * b + l);
        ++i;
        v->h->i(c);
        v->h->u(c, v->r + i * b, b);
        v->h->f(c, g);
        g += b;
      }
      ++i;
    }
  }
  for (k = j = 0; i < s; ++i, ++j) {
    *(w + j) = 0;
    v->h->i(c);
    v->h->u(c, v->r + i * b, b);
    v->h->f(c, wh + j * b);
    while (j > k && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      v->h->i(c);
      v->h->u(c, wh + j * b, b2);
      v->h->f(c, wh + j * b);
    }
    if (*(w + j) == m)
      for (++k, ++m, l = n; l && (t = *(z + l + (l - 1) * b)) <= m; --l)
        if (t == m)
          ++m;
  }
  *g++ = j;
  for (k = 0; k < j; ++k) {
    *g++ = *(w + k);
    for (l = 0; l < b; ++l)
      *g++ = *(wh + k * b + l);
  }
  if (v->h->d)
    v->h->d(c);
  return (g);
}

mlsSz_t
mlsEgSz(
  unsigned char h
 ,const unsigned char *g
 ,unsigned int l
){
  if (!g || !l || l <= 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h)))
    return (0);
  /* signings from levels inside signature */
  return(mlsSgSz(h, *g + *(g + 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h)))));
}

mlsSz_t
mlsEwSz(
  unsigned char h
 ,const unsigned char *g
 ,unsigned int l
){
  if (!g || !l || l <= 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h)))
    return (0);
  /* signings from levels inside signature */
  return(mlsWaSz(h, *g + *(g + 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h)))));
}

unsigned char *
mlsExtract(
  mlsHsh_t *v
 ,unsigned char *w
 ,const unsigned char *a
 ,const unsigned char *g
){
  unsigned char *wh; /* work area hashes */
  void *c;
  unsigned int b;
  unsigned int b2;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned char t;

  if (!v || !w || !a || !g
   || !v->a || !v->i || !v->u || !v->f
   || !(c = v->a()))
    return (0);
  b = 1U << v->h;
  b2 = *g + *(g + 1 + *g * (1 + b) + (b << (v->h + 4)));
  wh = w + v->h + 3 + (b2 > 1 ? 2 * b2 : 3);
  b2 = b << 1;
  j = *g++;
  for (k = 0; k < j; ++k) {
    *(w + k) = *g++;
    for(i = 0; i < b; ++i)
      *(wh + k * b + i) = *g++;
  }
  for (k = 0; k < b; ++k) {
    for (t = 0x80; t; t >>= 1) {
      *(w + j) = 0;
      if (*(a + k) & t) {
        for (i = 0; i < b; ++i)
          *(wh + j * b + i) = *g++;
        ++j;
        v->i(c);
        v->u(c, g, b);
        v->f(c, wh + j * b);
        g += b;
      } else {
        v->i(c);
        v->u(c, g, b);
        v->f(c, wh + j * b);
        g += b;
        ++j;
        for (i = 0; i < b; ++i)
          *(wh + j * b + i) = *g++;
      }
      *(w + j) = 0;
      while (j && *(w + j - 1) == *(w + j)) {
        ++*(w + --j);
        v->i(c);
        v->u(c, wh + j * b, b2);
        v->f(c, wh + j * b);
      }
      ++j;
    }
  }
  k = *g++;
  for (; k; ++j, --k) {
    *(w + j) = *g++;
    for (i = 0; i < b; ++i)
      *(wh + j * b + i) = *g++;
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      v->i(c);
      v->u(c, wh + j * b, b2);
      v->f(c, wh + j * b);
    }
  }
  if (v->d)
    v->d(c);
  return (wh);
}
