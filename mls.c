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

#include <string.h>
#include "mls.h"

mlsSz_t
mlsPrSz(
  const mlsCtx_t *v
){
  if (!v || !v->h || v->h->h + 3 + 1 + v->h->h + v->s >= sizeof (mlsSz_t) * 8)
    return (0);
  /*
   * private data size in bytes:
   *       (2^h) bytes per hash
   * times (2^3) bits per byte
   * times (2^1) values per hash bit
   * times (2^h) bytes per hash
   * times (2^s) number of signings
   */
  return (1U << (v->h->h + 3 + 1 + v->h->h + v->s));
}

mlsSz_t
mlsWaSz(
  const mlsCtx_t *v
){
  if (!v || !v->h)
    return (0);
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
  return ((v->h->h + 3 + (v->s > 1 ? 2 * v->s : 3)) * (1 + (1U << v->h->h)));
}

unsigned char *
mlsHash(
  mlsCtx_t *v
 ,unsigned char *w
){
  const mlsHsh_t *hv;
  unsigned char *wh;
  unsigned char *rp;
  void *c;
  void (*hi)(void *);
  void (*hu)(void *, const unsigned char *, unsigned int);
  void (*hf)(void *, unsigned char *);
  mlsSz_t s;
  unsigned int b;
  unsigned int b2;
  unsigned int i;
  unsigned int j;

  if (!v || !w
   || !v->h || !v->h->a || !v->h->i || !v->h->u || !v->h->f
   || !v->r
   || !(s = mlsPrSz(v))
   || !(c = v->h->a()))
    return (0);
  hv = v->h;
  hi = hv->i;
  hu = hv->u;
  hf = hv->f;
  s >>= hv->h;
  wh = w + hv->h + 3 + (v->s > 1 ? 2 * v->s : 3);
  b = 1U << hv->h;
  b2 = b << 1;
  rp = v->r;
  for (i = j = 0; i < s; ++i, ++j, rp += b) {
    *(w + j) = 0;
    hi(c);
    hu(c, rp, b);
    hf(c, wh + j * b);
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      hi(c);
      hu(c, wh + j * b, b2);
      hf(c, wh + j * b);
    }
  }
  if (hv->d)
    hv->d(c);
  return (wh);
}

mlsSz_t
mlsSgSz(
  const mlsCtx_t *v
){
  if (!v || !v->h)
    return (0);
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
  return (1 + 1 + v->s + (v->s << v->h->h) + (1U << (v->h->h + 3 + 1 + v->h->h)));
}

unsigned char *
mlsSign(
  mlsCtx_t *v
 ,unsigned char *w
 ,const unsigned char *a
 ,unsigned char *g
 ,unsigned int o
){
  const mlsHsh_t *hv;
  unsigned char *z;
  unsigned char *wh; /* work area hashes */
  unsigned char *rp;
  void *c;
  void (*hi)(void *);
  void (*hu)(void *, const unsigned char *, unsigned int);
  void (*hf)(void *, unsigned char *);
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
   || !(s = mlsPrSz(v))
   || !(c = v->h->a()))
    return (0);
  hv = v->h;
  hi = hv->i;
  hu = hv->u;
  hf = hv->f;
  s >>= hv->h;
  wh = w + hv->h + 3 + (v->s > 1 ? 2 * v->s : 3);
  b = 1U << hv->h;
  b2 = b << 1;
  o <<= hv->h + 3 + 1;
  rp = v->r;
  for (i = j = 0; i < o; ++i, ++j, rp += b) {
    *(w + j) = 0;
    hi(c);
    hu(c, rp, b);
    hf(c, wh + j * b);
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      hi(c);
      hu(c, wh + j * b, b2);
      hf(c, wh + j * b);
    }
  }
  z = g;
  *g++ = j;
  for (k = 0; k < j; ++k) {
    *g++ = *(w + k);
    memcpy(g, wh + k * b, b);
    g += b;
  }
  for (m = hv->h + 3 + 1, n = j; j && *(w + j - 1) <= m; ++m, --j);
  for (k = 0; k < b; ++k) {
    for (t = 0x80; t; t >>= 1) {
      if (*(a + k) & t) {
        hi(c);
        hu(c, rp, b);
        hf(c, g);
        g += b;
        memcpy(g, rp + b, b);
        g += b;
      } else {
        memcpy(g, rp, b);
        g += b;
        hi(c);
        hu(c, rp + b, b);
        hf(c, g);
        g += b;
      }
      rp += b2;
      i += 2;
    }
  }
  for (k = j = 0; i < s; ++i, ++j, rp += b) {
    *(w + j) = 0;
    hi(c);
    hu(c, rp, b);
    hf(c, wh + j * b);
    while (j > k && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      hi(c);
      hu(c, wh + j * b, b2);
      hf(c, wh + j * b);
    }
    if (*(w + j) == m)
      for (++k, ++m, l = n; l && (t = *(z + l + (l - 1) * b)) <= m; --l)
        if (t == m)
          ++m;
  }
  *g++ = j;
  for (k = 0; k < j; ++k) {
    *g++ = *(w + k);
    memcpy(g, wh + k * b, b);
    g += b;
  }
  if (hv->d)
    hv->d(c);
  return (g);
}

mlsSz_t
mlsEgSz(
  unsigned char h
 ,const unsigned char *g
 ,unsigned int l
){
  unsigned int off;

  if (!g || !l)
    return (0);
  off = 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h));
  if (l <= off)
    return (0);
  /* signings from levels inside signature (see mlsSgSz) */
  off = *g + *(g + off);
  return (1 + 1 + off + (off << h) + (1U << (h + 3 + 1 + h)));
}

mlsSz_t
mlsEwSz(
  unsigned char h
 ,const unsigned char *g
 ,unsigned int l
){
  unsigned int off;

  if (!g || !l)
    return (0);
  off = 1 + *g * (1 + (1U << h)) + (1U << (h + 3 + 1 + h));
  if (l <= off)
    return (0);
  /* signings from levels inside signature (see mlsWaSz) */
  off = *g + *(g + off);
  return ((h + 3 + (off > 1 ? 2 * off : 3)) * (1 + (1U << h)));
}

unsigned int
mlsEgOf(
  unsigned char h
 ,const unsigned char *g
 ,unsigned int l
){
  unsigned int b;
  unsigned int o;
  unsigned int j;

  if (!g || !l)
    return (0);
  b = 1U << h;
  /* left authentication block must fit: count byte + j * (level + hash) */
  if (l < 1 + *g * (1 + b))
    return (0);
  for (o = 0, j = *g++; j; --j, g += b)
    o += 1U << *g++;
  return ((o >> (h + 3 + 1)) + 1);
}

unsigned char *
mlsExtract(
  const mlsHsh_t *v
 ,unsigned char *w
 ,const unsigned char *a
 ,const unsigned char *g
){
  unsigned char *wh; /* work area hashes */
  void *c;
  void (*hi)(void *);
  void (*hu)(void *, const unsigned char *, unsigned int);
  void (*hf)(void *, unsigned char *);
  unsigned int b;
  unsigned int b2;
  unsigned int j;
  unsigned int k;
  unsigned char t;

  if (!v || !w || !a || !g
   || !v->a || !v->i || !v->u || !v->f
   || !(c = v->a()))
    return (0);
  hi = v->i;
  hu = v->u;
  hf = v->f;
  b = 1U << v->h;
  b2 = *g + *(g + 1 + *g * (1 + b) + (b << (v->h + 4)));
  wh = w + v->h + 3 + (b2 > 1 ? 2 * b2 : 3);
  b2 = b << 1;
  j = *g++;
  for (k = 0; k < j; ++k) {
    *(w + k) = *g++;
    memcpy(wh + k * b, g, b);
    g += b;
  }
  for (k = 0; k < b; ++k) {
    for (t = 0x80; t; t >>= 1) {
      *(w + j) = 0;
      if (*(a + k) & t) {
        memcpy(wh + j * b, g, b);
        g += b;
        ++j;
        hi(c);
        hu(c, g, b);
        hf(c, wh + j * b);
        g += b;
      } else {
        hi(c);
        hu(c, g, b);
        hf(c, wh + j * b);
        g += b;
        ++j;
        memcpy(wh + j * b, g, b);
        g += b;
      }
      *(w + j) = 0;
      while (j && *(w + j - 1) == *(w + j)) {
        ++*(w + --j);
        hi(c);
        hu(c, wh + j * b, b2);
        hf(c, wh + j * b);
      }
      ++j;
    }
  }
  k = *g++;
  for (; k; ++j, --k) {
    *(w + j) = *g++;
    memcpy(wh + j * b, g, b);
    g += b;
    while (j && *(w + j - 1) == *(w + j)) {
      ++*(w + --j);
      hi(c);
      hu(c, wh + j * b, b2);
      hf(c, wh + j * b);
    }
  }
  if (v->d)
    v->d(c);
  return (wh);
}
