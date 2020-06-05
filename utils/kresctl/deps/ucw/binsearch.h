/*
 *	UCW Library -- Generic Binary Search
 *
 *	(c) 2005 Martin Mares <mj@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Find the first element not lower than \p x in the sorted array \p ary of \p N elements (non-decreasing order).
 * Returns the index of the found element or \p N if no exists. Uses `ary_lt_x(ary,i,x)` to compare the i'th element with \p x.
 * The time complexity is `O(log(N))`.
 **/
#define BIN_SEARCH_FIRST_GE_CMP(ary, N, ary_lt_x, x, ...)  ({	\
  unsigned l = 0, r = (N);						\
  while (l < r)							\
    {								\
      unsigned m = (l+r)/2;						\
      if (ary_lt_x(ary, m, x, __VA_ARGS__))			\
        l = m+1;						\
      else							\
        r = m;							\
    }								\
  l;								\
})

/**
 * The default comparison macro for \ref BIN_SEARCH_FIRST_GE_CMP().
 **/
#define ARY_LT_NUM(ary,i,x) (ary)[i] < (x)

/**
 * Same as \ref BIN_SEARCH_FIRST_GE_CMP(), but uses the default `<` operator for comparisons.
 **/
#define BIN_SEARCH_FIRST_GE(ary,N,x) BIN_SEARCH_FIRST_GE_CMP(ary,N,ARY_LT_NUM,x)

/**
 * Search the sorted array \p ary of \p N elements (non-decreasing) for the first occurrence of \p x.
 * Returns the index or -1 if no such element exists. Uses the `<` operator for comparisons.
 **/
#define BIN_SEARCH_EQ(ary,N,x) ({ int i = BIN_SEARCH_FIRST_GE(ary,N,x); if (i >= (N) || (ary)[i] != (x)) i=-1; i; })
