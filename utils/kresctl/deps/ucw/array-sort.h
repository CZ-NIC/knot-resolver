/*
 *	UCW Library -- Universal Simple Array Sorter
 *
 *	(c) 2003--2008 Martin Mares <mj@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

#include "contrib/macros.h"

/*
 *  This is not a normal header file, it's a generator of sorting
 *  routines.  Each time you include it with parameters set in the
 *  corresponding preprocessor macros, it generates an array sorter
 *  with the parameters given.
 *
 *  You might wonder why the heck do we implement our own array sorter
 *  instead of using qsort(). The primary reason is that qsort handles
 *  only continuous arrays, but we need to sort array-like data structures
 *  where the only way to access elements is by using an indexing macro.
 *  Besides that, we are more than 2 times faster.
 *
 *  So much for advocacy, there are the parameters (those marked with [*]
 *  are mandatory):
 *
 *  ASORT_PREFIX(x) [*]	add a name prefix (used on all global names
 *			defined by the sorter)
 *  ASORT_KEY_TYPE  [*]	data type of a single array entry key
 *  ASORT_ELT(i)	returns the key of i-th element; if this macro is not
 *			defined, the function gets a pointer to an array to be sorted
 *  ASORT_LT(x,y)	x < y for ASORT_KEY_TYPE (default: "x<y")
 *  ASORT_SWAP(i,j)	swap i-th and j-th element (default: assume _ELT
 *			is an l-value and swap just the keys)
 *  ASORT_THRESHOLD	threshold for switching between quicksort and insertsort
 *  ASORT_EXTRA_ARGS	extra arguments for the sort function (they are always
 *			visible in all the macros supplied above), starts with comma
 *
 *  After including this file, a function ASORT_PREFIX(sort)(unsigned array_size)
 *  or ASORT_PREFIX(sort)(ASORT_KEY_TYPE *array, unsigned array_size) [if ASORT_ELT
 *  is not defined] is declared and all parameter macros are automatically
 *  undef'd.
 */

#ifndef ASORT_LT
#define ASORT_LT(x,y) ((x) < (y))
#endif

#ifndef ASORT_SWAP
#define ASORT_SWAP(i,j) do { ASORT_KEY_TYPE tmp = ASORT_ELT(i); ASORT_ELT(i)=ASORT_ELT(j); ASORT_ELT(j)=tmp; } while (0)
#endif

#ifndef ASORT_THRESHOLD
#define ASORT_THRESHOLD 8		/* Guesswork and experimentation */
#endif

#ifndef ASORT_EXTRA_ARGS
#define ASORT_EXTRA_ARGS
#endif

#ifndef ASORT_ELT
#define ASORT_ARRAY_ARG ASORT_KEY_TYPE *array,
#define ASORT_ELT(i) array[i]
#else
#define ASORT_ARRAY_ARG
#endif

/**
 * The generated sorting function. If `ASORT_ELT` macro is not provided, the
 * @ASORT_ARRAY_ARG is equal to `ASORT_KEY_TYPE *array` and is the array to be
 * sorted. If the macro is provided, this parameter is omitted. In that case,
 * you can sort global variables or pass your structure by @ASORT_EXTRA_ARGS.
 **/
static void ASORT_PREFIX(sort)(ASORT_ARRAY_ARG unsigned array_size ASORT_EXTRA_ARGS)
{
  struct stk { int l, r; } stack[8*sizeof(unsigned)];
  int l, r, left, right, m;
  unsigned sp = 0;
  ASORT_KEY_TYPE pivot;

  if (array_size <= 1)
    return;

  /* QuickSort with optimizations a'la Sedgewick, but stop at ASORT_THRESHOLD */

  left = 0;
  right = array_size - 1;
  for(;;)
    {
      l = left;
      r = right;
      m = (l+r)/2;
      if (ASORT_LT(ASORT_ELT(m), ASORT_ELT(l)))
	ASORT_SWAP(l,m);
      if (ASORT_LT(ASORT_ELT(r), ASORT_ELT(m)))
	{
	  ASORT_SWAP(m,r);
	  if (ASORT_LT(ASORT_ELT(m), ASORT_ELT(l)))
	    ASORT_SWAP(l,m);
	}
      pivot = ASORT_ELT(m);
      do
	{
	  while (ASORT_LT(ASORT_ELT(l), pivot))
	    l++;
	  while (ASORT_LT(pivot, ASORT_ELT(r)))
	    r--;
	  if (l < r)
	    {
	      ASORT_SWAP(l,r);
	      l++;
	      r--;
	    }
	  else if (l == r)
	    {
	      l++;
	      r--;
	    }
	}
      while (l <= r);
      if ((r - left) >= ASORT_THRESHOLD && (right - l) >= ASORT_THRESHOLD)
	{
	  /* Both partitions ok => push the larger one */
	  if ((r - left) > (right - l))
	    {
	      stack[sp].l = left;
	      stack[sp].r = r;
	      left = l;
	    }
	  else
	    {
	      stack[sp].l = l;
	      stack[sp].r = right;
	      right = r;
	    }
	  sp++;
	}
      else if ((r - left) >= ASORT_THRESHOLD)
	{
	  /* Left partition OK, right undersize */
	  right = r;
	}
      else if ((right - l) >= ASORT_THRESHOLD)
	{
	  /* Right partition OK, left undersize */
	  left = l;
	}
      else
	{
	  /* Both partitions undersize => pop */
	  if (!sp)
	    break;
	  sp--;
	  left = stack[sp].l;
	  right = stack[sp].r;
	}
    }

  /*
   * We have a partially sorted array, finish by insertsort. Inspired
   * by qsort() in GNU libc.
   */

  /* Find minimal element which will serve as a barrier */
  r = MIN(array_size, ASORT_THRESHOLD);
  m = 0;
  for (l=1; l<r; l++)
    if (ASORT_LT(ASORT_ELT(l),ASORT_ELT(m)))
      m = l;
  ASORT_SWAP(0,m);

  /* Insertion sort */
  for (m=1; m<(int)array_size; m++)
    {
      l=m;
      while (ASORT_LT(ASORT_ELT(m),ASORT_ELT(l-1)))
	l--;
      while (l < m)
	{
	  ASORT_SWAP(l,m);
	  l++;
	}
    }
}

#undef ASORT_PREFIX
#undef ASORT_KEY_TYPE
#undef ASORT_ELT
#undef ASORT_LT
#undef ASORT_SWAP
#undef ASORT_THRESHOLD
#undef ASORT_EXTRA_ARGS
#undef ASORT_ARRAY_ARG
