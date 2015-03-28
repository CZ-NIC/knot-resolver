/*
 * critbit89 - A crit-bit tree implementation for strings in C89
 * Written by Jonas Gehring <jonas@jgehring.net>
 */


#ifndef CRITBIT_H_
#define CRITBIT_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/*! Main data structure */
typedef struct {
	void *root;
	void *(*malloc)(size_t size, void *baton);
	void (*free)(void *ptr, void *baton);
	void *baton; /*! Passed to malloc() and free() */
} cb_tree_t;

/*! Creates an new, empty critbit tree */
extern cb_tree_t cb_tree_make();

/*! Returns non-zero if tree contains str */
extern int cb_tree_contains(cb_tree_t *tree, const char *str);

/*! Inserts str into tree, returns 0 on suceess */
extern int cb_tree_insert(cb_tree_t *tree, const char *str);

/*! Deletes str from the tree, returns 0 on suceess */
extern int cb_tree_delete(cb_tree_t *tree, const char *str);

/*! Clears the given tree */
extern void cb_tree_clear(cb_tree_t *tree);

/*! Calls callback for all strings in tree with the given prefix  */
extern int cb_tree_walk_prefixed(cb_tree_t *tree, const char *prefix,
	int (*callback)(const char *, void *), void *baton);


#ifdef __cplusplus
}
#endif

#endif /* CRITBIT_H_ */