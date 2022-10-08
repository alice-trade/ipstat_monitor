#include "../include/lib_tree.h"
#include <stdlib.h>

#undef  MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

static ITree_Node*	i_tree_node_new(ipointer key, ipointer value);
static void			i_tree_node_destroy (ITree_Node *node);
static ITree_Node*	i_tree_node_insert(ITree_Node *node, ICompareFunc compare, ipointer key, ipointer value, iint *inserted);
static ITree_Node*	i_tree_node_balance(ITree_Node *node);
static ipointer		i_tree_node_lookup (ITree_Node *node, ICompareFunc compare, ipointer key);
static iint			i_tree_node_pre_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data);
static iint			i_tree_node_in_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data);
static iint			i_tree_node_post_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data);
static ITree_Node*	i_tree_node_rotate_left(ITree_Node *node);
static ITree_Node*	i_tree_node_rotate_right(ITree_Node *node);

ITree*
i_tree_new(ICompareFunc func)
{
	ITree	*ptr = NULL;
	
	if ((ptr = (ITree*) malloc(sizeof(ITree))) == NULL) return NULL;
	ptr->nnodes 	= 0;
	ptr->height 	= 0;
	ptr->root		= NULL;
	ptr->cmp_func	= func;
	i_mutex_init(&ptr->mutex, NULL);

	return ptr;
}

void
i_tree_destroy(ITree *tree)
{
	i_mutex_destroy(&tree->mutex);
	i_tree_node_destroy (tree->root);
	free(tree);
	tree = NULL;
}

ires
i_tree_insert(ITree *tree, ipointer key, ipointer value)
{
	iint		inserted = FALSE;
	i_mutex_lock(&tree->mutex);
		tree->root = i_tree_node_insert (tree->root, tree->cmp_func, key, value, &inserted);
	i_mutex_unlock(&tree->mutex);
	
	return (ires) inserted;
}

ipointer
i_tree_lookup(ITree *tree, ipointer key)
{
	ipointer	*ptr;
	
	i_mutex_lock(&tree->mutex);
		ptr = i_tree_node_lookup (tree->root, tree->cmp_func, key);
	i_mutex_unlock(&tree->mutex);
	
	return ptr;
}

void
i_tree_traverse(ITree *tree, ITraverseFunc traverse_func, ITraverseType traverse_type, ipointer data)
{
	if (!tree->root) return;

	switch (traverse_type){
		case I_PRE_ORDER:
					i_tree_node_pre_order(tree->root, traverse_func, data);
					break;
		case I_IN_ORDER:
					i_tree_node_in_order(tree->root, traverse_func, data);
					break;
		case I_POST_ORDER:
					i_tree_node_post_order(tree->root, traverse_func, data);
					break;
	}
}

static ITree_Node*
i_tree_node_new(ipointer key, ipointer value)
{
	ITree_Node	*node;
	
	if ((node = (ITree_Node*) malloc(sizeof(ITree_Node))) == NULL) return NULL;
	
	node->balance	= 0;
	node->key 		= key;
	node->value		= value;
	node->parent	= NULL;
	node->left		= NULL;
	node->right		= NULL;
	
	return node;
}

static void
i_tree_node_destroy(ITree_Node *node)
{
	if (node){
		if (node->right) i_tree_node_destroy (node->right);
		if (node->left)  i_tree_node_destroy (node->left);
		free(node);
	}
}

static ITree_Node*
i_tree_node_insert(ITree_Node *node, ICompareFunc compare, ipointer key, ipointer value, iint *inserted)
{
	iint old_balance;
	iint cmp;

	if (!node){
		*inserted = TRUE;
		return i_tree_node_new (key, value);
	}

	cmp = (* compare) (key, node->key);
	if (cmp == 0){
		*inserted = FALSE;
		node->value = value;
		return node;
	}

	if (cmp < 0){
		if (node->left){
			old_balance = node->left->balance;
			node->left = i_tree_node_insert (node->left, compare, key, value, inserted);

			if ((old_balance != node->left->balance) && node->left->balance)
				node->balance -= 1;
		}else{
			*inserted = TRUE;
			node->left = i_tree_node_new (key, value);
			node->balance -= 1;
		}
	}else if (cmp > 0){
		if (node->right){
			old_balance = node->right->balance;
			node->right = i_tree_node_insert (node->right, compare, key, value, inserted);

			if ((old_balance != node->right->balance) && node->right->balance)
				node->balance += 1;
		}else{
			*inserted = TRUE;
			node->right = i_tree_node_new (key, value);
			node->balance += 1;
		}
	}

	if (*inserted){
		if ((node->balance < -1) || (node->balance > 1))
		node = i_tree_node_balance (node);
	}

	return node;
}

static ITree_Node*
i_tree_node_balance(ITree_Node *node)
{
	if (node->balance < -1){
		if (node->left->balance > 0) node->left = i_tree_node_rotate_left (node->left);
		node = i_tree_node_rotate_right (node);
	}else if (node->balance > 1){
		if (node->right->balance < 0)node->right = i_tree_node_rotate_right (node->right);
		node = i_tree_node_rotate_left (node);
	}
	return node;
}

static ipointer
i_tree_node_lookup(ITree_Node *node, ICompareFunc compare, ipointer key)
{
	iint cmp;

	if (!node) return NULL;

	cmp = (* compare)(key, node->key);
	if (cmp == 0) return node->value;

	if (cmp < 0){
		if (node->left) return i_tree_node_lookup(node->left, compare, key);
	}else if (cmp > 0){
		if (node->right) return i_tree_node_lookup(node->right, compare, key);
	}
	return NULL;
}


static iint
i_tree_node_pre_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data)
{
	if ((*traverse_func)(node->key, node->value, data)) return TRUE;
	if (node->left){
		if (i_tree_node_pre_order(node->left, traverse_func, data))
		return TRUE;
	}
	if (node->right){
		if (i_tree_node_pre_order(node->right, traverse_func, data))
		return TRUE;
	}
	return FALSE;
}

static iint
i_tree_node_in_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data)
{
	if (node->left){
		if (i_tree_node_in_order(node->left, traverse_func, data)) return TRUE;
	}
	if ((*traverse_func)(node->key, node->value, data)) return TRUE;
	if (node->right){
		if (i_tree_node_in_order(node->right, traverse_func, data)) return TRUE;
	}
	return FALSE;
}

static iint
i_tree_node_post_order(ITree_Node *node, ITraverseFunc traverse_func, ipointer data)
{
	if (node->left){
		if (i_tree_node_post_order(node->left, traverse_func, data)) return TRUE;
    }
	if (node->right){
		if (i_tree_node_post_order(node->right, traverse_func, data)) return TRUE;
	}
	if ((*traverse_func)(node->key, node->value, data)) return TRUE;
	return FALSE;
}


static ITree_Node*
i_tree_node_rotate_left(ITree_Node *node)
{
	ITree_Node *left;
	ITree_Node *right;
	iint a_bal;
	iint b_bal;

	left = node->left;
	right = node->right;

	node->right = right->left;
	right->left = node;

	a_bal = node->balance;
	b_bal = right->balance;

	if (b_bal <= 0){
		if (a_bal >= 1) right->balance = b_bal - 1;
		else			right->balance = a_bal + b_bal - 2;

		node->balance = a_bal - 1;
	}else{
		if (a_bal <= b_bal) right->balance = a_bal - 2;
		else				right->balance = b_bal - 1;
		node->balance = a_bal - b_bal - 1;
	}
	return right;
}

static ITree_Node*
i_tree_node_rotate_right(ITree_Node *node)
{
	ITree_Node *left;
	iint a_bal;
	iint b_bal;

	left = node->left;
	node->left = left->right;
	left->right = node;
	a_bal = node->balance;
	b_bal = left->balance;

	if (b_bal <= 0){
		if (b_bal > a_bal)	left->balance = b_bal + 1;
		else				left->balance = a_bal + 2;
		node->balance = a_bal - b_bal + 1;
	}else{
		if (a_bal <= -1)	left->balance = b_bal + 1;
		else				left->balance = a_bal + b_bal + 2;
		node->balance = a_bal + 1;
	}
	return left;
}
