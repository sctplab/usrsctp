/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019, by https://github.com/sctplab. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "sctp_callout_queue.h"
#include "user_environment.h"
#include "sctp_os_userspace.h"
#include "sctp_pcb.h"

#include <inttypes.h>


#if defined(SCTP_DEBUG)
// Uncomment or define via compiler switch to enable
// checking of correctness of heap mutation functions
//#define SCTP_BINARY_HEAP_VERIFY_MUTATE_FUNCTIONS
#endif


static int
sctp_binary_heap_node_compare_data(
	const sctp_binary_heap_t* heap,
	const sctp_binary_heap_node_t* a,
	const sctp_binary_heap_node_t* b)
{
	const int cmp = heap->comparer(a->data, b->data);
	if (cmp != 0)
	{
		return cmp;
	}
	// break equal priorities by order of push into heap
	if (a->sequence == b->sequence)
	{
		KASSERT(a == b, ("Only possible when compared to itself"));
		return 0;
	}
	return SCTP_UINT32_GT(a->sequence, b->sequence) ? 1 : -1;
}


static int
sctp_binary_heap_node_verify_priorities(
	const sctp_binary_heap_t* heap,
	const sctp_binary_heap_node_t* node)
{
	if (node == NULL)
	{
		return 0;
	}

	if (node->parent != NULL && sctp_binary_heap_node_compare_data(heap, node->parent, node) > 0)
	{
		KASSERT(0, ("Parent has bigger priority"));
		return -1;
	}

	int err = 0;
	if (err == 0 && node->left != NULL)
	{
		err = sctp_binary_heap_node_verify_priorities(heap, node->left);
	}
	if (err == 0 && node->right != NULL)
	{
		err = sctp_binary_heap_node_verify_priorities(heap, node->right);
	}
	return err;
}


static int
sctp_binary_heap_node_verify_connectivity(
	const sctp_binary_heap_t* heap,
	const sctp_binary_heap_node_t* node) 
{
	if (node == NULL)
	{
		return 0;
	}
	if (heap != node->heap)
	{
		KASSERT(0, ("Node belong to different heap"));
		return -1;
	}
	if (node == heap->root && node->parent != NULL)
	{
		KASSERT(0, ("Root node must have parent set to NULL"));
		return -1;
	}

	int err = 0;
	if (err == 0 && node->left != NULL)
	{
		if (node->left->parent != node)
		{
			KASSERT(0, ("Left substree has wrong link to parent"));
			return -1;
		}
		err = sctp_binary_heap_node_verify_connectivity(heap, node->left);
	}

	if (err == 0 && node->right != NULL)
	{
		if (node->right->parent != node)
		{
			KASSERT(0, ("Right substree has wrong link to parent"));
			return -1;
		}
		err = sctp_binary_heap_node_verify_connectivity(heap, node->right);
	}

	return err;
}


static void
sctp_binary_heap_node_swap_non_adjacent(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* a,
	sctp_binary_heap_node_t* b)
{
	if (a->heap != b->heap)
	{
		KASSERT(0, ("Nodes belong to the different heaps"));
		return;
	}
	if (heap != a->heap)
	{
		KASSERT(0, ("Nodes does not belong to the heap"));
		return;
	}
	if (a->parent == b || b->parent == a)
	{
		KASSERT(0, ("Nodes are adjacent"));
		return;
	}
	sctp_binary_heap_node_t* const a_parent = a->parent;
	sctp_binary_heap_node_t* const a_left_child = a->left;
	sctp_binary_heap_node_t* const a_right_child = a->right;

	sctp_binary_heap_node_t* const b_parent = b->parent;
	sctp_binary_heap_node_t* const b_left_child = b->left;
	sctp_binary_heap_node_t* const b_right_child = b->right;

	sctp_binary_heap_node_t** a_from_parent = NULL;
	if (a_parent != NULL)
	{
		if (a_parent->left == a)
		{
			a_from_parent = &a_parent->left;
		}
		else if (a_parent->right == a)
		{
			a_from_parent = &a_parent->right;
		}
		else
		{
			KASSERT(0, ("Heap inconsistency detected"));
			return;
		}
	}

	sctp_binary_heap_node_t** b_from_parent = NULL;
	if (b_parent != NULL)
	{
		if (b_parent->left == b)
		{
			b_from_parent = &b_parent->left;
		}
		else if (b_parent->right == b)
		{
			b_from_parent = &b_parent->right;
		}
		else
		{
			KASSERT(0, ("Heap inconsistency detected"));
			return;
		}
	}
	// swap
	// a
	a->left = b_left_child;
	if (b_left_child != NULL)
	{
		b_left_child->parent = a;
	}

	a->right = b_right_child;
	if (b_right_child != NULL)
	{
		b_right_child->parent = a;
	}

	a->parent = b_parent;
	if (b_from_parent != NULL)
	{
		*b_from_parent = a;
	}

	// b
	b->left = a_left_child;
	if (a_left_child != NULL)
	{
		a_left_child->parent = b;
	}

	b->right = a_right_child;
	if (a_right_child != NULL)
	{
		a_right_child->parent = b;
	}

	b->parent = a_parent;
	if (a_from_parent != NULL)
	{
		*a_from_parent = b;
	}

	// maybe update root
	if (heap->root == a)
	{
		heap->root = b;
	}
	else if (heap->root == b)
	{
		heap->root = a;
	}
#if defined(SCTP_BINARY_HEAP_VERIFY_MUTATE_FUNCTIONS)
	sctp_binary_heap_node_verify_connectivity(heap, heap->root);
#endif
}


static void
sctp_binary_heap_node_swap_with_parent(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* node)
{
	if (heap != node->heap)
	{
		KASSERT(0, ("Node does notbelong to the heap"));
		return;
	}

	sctp_binary_heap_node_t* const parent = node->parent;
	if (parent == NULL)
	{
		return;
	}

	const int parent_is_root = (parent == heap->root);

	// populate pointers to neighbor nodes
	sctp_binary_heap_node_t* const parent_parent = parent->parent;
	sctp_binary_heap_node_t* const parent_left_child = parent->left;
	sctp_binary_heap_node_t* const parent_right_child = parent->right;
	sctp_binary_heap_node_t* const node_left_child = node->left;
	sctp_binary_heap_node_t* const node_right_child = node->right;

	sctp_binary_heap_node_t** parent_parent_child = NULL;
	if (parent_parent != NULL)
	{
		if (parent_parent->left == parent)
		{
			parent_parent_child = &parent_parent->left;
		}
		else if (parent_parent->right == parent)
		{
			parent_parent_child = &parent_parent->right;
		}
		else
		{
			KASSERT(0, ("Heap inconsistency detected"));
			return;
		}
	}

	// updated pointers (up to 10)
	node->parent = parent_parent;
	if (parent_parent_child != NULL)
	{
		*parent_parent_child = node;
	}
	parent->parent = node;

	if (node_left_child != NULL)
	{
		node_left_child->parent = parent;
	}
	if (node_right_child != NULL)
	{
		node_right_child->parent = parent;
	}

	parent->right = node_right_child;
	parent->left = node_left_child;

	if (node == parent_left_child)
	{
		node->left = parent;
		node->right = parent_right_child;
		if (parent_right_child != NULL)
		{
			parent_right_child->parent = node;
		}
	}
	else
	{
		node->right = parent;
		node->left = parent_left_child;
		if (parent_left_child != NULL)
		{
			parent_left_child->parent = node;
		}
	}

	if (parent_is_root)
	{
		heap->root = node;
	}

#if defined(SCTP_BINARY_HEAP_VERIFY_MUTATE_FUNCTIONS)
	sctp_binary_heap_node_verify_connectivity(heap, heap->root);
#endif
}


static void
sctp_binary_heap_node_swap_nodes(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* a,
	sctp_binary_heap_node_t* b)
{
	if (a->heap != b->heap)
	{
		KASSERT(0, ("Nodes belong to the different heaps"));
		return;
	}
	if (heap != a->heap)
	{
		KASSERT(0, ("Nodes does not belong to the heap"));
		return;
	}
	if (a == b) 
	{
		return;
	}

	if (a->parent == b)
	{
		sctp_binary_heap_node_swap_with_parent(heap, a);
	}
	else if (b->parent == a)
	{
		sctp_binary_heap_node_swap_with_parent(heap, b);
	}
	else
	{
		sctp_binary_heap_node_swap_non_adjacent(heap, a, b);
	}
}


static void
sctp_binary_heap_bubble_up(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* node)
{
	sctp_binary_heap_node_t *n = node;
	while (n->parent != NULL)
	{
		if (sctp_binary_heap_node_compare_data(heap, n, n->parent) > 0)
		{
			break;
		}
		sctp_binary_heap_node_swap_with_parent(heap, n);
	}
}


static void
sctp_binary_heap_bubble_down(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* node)
{
	for (uint32_t depth = 0; depth < 64; depth++)
	{
		sctp_binary_heap_node_t* smallest = node;
		if (node->left != NULL && sctp_binary_heap_node_compare_data(heap, node->left, smallest) < 0)
		{
			smallest = node->left;
		}
		if (node->right != NULL && sctp_binary_heap_node_compare_data(heap, node->right, smallest) < 0)
		{
			smallest = node->right;
		}
		if (smallest == node)
		{
			return;
		}
		sctp_binary_heap_node_swap_with_parent(heap, smallest);
	}
}


static size_t
sctp_binary_heap_node_parent_index(size_t index)
{
	return (index - 1) / 2;
}


static size_t
sctp_binary_heap_node_count_descendants(const sctp_binary_heap_node_t* node)
{
	if (node == NULL)
	{
		return 0;
	}
	return 1
		+ sctp_binary_heap_node_count_descendants(node->left)
		+ sctp_binary_heap_node_count_descendants(node->right);
}


static void
sctp_binary_heap_node_print(sctp_binary_heap_node_t *node, uint32_t space) 
{ 
	if (node == NULL) 
	{
		return; 
	}
	const uint32_t indent = 10;

	space += indent; 
  
	sctp_binary_heap_node_print(node->right, space); 

	printf("\n"); 
	for (uint32_t i = indent; i < space; i++)
	{
		printf(" ");
	}
	if (node->heap->data_visualizer != NULL) 
	{
		char vis[11] = {0};
		node->heap->data_visualizer(node->data, sizeof(vis) - 1, vis);
		vis[sizeof(vis)-1] = 0; 
		printf("%s\n", vis); 
	}
	else 
	{
		printf("%p\n", node->data); 
	}
	sctp_binary_heap_node_print(node->left, space); 
}


void
sctp_binary_heap_node_get_traverse_path_from_index(
	size_t index, 
	size_t* out_path, 
	uint8_t* out_depth)
{
	size_t path = 0;
	uint8_t depth = 0;
	size_t parent = index;
	while (parent != 0)
	{
		path = path << 1;
		path |= (parent % 2 == 0 ? 1 : 0);
		parent = sctp_binary_heap_node_parent_index(parent);
		depth++;
	}
	*out_path = path;
	*out_depth = depth;
}


int
sctp_binary_heap_get_node_by_index(
	sctp_binary_heap_t* heap,
	size_t index,
	sctp_binary_heap_node_t **out_parent,
	sctp_binary_heap_node_t ***out_node)
{
	if (out_parent == NULL || out_node == NULL || index > heap->size)
	{
		return -1;
	}

	size_t path = 0;
	uint8_t depth = 0;
	sctp_binary_heap_node_get_traverse_path_from_index(index, &path, &depth);

	sctp_binary_heap_node_t *parent = NULL, **node = &heap->root;
	for (uint8_t i = 0; i < depth; i++)
	{
		parent = *node;
		if (path & (((size_t)1) << i))
		{
			node = &(*node)->right;
		}
		else
		{
			node = &(*node)->left;
		}
	}
	*out_parent = parent;
	*out_node = node;
	return 0;
}


void
sctp_binary_heap_init(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_data_comparer comparer,
	sctp_binary_heap_node_data_visualizer data_visualizer)
{
	memset(heap, 0, sizeof(*heap));
	heap->comparer = comparer;
	heap->data_visualizer = data_visualizer;
}


void
sctp_binary_heap_node_init(
	sctp_binary_heap_node_t* node,
	void* data)
{
	memset(node, 0, sizeof(*node));
	node->data = data;
}


size_t 
sctp_binary_heap_size(
	const sctp_binary_heap_t* heap)
{
	return heap->size;
}

uint32_t
sctp_binary_heap_version(
	const sctp_binary_heap_t* heap)
{
	return heap->mod_count;
}


int
sctp_binary_heap_contains_node(
	const sctp_binary_heap_t* heap,
	const sctp_binary_heap_node_t* node)
{
	return heap == node->heap;
}


void
sctp_binary_heap_remove(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* node)
{
	if (heap != node->heap)
	{
		KASSERT(0, ("Node's heap is other than heaps"));
		return;
	}

	heap->size -= 1;
	heap->mod_count += 1;
	if (heap->size > 0)
	{
		sctp_binary_heap_node_t* parent;
		sctp_binary_heap_node_t* last_node, **last_node_loc;
		int ret = sctp_binary_heap_get_node_by_index(heap, heap->size, &parent, &last_node_loc);
		KASSERT(ret == 0, ("Node lookup must succeed"));
		(void)ret;
		last_node = *last_node_loc;

		sctp_binary_heap_node_swap_nodes(heap, node, last_node);
		if (node->parent->left == node) 
		{
			node->parent->left = NULL;
		}
		else if (node->parent->right == node) 
		{
			node->parent->right = NULL;
		}
		else 
		{
			KASSERT(0, ("Wrong link from parent node"));
			return;
		}

		sctp_binary_heap_bubble_down(heap, last_node);
		sctp_binary_heap_bubble_up(heap, last_node);
	}
	else
	{
		heap->root = NULL;
	}

	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;
	node->heap = NULL;
	node->sequence = 0;
#if defined(SCTP_BINARY_HEAP_VERIFY_MUTATE_FUNCTIONS)
	sctp_binary_heap_verify(heap);
#endif
}


int
sctp_binary_heap_peek(
	const sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t** out_node)
{
	if (heap->size > 0)
	{
		KASSERT(heap->root != NULL, ("Heap root must be not null when size is not 0"));
		*out_node = heap->root;
		return 0;
	}
	return -1;
}


int
sctp_binary_heap_pop(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t** out_node)
{
	if (0 != sctp_binary_heap_peek(heap, out_node))
	{
		return -1;
	}
	sctp_binary_heap_remove(heap, *out_node);
	return 0;
}


void
sctp_binary_heap_push(
	sctp_binary_heap_t* heap,
	sctp_binary_heap_node_t* node)
{
	if (node->heap != NULL)
	{
		KASSERT(0, ("Node is already inserted into the heap"));
		return;
	}
	sctp_binary_heap_node_t* parent, **next;
	sctp_binary_heap_get_node_by_index(heap, heap->size, &parent, &next);
	*next = node;
	node->heap = heap;
	node->parent = parent;
	node->sequence = heap->mod_count;
	heap->size += 1;
	heap->mod_count += 1;
	sctp_binary_heap_bubble_up(heap, node);
#if defined(SCTP_BINARY_HEAP_VERIFY_MUTATE_FUNCTIONS)
	sctp_binary_heap_verify(heap);
#endif
}


int
sctp_binary_heap_verify(
	const sctp_binary_heap_t* heap)
{
	const size_t actual_nodes_count = sctp_binary_heap_node_count_descendants(heap->root);
	if (actual_nodes_count != heap->size)
	{
		KASSERT(0, ("Actual and declared nodes count mismatch"));
		return -1;
	}

	int err = sctp_binary_heap_node_verify_connectivity(heap, heap->root);
	if (err != 0) 
	{
		return err;
	}
	return sctp_binary_heap_node_verify_priorities(heap, heap->root);
}


void 
sctp_binary_heap_print(
	const sctp_binary_heap_t* heap) 
{
	sctp_binary_heap_node_print(heap->root, 0);
}
