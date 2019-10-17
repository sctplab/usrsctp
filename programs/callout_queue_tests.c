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


#include <netinet/sctp_callout_queue.h>
#include "netinet/sctp_constants.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>


typedef struct item
{
	sctp_binary_heap_node_t heap_node;
	int32_t priority;
} item_t;


int
item_comparer(const void* x, const void* y)
{
	const item_t* X = x;
	const item_t* Y = y;
	return X->priority - Y->priority;
}


void
item_visualizer(const void* x, size_t max_len, char *out_buffer)
{
	const item_t* X = x;
	snprintf(out_buffer, max_len, "%" PRId32, X->priority);
}


int
always_equal_comparer(const void *x, const void *y)
{
	return 0;
}


void
shuffle_array(uint32_t *a, size_t size)
{
	// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
	for (size_t i = size - 1; i >= 1; i--) 
	{
		const size_t r = (size_t)1 * RAND_MAX * rand() + rand();
		size_t j = r % (i + 1);
		uint32_t temp = a[j];
		a[j] = a[i];
		a[i] = temp;
	}
}

/**
 * Simulates sctp_os_timer_t
 */
typedef struct {
	sctp_binary_heap_node_t heap_node;
	uint32_t time;
} simulated_timer_t;


int
timer_compare(const simulated_timer_t* a, const simulated_timer_t* b)
{
	if (a->time == b->time)
	{
		return 0;
	}
	return SCTP_UINT32_GT(a->time, b->time) ? 1 : -1;
}


void
test_sctp_binary_heap_node_traverse_path(void)
{
	/*
	 * heap keyed by node index
	 * 0             0
	 *             /   \
	 *            /     \
	 *           /       \
	 * 1        1         2
	 *        /   \     /   \
	 * 2     3     4   5     6
	 *      / \   /
	 * 3   7   8 9
	 */
	struct test_case
	{
		size_t index;
		size_t expected_path;
		uint8_t expected_depth;
	} test_cases[] = {
		{0, 0/* - */, 0},
		{1, 0/* 0 */, 1},
		{2, 1/* 1 */, 1},
		{3, 0/* 0 0 */, 2},
		{4, 2/* 1 0 */, 2},
		{5, 1/* 0 1 */, 2},
		{6, 3/* 1 1 */, 2},
		{7, 0/* 0 0 0 */, 3},
		{8, 4/* 1 0 0 */, 3},
		{9, 2/* 0 1 0 */, 3},
	};

	for (uint32_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
	{
		struct test_case tc = test_cases[i];
		size_t computed_path;
		uint8_t computed_depth;
		
		sctp_binary_heap_node_get_traverse_path_from_index(
			tc.index, &computed_path, &computed_depth);
		if (computed_depth != tc.expected_depth)
		{
			printf("%s test FAILED: Traverse path depth for index %zu expected to be %hhu, but was computed to %hhu\n",
				__func__, tc.index, tc.expected_depth, computed_depth);
			return;
		}


		if (computed_path != tc.expected_path)
		{
			printf("%s test FAILED: Traverse path for index %zu expected to be %zu, but was computed to %zu\n",
				__func__, tc.index, tc.expected_path, computed_path);
			return;
		}
	}
	printf("%s test PASSED\n", __func__);
}


void
test_sctp_binary_heap_get_node_by_index_simple(void)
{
	struct sctp_binary_heap heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	struct item root;
	root.priority = 1;
	sctp_binary_heap_node_init(&root.heap_node, &root);

	struct item left;
	left.priority = 2;
	sctp_binary_heap_node_init(&left.heap_node, &left);

	struct item right;
	right.priority = 3;
	sctp_binary_heap_node_init(&right.heap_node, &right);

	// manual heap construction
	heap.root = &root.heap_node;
	root.heap_node.parent = NULL;
	root.heap_node.heap = &heap;

	root.heap_node.left = &left.heap_node;
	left.heap_node.parent = &root.heap_node;
	left.heap_node.heap = &heap;

	root.heap_node.right = &right.heap_node;
	right.heap_node.parent = &root.heap_node;
	right.heap_node.heap = &heap;
	heap.size = 3;
	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		return;
	}
	
	sctp_binary_heap_node_t* parent, **node;
	sctp_binary_heap_get_node_by_index(&heap, 0, &parent, &node);

	if (parent != NULL || *node != &root.heap_node)
	{
		printf("%s test FAILED: Wrong node by index 0\n", __func__);
		return;
	}

	sctp_binary_heap_get_node_by_index(&heap, 1, &parent, &node);
	if (parent != &root.heap_node || *node != &left.heap_node)
	{
		printf("%s test FAILED: Wrong node by index 1\n", __func__);
		return;
	}

	sctp_binary_heap_get_node_by_index(&heap, 2, &parent, &node);
	if (parent != &root.heap_node || *node != &right.heap_node)
	{
		printf("%s test FAILED: Wrong node by index 2\n", __func__);
		return;
	}

	// Check position of next to add node can be obtained.
	sctp_binary_heap_get_node_by_index(&heap, 3, &parent, &node);
	if (parent != &left.heap_node || node != &left.heap_node.left|| *node != NULL)
	{
		printf("%s test FAILED: Wrong node by index 3\n", __func__);
		return;
	}
	printf("%s test PASSED\n", __func__);
}


void
test_sctp_binary_heap_get_node_by_index(void)
{
	const size_t items_count = 128;
	item_t* items = (item_t*)malloc(items_count * sizeof(item_t));
	if (items == NULL)
	{
		printf("%s test FAILED: failed to allocate memory\n", __func__);
		return;
	}

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	for (size_t i = 0; i < items_count; i++)
	{
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		items[i].priority = (int)i; // write node index as priority
		sctp_binary_heap_push(&heap, &items[i].heap_node);
	}

	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		goto free_mem;
	}

	for (size_t i = 0; i < items_count; i++)
	{
		sctp_binary_heap_node_t* parent, **node;
		sctp_binary_heap_get_node_by_index(&heap, i, &parent, &node);
		if (node == NULL || *node == NULL)
		{
			printf("%s test FAILED: unable to get heap node by index %zu\n", __func__, i);
			goto free_mem;
		}
		const size_t node_index = ((item_t*)(*node)->data)->priority;
		if (node_index != i)
		{
			printf("%s test FAILED: got wrong node by index %zu, obtained node has index %zu\n",
				__func__, i, node_index);
			goto free_mem;
		}
		if ((*node)->parent != parent)
		{
			printf("%s test FAILED: (*node)->parent does not match to parent at index %zu\n", __func__, i);
			goto free_mem;
		}
	}

	printf("%s test PASSED\n", __func__);

free_mem:
	if (items != NULL)
	{
		free(items);
		items = NULL;
	}
}


void
test_sctp_binary_heap_push_simple(void)
{
	struct sctp_binary_heap heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	struct item item1;
	item1.priority = 20;
	sctp_binary_heap_node_init(&item1.heap_node, &item1);

	struct item item2;
	item2.priority = 10;
	sctp_binary_heap_node_init(&item2.heap_node, &item2);

	struct item item3;
	item3.priority = 5;
	sctp_binary_heap_node_init(&item3.heap_node, &item3);

	sctp_binary_heap_push(&heap, &item1.heap_node);
	if (sctp_binary_heap_size(&heap) != 1)
	{
		printf("%s test FAILED: Heap size must be 1 after insert\n", __func__);
		return;
	}
	if (heap.root != &item1.heap_node)
	{
		printf("%s test FAILED: Item 1 with priority %"PRId32" must be at heap root after insert\n", 
			__func__, item1.priority);
		return;
	}
	
	sctp_binary_heap_push(&heap, &item2.heap_node);
	if (sctp_binary_heap_size(&heap) != 2)
	{
		printf("%s test FAILED: Heap size must be 2 after insert\n", __func__);
		return;
	}
	if (heap.root != &item2.heap_node)
	{
		printf("%s test FAILED: Item 2 with priority %"PRId32" must be at heap root after insert\n",
			__func__, item2.priority);
		return;
	}

	sctp_binary_heap_push(&heap, &item3.heap_node);
	if (sctp_binary_heap_size(&heap) != 3)
	{
		printf("%s test FAILED: Heap size must be 3 after insert\n", __func__);
		return;
	}
	if (heap.root != &item3.heap_node)
	{
		printf("%s test FAILED: Item 3 with priority %"PRId32" must be at heap root after insert\n",
			__func__, item3.priority);
		return;
	}
	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		return;
	}

	printf("%s test PASSED\n", __func__);
}


void
test_sctp_binary_heap_push_pop_sequential_items(void)
{
	const size_t items_count = 1024 * 1024;
	item_t* items = (item_t*)malloc(items_count * sizeof(item_t));
	if (items == NULL)
	{
		printf("%s test FAILED: failed to allocate memory for items\n", __func__);
		return;
	}

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	for (size_t i = 0; i < items_count; i++)
	{
		items[i].priority = (int32_t)(items_count - 1 - i);
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		sctp_binary_heap_push(&heap, &items[i].heap_node);
		if (sctp_binary_heap_size(&heap) != i + 1)
		{
			printf("%s test FAILED: heap size expected to be %zu\n",
				__func__, i + 1);
			goto free_mem;
		}
	}

	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		goto free_mem;
	}

	sctp_binary_heap_node_t *node;
	size_t index = 0;
	while (0 == sctp_binary_heap_pop(&heap, &node))
	{
		const size_t item_priority = ((item_t*)node->data)->priority;
		if (item_priority != index)
		{
			printf("%s test FAILED: expected to extract item with priority %zu but extracted with priority %zu\n",
				__func__, index, item_priority);
		}

		index++;

		if (sctp_binary_heap_size(&heap) != items_count - index)
		{
			printf("%s test FAILED: heap size expected to be %zu\n",
				__func__, index);
			goto free_mem;
		}
	}
	if (sctp_binary_heap_size(&heap) != 0)
	{
		printf("%s test FAILED: heap size expected to be 0\n",
			__func__);
		goto free_mem;
	}
	
	printf("%s test PASSED\n", __func__);

free_mem:
	if (items != NULL)
	{
		free(items);
		items = NULL;
	}
}


void 
test_sctp_binary_heap_push_pop_random_items(void)
{
	const size_t items_count = 1024 * 1024;
	item_t *items = (item_t*) malloc(items_count * sizeof(item_t));
	if (items == NULL)
	{
		printf("%s test FAILED: failed to allocate memory for items\n",
			__func__);
		return;
	}

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	for (size_t i = 0; i < items_count; i++)
	{
		items[i].priority = (int32_t)rand() % items_count;
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		sctp_binary_heap_push(&heap, &items[i].heap_node);
		if (sctp_binary_heap_size(&heap) != i + 1)
		{
			printf("%s test FAILED: heap size expected to be %zu\n",
				__func__, i + 1);
			goto free_mem;
		}
	}

	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		goto free_mem;
	}

	int32_t root_priority = INT32_MIN;
	sctp_binary_heap_node_t * top;
	while(0 == sctp_binary_heap_pop(&heap, &top))
	{
		const int32_t next_priority = ((item_t*)top->data)->priority;
		if (root_priority > next_priority)
		{
			printf("%s test FAILED: Priority %"PRId32" of popped item is less than previously popped %"PRId32" \n",
				__func__, next_priority, root_priority);
			goto free_mem;
		}
		root_priority = next_priority;
	}

	if (sctp_binary_heap_size(&heap) != 0)
	{
		printf("%s test FAILED: heap size expected to be 0\n",
			__func__);
		goto free_mem;
	}
	printf("%s test PASSED\n", __func__);

free_mem:
	if (items != NULL)
	{
		free(items);
		items = NULL;
	}
}


void
test_sctp_binary_heap_push_interleaved_with_pop_random_items(void)
{
	const size_t items_count = 1024 * 1024;
	item_t* items = (item_t*)malloc(items_count * sizeof(item_t));
	if (items == NULL)
	{
		printf("%s test FAILED: failed to allocate memory for items\n",
			__func__);
		return;
	}

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	for (size_t i = 0; i < items_count; i++)
	{
		items[i].priority = (int32_t)rand() % items_count;
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		sctp_binary_heap_push(&heap, &items[i].heap_node);
		if (sctp_binary_heap_size(&heap) != i + 1)
		{
			printf("%s test FAILED: heap size expected to be %zu\n",
				__func__, i + 1);
			goto free_mem;
		}
	}

	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		goto free_mem;
	}

	int32_t root_priority = INT32_MIN;
	sctp_binary_heap_node_t* top;
	size_t iterations = 0;
	while (sctp_binary_heap_size(&heap) != 0)
	{
		sctp_binary_heap_pop(&heap, &top);
		item_t *top_item = (item_t *)(top->data);
		int32_t next_priority = top_item->priority;

		if (root_priority > next_priority)
		{
			printf("%s test FAILED: Priority %"PRId32" of popped item is less than previously popped %"PRId32" \n",
				__func__, next_priority, root_priority);
			goto free_mem;
		}

		if (iterations % 2 == 0)
		{
			top_item->priority = rand();
			sctp_binary_heap_node_init(&top_item->heap_node, top_item);
			sctp_binary_heap_push(&heap, &top_item->heap_node);
			if (top_item->priority < next_priority)
			{
				next_priority = top_item->priority;
			}
		}

		root_priority = next_priority;
		iterations++;
	}


	printf("%s test PASSED\n", __func__);

free_mem:
	if (items != NULL)
	{
		free(items);
		items = NULL;
	}
}


void
test_sctp_binary_heap_priority_collision_handled_in_push_order(void)
{
	item_t items[512];

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, always_equal_comparer, item_visualizer);

	for (size_t i = 0; i < 512; i++)
	{
		items[i].priority = (int32_t)i;
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		sctp_binary_heap_push(&heap, &items[i].heap_node);
	}

	if (0 != sctp_binary_heap_verify(&heap))
	{
		printf("%s test FAILED: Heap is not valid\n", __func__);
		return;
	}

	for (size_t i = 0; i < 512; i++)
	{
		sctp_binary_heap_node_t* node;
		sctp_binary_heap_pop(&heap, &node);
		item_t* item = (item_t*)node->data;
		if (item->priority != (int32_t)i)
		{
			printf("%s test FAILED: Priority %"PRId32" of popped item does not match push order %zu\n",
				__func__, item->priority, i);
			return;
		}
	}

	if (sctp_binary_heap_size(&heap) != 0)
	{
		printf("%s test FAILED: heap size expected to be 0\n",
			__func__);
		return;
	}
	printf("%s test PASSED\n", __func__);
}

void
test_random_remove(void)
{
	const uint32_t items_count = 30 * 1024;
	uint32_t* remove_order = NULL;
	item_t* items = NULL;

	items = (item_t*)malloc(items_count * sizeof(item_t));
	if (items == NULL)
	{
		printf("%s test FAILED: failed to allocate memory for items\n",
			__func__);
		goto free_mem;
	}

	remove_order = (uint32_t *)malloc(items_count * sizeof(uint32_t));
	if (remove_order == NULL) 
	{
		printf("%s test FAILED: failed to allocate memory for remove order array \n",
			__func__);
		goto free_mem;
	}

	sctp_binary_heap_t heap;
	sctp_binary_heap_init(&heap, item_comparer, item_visualizer);

	for (uint32_t i = 0; i < items_count; i++) 
	{
		remove_order[i] = i;
		items[i].priority = (i + 1);
		sctp_binary_heap_node_init(&items[i].heap_node, &items[i]);
		sctp_binary_heap_push(&heap, &items[i].heap_node);
	}

	shuffle_array(remove_order, items_count);

	for (uint32_t i = 0; i < items_count; i++) 
	{
		sctp_binary_heap_remove(&heap, &items[remove_order[i]].heap_node);

		if (0 != sctp_binary_heap_verify(&heap)) 
		{
			printf("%s test FAILED: heap state is invalid after remove\n",
				__func__);
			goto free_mem;
		}
	}

	if (sctp_binary_heap_size(&heap) != 0)
	{
		printf("%s test FAILED: heap size expected to be 0\n",
			__func__);
		goto free_mem;
	}
	printf("%s test PASSED\n", __func__);

free_mem:
	if (items != NULL)
	{
		free(items);
		items = NULL;
	}
	if (remove_order != NULL)
	{
		free(remove_order);
		remove_order = NULL;
	}
}


void
test_timer_overflow(void)
{
	struct test_case {
		uint32_t earlier_timer;
		uint32_t later_timer;
	} test_cases[] = {
		{ UINT32_MAX, 0},
		{ 10, 20 },
		{ UINT32_MAX - 10, 10 /* UINT32_MAX */ },
		{ UINT32_MAX / 2 - 10, UINT32_MAX / 2 + 10 },
	};
	
	for (size_t i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++)
	{
		const struct test_case tc = test_cases[i];

		simulated_timer_t timer1;
		timer1.time = tc.later_timer;
		sctp_binary_heap_node_init(&timer1.heap_node, &timer1);

		simulated_timer_t timer2;
		timer2.time = tc.earlier_timer;
		sctp_binary_heap_node_init(&timer2.heap_node, &timer2);

		sctp_binary_heap_t heap;
		sctp_binary_heap_init(&heap, (sctp_binary_heap_node_data_comparer)timer_compare, item_visualizer);

		sctp_binary_heap_push(&heap, &timer1.heap_node);
		sctp_binary_heap_push(&heap, &timer2.heap_node);

		sctp_binary_heap_node_t* node;
		simulated_timer_t* timer;

		sctp_binary_heap_pop(&heap, &node);
		timer = (simulated_timer_t*)node->data;
		if (timer->time != tc.earlier_timer)
		{
			printf("%s test FAILED: expected to extract timer with c_time %"PRIu32"\n",
				__func__, tc.earlier_timer);
			return;
		}

		sctp_binary_heap_pop(&heap, &node);
		timer = (simulated_timer_t*)node->data;
		if (timer->time != tc.later_timer)
		{
			printf("%s test FAILED: expected to extract timer with c_time %"PRIu32"\n",
				__func__, tc.later_timer);
			return;
		}
	}

	printf("%s test PASSED\n", __func__);
}

int main(void)
{
	srand(42);
	test_sctp_binary_heap_node_traverse_path();
	test_sctp_binary_heap_get_node_by_index_simple();
	test_sctp_binary_heap_get_node_by_index();
	test_sctp_binary_heap_push_simple();
	test_sctp_binary_heap_push_pop_sequential_items();
	test_sctp_binary_heap_push_pop_random_items();
	test_sctp_binary_heap_push_interleaved_with_pop_random_items();
	test_sctp_binary_heap_priority_collision_handled_in_push_order();
	test_timer_overflow();
	test_random_remove();
}
