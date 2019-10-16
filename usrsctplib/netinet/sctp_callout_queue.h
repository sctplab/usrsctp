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


#ifndef _SCTP_CALLOUT_QUEUE_H_
#define _SCTP_CALLOUT_QUEUE_H_

#include <stdint.h>
#include <stddef.h>


typedef struct sctp_binary_heap_node sctp_binary_heap_node_t;

typedef struct sctp_binary_heap sctp_binary_heap_t;

/* function to compare data stored in heap nodes */
typedef int (*sctp_binary_heap_node_data_comparer)(const void*, const void*);

/* function to visualize node's data as a string */
typedef void (*sctp_binary_heap_node_data_visualizer)(const void*, size_t max_len, char *out_buffer);

/* structure representing heap node */
struct sctp_binary_heap_node
{
	void* data; /* pointer to data associated with heap node */
	sctp_binary_heap_node_t* parent; /* pointer to parent node in heap, can be null */
	sctp_binary_heap_node_t* left; /* pointer to left child of node in heap, can be null */
	sctp_binary_heap_node_t* right; /* pointer to right child of the heap, can be null */
	sctp_binary_heap_t* heap; /* pointer to a heap containing this node */
	uint32_t sequence; /* sequence number of this node, used to resolve priority collision in push order */
};

/* structure representing heap  */
struct sctp_binary_heap
{
	sctp_binary_heap_node_t* root; /* pointer to root node of the heap */
	uint32_t mod_count; /* number of heap modification operations executed */
	size_t size; /* number of nodes stored in this heap */
	sctp_binary_heap_node_data_comparer comparer; /* function to compare data associated with nodes */
	sctp_binary_heap_node_data_visualizer data_visualizer; /* optional user-provided function to provide human readable representation of node's data */
};


void
sctp_binary_heap_node_get_traverse_path_from_index(
	size_t,
	size_t*, 
	uint8_t*);


int
sctp_binary_heap_get_node_by_index(
	sctp_binary_heap_t*,
	size_t,
	sctp_binary_heap_node_t**,
	sctp_binary_heap_node_t***);


void
sctp_binary_heap_init(
	sctp_binary_heap_t*,
	sctp_binary_heap_node_data_comparer,
	sctp_binary_heap_node_data_visualizer);


void
sctp_binary_heap_node_init(
	sctp_binary_heap_node_t*,
	void*);


size_t
sctp_binary_heap_size(
	const sctp_binary_heap_t*);


uint32_t
sctp_binary_heap_version(
	const sctp_binary_heap_t*);


int
sctp_binary_heap_contains_node(
	const sctp_binary_heap_t*,
	const sctp_binary_heap_node_t*);


void
sctp_binary_heap_push(
	sctp_binary_heap_t*,
	sctp_binary_heap_node_t*);


void
sctp_binary_heap_remove(
	sctp_binary_heap_t*,
	sctp_binary_heap_node_t*);


int
sctp_binary_heap_pop(
	sctp_binary_heap_t*,
	sctp_binary_heap_node_t**);


int
sctp_binary_heap_peek(
	const sctp_binary_heap_t*,
	sctp_binary_heap_node_t**);


int
sctp_binary_heap_verify(
	const sctp_binary_heap_t*);


void 
sctp_binary_heap_print(
	const sctp_binary_heap_t*);

#endif
