#include "coroutine.h"

static inline bool m0_is_po2(uint64_t val)
{
	return (val & (val - 1)) == 0;
}

static inline uint64_t m0_align(uint64_t val, uint64_t alignment)
{
	uint64_t mask;

	M0_PRE(m0_is_po2(alignment));
	mask = alignment - 1;
	return (val + mask) & ~mask;
}

static inline bool m0_is_aligned(uint64_t val, uint64_t alignment)
{
	uint64_t mask;

	M0_PRE(m0_is_po2(alignment));
	mask = alignment - 1;
	return (val & mask) == 0;
}

static void m0_free_aligned(void *data, size_t size, unsigned shift)
{
	free(data);
}

static void *m0_alloc_aligned(size_t size, size_t alignment)
{
	int   rc;
	void *result;

	rc = posix_memalign(&result, 1 << alignment, size);
	if (rc != 0)
		result = NULL;

	return result;
}

static int locals_alloc_init(struct m0_co_locals_allocator *alloc)
{
	alloc->la_pool = m0_alloc_aligned(M0_MCC_LOCALS_ALLOC_SZ,
					  M0_MCC_LOCALS_ALLOC_SHIFT);
	alloc->la_frame = 0;
	return alloc->la_pool == NULL ? -ENOMEM : 0;
}

static void locals_alloc_fini(struct m0_co_locals_allocator *alloc)
{
	M0_PRE(alloc->la_frame == 0);
	m0_free_aligned(alloc->la_pool, M0_MCC_LOCALS_ALLOC_SZ,
			M0_MCC_LOCALS_ALLOC_SHIFT);
}

static void *locals_alloc(struct m0_co_locals_allocator *alloc, uint64_t frame,
			  uint64_t size)
{
	struct m0_co_la_item *curr;
	struct m0_co_la_item *prev;
	uint64_t              i;
	uint64_t              aligned_sz = m0_align(size +
						    M0_MCC_LOCALS_ALLOC_PAD_SZ,
						    M0_MCC_LOCALS_ALLOC_ALIGN);
	M0_PRE(alloc->la_frame == frame);

	curr = &alloc->la_items[alloc->la_frame];
	if (alloc->la_frame == 0) {
		curr->lai_addr = alloc->la_pool;
		curr->lai_size = aligned_sz;
		alloc->la_total = curr->lai_size;
	} else {
		prev = &alloc->la_items[alloc->la_frame - 1];
		curr->lai_addr = prev->lai_addr + prev->lai_size;
		M0_ASSERT(m0_is_aligned((uint64_t) curr->lai_addr,
					M0_MCC_LOCALS_ALLOC_ALIGN));
		curr->lai_size = aligned_sz;
		alloc->la_total += curr->lai_size;
	}

	M0_ASSERT(alloc->la_total < M0_MCC_LOCALS_ALLOC_SZ);
	M0_ASSERT(alloc->la_frame < M0_MCC_STACK_NR);

	/* test memory's zeroed */
	for (i = 0; i < curr->lai_size; ++i)
		M0_ASSERT(((uint8_t*) curr->lai_addr)[i] == 0x00);

	memset(curr->lai_addr, 0xCC, aligned_sz);
	alloc->la_frame++;

	return curr->lai_addr;
}

static void locals_free(struct m0_co_locals_allocator *alloc, uint64_t frame)
{
	uint64_t              i;
	struct m0_co_la_item *curr;

	curr = &alloc->la_items[--alloc->la_frame];
	M0_PRE(alloc->la_frame >= 0);
	M0_PRE(alloc->la_frame == frame);

	/* test pad is CC-ed */
	for (i = curr->lai_size - M0_MCC_LOCALS_ALLOC_PAD_SZ;
	     i < curr->lai_size; ++i)
		M0_ASSERT(((uint8_t*) curr->lai_addr)[i] == 0xCC);

	memset(curr->lai_addr, 0x00, curr->lai_size);
	alloc->la_total -= curr->lai_size;
	curr->lai_addr = NULL;
	curr->lai_size = 0;

	M0_ASSERT(ergo(frame == 0, alloc->la_total == 0));
}

M0_INTERNAL void m0_co_context_locals_alloc(struct m0_co_context *context,
					    uint64_t size)
{
	context->mc_locals[context->mc_frame] =
		locals_alloc(&context->mc_alloc, context->mc_frame, size);

	M0_LOG(M0_CALL, "alloc=%p size=%"PRIu64,
	       context->mc_locals[context->mc_frame], size);
}

M0_INTERNAL void m0_co_context_locals_free(struct m0_co_context *context)
{
	M0_LOG(M0_CALL, "free=%p", context->mc_locals[context->mc_frame]);

	locals_free(&context->mc_alloc, context->mc_frame);
	context->mc_locals[context->mc_frame] = NULL;
}

M0_INTERNAL void *m0_co_context_locals(struct m0_co_context *context)
{
	return context->mc_locals[context->mc_yield ? context->mc_yield_frame :
				  context->mc_frame];
}

M0_INTERNAL int m0_co_context_init(struct m0_co_context *context)
{
	*context = (struct m0_co_context) { .mc_yield = false };
	return locals_alloc_init(&context->mc_alloc);
}

M0_INTERNAL void m0_co_context_fini(struct m0_co_context *context)
{
	locals_alloc_fini(&context->mc_alloc);
}
