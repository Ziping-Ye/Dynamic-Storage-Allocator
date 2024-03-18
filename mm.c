/*
 * mm.c
 *
 * Name: Ziping Ye, Joseph Anthony Alfano
 * Project description: 
 * This program implements a dynamic memory allocator in C. We implement functions malloc, free, and realloc
 * which user can call to request and free heap memory. We use explicit list to keep track of free blocks, 
 * and use first fit strategy to find a large enough block to fit the payload (and padding for alignment) and
 * a header anf footer for coalescing consecutive free blocks.
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
//#define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16
/* What is the size of a word and two words on 64 bits machine? */
#define WORD 8
#define DWORD 16

#define NUM_CLASS 32

/* global variable that points to the beginning of the heap */
void *heap;

/* a struct that contains two pointers */
typedef struct Node{
  struct Node *next;
  struct Node *prev;
} node;


static void add_block_with_splitting(node *p, size_t adjusted_size);
static void add_block_without_splitting(node *p, size_t adjusted_size);

/* global variable that points to the first element of the list of pointers */
node **head;

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}


/*
 * Helper functions
 * Reference - CSAPP Chapter 9.9 and slides
 */

/*
 * A function that writes a word at address p
 * Input: a pointer p and the value we want to write
*/
static void write_word(void *p, unsigned long long value) {
  //printf("we are writing word - %lld\n", value);
  *(size_t *)(p) = value;
}

/*
 * A function that extracts the size from the word at address p
 * Input: a pointer p
 * Output: the size information from the word at address p points to
 */
static size_t get_size (void *p) {
  return (*(size_t *) p) & ~0x1;
}

size_t int_log2(size_t a) // int_log2(0) is undefined
{
return (sizeof(size_t) * 8 - 1) ^ __builtin_clzl(a);
}

size_t find_class(size_t size) {
  size_t class = int_log2(size);
  if (class >= NUM_CLASS)
    class = NUM_CLASS - 1;
  return class;
}

/*
 * A function that extracts the allocation bit from the word at address p
 * Input: a pointer p
 * Output: the allocation information from the word at address p points to
*/
static size_t get_alloc (void *p) {
  return (*(size_t *) p) & 0x1;
}

static void add_node(node *n) {
  size_t size = get_size((void *) n - WORD);
  size_t class = find_class(size);
  assert(class >= 5);
  node *first = head[class];

  n->prev = NULL;
  n->next = head[class];
  
  if (first != NULL)
    first->prev = n;
  head[class] = n;
}

static void delete_node(node *n) {
  size_t size = get_size((void *)n - WORD);
  size_t class = find_class(size);
  assert(class >= 5);
  //node *first = *(head + class);

  //assert(first != NULL);
  if (n->prev == NULL) //first node in the list
    head[class] = n->next;
  else
    (n->prev)->next = n->next;

  if (n->next != NULL) 
    (n->next)->prev = n->prev;
}


/*
 * A function that takes in a pointer to a free block, and tries to coalesces it with consecutive free blocks if possible
 * Input: a pointer to a free block (the header of the free block)
 * Output: a pointer to the free block after coalescing
 */
static void *coalesce(void *block) {
  size_t current_block_size = get_size(block - WORD);
  size_t total_size, next_block_size, prev_block_size;
  size_t prev_alloc = get_alloc(block - DWORD);
  size_t next_alloc = get_alloc(block + current_block_size - WORD);

  
  // Case 1: Both the previous and next block are allocated
  if (prev_alloc == 1 && next_alloc == 1) {
    node *new_node = (node *) block;
    add_node(new_node);
    return block;
  }

  // Case 2: The previous is allocated and the next is free - coalesce with the next block
  else if (prev_alloc == 1 && next_alloc == 0) {
    //delete next block from the explicit free list
    node *next_block = (node *) (block + current_block_size);
    delete_node(next_block);
    //rewrite header and footer
    next_block_size = get_size(block + current_block_size - WORD);
    total_size = current_block_size + next_block_size;
    write_word(block - WORD, (total_size | 0));
    write_word(block + total_size - DWORD, (total_size | 0));
    //add the resulting block at the beginning
    node *new_node = (node *) block;
    add_node(new_node);
    return block;
  }

  // Case 3: The next is allocated and the previous is free - coalesce with the previous block
  else if (prev_alloc == 0 && next_alloc == 1) {
    prev_block_size = get_size(block - DWORD);
    //delete previous block from the explicit free list
    node *prev_block = (node *) (block - prev_block_size);
    delete_node(prev_block);  
    //rewrite header and footer
    total_size = current_block_size + prev_block_size;
    write_word(block - prev_block_size - WORD, (total_size | 0));
    write_word(block + current_block_size - DWORD, (total_size | 0));
    //add the resulting block at the beginning
    node *new_node = (node *) (block - prev_block_size);
    add_node(new_node);
    return (block - prev_block_size);
  }

  // Case 4: Both previous and next blocks are free - coalesce with both
  else {
    assert(prev_alloc == 0 && next_alloc == 0);
    prev_block_size = get_size(block - DWORD);
    //delete both previous and next block from the explicit free list
    node *prev_block = (node *) (block - prev_block_size);
    delete_node(prev_block);
    node *next_block = (node *) (block + current_block_size);
    delete_node(next_block);
    //rewrite header and footer
    next_block_size = get_size(block + current_block_size - WORD);    
    total_size = current_block_size + prev_block_size + next_block_size;
    write_word(block - WORD - prev_block_size, (total_size | 0));
    write_word(block - DWORD + current_block_size + next_block_size, (total_size | 0));
    //add the resulting block at the beginning
    node *new_node = (node *) (block - prev_block_size);
    add_node(new_node);    
    return (block - prev_block_size);
  }
  
}


/*
 * A function that requests more virtual memory for heap
 * Input: the size that user wants to increase the heap in bytes
 * Output: a pointer to the beginning of the newly allocated heap area 
 * Ziping Ye
 */
static void *extend_heap(size_t bytes) {
  void *new_heap;
  //size_t size = align(bytes); //the actual size we will extend (satisfying alignment requirement)
  
  if ((new_heap = mem_sbrk(bytes)) == (void *) - 1)
    return NULL;

  //the newly allocated heap itself is a large free block - mark the size and alloc of it
  //move the fake header to the end of the new heap
  write_word(new_heap - WORD, (bytes | 0));
  write_word(new_heap + bytes - DWORD, (bytes | 0));
  write_word(new_heap + bytes - WORD, (0 | 1));
  
  //coalesce if necessary
  //return new_heap;
  return coalesce(new_heap);
}
 

static void *first_fit(size_t adjusted_size) {
    size_t class = find_class(adjusted_size);
    size_t offset;
    assert(class >= 5);
    node *first;
    node *p;

    size_t current_block_size;


    for (offset = class; offset < NUM_CLASS; offset++) {
      first = *(head + offset);
      p = first;

      while (p != NULL) {
        //printf("best_fit - searching over explicit free list...\n");
        //printf("best_fit - header address of p = %p\n", (char *) p - WORD);
        current_block_size = get_size((char *) p - WORD);
        if (current_block_size >= adjusted_size && current_block_size - adjusted_size >= 4*WORD) {
          //printf("best_fit - address that we will add block with splitting = %p\n", p);
          add_block_with_splitting(p, adjusted_size);
          return (void *) p;
        } else if (current_block_size >= adjusted_size && current_block_size - adjusted_size < 4*WORD) {
          add_block_without_splitting(p, adjusted_size);
          return (void *) p;
        } else {
            p = p->next;
        }
      }
    }

  return NULL;

}

static void *best_fit(size_t adjusted_size) {
    size_t class = find_class(adjusted_size);
    size_t offset;
    assert(class >= 5);
    node *first;
    node *p;

    node *min_enough_block = NULL;
    size_t min_enough_size;

    size_t current_block_size;

    for (offset = class; offset < NUM_CLASS; offset++) {
      first = *(head + offset);
      p = first;

      while (p != NULL) {
        current_block_size = get_size((char *) p - WORD);
        if (current_block_size >= adjusted_size) {
            if (current_block_size == adjusted_size) {
                add_block_without_splitting(p, adjusted_size);
                return (void *) p;
            }
            if (min_enough_block == NULL) {
                min_enough_size = current_block_size;
                min_enough_block = p;
            }
            if (current_block_size < min_enough_size) {
                min_enough_size = current_block_size;
                min_enough_block = p;
            }
        }
        p = p->next;
      }

      if (min_enough_block != NULL) {
          assert(min_enough_size >= adjusted_size);
          if (min_enough_size - adjusted_size >= 4*WORD) {
              add_block_with_splitting(min_enough_block, adjusted_size);
          } else {
              assert(min_enough_size - adjusted_size < 4*WORD);
              add_block_without_splitting(min_enough_block, adjusted_size);
          }
          return (void *) min_enough_block;
      }

    }

  return NULL;

}

    
 
/*
 * Initialize: returns false on error, true on success.
 * Ziping Ye
 */
bool mm_init(void)
{
  /* create initial heap area */
  if ((heap = mem_sbrk(DWORD + NUM_CLASS * WORD)) == (void *) -1)
    return false;

  write_word(heap + NUM_CLASS * WORD, (0 | 1)); //fake footer
  write_word(heap + NUM_CLASS * WORD + WORD, (0 | 1)); //fake header
  
  head = (node **) heap;

  //initialize all pointers to NULL
  for (int i = 0; i < NUM_CLASS; i ++) {
    head[i] = NULL;
  }

  return true;
}


static void add_block_with_splitting(node *p, size_t adjusted_size) {
  delete_node(p);
  size_t current_block_size = get_size((char *) p - WORD);
  //printf("add_block_with_splitting - current_block_size = %ld\n", current_block_size);
  size_t remain_size = current_block_size - adjusted_size;
  assert(current_block_size > adjusted_size);
  assert(current_block_size - adjusted_size >= 4*WORD);
  //rewrite header and footer
  write_word((char *) p - WORD, (adjusted_size | 1));
  write_word((char *) p + adjusted_size - DWORD, (adjusted_size | 1));
  write_word((char *) p + adjusted_size - WORD, (remain_size | 0));
  write_word((char *) p + current_block_size - DWORD, (remain_size | 0));
  //delete the first part (allocated) from explicit free list
  node *new_node = (node *) ((char *) p + adjusted_size);
  add_node(new_node);
}


static void add_block_without_splitting(node *p, size_t adjusted_size) {
  delete_node(p);
  //printf("just jump in add_block_without_splitting - p = %p\n", p);
  size_t current_block_size = get_size((char *) p - WORD);
  assert(current_block_size >= adjusted_size);
  //rewrite header and footer
  write_word((char *) p - WORD, (current_block_size| 1));
  write_word((char *) p + current_block_size - DWORD, (current_block_size | 1));
  //update pointers
  //delete this block from explicit free list
  //printf("before calling delete_node - p = %p\n", p);
}

									       
/*
 * malloc will allocate a block from the free list.
 * malloc will search the free list for a large enough block and return a pointer to that block.
 */
void *malloc(size_t size)
{
  //mm_checkheap(__LINE__);
  size_t adjusted_size, extend_size, current_block_size;
  void *p = NULL;

  // If the requested size equals 0
  if (size == 0)
    return NULL;

  // Adjust the block size for alignment requirement
  if (size <= ALIGNMENT) 
    adjusted_size = ALIGNMENT + DWORD;
  else
    adjusted_size = align(size) + DWORD;

  assert(adjusted_size >= 32);
  assert(adjusted_size % ALIGNMENT == 0);

  // Find the first fit for the adjusted size
  //p = first_fit(adjusted_size);
  p = best_fit(adjusted_size);

  if (p != NULL) 
    return p;
    

  // No fit or empty free list 
  if (adjusted_size > 4096)
    extend_size = adjusted_size;
  else 
    extend_size = 4096;
         
  if ((p = extend_heap(extend_size)) == NULL)
    return NULL;
    
  //printf("malloc - extened heap!!\n");
  //printf("malloc - p = %p\n", p);
  current_block_size = get_size(p - WORD);

  if (current_block_size > adjusted_size && current_block_size - adjusted_size >= 4*WORD) {
    //printf("malloc - address that we will add block with splitting = %p\n", p);
    add_block_with_splitting(p, adjusted_size);
  } else {
    assert(current_block_size >= adjusted_size && current_block_size - adjusted_size < 4*WORD);
    add_block_without_splitting(p, adjusted_size);
  }
  //mm_checkheap(__LINE__)
  return p;
}


/*
 * free the allocated block and merge adjacent free blocks
 */
void free(void* block)
{
  //printf("free -- passed in address = %p\n", block);
  //printf("free - block that gotta free - size at header = %ld\n", get_size(block - WORD));
  //printf("free - block that gotta free - size at footer = %ld\n", get_size(block + get_size(block - WORD) - DWORD));
  //if block is NULL, do nothing
  if (block == NULL)
    return;

  //check if the block's allocation bit is 1
  if (get_alloc(block - WORD) == 1) {
    size_t size = get_size(block - WORD);
    //rewrite header and footer
    write_word(block - WORD, (size | 0));
    write_word(block - DWORD + size, (size | 0));
    coalesce(block);
  }
  mm_checkheap(__LINE__);
  return;
}

/*
 * realloc
 * Ziping Ye
 */
void* realloc(void* oldptr, size_t size)
{
  if (oldptr == NULL)
    return malloc(size);

  if (size == 0){
    free(oldptr);
    return NULL;
  }

  //check if the oldptr is returned by an earlier malloc, calloc, or realloc
  if (get_alloc(oldptr - WORD) == 1) {
    size_t current_block_payload_size = get_size(oldptr - WORD) - DWORD;
    size_t next_alloc = get_alloc(oldptr + current_block_payload_size + WORD);
    size_t next_block_size = get_size(oldptr + current_block_payload_size + WORD);

    if (current_block_payload_size >= size) {//we have enough memory in the current block to statisfy reallloc
      return oldptr;
    } else if (next_alloc == 0 && (current_block_payload_size + next_block_size) >= size) {//next block happens to be free, and the total size of current block and next block is enough, we expend to next block
      //delete next block from explicit free list
      node *next_block = (node *) (oldptr + current_block_payload_size + DWORD);
      delete_node(next_block);
      //rewrite header and footer
      write_word(oldptr - WORD, ((current_block_payload_size + next_block_size + DWORD) | 1));
      write_word(oldptr + current_block_payload_size + next_block_size, ((current_block_payload_size + next_block_size + DWORD) | 1));
      return oldptr;      
      } else { //we have to find a new block
      void *newptr = malloc(size);
      //copy the content from old block to new block
      memcpy(newptr, oldptr, current_block_payload_size);
      free(oldptr);
      return newptr;
    }
  }
  return NULL;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
  // Is every block in the free list marked as free?
  node *p;
  // Creater pointer to first block in heap
  for (int i = 0; i < NUM_CLASS; i ++) {
    p = head[i];
    while (p != NULL) {
      if (get_alloc((void *) p - WORD) != 0) {
        printf("Heap Check Error: Not every block in the free list is marked as free.\n");
      }
      if (p > mem_heap_hi() || p < mem_heap_lo()) {
        printf("Heap Check Error: Free block in a location that is not a valid free block.\n");
      }
      p = p->next;
    }
  }
 

  // Are there any contiguous free blocks that somehow escaped coalescing?
  // Create pointer pointing to the first and second blocks of the heap
  void *heap_element = mem_heap_lo() + NUM_CLASS * WORD + WORD;
  size_t prev_alloc, next_alloc, current_alloc, current_size;
  while (heap_element < mem_heap_hi()) {
    current_size = get_size(heap_element);
    current_alloc = get_alloc(heap_element);
    prev_alloc = get_alloc(heap_element - WORD);
    next_alloc = get_alloc(heap_element + current_size);
    if (current_alloc == 0) {
      if (prev_alloc == 0 || next_alloc == 0)
        return false;
    }
    heap_element += current_size;
  }
   

  // Do any allocated blocks overlap?
  // Create the heap pointer pointing to the first block in the heap
  void *heap_element = heap;

  // Check to make sure the block is not NULL and loop otherwise
  while (heap_element != NULL) {
    // Make sure the block is allocated
    if (get_alloc(heap_element) == 1) {
      // Declare the next pointer in the heap
      void *next_heap_element = (char *)heap_element + (char *)get_size(heap_element);
      if ((char *)heap_element + (char *)(next - heap_element) < next_heap_element) {
        // Error message and return false
        printf("Heap Check Error: Allocated blocks overlap.");
        return false;
      }
    }
    // Increment the heap pointers
    heap_element = next_heap_element;
  }

  // Is every free block actually in the free list?
  // Creater pointer to first block in heap
  *heap_element = mem_heap_lo() + NUM_CLASS * WORD + WORD;
  size_t alloc, size, class;

  // Loop through the heap
  while (heap_element < mem_heap_hi()) {
    
    alloc = get_alloc(heap_element);
    size = get_size(heap_element);
    class = find_class(size);
    node *p = head[class];
    bool find = false;

    //Check if block is allocated
    if (alloc == 0) {
    // Loop through the class list
      while (p != NULL) {
        if ((void *)p == heap_element + WORD) {
          find = true;
          break;
        }
        p = p -> next;
      }

      // Free block is not in the free list
      if (find == false) {
        // Error message and return false
          printf("Heap Check Error: Not every block is in the free list.");
          return false;
      }
    }
    
    heap_element += size;
  }

    
#endif /* DEBUG */
  return true;

}
