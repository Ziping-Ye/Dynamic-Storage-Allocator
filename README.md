# Dynamic Storage Allocator

## Introduction
This project is an implementation of a dynamic storage allocator for C programs, which includes custom versions of the malloc, free, and realloc functions. The main goal was to explore the design space and implement an allocator that is correct, space efficient, and fast. This involved creative problem-solving and in-depth understanding of memory management.

## Key Features
- Implements `malloc`, `free`, `realloc`, and `mm_init` functions.
- Includes a heap consistency checker (`mm_checkheap`) to help debug and ensure the integrity of the memory allocation process.
- Designed to be space-efficient and performant in 64-bit environments.
- Enforces 16-byte alignment for allocated blocks, mimicking the standard C library behavior.

## Programming and Design Considerations
- All memory management functions are implemented in a single file (`mm.c`) without modifications to other project files.
- The code avoids using memory-management related library calls or system calls like `sbrk` or `brk`. Instead, it utilizes a provided `mem_sbrk` function.
- Emphasis on writing clear, comprehensible comments and documenting the overall design at the top of the `mm.c` file.
- Strict adherence to programming rules set forth to ensure compatibility and reliability.

## Dynamic Memory Allocator Functions
- **`mm_init`**: Initializes the allocator, setting up the initial heap area.
- **`malloc`**: Allocates a block of at least a specified size, returning a 16-byte aligned pointer.
- **`free`**: Frees the block pointed to by the provided pointer.
- **`realloc`**: Changes the size of the memory block, potentially moving it to a new location.

## Support Functions and Heap Consistency Checker
- The `memlib.c` package simulates the memory system, providing functions to manage the heap and perform memory operations.
- A comprehensive heap consistency checker is implemented to verify the allocator's correctness, checking for common issues like uncoalesced free blocks, overlap, and proper free list management.

## Testing and Evaluation
- The project includes a testing framework (`mdriver`) for evaluating the implementation against a suite of trace files that simulate allocation patterns.
- The allocator's performance is assessed based on space utilization and throughput, balancing efficiency and speed.

## Getting Started
To build and test the allocator:
1. Compile the code using `make`.
2. Run tests using `make test` or individually with `./mdriver -f traces/tracefile.rep`.

## Debugging
- Debugging support is integrated, with detailed instructions for using `gdb` and enabling debug messages.

This project represents a comprehensive exercise in low-level memory management and efficient algorithm implementation, challenging participants to achieve a balance between space utilization and operational throughput.
