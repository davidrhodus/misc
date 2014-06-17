#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <malloc/malloc.h> // for malloc_printf()

// Note: Compile with GCC, not cc (important)
//
//
// This is the expected interpose structure
 typedef struct interpose_s { void *new_func;
			       void *orig_func; } interpose_t;
// Our prototypes - requires since we are putting them in 
//  the interposing_functions, below

void *my_malloc(int size); // matches real malloc()
void my_free (void *); // matches real free()

static const interpose_t interposing_functions[] \ 
    __attribute__ ((section("__DATA, __interpose"))) = {

 { (void *)my_free, (void *)free },
 { (void *)my_malloc, (void *)malloc } 

};

void *
my_malloc (int size) {
 // In our function we have access to the real malloc() -
 // and since we don’t want to mess with the heap ourselves,
 // just call it
 //
void *returned = malloc(size);
// call malloc_printf() because the real printf() calls malloc()
// // internally - and would end up calling us, recursing ad infinitum

  malloc_printf ( "+ %p %d\n", returned, size); return (returned);
}
void
my_free (void *freed) {
// Free - just print the address, then call the real free()


  malloc_printf ( "- %p\n", freed); free(freed);
}



#if 0
  From output 4-11:

 morpheus@Ergo(~)$ gcc -dynamiclib l.c -o libMTrace.dylib -Wall  // compile to dylib
 morpheus@Ergo(~)$ DYLD_INSERT_LIBRARIES=libMTrace.dylib ls     // force insert into ls
 ls(24346) malloc: + 0x100100020 88
 ls(24346) malloc: + 0x100800000 4096
 ls(24346) malloc: + 0x100801000 2160 
 ls(24346) malloc: - 0x100800000 
 ls(24346) malloc: + 0x100801a00 3312 ... // etc.

#endif
