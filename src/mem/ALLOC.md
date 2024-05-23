we got the pageframe alloctor that finds the pages in kernel space
above that we got the virtual memory manaer also in kernel space that creaets the page mapping

above that we got the "clients" that reside in kernel space, that acn be the kernel allocator or mmap gives memory
capabilites to users sapce

and in userspace we got the user space allocator that requetst memory at addr and size that is implemented in the std
lib
this allocaotr craetes the idea of where the heap is. 