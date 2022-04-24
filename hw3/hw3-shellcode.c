#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

struct expose_pte_args {
	//PID of the target task to expose pte (can be the caller task or others)
        pid_t pid;
	//begin userspace VA of the flattened page table
        unsigned long begin_fpt_vaddr;
	//end userspace VA of the flattened page table
        unsigned long end_fpt_vaddr;
	//begin userspace VA of the remapped PTE table
        unsigned long begin_pte_vaddr;
	//end userspace VA of the remapped PTE table
        unsigned long end_pte_vaddr;
	//begin of userspace VA to expose PTE mappings
        unsigned long begin_vaddr;
	//end of userspace VA to expose PTE mappings
        unsigned long end_vaddr;
};

extern void shellcode();
__asm__(".global shellcode\n"
	"shellcode:\n\t"
	/* push b'/bin///sh\x00' */
	/* Set x14 = 8299904519029482031 = 0x732f2f2f6e69622f */
	"mov  x14, #25135\n\t"
	"movk x14, #28265, lsl #16\n\t"
	"movk x14, #12079, lsl #0x20\n\t"
	"movk x14, #29487, lsl #0x30\n\t"
	"mov  x15, #104\n\t"
	"stp x14, x15, [sp, #-16]!\n\t"
	/* execve(path='sp', argv=0, envp=0) */
	"mov  x0, sp\n\t"
	"mov  x1, xzr\n\t"
	"mov  x2, xzr\n\t"
	/* call execve() */
	"mov  x8, #221\n\t" // SYS_execve
	"svc 0");

extern void shellcode_touch();
__asm__(".global shellcode_touch\n"
	"shellcode_touch:\n\t"
	/* execve(path='/bin/touch', argv=['touch', 'a.log'], envp=0) */
    	/* push b'/bin/touch\x00' */
    	/* Set x14 = 8462109971917136431 = 0x756f742f6e69622f */
    	"mov  x14, #25135\n\t"
   	"movk x14, #28265, lsl #16\n\t"
  	"movk x14, #29743, lsl #0x20\n\t"
    	"movk x14, #30063, lsl #0x30\n\t"
    	"mov  x15, #26723\n\t"
    	"stp x14, x15, [sp, #-16]!\n\t"
    	"mov  x0, sp\n\t"
    	/* push argument array [b'touch\x00', b'a.log\x00'] */
    	/* push b'touch\x00a.log\x00' */
    	/* Set x14 = 3341952846830858100 = 0x2e61006863756f74 */
    	"mov  x14, #28532\n\t"
    	"movk x14, #25461, lsl #16\n\t"
    	"movk x14, #104, lsl #0x20\n\t"
    	"movk x14, #11873, lsl #0x30\n\t"
    	/* Set x15 = 6778732 = 0x676f6c */
    	"mov  x15, #28524\n\t"
    	"movk x15, #103, lsl #16\n\t"
    	"stp x14, x15, [sp, #-16]!\n\t"
    	/* push null terminator */
    	"mov  x14, xzr\n\t"
    	"str x14, [sp, #-8]!\n\t"
    	/* push pointers onto the stack */
    	"mov  x14, #14\n\t"
    	"add x14, sp, x14\n\t"
    	"str x14, [sp, #-8]!\n\t" /* b'touch\x00' */
    	"mov  x14, #16\n\t"
    	"add x14, sp, x14\n\t"
    	"str x14, [sp, #-8]!\n\t" /* b'a.log\x00' */
    	/* set x1 to the current top of the stack */
    	"mov  x1, sp\n\t"
    	"mov  x2, xzr\n\t"
    	/* call execve() */
    	"mov  x8, #221\n\t"
    	"svc 0");

char *create_shellcode(unsigned long len) {
	int i;
	char *shellcode_addr;

	// allocate memory page
	shellcode_addr = (char*)mmap(NULL, len,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (!shellcode_addr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};

	// fill memory with nop instructions
	for (i = 0; i < len/4; i++) {
		((int*)shellcode_addr)[i] = 0xd503201f;  // nop opcode
	};

	// copy shellcode to memory page
	// TODO: replace |0x100| with your shellcode length
	memcpy(shellcode_addr + len - 0x100, &shellcode_touch, 0x100);

	return shellcode_addr;
}

#define PAGE_SIZE 4096

int main(int argc, char* argv[])
{
	int ret = 0, len;
	char *sc_begin;

	len = PAGE_SIZE;
	sc_begin = create_shellcode(len);
        printf("sc_begin: %lx len: %ld\n", (unsigned long)sc_begin, (unsigned long)len);
	// (*(void(*)())sc_begin)();
	while (1) {}
	return ret;
}
