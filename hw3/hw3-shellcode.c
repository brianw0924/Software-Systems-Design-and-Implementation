#include <unistd.h>
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

extern void shellcode_echo();
__asm__(".global shellcode_echo\n"
	"shellcode_echo:\n\t"
	/* execve(path='/bin/sh', argv=['sh', '-c', 'echo Hello > /tmp/a.txt'], envp=0) */
    	/* push b'/bin/sh\x00' */
    	/* Set x14 = 29400045130965551 = 0x68732f6e69622f */
    	"mov  x14, #25135\n\t"
    	"movk x14, #28265, lsl #16\n\t"
    	"movk x14, #29487, lsl #0x20\n\t"
    	"movk x14, #104, lsl #0x30\n\t"
    	"str x14, [sp, #-16]!\n\t"
    	"mov  x0, sp\n\t"
    	/* push argument array [b'sh\x00', b'-c\x00', b'echo Hello > /tmp/a.txt\x00'] */
    	/* push b'sh\x00-c\x00echo Hello > /tmp/a.txt\x00' */
    	/* Set x14 = 3418352462948482592 = 0x2f706d742f203e20 */
    	"mov  x14, #15904\n\t"
    	"movk x14, #12064, lsl #16\n\t"
    	"movk x14, #28020, lsl #0x20\n\t"
    	"movk x14, #12144, lsl #0x30\n\t"
    	/* Set x15 = 500237086305 = 0x7478742e61 */
    	"mov  x15, #11873\n\t"
    	"movk x15, #30836, lsl #16\n\t"
    	"movk x15, #116, lsl #0x20\n\t"
    	"stp x14, x15, [sp, #-16]!\n\t"
    	/* Set x14 = 7162131208359405683 = 0x636500632d006873 */
    	"mov  x14, #26739\n\t"
    	"movk x14, #11520, lsl #16\n\t"
    	"movk x14, #99, lsl #0x20\n\t"
    	"movk x14, #25445, lsl #0x30\n\t"
    	/* Set x15 = 8028911417952333672 = 0x6f6c6c6548206f68 */
    	"mov  x15, #28520\n\t"
    	"movk x15, #18464, lsl #16\n\t"
    	"movk x15, #27749, lsl #0x20\n\t"
    	"movk x15, #28524, lsl #0x30\n\t"
    	"stp x14, x15, [sp, #-16]!\n\t"
    	/* push null terminator */
    	"mov  x14, xzr\n\t"
    	"str x14, [sp, #-8]!\n\t"
    	/* push pointers onto the stack */
    	"mov  x14, #14\n\t"
    	"add x14, sp, x14\n\t"
    	"str x14, [sp, #-8]!\n\t" /* b'sh\x00' */
    	"mov  x14, #19\n\t"
    	"add x14, sp, x14\n\t"
    	"str x14, [sp, #-8]!\n\t" /* b'echo Hello > /tmp/a.txt\x00' */
    	"mov  x14, #24\n\t"
    	"add x14, sp, x14\n\t"
    	"str x14, [sp, #-8]!\n\t" /* b'-c\x00' */
    	/* set x1 to the current top of the stack */
    	"mov  x1, sp\n\t"
    	"mov  x2, xzr\n\t"
    	/* call execve() */
    	"mov  x8, #221\n\t"
    	"svc 0");

#define PAGE_SIZE 4096
char *create_shellcode(unsigned long len, char *option) {
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
	if(strcmp(option, "shellcode") == 0){
		memcpy(shellcode_addr + len - 0x100, &shellcode, 0x100);
	}
	else if(strcmp(option, "bonus") == 0){
		memcpy(shellcode_addr + len - 0x100, &shellcode_echo, 0x100);
	} else{
		printf("error: Unknown argument\n");
		exit(-1);
	}

	return shellcode_addr;
}

int main(int argc, char* argv[])
{
	int ret = 0, len;
	char *sc_begin;
	len = atoi(argv[1]) * PAGE_SIZE;
	sc_begin = create_shellcode(len, argv[2]); 
	printf("%ld\n",(unsigned long)sc_begin);
	printf("pid: %d\nsc_begin_vaddr: %lx\nsc_end_vaddr: %lx\n",
		getpid(), (unsigned long)sc_begin, (unsigned long)sc_begin + len);

	// (*(void(*)())sc_begin)();
	while (1) {}
	return ret;
}
