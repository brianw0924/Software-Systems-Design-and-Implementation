#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/types.h>

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

#define PMD_SHIFT 21
#define PAGE_SHIFT 12
#define PTRS_PER_PTE 512
#define PTRS_PER_PMD 512
#define PAGE_SIZE 4096

struct expose_pte_args expose_pte(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {
        unsigned long begin_fpt_vaddr, end_fpt_vaddr, begin_pte_vaddr, end_pte_vaddr;
        unsigned long pte_cnt, pte_off, page_off;

        pte_cnt = 1 + (end_vaddr >> PMD_SHIFT) - (begin_vaddr >> PMD_SHIFT);
        begin_fpt_vaddr = (unsigned long)mmap(NULL, (pte_cnt) * 8,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!begin_fpt_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
        end_fpt_vaddr = begin_fpt_vaddr + pte_cnt * 8;
        begin_pte_vaddr = (unsigned long)mmap(NULL, pte_cnt * PAGE_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (!begin_pte_vaddr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
        end_pte_vaddr = begin_pte_vaddr + pte_cnt * PAGE_SIZE;

        struct expose_pte_args args = {
		pid,
		begin_fpt_vaddr,
		end_fpt_vaddr,
		begin_pte_vaddr,
		end_pte_vaddr,
		begin_vaddr,
		end_vaddr
	};

        int ret = syscall(436, &args);
        return args;
}

unsigned long *get_pte_p(struct expose_pte_args args, unsigned long va) {
        unsigned long fpt_offset, pte_offset, pte_addr, *pte_p;
        fpt_offset = (va >> PMD_SHIFT) - (args.begin_vaddr >> PMD_SHIFT);
        pte_addr = *((unsigned long*)(args.begin_fpt_vaddr) + fpt_offset);
        if(pte_addr) {
		pte_p = (unsigned long*)pte_addr;
		pte_offset = ((va) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	        return pte_p + pte_offset;
        } else {
		printf("va %lx pa not exists.\n", va);
                return 0;
	}
}

void code_injection(pid_t sc_pid, unsigned long sc_begin, unsigned long *target_pte_p) {
        struct expose_pte_args args = expose_pte(sc_pid, sc_begin, sc_begin + PAGE_SIZE);
        unsigned long *pte_p = get_pte_p(args, sc_begin);
        if(pte_p) {
                *target_pte_p = *(pte_p);
        }
        else {
                // pte doesn't exist
        }
}

void inspection(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {
        struct expose_pte_args args = expose_pte(pid, begin_vaddr, end_vaddr);
        unsigned long va, idx, *pte_p;
        for(idx = 1, va = args.begin_vaddr; va < args.end_vaddr; va+=PAGE_SIZE, idx++) {
                pte_p = get_pte_p(args, va);
                if(pte_p) {
                        printf("va%ld %lx pa%ld %lx\n", idx, va, idx, *pte_p);
                } else {
                        printf("va%ld %lx pa%ld not exists.\n", idx, va, idx);
                }
        }

}

unsigned long *get_target_pte_p(pid_t tar_pid, unsigned long tar_begin, unsigned long tar_end) {
        struct expose_pte_args args = expose_pte(tar_pid, tar_begin, tar_end);
        return get_pte_p(args, tar_begin);
}

int main(int argc, char *argv[]) {
        if (argc < 5) {
                printf("Usage: %s <tar_pid> <tar_begin_va> <tar_end_va> <sc_pid> <sc_begin>\n", argv[0]);
                return 0;
        }
        // va inspection
        printf("va inspection\n");
        inspection((pid_t)atoi(argv[1]), strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16));

        // code injection
        printf("code injection\n");
        unsigned long *target_pte_p = get_target_pte_p((pid_t)atoi(argv[1]), strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16));
        code_injection((pid_t)atoi(argv[4]), strtoul(argv[5], NULL, 16), target_pte_p);

        return 0;
}

