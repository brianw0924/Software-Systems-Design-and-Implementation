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

#define PMD_SHIFT 21
#define PAGE_SHIFT 12
#define PTRS_PER_PTE 512
#define PTRS_PER_PMD 512
#define PAGE_SIZE 4096
#define PHYS_ADDR_SHIFT 32

struct expose_pte_args expose_pte(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {
        unsigned long begin_fpt_vaddr, end_fpt_vaddr, begin_pte_vaddr, end_pte_vaddr, pte_cnt;

        // Count the pmd index change, which is the number of PTE within [begin_vaddr, end_vaddr)
        pte_cnt = 1 + ((end_vaddr - 1) >> PMD_SHIFT) - (begin_vaddr >> PMD_SHIFT);

        // mmap flattened table. Each entry is 8 byte
        begin_fpt_vaddr = (unsigned long)mmap(NULL, (pte_cnt) * 8,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (begin_fpt_vaddr == ((unsigned long)-1)) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
        end_fpt_vaddr = begin_fpt_vaddr + pte_cnt * 8;

        // mmap remapped PTE
        begin_pte_vaddr = (unsigned long)mmap(NULL, pte_cnt * PAGE_SIZE,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (begin_pte_vaddr == ((unsigned long)-1)) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};
        end_pte_vaddr = begin_pte_vaddr + pte_cnt * PAGE_SIZE;

        // system call
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
        if(ret) {
                printf("error: System call failed\n");
                exit(-1);
        } else
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
        } else
                return NULL;
}

int code_injection(pid_t tar_pid, unsigned long tar_begin_vaddr, unsigned long tar_end_vaddr,
        pid_t sc_pid, unsigned long sc_begin_vaddr, unsigned long sc_end_vaddr) {

        if(((tar_end_vaddr - tar_begin_vaddr) >> PAGE_SHIFT) != ((sc_end_vaddr - sc_begin_vaddr) >> PAGE_SHIFT)){
                printf("error: Number of shellcode page != Number of target page\n");
                exit(-1);
        }

        unsigned long tar_va, sc_va, *sc_pte_p, *target_pte_p;
        struct expose_pte_args tar_args = expose_pte(tar_pid, tar_begin_vaddr, tar_end_vaddr);
        struct expose_pte_args sc_args = expose_pte(sc_pid, sc_begin_vaddr, sc_end_vaddr);

        for(tar_va = tar_args.begin_vaddr, sc_va = sc_args.begin_vaddr;
                sc_va < sc_args.end_vaddr;
                        tar_va+=PAGE_SIZE, sc_va+=PAGE_SIZE) {
                
                // get the pte entry of shellcode and target process
                sc_pte_p = get_pte_p(sc_args, sc_begin_vaddr);
                if(!sc_pte_p){
                        printf("error: shellcode pte not exists.\n");
                        continue;
                }
                target_pte_p = get_pte_p(tar_args, tar_begin_vaddr);
                if(!target_pte_p){
                        printf("error: target pte not exists.\n");
                        continue;
                }
                // change the entry mapping
                *target_pte_p = *(sc_pte_p);
        }
        return 0;
}

int inspection(pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {
        struct expose_pte_args args = expose_pte(pid, begin_vaddr, end_vaddr);
        unsigned long va, pa, idx, *pte_p;
        for(idx = 1, va = args.begin_vaddr; va < args.end_vaddr; va+=PAGE_SIZE, idx++) {
                pte_p = get_pte_p(args, va);
                if(pte_p) {
                        pa = (*pte_p) & (((unsigned long)1 << PHYS_ADDR_SHIFT) -1);
                        printf("va%ld %lx pa%ld %lx\n", idx, va, idx, pa);
                } else
                        printf("va%ld %lx pa%ld not exists.\n", idx, va, idx);
        }
        return 0;
}

int main(int argc, char *argv[]) {
        /*
         * Error handling requirements:
         * 0. Input addresses should aligned to page size (4K)
         * 1. Ensure kernel does not free target task's resources
         * 2. given task's PID should exists
         * 3. flattened page table and remapped PTE tables should be reserved in caller's task's address space
        */

        // check arguments
        if (argc != 4 && argc != 7) {
                printf("Virtual Address Space Inspection: %s <tar_pid> <tar_begin_va> <tar_end_va> <sc_pid> <sc_begin>\n", argv[0]);
                printf("Code injection: %s <tar_pid> <tar_begin_va> <tar_end_va> <sc_pid> <sc_begin_va> <sc_end_va>\n", argv[0]);
                return 0;
        }

        int ret;


        if (argc == 4) {
                // va inspection
                ret = inspection((pid_t)atoi(argv[1]), strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16));
        } else if (argc == 7){
                // code injection
                ret = code_injection((pid_t)atoi(argv[1]), strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16),
                        (pid_t)atoi(argv[4]), strtoul(argv[5], NULL, 16), strtoul(argv[6], NULL, 16));
        }
        return ret;
}

