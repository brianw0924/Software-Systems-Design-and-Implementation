# Makefile
How to compile the source code:
```bash
make
```
# System call: expose_pte
## Figure
<p align="center"><img src="figure.jpg"></p>

## Explanation
* The system call `expose_pte` converts the 4-level page table to a 2-level page table in userspace adress space.
* First, we can know how many PTE page tables will be covered from `begin_vaddr` to `end_vaddr` by PMD index, which is at 29:21.
* We use 4 function to walk through page table: `pgd_offset()`, `pud_offset()`, `pmd_offset()`, `pte_offset_map()`
* Get the PTE page table's physical frame number by `pmd_page_paddr` and `__phys_to_pfn`.
* Remap the PTE page table's physical address by `remap_pfn_range` if exists.
* Map the corresponding entry in the flattened page table to the remapped PTE page table. Otherwise store zero to the respective entry in the flattened page table.
# Test program
## Virtual address inspection
* Step 1: Get the process' pid and virtual address
```bash
ps -x
cat /proc/<PID>/maps
```
* Step 2: Use the test program to inspect the va to pa translation
```bash
./hw3-test <TARGET_PID> <TARGET_BEGIN_VADDR> <TARGET_END_VADDR>
```
* The test program will call expose_pte system call and then walk through the flattened page table and remapped PTE page tables to translate the va to pa from `begin_vaddr` to `end_vaddr` page by page.
## Code Injection
* Step 1: Run `sheep` in background
```bash
./sheep &
```
* Step 2: Run shellcode in background
```bash
./hw3-shellcode 1 shellcode &
```
* Step 3: Find the virtual address of code section from `sheep`
```bash
cat /proc/<SHEEP_PID>/maps
```
* Step 4: The shellcode will print `sc_pid` and `sc_begin_vaddr` and `sc_end_vaddr`. Then run the test program to inject the code (The arguments might be too long in QEMU, you can new line by `\`)
```bash
./hw3-test <SHEEP_PID> <SHEEP_BEGIN_VADDR> <SHEEP_END_VADDR> <SC_PID> <SC_BEGIN_VADDR> <SC_END_VADDR>
```
* The test program will inject the code from (`sc_begin_vaddr`, `sc_end_vaddr`) to (`sheep_begin_vaddr`, `sheep_end_vaddr`). The number of pages should match.
## Bonus
* We can only inject the code to sheep
* follow the steps above, but change Step 2 to
```bash
./hw3-shellcode 1 bonus &
```
# Contributions
* 王韋翰/黃珮欣: 50/50
# References