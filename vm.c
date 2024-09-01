#include <types.h>
#include <kern/errno.h>
#include <lib.h>
#include <spl.h>
#include <spinlock.h>
#include <proc.h>
#include <current.h>
#include <cpu.h>
#include <mips/tlb.h>
#include <addrspace.h>
#include <vm.h>
#include <vnode.h>
#include <stat.h>
#include <uio.h>
#include <vfs.h>
#include <bitmap.h>
#include <kern/fcntl.h>
#include <synch.h>

/*
	A NOTE ON INITIALIZING THE VM SYSTEM:

  	- 2 functions (init_coremap and init_diskmap) are called in the main() function in kern/main
	  to start the coremap and the swap space (in disk). That's why, in comparison to DUMBVM, we don't
   	  have a vm_bootstrap function.
*/



/*
 spinlock for coremap and disk
 */
static struct spinlock coremap_splock = SPINLOCK_INITIALIZER;
static struct spinlock diskmap_splock = SPINLOCK_INITIALIZER;

/*
	Usable part of phys mem
*/
static paddr_t first_paddr, last_paddr;

struct coremap_page *coremap_array;
struct diskmap diskmap_swap;

/*
	phys mem stat
*/
static unsigned int total_pages, used_pages;
static volatile unsigned int last_evicted_index;

/*
	backup page for kernel
	This is used in case that phys mem is full
	and we can't swapout a page(this happens if the process is holding a spinlock)
*/
static volatile paddr_t backup_kpage;

/*
	Make sure that all page table entry(pte) locks are released
*/
void check_pte_locks(void) {
	bool spl_acquired = false;
	// acquire coremap splk
	if (!spinlock_do_i_hold(&coremap_splock)) {
		spl_acquired = true;
		spinlock_acquire(&coremap_splock);
	}
	
	struct pagetable_entry *pte;
	// check if all locks are released
	for (unsigned int i = 0; i < last_paddr/PAGE_SIZE; i++) {

		if (coremap_array[i].addrspace_owner != NULL) {
			for (
				pte = coremap_array[i].addrspace_owner->as_pagetable_head;
				pte != NULL;
				pte = pte->next_entry
			) {
				KASSERT(lock_do_i_hold(pte->lock) != true);
			}
		}
	}

	if (spl_acquired)
		spinlock_release(&coremap_splock);
}


static
void
as_zero_region(paddr_t paddr, unsigned npages)
{
	bzero((void *)PADDR_TO_KVADDR(paddr), npages * PAGE_SIZE);
}

/*
	Initialize the coremap
	keeps data of the status of each physical page
*/
void 
init_coremap(void) {
	// get size of space available to memory
	last_paddr = ram_getsize();
	first_paddr = ram_getfirstfree();

	// align start point to page size
	if (first_paddr % PAGE_SIZE != 0) {
		first_paddr = (first_paddr/PAGE_SIZE + 1)*PAGE_SIZE;
	}

	// initialize coremap struct
	coremap_array = (struct coremap_page *)PADDR_TO_KVADDR(first_paddr);

	int num_pages = last_paddr/PAGE_SIZE;

	int size_coremap_array = sizeof(struct coremap_page)*num_pages;

	// align coremap to page size
	if (size_coremap_array % PAGE_SIZE != 0) {
		size_coremap_array = (size_coremap_array/PAGE_SIZE + 1)*PAGE_SIZE;
	}

	first_paddr += size_coremap_array;

	// initialize all elements in the coremap to either padding or free
	for(unsigned int i = 0; i < first_paddr/PAGE_SIZE; i++) {
		coremap_array[i].state = pstate_padding;
	}

	for (unsigned int i = first_paddr/PAGE_SIZE; i < last_paddr/PAGE_SIZE; i++) {
		coremap_array[i].state = pstate_free;
		coremap_array[i].chunk_size = 0;
	}

	// set global variables , and return
	total_pages = (last_paddr - first_paddr)/PAGE_SIZE;

	last_evicted_index = first_paddr/PAGE_SIZE;

	backup_kpage = 0;
}

/*
	Initialize diskmap
*/
void
init_diskmap(void) {
	int err;
	char path_disk[] = "lhd0raw:";
	struct stat disk_stat;
	diskmap_swap.present = false;

	// open file location of simulated "external memory"
	err = vfs_open(path_disk, O_RDWR, 0, &diskmap_swap.vnode);
	if (err) {
		return;
	}

	err = VOP_STAT(diskmap_swap.vnode, &disk_stat);
	if (err) {
		vfs_close(diskmap_swap.vnode);
		return;
	}
	
	// intiailize the bitmap for diskmap
	KASSERT(disk_stat.st_size % PAGE_SIZE == 0);
	diskmap_swap.bitmap = bitmap_create(disk_stat.st_size/PAGE_SIZE);
	diskmap_swap.present = true;
	diskmap_swap.swap_size = disk_stat.st_size;
	
	return;
}


/*
	Find free physical pages
*/
static
paddr_t
getppages(unsigned long npages)
{
	unsigned int cntr_free = 0;
	int starting_index = -1;

	spinlock_acquire(&coremap_splock);
	// check coremap for which pages are free, increment counter if they are
	for (unsigned int i = first_paddr/PAGE_SIZE; i < last_paddr/PAGE_SIZE; i++) {
		if (coremap_array[i].state == pstate_free) {
			if (starting_index == -1) {
				starting_index = i;
			}

			cntr_free += 1;

			if (cntr_free == npages) {
				break;
			}
		} else {
			starting_index = -1;
			cntr_free = 0;
		}
	}
	// if we find a different number of free pages
	if (cntr_free != npages) {
		spinlock_release(&coremap_splock);
		return 0;
	}
	// for all the pages we found, allocate them
	for (unsigned int i = 0; i < npages; i++) {
		coremap_array[starting_index + i].state = pstate_used;
		coremap_array[starting_index + i].addrspace_owner = NULL;
		coremap_array[starting_index + i].vaddr_owner = 0;
	}
	// set correct values in coremap
	coremap_array[starting_index].chunk_size = npages;

	paddr_t addr = starting_index*PAGE_SIZE;

	as_zero_region(addr, npages);

	used_pages += npages;

	spinlock_release(&coremap_splock);
	
	return addr;
}

/*
	Allocate physical page for user
	1. Checks for free physical page
	2. Uses disk if none found
*/
paddr_t
getuserppage(struct addrspace *as_owner, vaddr_t mapped_vaddr, bool from_as) {
	(void)from_as;

	paddr_t addr;
	int starting_index = -1;

	addr = getppages(1);
	// if no free pages found, evict pages from coremap into disk
	if (addr == 0 && diskmap_swap.present) {
		spinlock_acquire(&coremap_splock);
		addr = evict_ppage_user();
		spinlock_release(&coremap_splock);
		
		if (addr == 0) {
			return 0;
		}
		starting_index = addr/PAGE_SIZE;
	} else {
		starting_index = addr/PAGE_SIZE;
	}	
	// otherwise allocate page found
	spinlock_acquire(&coremap_splock);
	coremap_array[starting_index].state = pstate_used;
	coremap_array[starting_index].addrspace_owner = as_owner;
	coremap_array[starting_index].vaddr_owner = mapped_vaddr;
	coremap_array[starting_index].chunk_size = 1;
	spinlock_release(&coremap_splock);

	as_zero_region(addr, 1);
	
	return addr;
}

/*
	Free physical mem and update coremap
*/
void 
free_ppages(paddr_t addr) {
	KASSERT(addr % PAGE_SIZE == 0);

	spinlock_acquire(&coremap_splock);
	// free page
	unsigned int index_page = addr/PAGE_SIZE;

	if (coremap_array[index_page].state == pstate_free) {
		spinlock_release(&coremap_splock);
		return;
	}

	unsigned int npages = coremap_array[index_page].chunk_size;
	
	KASSERT(npages == 1);
	// update coremap
	coremap_array[index_page].state = pstate_free;
	coremap_array[index_page].chunk_size = 0;
	coremap_array[index_page].addrspace_owner = NULL;
	coremap_array[index_page].vaddr_owner = 0;
	
	used_pages -= npages;

	spinlock_release(&coremap_splock);
}

/*
	Free disk mem
*/
void 
free_swap_page(paddr_t addr) {
	unsigned int index = addr/PAGE_SIZE;

	KASSERT(bitmap_isset(diskmap_swap.bitmap, index) != 0);
	// free page in disk
	spinlock_acquire(&diskmap_splock);
	bitmap_unmark(diskmap_swap.bitmap, index);
	spinlock_release(&diskmap_splock);
}

/* 
	Allocate/free some kernel-space virtual pages 
	1. Checks for free physical page
	2. Uses disk if none found

	If possible, will reserve a backup page for kernel
	this is to be used in cases that the current cpu is holding
	a spinlock, therefore is unable to perform swap operation
*/
vaddr_t
alloc_kpages(unsigned npages)
{
	paddr_t pa;
	// get available pages
	pa = getppages(npages);
	// if no available pages, evict pages into disk
	if (pa == 0 && curcpu->c_spinlocks == 0 && diskmap_swap.present) {
		spinlock_acquire(&coremap_splock);
		pa = evict_ppage_kernel(npages);
		spinlock_release(&coremap_splock);
	}
	if (pa == 0) {
		if (backup_kpage != 0) {
			pa = backup_kpage;
			backup_kpage = 0;
		} else {
			return 0;
		}
	// if no mem available, use last resort backup page
	} else if (backup_kpage == 0) {
		backup_kpage = getppages(1);
		if (backup_kpage == 0 && curcpu->c_spinlocks == 0 && diskmap_swap.present) {
			spinlock_acquire(&coremap_splock);
			backup_kpage = evict_ppage_kernel(1);
			spinlock_release(&coremap_splock);
		}
	}
	
	as_zero_region(pa, npages);

	return PADDR_TO_KVADDR(pa);
}

/*
	Free kernel mem
*/
void
free_kpages(vaddr_t addr)
{
	vaddr_t vaddr = addr - MIPS_KSEG0;
	KASSERT(vaddr % PAGE_SIZE == 0);

	spinlock_acquire(&coremap_splock);

	unsigned int index_page = vaddr/PAGE_SIZE;

	unsigned int npages = coremap_array[index_page].chunk_size;

	for (unsigned int i = 0; i < npages; i++) {
		coremap_array[index_page + i].state = pstate_free;
		coremap_array[index_page + i].chunk_size = 0;
	}
	
	used_pages -= npages;

	spinlock_release(&coremap_splock);
}

/*
	Invalidate TLB Entry
*/
void 
vm_tlb_invalidate(vaddr_t vaddr_remove) {
	int indx, spl;
	spl = splhigh();
	indx = -1;
	indx = tlb_probe(vaddr_remove, 0);
	if (indx >= 0) {
		tlb_write(TLBHI_INVALID(indx), TLBLO_INVALID(), indx);
	}
    splx(spl);	
}


void
vm_tlbshootdown_all(void)
{
	panic("VM tried to do tlb shootdown?!\n");
}


void
vm_tlbshootdown(const struct tlbshootdown *ts)
{
	(void)ts;
	panic("VM tried to do tlb shootdown?!\n");
}

/*
	VM FAULT
*/
int
vm_fault(int faulttype, vaddr_t faultaddress)
{
	(void)faulttype;
	struct cpu *my_cpu = curcpu;
	
	struct addrspace *as = proc_getas();
	KASSERT(as != NULL);
	KASSERT(as->as_region_head != NULL);
	struct as_region *reg_ptr = as->as_region_head;

	vaddr_t stacktop = USERSTACK;
	vaddr_t stackbase = USERSTACK - VM_STACKPAGES * PAGE_SIZE;

	bool is_vaddr_valid = false;

	faultaddress &= PAGE_FRAME;

	/* Check if faultaddress is valid */
	if (faultaddress >= stackbase && faultaddress < stacktop) {
		is_vaddr_valid = true;
	} else if (faultaddress >= as->as_heap_start && faultaddress < as->as_heap_end) {
		is_vaddr_valid = true;
	} else {
		while (reg_ptr) {
			if (
				faultaddress >= reg_ptr->vaddr_start 
				&& faultaddress < reg_ptr->vaddr_start + reg_ptr->size
			) {
				is_vaddr_valid = true;
				break;
			}
			reg_ptr = reg_ptr->next_region;
		}
	}

	if (!is_vaddr_valid) {
		return EFAULT;
	}

	/* 
		Find the pagetable entry 
		If doesn't exist, create one and 
		add the mapping	
	*/
	struct pagetable_entry *pte, *pte_prev;
	paddr_t ppage;
	int err;
	
	if (as->as_pagetable_head) {
		pte = as->as_pagetable_head;

		while (pte) {
			lock_acquire(pte->lock);

			if (pte->vpage_addr == faultaddress) {
				if (pte->state == vpage_swapped) {
					/* Swap in */
					lock_release(pte->lock);

					KASSERT(my_cpu->c_spinlocks == 0);
					ppage = getuserppage(as, faultaddress, true);

					if (ppage == 0) {
						return ENOMEM;
					}

					lock_acquire(pte->lock);
					err = swapin(pte->ppage_addr, ppage);

					if (err) {
						lock_release(pte->lock);
						free_ppages(ppage);
						return err;
					}

					free_swap_page(pte->ppage_addr);
					pte->state = vpage_mapped;
					pte->ppage_addr = ppage;

				} else if (pte->state == vpage_mapped) {
					ppage = pte->ppage_addr;

				} else {
					panic("UNMAPPED PAGE TABLE ENTRY");
				}

				lock_release(pte->lock);

				break;
			}

			lock_release(pte->lock);
			pte_prev = pte;
			pte = pte->next_entry;
		}

		/* If no pte maps to this address, create a new one */
		if (pte == NULL) {
			pte = kmalloc(sizeof(struct pagetable_entry));
			
			if (pte == NULL) {
				return ENOMEM;
			}

			pte->lock = lock_create("PTL");
			
			if (pte->lock == NULL) {
				kfree(pte);
				return ENOMEM;
			}

			pte->vpage_addr = faultaddress;

			KASSERT(my_cpu->c_spinlocks == 0);
			ppage = getuserppage(as, faultaddress, true);
			
			if (ppage == 0) {
				lock_destroy(pte->lock);
				kfree(pte);
				return ENOMEM;
			}

			pte->ppage_addr = ppage;
			pte->permissions = 0;
			pte->state = vpage_mapped;
			pte->next_entry = NULL;

			lock_acquire(pte_prev->lock);
			KASSERT(pte_prev->next_entry == NULL);
			pte_prev->next_entry = pte;
			lock_release(pte_prev->lock);
		}
	} else {
		/* If addrspace has not page table, create one */

		pte = kmalloc(sizeof(struct pagetable_entry));
		
		if (pte == NULL) {
			return ENOMEM;
		}

		pte->lock = lock_create("PTL");
		
		if (pte->lock == NULL) {
			kfree(pte);
			return ENOMEM;
		}
		
		pte->vpage_addr = faultaddress;
		KASSERT(my_cpu->c_spinlocks == 0);
		ppage = getuserppage(as, faultaddress, true);
		if (ppage == 0) {
			lock_destroy(pte->lock);
			kfree(pte);
			return ENOMEM;
		}

		pte->ppage_addr = ppage;
		pte->permissions = 0;
		pte->state = vpage_mapped;
		pte->next_entry = NULL;

		KASSERT(as->as_pagetable_head == NULL);
		as->as_pagetable_head = pte;
	}

	KASSERT(spinlock_do_i_hold(&coremap_splock) != true);
	KASSERT(spinlock_do_i_hold(&diskmap_splock) != true);

	unsigned int i;
	uint32_t ehi, elo;
	int spl;

	/* make sure it's page-aligned */
	KASSERT((ppage & PAGE_FRAME) == ppage);

	/* Disable interrupts on this CPU while frobbing the TLB. */
	spl = splhigh();

	for (i = 0; i < NUM_TLB; i++) {
		tlb_read(&ehi, &elo, i);

		if (elo & TLBLO_VALID) {
			continue;
		}

		ehi = faultaddress;
		elo = ppage | TLBLO_DIRTY | TLBLO_VALID;
		
		DEBUG(DB_VM, "VM: 0x%x -> 0x%x\n", faultaddress, ppage);

		tlb_write(ehi, elo, i);
		
		splx(spl);
		
		return 0;
	}

	/* If TLB is full, randomly replace one entry */
	ehi = faultaddress;
	elo = ppage | TLBLO_DIRTY | TLBLO_VALID;
	
	tlb_random(ehi, elo);
	
	splx(spl);
	
	return 0;
}

/*
	Read and write to disk
	assumes that no spinlock is held
*/
int 
swap_read_write(paddr_t addr, unsigned int index, bool read) {
	KASSERT(spinlock_do_i_hold(&coremap_splock) != true);
	KASSERT(spinlock_do_i_hold(&diskmap_splock) != true);


	struct vnode *vn = diskmap_swap.vnode;
    struct iovec iov;
	struct uio uio;

	
	uio_kinit(
		&iov, 
		&uio, 
		(void *)PADDR_TO_KVADDR(addr), 
		PAGE_SIZE, 
		index*PAGE_SIZE, 
		read ? UIO_READ : UIO_WRITE
	);

	int err;
	
	// swap from core to disk depending on input bool read 
	if (read) {
		err = VOP_READ(vn, &uio);
	} else {
		err = VOP_WRITE(vn, &uio);
	}

	if (err) {
		return err;
	}

	return 0;
}

/*
	Swaps in the diskpage from disk to ppage in physical mem
*/
int
swapin(paddr_t diskpage, paddr_t ppage) {	
	unsigned int index = diskpage/PAGE_SIZE;

	KASSERT(bitmap_isset(diskmap_swap.bitmap, index) != 0);
	
	int err;
	
	/* read from "diskpage" to "ppage" */
	err = swap_read_write(ppage, index, true);
	
	if (err) {
		return err;
	}
	
	return 0;
}

/*
	Swaps out the ppage from physical mem to index*PAGE_SIZE in disk
*/
int 
swapout(paddr_t ppage, unsigned int index) {
	KASSERT(bitmap_isset(diskmap_swap.bitmap, index) != 0);

	int err;

	/* write to "index" from "ppage" */
	err = swap_read_write(ppage, index, false);

	if (err) {
		return err;	
	} else {
		return 0;
	}
}	

/*
	Evict a physical page to disk
	Eviction Policy:
		We use a pointer "last_evicted_index" to a page in the physical mem.
		We move this page everytime we evict, and when it reaches the end of the physical mem
		We move it to the beginning

	Assumes that coremap_splock is held
	Assumes that no other spinlock is held
*/
paddr_t
evict_ppage_user(void) {
	KASSERT(spinlock_do_i_hold(&coremap_splock) == true);
	KASSERT(curcpu->c_spinlocks == 1);

	unsigned int cntr = 0;
	bool found = false;
	int err;
	unsigned int disk_index;

	spinlock_acquire(&diskmap_splock);
	err = bitmap_alloc(diskmap_swap.bitmap, &disk_index);
	spinlock_release(&diskmap_splock);

	if (err) {
		return 0;
	}

	while (cntr < total_pages) {
		if (last_evicted_index >= last_paddr/PAGE_SIZE) {
			last_evicted_index = first_paddr/PAGE_SIZE;
		}

		/*
			We look for a page to evict
			- this page must be used(otherwise we would have found it)
			- the page must NOT be used by kernel
			- if the as_pagetable_head of the addrspace is NULL, it means that its being copied so we avoid using it
		*/
		if (
			coremap_array[last_evicted_index].state == pstate_used
			&& coremap_array[last_evicted_index].addrspace_owner != NULL
			&& coremap_array[last_evicted_index].addrspace_owner->as_pagetable_head != NULL
		) {
			found = true;
			break;
		}
		
		cntr++;
		last_evicted_index++;
	}

	if (!found) {
		return 0;
	}

	unsigned int eviction_index = last_evicted_index;

	struct addrspace *as = coremap_array[last_evicted_index].addrspace_owner;
	KASSERT(as != NULL);
	coremap_array[last_evicted_index].addrspace_owner = NULL;

	paddr_t va_owner = coremap_array[last_evicted_index].vaddr_owner;
	KASSERT(va_owner != 0);
	coremap_array[last_evicted_index].vaddr_owner = 0;

	last_evicted_index++;

	/* Release coremap spin lock and acquire addrspace lock */
	spinlock_release(&coremap_splock);
	lock_acquire(as->as_lock);

	/* Check if as was not destroyed */
	if (as->as_pagetable_head == NULL) {
		lock_release(as->as_lock);
		spinlock_acquire(&coremap_splock);

		return eviction_index*PAGE_SIZE;
	}

	struct pagetable_entry *pte = as->as_pagetable_head;
	KASSERT(pte != NULL);

	while (pte) {
		lock_acquire(pte->lock);
		if (
			pte->ppage_addr == eviction_index*PAGE_SIZE
			&& pte->state == vpage_mapped
		) {
			KASSERT(pte->vpage_addr == va_owner);
			break;
		}
		lock_release(pte->lock);
		pte = pte->next_entry;
	}

	/* 
		If the page was not found in the pte s
		means that the pte was removed by sbrk
	*/
	if (pte == NULL) {
		lock_release(as->as_lock);
		spinlock_acquire(&coremap_splock);

		return eviction_index*PAGE_SIZE;
	}

	pte->state = vpage_swapped;

	/* swap out the phys page */
	err = swapout(eviction_index*PAGE_SIZE, disk_index);

	if (err) {
		lock_release(pte->lock);
		lock_release(as->as_lock);

		spinlock_acquire(&coremap_splock);
		coremap_array[eviction_index].addrspace_owner = as;
		coremap_array[eviction_index].vaddr_owner = va_owner;
		
		spinlock_acquire(&diskmap_splock);
		bitmap_unmark(diskmap_swap.bitmap, disk_index);
		spinlock_release(&diskmap_splock);

		return 0;
	}

	pte->ppage_addr = disk_index*PAGE_SIZE;
	pte->state = vpage_swapped;
	lock_release(pte->lock);
	lock_release(as->as_lock);

	spinlock_acquire(&coremap_splock);
	vm_tlb_invalidate(va_owner);

	return eviction_index*PAGE_SIZE;
}

/*
	Evict a physical page to disk for kernel
	Eviction Policy:
		evict the first ppage of a user

	Assumes that coremap_splock is held
	Assumes that no other spinlock is held
*/
paddr_t
evict_ppage_kernel(size_t npages) {
	check_pte_locks();

	KASSERT(spinlock_do_i_hold(&coremap_splock) == true);
	KASSERT(curcpu->c_spinlocks == 1);
	
	unsigned int start_index = 0;
	unsigned int cntr = 0;
	unsigned int i;

	for (i = first_paddr/PAGE_SIZE; i < last_paddr/PAGE_SIZE; i++) {
		if (
			coremap_array[i].state == pstate_free 
			|| (
				coremap_array[i].state == pstate_used 
				&& coremap_array[i].addrspace_owner != NULL
				&& coremap_array[i].addrspace_owner->as_pagetable_head != NULL
			)
		) {
			start_index = (start_index == 0) ? i : start_index;
			cntr += 1;

		} else {
			start_index = 0;
			cntr = 0;
		}

		if (cntr == npages) {
			break;
		}
	}

	if (start_index == 0) {
		return 0;
	}

	/* Store the addrspace and vaddr of pages we want to evict */
	struct addrspace *arr_as[npages];
	vaddr_t arr_vaddr[npages];

	for (i = start_index; i < start_index+npages; i++) {
		arr_as[i-start_index] = coremap_array[i].addrspace_owner;
		arr_vaddr[i-start_index] = coremap_array[i].vaddr_owner;
		
		/* modify these entries so no other thread can modify them */
		coremap_array[i].addrspace_owner = NULL;
		coremap_array[i].vaddr_owner = 0;
		coremap_array[i].state = pstate_used;
	}

	struct addrspace *as;
	struct pagetable_entry *pte;

	int err;
	unsigned int index;

	/* release coremap spinlock */
	spinlock_release(&coremap_splock);

	for (i = start_index; i < start_index+npages; i++) {
		if (arr_as[i-start_index] != NULL) {
			lock_acquire(arr_as[i-start_index]->as_lock);

			/* if the as is being removed, take the page :) */
			if (arr_as[i-start_index]->as_pagetable_head == NULL) {
				lock_release(arr_as[i-start_index]->as_lock);
				continue;
			}

			spinlock_acquire(&diskmap_splock);
			err = bitmap_alloc(diskmap_swap.bitmap, &index);
			spinlock_release(&diskmap_splock);

			if (err) {
				lock_release(arr_as[i-start_index]->as_lock);
				spinlock_release(&coremap_splock);

				return 0;
			}

			as = arr_as[i-start_index];
			KASSERT(as != NULL);

			pte = as->as_pagetable_head;
			KASSERT(pte != NULL);

			while (pte) {
				lock_acquire(pte->lock);
				if (
					pte->ppage_addr == i*PAGE_SIZE
					&& pte->state == vpage_mapped
				) {
					break;
				}
				lock_release(pte->lock);
				pte = pte->next_entry;
			}
			
			/* 
				If the page was not found in the pte s
				means that the pte was removed by sbrk
			*/
			if (pte != NULL) {	
				KASSERT(curcpu->c_spinlocks == 0);
				
				err = swapout(pte->ppage_addr, index);
				
				if (err) {
					lock_release(pte->lock);

					spinlock_acquire(&coremap_splock);

					for (unsigned int j = i; j < npages; j++) {
						coremap_array[j].addrspace_owner = arr_as[j-start_index];
						coremap_array[j].vaddr_owner = arr_vaddr[j-start_index];
						coremap_array[j].state = (arr_as[j-start_index] == NULL) ? pstate_free : pstate_used;
					}
									
					spinlock_acquire(&diskmap_splock);
					bitmap_unmark(diskmap_swap.bitmap, index);
					spinlock_release(&diskmap_splock);
					
					return err;
				}

				vm_tlb_invalidate(pte->vpage_addr);

				pte->ppage_addr = index*PAGE_SIZE;
				pte->state = vpage_swapped;
				lock_release(pte->lock);
			}

			lock_release(arr_as[i-start_index]->as_lock);
		}
	}
	
	spinlock_acquire(&coremap_splock);

	coremap_array[start_index].chunk_size = npages;

	KASSERT(coremap_array[start_index].addrspace_owner == NULL);

	return start_index*PAGE_SIZE;
}
