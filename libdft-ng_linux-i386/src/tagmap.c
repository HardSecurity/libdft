/*-
 * Copyright (c) 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2011.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/mman.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "branch_pred.h"

#ifdef	HUGE_TLB
#ifndef	MAP_HUGETLB
#define	MAP_HUGETLB	0x40000	/* architecture specific */
#endif
#define MAP_FLAGS	MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB
#else
#define MAP_FLAGS	MAP_PRIVATE | MAP_ANONYMOUS
#endif


/*
 * tagmap
 *
 * the tagmap is the data structure that keeps tag information for the virtual
 * address space of a process. In the 32-bit x86 architecture (i386), it is
 * implemented using tagmap segments of PAGE_SZ bytes. We assign a tagmap
 * segment to each chunk in the virtual address space that is PAGE_SZ bytes,
 * and the mapping is done byte-to-byte (i.e., every addressable byte has a
 * ``shadow'' byte in its corresponding tagmap segment that can hold up to 8
 * different tags)
 */

/*
 * STAB
 *
 * the segment table (STAB) keeps the necessary information for translating
 * virtual addresses to their ``shadowed'' addresses. In the 32-bit x86
 * architecture (i386), it is implemented using a single level page-table-like
 * structure with 4 GB/PAGE_SZ entries. Each entry, translates all the
 * addresses of a PAGE_SZ chunk to their shadowed bytes in a tagmap segment,
 * and the translation is performed as follows:
 *
 * 	taddr = vaddr + STAB[vaddr >> lg(PAGE_SZ)]
 *
 */
uint32_t	*STAB		= NULL;

/* program break */
size_t		brk_start	= 0;
size_t		brk_end		= 0;

/* ``hardcoded'' tagmap segments */
void		*null_seg	= NULL;
#ifdef TAGMAP_COLLAPSE
void		*zero_seg	= NULL;
#else
static void	*zero_seg	= NULL;
#endif

/*
 * track when the dynamic linker/loader
 * is loaded into the address space of
 * the process (flag)
 */
static
size_t dynldlnk_loaded	= 0;

/*
 * get the starting and ending
 * addresses of the vDSO mapping
 *
 *
 * @saddr: 	the starting address of vDSO
 * @eaddr:	the ending address of VDSO
 *
 * returbs:	saddr and eaddr have the appropriate
 * 		values after invocation; if vDSO
 * 		is not found saddr and eaddr will
 * 		be zero
 */
static inline
void get_vdso(size_t *saddr, size_t *eaddr)
{
	/* file pointer */
	FILE	*fp		= NULL;
	/* path to /proc/<pid>/maps */
	char	maps_path[PATH_MAX];
	/* line buffer */
	char	lbuf[MAPS_ENTRY_MAX];
	
	/* initialization */
	*saddr = *eaddr = 0;

	/* cleanup */
	(void)memset(maps_path, 0, PATH_MAX);

	/* prepare the pathname for /proc/<pid>/maps */
	if (snprintf(maps_path, PATH_MAX, "/proc/%d/maps",
				PIN_GetPid()) > PATH_MAX) {
		/* failed */
		LOG(string(__func__) + ": failed while trying to assemble "
				+ string(maps_path) + " -- (" +
				string(strerror(errno)) + ")\n");
		return;
	}

	/* open /proc/<pid>/maps */
	if ((fp = fopen(maps_path, "r")) == NULL) {
		/* failed */
		LOG(string(__func__) + ": failed while trying to open "
				+ string(maps_path) + " -- (" +
				string(strerror(errno)) + ")\n");
		return;
	}
	
	/* read the file */
	while(!feof(fp)) {
		/* buffer cleanup */
		(void)memset(lbuf, 0, MAPS_ENTRY_MAX);
	
		/* read a line */
		if (fgets(lbuf, MAPS_ENTRY_MAX, fp) == NULL) {
			/* something went wrong */
			if (ferror(fp)) {
				/* verbose */
				LOG(string(__func__) +
					": failed while trying to read"
					+ string(maps_path) + " -- (" +
					string(strerror(errno)) + ")\n");
				break;
			}
		}
		
		/* check for the vDSO entry */
		if (strstr(lbuf, VDSO_STR) != NULL) {
			/* update saddr and eaddr */
			(void)sscanf(lbuf, "%x-%x %*s:4 %*x %*s:5 %*u%*s\n",
					saddr, eaddr);
			/* done */
			break;
		}
	}

	/* cleanup */
	(void)fclose(fp);
}

#ifdef TAGMAP_COLLAPSE
/*
 * ELF image loading callback
 *
 * capture the loading of an image and setup the tagmap accordingly;
 * read-only sections are mapped to zero_seg, whereas for each writeable
 * section we allocate a tagmap segment and adjust the STAB
 *
 * @img:	image handle
 * @v:		callback value
 */
static void
elf_load(IMG img, VOID *v)
{
	SEC	sec;	/* section iterator		*/
	SEC	lread;	/* last read-only section	*/
	size_t	i, j;	/* STAB iterators		*/
	void*	tseg;	/* tagmap segment		*/
	size_t	slen;	/* segment length 		*/

	/* 
	 * after the dynamic linker/loaded is mapped into
	 * the address space of the process, the image loading
	 * is handled via mmap(2). However, we cannot unregister
	 * elf_load, so we rely on this ugly hack; optimized branch
	 */ 
	if (likely(dynldlnk_loaded == 1))
		return;

#ifdef DEBUG_MEMTRACK
	/* verbose */
	LOG(string(__func__) + ": " +
		IMG_Name(img) + " " +
		hexstr(IMG_LowAddress(img)) + "-" +
		hexstr(IMG_HighAddress(img)) + "\n");

	for (sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		LOG("\t" + SEC_Name(sec) + ": " +
			hexstr(SEC_Address(sec)) + "-" +
			hexstr(SEC_Address(sec) + SEC_Size(sec) - 1) + " ");
		if (SEC_IsReadable(sec)) LOG("R"); else LOG("-");
		if (SEC_IsWriteable(sec)) LOG("W"); else LOG("-");
		if (SEC_IsExecutable(sec)) LOG("X"); else LOG("-");
		if (!SEC_Mapped(sec)) LOG(" (not mapped)");
		LOG("\n");
	}
#endif
	
	/* 
	 * iterate the sections in the ELF image (forward pass)
	 * until the first writeable section is encountered
	 */
	for (sec = IMG_SecHead(img), lread = SEC_Invalid();
			SEC_Valid(sec) && !SEC_IsWriteable(sec);
			sec = SEC_Next(sec)) {
		/* ignore unmapped sections; optimized branch */
		if (unlikely(!SEC_Mapped(sec)))
			continue;

		/* update the last read-only section */
		lread = sec;
	}
	
	/* read-only sections exist; optimized branch */
	if (likely(SEC_Valid(lread))) {
		/* get the last read-only section
		 * (tagmap collapse optimization)
		 * 
		 * read-only sections are mapped to zero_seg for reducing
		 * address space waste; reading from zero_seg always results
		 * in clear tags
		 */
		
		/* STAB setup */
		for (i = VIRT2STAB(IMG_LowAddress(img));
		i <= VIRT2STAB(SEC_Address(lread) + SEC_Size(lread) - 1); i++)
			STAB[i] = (uint32_t)zero_seg - STAB2VIRT(i);
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": mapping read sections " +
			hexstr(IMG_LowAddress(img)) + "-" + 
			hexstr(SEC_Address(lread) + SEC_Size(lread) - 1) +
			" [" +
			hexstr(STAB[VIRT2STAB(IMG_LowAddress(img))] + 
					IMG_LowAddress(img)) + "-" +
			hexstr(STAB[VIRT2STAB(SEC_Address(lread) +
					SEC_Size(lread) - 1)] +
			       SEC_Address(lread) + SEC_Size(lread) - 1) +
			"]\n");	
#endif
	}
	
	/* writeable sections exist; optimized branch */
	if (likely(SEC_IsWriteable(sec))) {
		/* estimate the length of the tagmap segment */
		slen	= PAGE_ALIGN(IMG_HighAddress(img)) -
				PAGE_ALIGN(SEC_Address(sec)) + PAGE_SZ;
	
		/*
		 * allocate space for a new tagmap
		 * segment by invoking mmap(2)
		 */
		if (unlikely(((tseg = mmap(NULL, slen,
			/* RW- */
			PROT_READ | PROT_WRITE | ~PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED))) {
			
			/* error message */
			LOG(string(__func__) +
				": tagmap segment allocation failed (" +
				string(strerror(errno)) + ")\n");

			/* die */
			libdft_die();
		}
		
		/* STAB setup */	
		for (i = VIRT2STAB(SEC_Address(sec)), j = 0;
			i <= VIRT2STAB(IMG_HighAddress(img)); i++, j++)
			STAB[i] = (uint32_t)tseg - STAB2VIRT(i) + (j * PAGE_SZ);
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": mapping write sections " +
			hexstr(SEC_Address(sec)) + "-" + 
			hexstr(IMG_HighAddress(img)) + " [" +
			hexstr(STAB[VIRT2STAB(SEC_Address(sec))] +
			       SEC_Address(sec)) + "-" +
			hexstr(STAB[VIRT2STAB(IMG_HighAddress(img))] + 
					IMG_HighAddress(img)) + "]\n");
#endif
	}
	
	/* setup the program break */
	if (brk_end == 0) {
		brk_start = brk_end =
			PAGE_ALIGN(IMG_HighAddress(img)) + PAGE_SZ;
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": brk is set at " +
				hexstr(brk_end) + "\n");
#endif
	}

	/* check if the loaded image was the dynamic linker/loader */
	if (IMG_Name(img).compare(DYNLDLNK) == 0 ||
			IMG_Type(img) == IMG_TYPE_STATIC)
		/* set the corresponding flag accordingly */
		dynldlnk_loaded = 1;
}
#else
/*
 * ELF image loading callback
 *
 * capture the loading of an image and setup the tagmap; we
 * allocate a tagmap segment and adjust the STAB accordingly 
 *
 * @img:	image handle
 * @v:		callback value
 */
static void
elf_load(IMG img, VOID *v)
{
	size_t	i, j;	/* STAB iterators		*/
	void*	tseg;	/* tagmap segment		*/
	size_t	slen;	/* segment length 		*/

	/* 
	 * after the dynamic linker/loaded is mapped into
	 * the address space of the process, the image loading
	 * is handled via mmap(2). However, we cannot unregister
	 * elf_load, so we rely on this ugly hack; optimized branch
	 */ 
	if (likely(dynldlnk_loaded == 1))
		return;

#ifdef DEBUG_MEMTRACK
	/* verbose */
	LOG(string(__func__) + ": " +
		IMG_Name(img) + " " +
		hexstr(IMG_LowAddress(img)) + "-" +
		hexstr(IMG_HighAddress(img)) + "\n");
#endif
	
	/* estimate the length of the tagmap segment */
	slen	= PAGE_ALIGN(IMG_HighAddress(img)) -
			PAGE_ALIGN(IMG_LowAddress(img)) + PAGE_SZ;
	
	/*
	 * allocate space for a new tagmap
	 * segment by invoking mmap(2)
	 */
	if (unlikely(((tseg = mmap(NULL, slen,
		/* RW- */
		PROT_READ | PROT_WRITE | ~PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED))) {
			
		/* error message */
		LOG(string(__func__) +
			": tagmap segment allocation failed (" +
			string(strerror(errno)) + ")\n");

		/* die */
		libdft_die();
	}
		
	/* STAB setup */	
	for (i = VIRT2STAB(IMG_LowAddress(img)), j = 0;
		i <= VIRT2STAB(IMG_HighAddress(img)); i++, j++)
		STAB[i] = (uint32_t)tseg - STAB2VIRT(i) + (j * PAGE_SZ);
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": mapping sections " +
			hexstr(IMG_LowAddress(img)) + "-" + 
			hexstr(IMG_HighAddress(img)) + " [" +
			hexstr(STAB[VIRT2STAB(IMG_LowAddress(img))] +
			       IMG_LowAddress(img)) + "-" +
			hexstr(STAB[VIRT2STAB(IMG_HighAddress(img))] + 
					IMG_HighAddress(img)) + "]\n");
#endif
	/* setup the program break */
	if (brk_end == 0) {
		brk_start = brk_end =
			PAGE_ALIGN(IMG_HighAddress(img)) + PAGE_SZ;
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": brk is set at " +
				hexstr(brk_end) + "\n");
#endif
	}

	/* check if the loaded image was the dynamic linker/loader */
	if (IMG_Name(img).compare(DYNLDLNK) == 0 ||
			IMG_Type(img) == IMG_TYPE_STATIC)
		/* set the corresponding flag accordingly */
		dynldlnk_loaded = 1;
}
#endif

/*
 * initialize the STAB/tagmap
 *
 * allocate space for the STAB structure and the three ``hardcoded''
 * tagmap segments: zero_seg (PAGE_SZ), null_seg (PAGE_SZ), and
 * stack_seg (STACK_SZ)
 *
 * returns:	0 on success, 1 on error 
 */
int
tagmap_alloc(void)
{
	size_t	i, j;	/* iterators		*/
			/* STAB size in bytes	*/
	size_t 	len		= STAB_SIZE * sizeof(uint32_t);
			/* vDSO handling */
	size_t	vdso_start, vdso_end;
			/* stack segment */
	void	*stack_seg	= NULL;
		
	/*
	 * allocate space for STAB/zero_seg/null_seg/stack_seg by invoking
	 * mmap(2); if HUGE_TLB is defined, then the mapping is done using
	 * ``huge pages''
	 */
	if (unlikely(
		/* STAB */
		((STAB = (uint32_t *)mmap(NULL, len,
			/* RW- */
			PROT_READ | PROT_WRITE | ~PROT_EXEC,
			MAP_FLAGS, -1, 0)) == MAP_FAILED)		||
		/* stack_seg; zero_seg, null_seg; default segments */
		((stack_seg = mmap(NULL, STACK_SZ,
			/* RW- */
			PROT_READ | PROT_WRITE | ~PROT_EXEC,
			MAP_FLAGS, -1, 0)) == MAP_FAILED)		||
		((zero_seg = mmap(NULL, PAGE_SZ,
			/* R-- */
			PROT_READ | ~PROT_WRITE | ~PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)	||
		((null_seg = mmap(NULL, PAGE_SZ,
			/* --- */
			PROT_NONE, 
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED))) {
		/* error message */
		LOG(string(__func__) +
			": tagmap segment allocation failed (" +
			string(strerror(errno)) + ")\n");
	
		/* failed */
		goto err;
	}
	
	/* setup the STAB */

	/* 
	 * the upper 1G of the address space is mapped to zero_seg;
	 * this is how we handle vsyscall (i.e., reading from a
	 * kernel address will result in always reading clear tags)
	 */
	for (i = VIRT2STAB(KERN_START); i <= VIRT2STAB(KERN_END); i++)
		STAB[i] = (uint32_t)zero_seg - STAB2VIRT(i);

	/* 
	 * the lower 3G of the address space are considered unmapped, and
	 * hence they translate to null_seg (i.e., reading/writing from an
	 * unmapped address will fail)
	 */
	for (i = VIRT2STAB(USER_START); i <= VIRT2STAB(STACK_SEG_ADDR - 1); i++)
		STAB[i] = (uint32_t)null_seg - STAB2VIRT(i);
	
	/* 
	 * stack mapping
	 */
	for (i = VIRT2STAB(STACK_SEG_ADDR), j = 0;
			i <= VIRT2STAB(USER_END); i++, j++)
		STAB[i] = (uint32_t)stack_seg - STAB2VIRT(i) + (j * PAGE_SZ);
	
	/* try to get the vDSO address */
	get_vdso(&vdso_start, &vdso_end);
		
	/* check if we have the vDSO mapped */
	if (likely(vdso_start != 0)) {
		/* STAB setup */	
		for (i = VIRT2STAB(vdso_start);
				i <= VIRT2STAB(vdso_end - 1); i++)
			STAB[i] = (uint32_t)zero_seg - STAB2VIRT(i);
#ifdef DEBUG_MEMTRACK
		/* verbose */
		LOG(string(__func__) + ": mapping vDSO sections " +
			hexstr(vdso_start) + "-" + 
			hexstr(vdso_end - 1) + " [" +
			hexstr(STAB[VIRT2STAB(vdso_start)] +
			       vdso_start) + "-" +
			hexstr(STAB[VIRT2STAB(vdso_end - 1)] + 
					vdso_end - 1) + "]\n");
#endif
	}
	
	/* register the ELF image load callback */
	IMG_AddInstrumentFunction(elf_load, NULL);
	
	/* return with success */
	return 0;

err:	/* error handling */
	
	/* cleanup */
	if (STAB != NULL)
		/* deallocate the STAB space */
		(void)munmap(STAB, len);
	if (zero_seg != NULL)
		/* deallocate the zero segment space */
		(void)munmap(zero_seg, PAGE_SZ);
	if (null_seg != NULL)
		/* deallocate the null segment space */
		(void)munmap(null_seg, PAGE_SZ);
	if (stack_seg != NULL)
		/* deallocate the stack segment space */
		(void)munmap(stack_seg, STACK_SZ);

	/* return with failure */
	return 1;
}

/*
 * tag a byte in the virtual address space
 *
 * @addr:	the virtual address
 * @color:	the tag value
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setb(size_t addr, uint8_t color)
{
	/* tag the byte that corresponds to the given address */
	*(uint8_t *)(addr + STAB[VIRT2STAB(addr)]) = color;
}

/*
 * untag a byte in the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrb(size_t addr)
{
	/* clear the byte that corresponds to the given address */
	*(uint8_t *)(addr + STAB[VIRT2STAB(addr)]) = TAG_ZERO;
}

/*
 * get the tag value of a byte from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
uint8_t
tagmap_getb(size_t addr)
{
	/* get the byte that corresponds to the address */
	return *(uint8_t *)(addr + STAB[VIRT2STAB(addr)]);
}

/*
 * tag a word (i.e., 2 bytes) in the virtual address space
 *
 * @addr:	the virtual address
 * @color:	the tag value
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setw(size_t addr, uint16_t color)
{
	/* tag the bytes that correspond to the addresses of the word */
	*(uint16_t *)(addr + STAB[VIRT2STAB(addr)]) = color;
}

/*
 * untag a word (i.e., 2 bytes) in the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrw(size_t addr)
{
	/* clear the bytes that correspond to the addresses of the word */
	*(uint16_t *)(addr + STAB[VIRT2STAB(addr)]) = TAG_ZERO;
}

/*
 * get the tag value of a word (i.e., 2 bytes) from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
uint16_t
tagmap_getw(size_t addr)
{
	/* get the bytes that correspond to the addresses of the word */
	return *(uint16_t *)(addr + STAB[VIRT2STAB(addr)]);
}

/*
 * tag a long word (i.e., 4 bytes) in the virtual address space
 *
 * @addr:	the virtual address
 * @color:	the tag value
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_setl(size_t addr, uint32_t color)
{
	/* tag the bytes that correspond to the addresses of the long word */
	*(uint32_t *)(addr + STAB[VIRT2STAB(addr)]) = color;
}

/*
 * untag a long word (i.e., 4 bytes) in the virtual address space
 *
 * @addr:	the virtual address
 */
void PIN_FAST_ANALYSIS_CALL
tagmap_clrl(size_t addr)
{
	/* clear the bytes that correspond to the addresses of the long word */
	*(uint32_t *)(addr + STAB[VIRT2STAB(addr)]) = TAG_ZERO;
}

/*
 * get the tag value of a long word (i.e., 4 bytes) from the tagmap
 *
 * @addr:	the virtual address
 *
 * returns:	the tag value (e.g., 0, 1,...)
 */
uint32_t PIN_FAST_ANALYSIS_CALL
tagmap_getl(size_t addr)
{
	/* get the bytes that correspond to the addresses of the long word */
	return *(uint32_t *)(addr + STAB[VIRT2STAB(addr)]);
}

/* tag an arbitrary number of bytes in the virtual address space
 *
 * @addr:	the virtual address
 * @num:	the number of bytes to tag
 * @color:	the tag value
 */
void
tagmap_setn(size_t addr, size_t num, uint8_t color)
{
	/* tag the bytes that correspond to the addresses of the num bytes */
	(void)memset((void *)(addr + STAB[VIRT2STAB(addr)]), color, num);
}

/*
 * untag an arbitrary number of bytes in the virtual address space
 *
 * @addr:	the virtual address
 * @num:	the number of bytes to untag
 */
void
tagmap_clrn(size_t addr, size_t num)
{
	/* clear the bytes that correspond to the addresses of the num bytes */
	(void)memset((void *)(addr + STAB[VIRT2STAB(addr)]), TAG_ZERO, num);
}
