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

#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include "pin.H"

#define PAGE_SHIFT	12		/* page alignment offset (bits) */
#define PAGE_SZ		(1U << PAGE_SHIFT)	/* page size;
					   4 KB in x86 (i386) Linux	*/
#define STACK_SZ	(PAGE_SZ << 11)		/* stack size;
					   8 MB in x86 (i386) Linux	*/
#define STAB_SIZE	(1U << 20)	/* 1 M items; 4GB / PAGE_SZ	*/
#define USER_START	0x00000000U	/* userland starting address	*/
#define USER_END	0xBFFFFFFFU	/* userland ending address	*/
#define KERN_START	0xC0000000U	/* kernel starting address	*/
#define KERN_END	0xFFFFFFFFU	/* kernel ending address	*/
#define STACK_SEG_ADDR	(KERN_START - STACK_SZ)	/* 0xBF800000		*/

/* maximum size on an entry in /proc/<pid>/maps */
#define MAPS_ENTRY_MAX	128
/* vDSO string in /proc/<pid>/maps */
#define VDSO_STR	"[vdso]"
/* dynamic linker/loader					*/
#define	DYNLDLNK	"/lib/ld-linux.so.2"

/* get the offset on stlb given a virtual address		*/
#define VIRT2STAB(vaddr)	((vaddr) >> PAGE_SHIFT)
/* get the virtual address (page aligned) given an stlb offset	*/
#define STAB2VIRT(indx)		((indx) << PAGE_SHIFT)
/* page align a virtual address					*/
#define PAGE_ALIGN(vaddr)	((vaddr) & 0xFFFFF000)

/* tag values */
#define	TAG_ZERO	0x0U		/* clean		*/
#define	TAG_ALL8	0xFFU		/* all colors; 1 byte	*/


/* tagmap API */
int					tagmap_alloc(void);
void		PIN_FAST_ANALYSIS_CALL	tagmap_setb(size_t, uint8_t);
void		PIN_FAST_ANALYSIS_CALL	tagmap_clrb(size_t);
uint8_t					tagmap_getb(size_t);
void		PIN_FAST_ANALYSIS_CALL	tagmap_setw(size_t, uint16_t);
void		PIN_FAST_ANALYSIS_CALL	tagmap_clrw(size_t);
uint16_t				tagmap_getw(size_t);
void		PIN_FAST_ANALYSIS_CALL	tagmap_setl(size_t, uint32_t);
void		PIN_FAST_ANALYSIS_CALL	tagmap_clrl(size_t);
uint32_t	PIN_FAST_ANALYSIS_CALL	tagmap_getl(size_t);
void					tagmap_setn(size_t, size_t, uint8_t);
void					tagmap_clrn(size_t, size_t);

#endif /* __TAGMAP_H__ */
