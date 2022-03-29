#ifndef DEBUG
#define DEBUG 0
#endif

#include "include/linux.h"
void *mmap(void *, size_t, int, int, int, off_t);
#if defined(__i386__) || defined(__mips__) || defined(__powerpc__)
#define mmap_privanon(addr,len,prot,flgs) mmap((addr), (len), (prot), MAP_PRIVATE | MAP_ANONYMOUS | (flgs), -1, 0)
#else
void *mmap_privanon(void *, size_t, int, int);
#endif
ssize_t write(int, void const *, size_t);
#if !DEBUG
#define DPRINTF(fmt,args...) 
#else

#if defined(__powerpc__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mflr %0" : "=r"(r_fmt) : : "lr"); \
          dprintf(r_fmt, args); \
     })
#elif defined(__x86_64) || defined(__i386__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("call 0f; .asciz \"" fmt "\"; 0: pop %0" : "=r"(r_fmt)); \
          dprintf(r_fmt, args); \
     })
#elif defined(__arm__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("mov %0,pc; b 0f; \
        .asciz \"" fmt "\"; .balign 4; \
      0: "                                                                               \
              : "=r"(r_fmt)); \
          dprintf(r_fmt, args); \
     })
#elif defined(__mips__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm(".set noreorder; bal L%=j; move %0,$31; .set reorder; \
        .asciz \"" fmt "\"; .balign 4; \
      L%=j: "                                                                               \
              : "=r"(r_fmt) \
              : \
              : "ra"); \
          dprintf(r_fmt, args); \
     })
#endif

static int dprintf(char const *fmt, ...);

#ifdef __arm__
extern unsigned div10(unsigned);
#else
static unsigned div10(unsigned x)
{
     return x / 10u;
}
#endif

static int unsimal(unsigned x, char *ptr, int n)
{
     if (10 <= x) {
          unsigned const q = div10(x);
          x -= 10 * q;
          n = unsimal(q, ptr, n);
     }
     ptr[n] = '0' + x;
     return 1 + n;
}

static int decimal(int x, char *ptr, int n)
{
     if (x < 0) {
          x = -x;
          ptr[n++] = '-';
     }
     return unsimal(x, ptr, n);
}

static int heximal(unsigned long x, char *ptr, int n)
{
     unsigned j = -1 + 2 * sizeof(unsigned long);
     unsigned long m = 0xful << (4 * j);
     for (; j; --j, m >>= 4) {
          if (m & x)
               break;
     }
     for (; m; --j, m >>= 4) {
          unsigned d = 0xf & (x >> (4 * j));
          ptr[n++] = ((10 <= d) ? ('a' - 10) : '0') + d;
     }
     return n;
}

#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_list __builtin_va_list
#define va_start __builtin_va_start

static int dprintf(char const *fmt, ...)
{
     int n = 0;
     char const *literal = 0;
     char buf[24];
     va_list va;
     va_start(va, fmt);
     for (;;) {
          char c = *fmt++;
          if (!c) {
               if (literal) {
                    goto finish;
               }
               break;
          }
          if ('%' != c) {
               if (!literal) {
                    literal = fmt;
               }
               continue;
          }

          if (literal) {
          finish:
               n += write(2, -1 + literal, fmt - literal);
               literal = 0;
               if (!c) {
                    break;
               }
          }
          switch (c = *fmt++) {
               default: {
                    n += write(2, -1 + fmt, 1);
               } break;
               case 0: {
                    goto done;
               } break;
               case 'u': {
                    n += write(2, buf, unsimal(va_arg(va, unsigned), buf, 0));
               } break;
               case 'd': {
                    n += write(2, buf, decimal(va_arg(va, int), buf, 0));
               } break;
               case 'p': {
                    buf[0] = '0';
                    buf[1] = 'x';
                    n += write(2, buf, heximal((unsigned long)va_arg(va, void *), buf, 2));
               } break;
               case 'x': {
                    buf[0] = '0';
                    buf[1] = 'x';
                    n += write(2, buf, heximal(va_arg(va, int), buf, 2));
               } break;
          }
     }
done:
     va_end(va);
     return n;
}
#endif

#define MAX_ELF_HDR 512

typedef struct {
     size_t size;
     char * buf;
} Extent;

static void
#if (ACC_CC_GNUC >= 0x030300) && defined(__i386__)
   __attribute__((__noinline__, __used__, regparm(3), stdcall))
#endif
   xread(Extent *x, char *buf, size_t count)
{
     char * p = x->buf, *q = buf;
     size_t j;
     DPRINTF("xread %%p(%%x %%p) %%p %%x\\n", x, x->size, x->buf, buf, count);
     if (x->size < count) {
          exit(127);
     }
     for (j = count; 0 != j--; ++p, ++q) {
          *q = *p;
     }
     x->buf += count;
     x->size -= count;
}

#if !DEBUG
#define ERR_LAB \
     error: \
     exit(127);
#define err_exit(a) goto error
#else
#define ERR_LAB 

extern void my_bkpt(int, ...);

static void __attribute__((__noreturn__)) err_exit(int a)
{
     DPRINTF("err_exit %%x\\n", a);
     (void)a;
#if defined(__powerpc__)
     my_bkpt(a);
#endif
     exit(127);
}
#endif

static void *do_brk(void *addr)
{
     return brk(addr);
}

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8, unsigned ftid);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, size_t *, unsigned);

static void unpackExtent(Extent *const xi, Extent *const xo, f_expand *const f_exp, f_unfilter *f_unf)
{
     DPRINTF("unpackExtent in=%%p(%%x %%p)  out=%%p(%%x %%p)  %%p %%p\\n",
             xi,
             xi->size,
             xi->buf,
             xo,
             xo->size,
             xo->buf,
             f_exp,
             f_unf);
     while (xo->size) {
          struct b_info h;

          xread(xi, (char *)&h, sizeof(h));
          if (h.sz_unc == 0) {
               if (h.sz_cpr != UPX_MAGIC_LE32)
                    err_exit(2);
               if (xi->size != 0)
                    err_exit(3);
               break;
          }
          if (h.sz_cpr <= 0) {
               err_exit(4);
               ERR_LAB
          }
          if (h.sz_cpr > h.sz_unc || h.sz_unc > xo->size) {
               DPRINTF("sz_cpr=%%x  sz_unc=%%x  xo->size=%%x\\n", h.sz_cpr, h.sz_unc, xo->size);
               err_exit(5);
          }

          if (h.sz_cpr < h.sz_unc) {
               size_t out_len = h.sz_unc;
               int const j = (*f_exp)((unsigned char *)xi->buf,
                                      h.sz_cpr,
                                      (unsigned char *)xo->buf,
                                      &out_len,
#if defined(__i386__)
                                      *(int *)(void *)&h.b_method
#else
                                      h.b_method
#endif
               );
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);

               if (h.b_ftid != 0 && f_unf && ((512 < out_len) || (xo->size == (unsigned)h.sz_unc))) {
                    (*f_unf)((unsigned char *)xo->buf, out_len, h.b_cto8, h.b_ftid);
               }
               xi->buf += h.sz_cpr;
               xi->size -= h.sz_cpr;
          }
          else {
               xread(xi, xo->buf, h.sz_cpr);
          }
          xo->buf += h.sz_unc;
          xo->size -= h.sz_unc;
     }
}

#if defined(__i386__)

static void *make_hatch_x86(Elf32_Phdr const *const phdr, ptrdiff_t reloc)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, 0);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
              (phdr->p_memsz == phdr->p_filesz && 4 <= (~PAGE_MASK & -(int)hatch)))

             || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr + reloc)->e_ident[12])), (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {

               unsigned escape = 0xc36180cd;

               if (*(volatile unsigned *)hatch != escape) {
                    *hatch = escape;
               }
               if (xprot) {
                    mprotect(hatch, 1 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
               DPRINTF(" hatch at %%p\\n", hatch);
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#elif defined(__arm__)
extern unsigned get_sys_munmap(void);

static void *make_hatch_arm(Elf32_Phdr const *const phdr, ptrdiff_t reloc)
{
     unsigned const sys_munmap = get_sys_munmap();
     unsigned xprot = 0;
     unsigned * hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, sys_munmap);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(~3u & (3 + phdr->p_memsz + phdr->p_vaddr + reloc))),
              (phdr->p_memsz == phdr->p_filesz && (2 * 4) <= (~PAGE_MASK & -(int)hatch)))

             || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr + reloc)->e_ident[8])), (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = sys_munmap;
               hatch[1] = 0xe1a0f00e;
               __clear_cache(&hatch[0], &hatch[2]);
               if (xprot) {
                    mprotect(hatch, 2 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#elif defined(__mips__)
static void *make_hatch_mips(Elf32_Phdr const *const phdr, ptrdiff_t reloc, unsigned const frag_mask)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, frag_mask);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
              (phdr->p_memsz == phdr->p_filesz && (3 * 4) <= (frag_mask & -(int)hatch)))

             || (xprot = 1, hatch = mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = 0x0000000c;
#define RS(r) ((037 & (r)) << 21)
#define JR 010
               hatch[1] = RS(30) | JR;
               hatch[2] = 0x00000000;
               if (xprot) {
                    mprotect(hatch, 3 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#elif defined(__powerpc__)
static void *make_hatch_ppc32(Elf32_Phdr const *const phdr, ptrdiff_t reloc, unsigned const frag_mask)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, frag_mask);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
              (phdr->p_memsz == phdr->p_filesz && (2 * 4) <= (frag_mask & -(int)hatch)))

             || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr + reloc)->e_ident[8])), (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = 0x44000002;
               hatch[1] = 0x4e800020;
               if (xprot) {
                    mprotect(hatch, 2 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#endif

static void
#if defined(__i386__)
   __attribute__((regparm(2), stdcall))
#endif
   upx_bzero(char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero

static Elf32_auxv_t *
#if defined(__i386__)
   __attribute__((regparm(2), stdcall))
#endif
   auxv_find(Elf32_auxv_t *av, unsigned const type)
{
     Elf32_auxv_t *avail = 0;
     if (av
#if defined(__i386__)
         && 0 == (1 & (int)av)
#endif
     ) {
          for (;; ++av) {
               if (av->a_type == type)
                    return av;
               if (av->a_type == AT_IGNORE)
                    avail = av;
          }
          if (0 != avail && AT_NULL != type) {
               av = avail;
               av->a_type = type;
               return av;
          }
     }
     return 0;
}

static void
#if defined(__i386__)
   __attribute__((regparm(3), stdcall))
#endif
   auxv_up(Elf32_auxv_t *av, unsigned const type, unsigned const value)
{
     DPRINTF("auxv_up  %%p %%x %%x\\n", av, type, value);
     av = auxv_find(av, type);
     if (av) {
          av->a_un.a_val = value;
     }
}

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

#if defined(__powerpc__)
extern size_t get_page_mask(void);
#elif defined(__mips__)

#else
size_t get_page_mask(void)
{
     return PAGE_MASK;
}
#endif

static ptrdiff_t
#if defined(__i386__)
   __attribute__((regparm(3), stdcall))
#endif
   xfind_pages(unsigned mflags,
               Elf32_Phdr const *phdr,
               int phnum,
               Elf32_Addr *const p_brk
#if defined(__mips__)
               ,
               size_t const page_mask
#endif
   )
{
#if !defined(__mips__)
     size_t const page_mask = get_page_mask();
#endif
     Elf32_Addr lo = ~0, hi = 0, addr = 0;
     DPRINTF("xfind_pages  %%x  %%p  %%d  %%p\\n", mflags, phdr, phnum, p_brk);
     for (; --phnum >= 0; ++phdr)
          if (PT_LOAD == phdr->p_type
#if defined(__arm__)
              && phdr->p_memsz
#endif
          ) {
               if (phdr->p_vaddr < lo) {
                    lo = phdr->p_vaddr;
               }
               if (hi < (phdr->p_memsz + phdr->p_vaddr)) {
                    hi = phdr->p_memsz + phdr->p_vaddr;
               }
          }
     lo -= ~page_mask & lo;
     hi = page_mask & (hi - lo - page_mask - 1);
     DPRINTF("  addr=%%p  lo=%%p  hi=%%p\\n", addr, lo, hi);
     addr = (Elf32_Addr)mmap_privanon((void *)lo, hi, PROT_NONE, mflags);
     DPRINTF("  addr=%%p\\n", addr);
     *p_brk = hi + addr;
     return (ptrdiff_t)addr - lo;
}

static Elf32_Addr do_xmap(int const fdi,
                          Elf32_Ehdr const *const ehdr,
                          Extent *const xi,
                          Elf32_auxv_t *const av,
                          unsigned *const p_reloc,
                          f_unfilter *const f_unf
#if defined(__mips__)
                          ,
                          size_t const page_mask
#endif
)
{
#if defined(__mips__)
     unsigned const frag_mask = ~page_mask;
#else
     unsigned const frag_mask = ~get_page_mask();
#endif
     Elf32_Phdr const *phdr = (Elf32_Phdr const *)(void const *)(ehdr->e_phoff + (char const *)ehdr);
     Elf32_Addr v_brk;
     Elf32_Addr reloc;
     if (xi) {

          Elf32_Addr ehdr0 = *p_reloc;
          Elf32_Phdr *phdr0 = (Elf32_Phdr *)(1 + (Elf32_Ehdr *)ehdr0);

          if (ET_EXEC == ((Elf32_Ehdr *)ehdr0)->e_type) {
               ehdr0 = phdr0[0].p_vaddr;
               reloc = 0;
          }
          else {
               ehdr0 -= phdr0[1].p_vaddr;
               reloc = ehdr0;
          }
          v_brk = phdr0->p_memsz + ehdr0;
          DPRINTF("do_xmap munmap [%%p, +%%x)\n", ehdr0, phdr0->p_memsz);
          munmap((void *)ehdr0, phdr0->p_memsz);
     }
     else {
          reloc = xfind_pages(((ET_DYN != ehdr->e_type) ? MAP_FIXED : 0),
                              phdr,
                              ehdr->e_phnum,
                              &v_brk
#if defined(__mips__)
                              ,
                              page_mask
#endif
          );
     }

#if DEBUG && !defined(__mips__)
     size_t const page_mask = 0;
#endif
     DPRINTF("do_xmap  fdi=%%x  ehdr=%%p  xi=%%p(%%x %%p)\\n"
             "  av=%%p  page_mask=%%p  reloc=%%p  p_reloc=%%p/%%p  f_unf=%%p\\n",
             fdi,
             ehdr,
             xi,
             (xi ? xi->size : 0),
             (xi ? xi->buf : 0),
             av,
             page_mask,
             reloc,
             p_reloc,
             *p_reloc,
             f_unf);
     int j;
     for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
          if (xi && PT_PHDR == phdr->p_type) {
               auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc);
          }
          else if (PT_LOAD == phdr->p_type
#if defined(__arm__)
                   && phdr->p_memsz
#endif
          ) {
               if (xi && !phdr->p_offset) {

                    auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc + ehdr->e_phoff);
                    auxv_up(av, AT_PHNUM, ehdr->e_phnum);
                    auxv_up(av, AT_PHENT, ehdr->e_phentsize);
               }
               unsigned const prot = PF_TO_PROT(phdr->p_flags);
               Extent xo;
               size_t mlen = xo.size = phdr->p_filesz;
               char * addr = xo.buf = (char *)(phdr->p_vaddr + reloc);
               char *const haddr = phdr->p_memsz + addr;
               size_t frag = (int)addr & frag_mask;
               mlen += frag;
               addr -= frag;
               DPRINTF(
                  "  phdr type=%%x  offset=%%x  vaddr=%%x  paddr=%%x  filesz=%%x  memsz=%%x  flags=%%x  align=%%x\\n",
                  phdr->p_type,
                  phdr->p_offset,
                  phdr->p_vaddr,
                  phdr->p_paddr,
                  phdr->p_filesz,
                  phdr->p_memsz,
                  phdr->p_flags,
                  phdr->p_align);
               DPRINTF("  addr=%%x  mlen=%%x  frag=%%x  prot=%%x\\n", addr, mlen, frag, prot);

#if defined(__i386__)

#define LEN_OVER 3
#else
#define LEN_OVER 0
#endif

               if (xi) {
                    if (addr != mmap_privanon(addr, LEN_OVER + mlen, PROT_WRITE | PROT_READ, MAP_FIXED))
                         err_exit(6);
                    unpackExtent(xi, &xo, (f_expand *)fdi, ((PROT_EXEC & prot) ? f_unf : 0));
               }
               else {
                    if (addr != mmap(addr, mlen, prot, MAP_FIXED | MAP_PRIVATE, fdi, phdr->p_offset - frag))
                         err_exit(8);
               }

               frag = (-mlen) & frag_mask;
               if (PROT_WRITE & prot) {
                    bzero(mlen + addr, frag);
               }
               if (xi) {
#if defined(__i386__)
                    void *const hatch = make_hatch_x86(phdr, reloc);
                    if (0 != hatch) {

                         auxv_up((Elf32_auxv_t *)(~1 & (int)av), AT_NULL, (unsigned)hatch);
                    }
#elif defined(__arm__)
                    void *const hatch = make_hatch_arm(phdr, reloc);
                    if (0 != hatch) {
                         auxv_up(av, AT_NULL, (unsigned)hatch);
                    }
#elif defined(__mips__)
                    void *const hatch = make_hatch_mips(phdr, reloc, frag_mask);
                    if (0 != hatch) {
                         auxv_up(av, AT_NULL, (unsigned)hatch);
                    }
#elif defined(__powerpc__)
                    void *const hatch = make_hatch_ppc32(phdr, reloc, frag_mask);
                    if (0 != hatch) {
                         auxv_up(av, AT_NULL, (unsigned)hatch);
                    }
#endif
                    if (0 != mprotect(addr, mlen, prot)) {
                         err_exit(10);
                         ERR_LAB
                    }
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    DPRINTF("addr=%%p  haddr=%%p\\n", addr, haddr);
                    if (addr != mmap_privanon(addr, haddr - addr, prot, MAP_FIXED)) {
                         for (;;)
                              ;
                         err_exit(9);
                    }
               }
#if defined(__i386__)
               else if (xi) {
                    mlen = frag_mask & (3 + mlen);
                    if (mlen <= 3) {
                         munmap(addr, mlen);
                    }
               }
#endif
          }
     if (xi && ET_DYN != ehdr->e_type) {

          do_brk((void *)v_brk);
     }
     if (0 != p_reloc) {
          *p_reloc = reloc;
     }
     return ehdr->e_entry + reloc;
}

#if 0 && defined(__arm__)
static uint32_t ascii5(char *p, uint32_t v, unsigned n)
{
    do {
        unsigned char d = (0x1f & v) + 'A';
        if ('Z' < d) d += '0' - (1+ 'Z');
        *--p = d;
        v >>= 5;
    } while (--n > 0);
    return v;
}
#endif
#if defined(__mips__)
void *upx_main(struct b_info const *const bi,
               size_t const sz_compressed,
               Elf32_Ehdr *const ehdr,
               Elf32_auxv_t *const av,
               f_expand *const f_exp,
               f_unfilter *const f_unf,
               Elf32_Addr const elfaddr,
               size_t const page_mask) __asm__("upx_main");
void *upx_main(struct b_info const *const bi,
               size_t const sz_compressed,
               Elf32_Ehdr *const ehdr,
               Elf32_auxv_t *const av,
               f_expand *const f_exp,
               f_unfilter *const f_unf,
               Elf32_Addr const elfaddr,
               size_t const page_mask)

#elif defined(__powerpc__)
void *upx_main(struct b_info const *const bi,
               size_t const sz_compressed,
               Elf32_Ehdr *const ehdr,
               Elf32_auxv_t *const av,
               f_expand *const f_exp,
               f_unfilter *const f_unf,
               Elf32_Addr elfaddr) __asm__("upx_main");
void *upx_main(struct b_info const *const bi,
               size_t const sz_compressed,
               Elf32_Ehdr *const ehdr,
               Elf32_auxv_t *const av,
               f_expand *const f_exp,
               f_unfilter *const f_unf,
               Elf32_Addr elfaddr)

#else
void *upx_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *const f_exp,
               f_unfilter * f_unfilter,
               Extent xo,
               Extent xi,
               Elf32_Addr const volatile elfaddr) __asm__("upx_main");
void *upx_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *const f_exp,
               f_unfilter * f_unf,
               Extent xo,
               Extent xi,
               Elf32_Addr const volatile elfaddr)
#endif
{
#if defined(__i386__)
     f_unf = (0xeb != *(unsigned char *)f_exp) ? 0 : (f_unfilter *)(2 + (long)f_exp);
#endif

#if !defined(__mips__) && !defined(__powerpc__)
     Elf32_Ehdr *const ehdr = (Elf32_Ehdr *)(void *)xo.buf;

     size_t const sz_first = xi.size;
#endif

#if defined(__powerpc__)
     size_t const sz_first = sizeof(*bi) + bi->sz_cpr;
     Extent xo, xi;
     xo.buf = (char *)ehdr;
     xo.size = bi->sz_unc;
     xi.buf = CONST_CAST(char *, bi);
     xi.size = sz_compressed;
#endif

#if defined(__mips__)
     Extent xo, xi, xj;
     xo.buf = (char *)ehdr;
     xo.size = bi->sz_unc;
     xi.buf = CONST_CAST(char *, bi);
     xi.size = sz_compressed;
     xj.buf = CONST_CAST(char *, bi);
     xj.size = sizeof(*bi) + bi->sz_cpr;
#endif

     DPRINTF("upx_main av=%%p  szc=%%x  f_exp=%%p  f_unf=%%p  "
             "  xo=%%p(%%x %%p)  xi=%%p(%%x %%p)  elfaddr=%%x\\n",
             av,
             sz_compressed,
             f_exp,
             f_unf,
             &xo,
             xo.size,
             xo.buf,
             &xi,
             xi.size,
             xi.buf,
             elfaddr);

#if defined(__mips__)

     unpackExtent(&xj, &xo, f_exp, 0);
#else

     unpackExtent(&xi, &xo, f_exp, 0);

     xi.buf -= sz_first;
     xi.size = sz_compressed;
#endif

     Elf32_Addr reloc = elfaddr;
     DPRINTF("upx_main1  .e_entry=%%p  reloc=%%p\\n", ehdr->e_entry, reloc);
     Elf32_Phdr *phdr = (Elf32_Phdr *)(1 + ehdr);

     Elf32_Addr entry = do_xmap((int)f_exp,
                                ehdr,
                                &xi,
                                av,
                                &reloc,
                                f_unf
#if defined(__mips__)
                                ,
                                page_mask
#endif
     );
     DPRINTF("upx_main2  entry=%%p  reloc=%%p\\n", entry, reloc);
     auxv_up(av, AT_ENTRY, entry);

     {
          int j;
          for (j = 0, phdr = (Elf32_Phdr *)(1 + ehdr); j < ehdr->e_phnum; ++phdr, ++j)
               if (PT_INTERP == phdr->p_type) {
                    int const fdi = open(reloc + (char const *)phdr->p_vaddr, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
                    if (MAX_ELF_HDR != read(fdi, (void *)ehdr, MAX_ELF_HDR)) {
                         ERR_LAB
                         err_exit(19);
                    }
                    entry = do_xmap(fdi,
                                    ehdr,
                                    0,
                                    av,
                                    &reloc,
                                    0
#if defined(__mips__)
                                    ,
                                    page_mask
#endif
                    );
                    DPRINTF("upx_main3  entry=%%p  reloc=%%p\\n", entry, reloc);
                    auxv_up(av, AT_BASE, reloc);
                    close(fdi);
                    break;
               }
     }

     return (void *)entry;
}
