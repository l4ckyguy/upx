#include "include/linux.h"
#define MAX_ELF_HDR 512

struct Extent {
     size_t size;
     char * buf;
};

static void
#if (ACC_CC_GNUC >= 0x030300)
   __attribute__((__noinline__, __used__, regparm(3), stdcall))
#endif
   xread(struct Extent *x, char *buf, size_t count)
{
     char * p = x->buf, *q = buf;
     size_t j;
     if (x->size < count) {
          exit(127);
     }
     for (j = count; 0 != j--; ++p, ++q) {
          *q = *p;
     }
     x->buf += count;
     x->size -= count;
}

#if 1
#define ERR_LAB \
     error: \
     exit(127);
#define err_exit(a) goto error
#else
#define ERR_LAB 
static void err_exit(int a)
{
     (void)a;
     exit(127);
}
#endif

static void *do_brk(void *addr)
{
     return brk(addr);
}

extern char *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, nrv_uint *, int method);

static void unpackExtent(struct Extent *const xi,
                         struct Extent *const xo,
                         f_expand *(*get_fexp(int)),
                         f_unfilter *(*get_funf(int)))
{
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
               err_exit(5);
          }

          if (h.sz_cpr < h.sz_unc) {
               nrv_uint out_len = h.sz_unc;
               int const j = (*get_fexp(h.b_method))((unsigned char *)xi->buf,
                                                     h.sz_cpr,
                                                     (unsigned char *)xo->buf,
                                                     &out_len,
                                                     *(int *)(void *)&h.b_method);
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);
               if (h.b_ftid != 0) {
                    (*get_funf(h.b_ftid))((unsigned char *)xo->buf, out_len, h.b_cto8);
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

static void *make_hatch(Elf32_Phdr const *const phdr)
{
     unsigned *hatch = 0;
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr)),
               (phdr->p_memsz == phdr->p_filesz && 4 <= (~PAGE_MASK & -(int)hatch)))

              || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr)->e_ident[12])), (phdr->p_offset == 0))) {

               unsigned escape = 0xc36180cd;

               if (*(volatile unsigned *)hatch != escape) {
                    *hatch = escape;
               }
          }
     }
     return hatch;
}

static void __attribute__((regparm(2), stdcall)) upx_bzero(char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero

static void __attribute__((regparm(3), stdcall)) auxv_up(Elf32_auxv_t *av, unsigned const type, unsigned const value)
{
     if (av && 0 == (1 & (int)av))
          for (;; ++av) {
               if (av->a_type == type || (av->a_type == AT_IGNORE && type != AT_NULL)) {
                    av->a_type = type;
                    av->a_un.a_val = value;
                    return;
               }
               if (av->a_type == AT_NULL) {

                    return;
               }
          }
}

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

static unsigned long __attribute__((regparm(3), stdcall))
xfind_pages(unsigned mflags, Elf32_Phdr const *phdr, int phnum, char **const p_brk)
{
     size_t lo = ~0, hi = 0, szlo = 0;
     char * addr;
     mflags += MAP_PRIVATE | MAP_ANONYMOUS;
     for (; --phnum >= 0; ++phdr)
          if (PT_LOAD == phdr->p_type) {
               if (phdr->p_vaddr < lo) {
                    lo = phdr->p_vaddr;
                    szlo = phdr->p_filesz;
               }
               if (hi < (phdr->p_memsz + phdr->p_vaddr)) {
                    hi = phdr->p_memsz + phdr->p_vaddr;
               }
          }
     szlo += ~PAGE_MASK & lo;
     lo -= ~PAGE_MASK & lo;
     hi = PAGE_MASK & (hi - lo - PAGE_MASK - 1);
     szlo = PAGE_MASK & (szlo - PAGE_MASK - 1);
     addr = mmap((void *)lo, hi, PROT_READ | PROT_WRITE | PROT_EXEC, mflags, 0, 0);
     *p_brk = hi + addr;
     munmap(szlo + addr, hi - szlo);
     return (unsigned long)addr - lo;
}

static Elf32_Addr do_xmap(int const fdi,
                          f_unfilter *(*get_funf(int)),
                          Elf32_Ehdr const *const ehdr,
                          struct Extent *const xi,
                          Elf32_auxv_t *const av)
{
     f_expand *(*(*get_fexp)(int));
     Elf32_Phdr const * phdr = (Elf32_Phdr const *)(ehdr->e_phoff + (char const *)ehdr);
     char * v_brk;
     unsigned long const reloc = xfind_pages(((ET_DYN != ehdr->e_type) ? MAP_FIXED : 0), phdr, ehdr->e_phnum, &v_brk);
     int j;

     *(int *)(void *)&get_fexp = fdi;
     for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
          if (PT_PHDR == phdr->p_type) {
               auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc);
          }
          else if (PT_LOAD == phdr->p_type) {
               unsigned const prot = PF_TO_PROT(phdr->p_flags);
               struct Extent xo;
               size_t mlen = xo.size = phdr->p_filesz;
               char * addr = xo.buf = (char *)phdr->p_vaddr;
               char * haddr = phdr->p_memsz + addr;
               size_t frag = (int)addr & ~PAGE_MASK;
               mlen += frag;
               addr -= frag;
               addr += reloc;
               haddr += reloc;

               if (addr
                   != mmap(addr,
                           mlen + (xi ? 3 : 0),
                           PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_PRIVATE | (xi ? MAP_ANONYMOUS : 0),
                           fdi,
                           phdr->p_offset - frag)) {
                    err_exit(8);
               }
               if (xi) {
                    unpackExtent(xi, &xo, get_fexp, get_funf);
               }
               bzero(addr, frag);
               frag = (-mlen) & ~PAGE_MASK;
               bzero(mlen + addr, frag);
               if (xi) {
                    void *const hatch = make_hatch(phdr);
                    if (0 != hatch) {

                         auxv_up((Elf32_auxv_t *)(~1 & (int)av), AT_NULL, (unsigned)hatch);
                    }
               }
               if (0 != mprotect(addr, mlen, prot)) {
                    err_exit(10);
                    ERR_LAB
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    if (addr != mmap(addr, haddr - addr, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)) {
                         err_exit(9);
                    }
               }
               else if (xi) {
                    mlen = ~PAGE_MASK & (3 + mlen);
                    if (mlen <= 3) {
                         munmap(addr, mlen);
                    }
               }
          }
     if (!xi) {
          if (0 != close((int)fdi)) {
               err_exit(11);
          }
     }
     else {
          if (ET_DYN != ehdr->e_type) {

               do_brk(v_brk);
          }
     }
     return ehdr->e_entry + reloc;
}
void *pti_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *(*get_fexp(int)),
               Elf32_Ehdr *const ehdr,
               struct Extent xo,
               struct Extent xi,
               f_unfilter *(*get_funf(int))) __asm__("pti_main");

void *pti_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *(*get_fexp(int)),
               Elf32_Ehdr *const ehdr,
               struct Extent xo,
               struct Extent xi,
               f_unfilter *(*get_funf(int)))
{
     Elf32_Phdr const *phdr = (Elf32_Phdr const *)(1 + ehdr);
     Elf32_Addr entry;

     size_t const sz_pckhdrs = xi.size;

     unpackExtent(&xi, &xo, get_fexp, get_funf);

     xi.buf -= sz_pckhdrs;
     xi.size = sz_compressed;

     auxv_up(av, AT_PHDR, (unsigned)(1 + (Elf32_Ehdr *)phdr->p_vaddr));
     auxv_up(av, AT_PHENT, ehdr->e_phentsize);
     auxv_up(av, AT_PHNUM, ehdr->e_phnum);

     auxv_up(av, AT_ENTRY, (unsigned)ehdr->e_entry);
     entry = do_xmap((int)get_fexp, get_funf, ehdr, &xi, av);

     {
          int j;
          for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
               if (PT_INTERP == phdr->p_type) {
                    char const *const iname = (char const *)phdr->p_vaddr;
                    int const fdi = open(iname, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
                    if (MAX_ELF_HDR != read(fdi, (void *)ehdr, MAX_ELF_HDR)) {
                         ERR_LAB
                         err_exit(19);
                    }
                    entry = do_xmap(fdi, 0, ehdr, 0, 0);
                    break;
               }
     }

     return (void *)entry;
}
