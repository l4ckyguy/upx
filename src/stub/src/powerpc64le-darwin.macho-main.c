#define __WORDSIZE 64
#include "include/darwin.h"
typedef struct {
     size_t size;
     char * buf;
} Extent;

static void xread(Extent *x, char *buf, size_t count)
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

struct l_info {
     unsigned l_checksum;
     unsigned l_magic;
     unsigned short l_lsize;
     unsigned char l_version;
     unsigned char l_format;
};
struct p_info {
     unsigned p_progid;
     unsigned p_filesize;
     unsigned p_blocksize;
};

struct b_info {
     unsigned sz_unc;
     unsigned sz_cpr;
     unsigned char b_method;
     unsigned char b_ftid;
     unsigned char b_cto8;
     unsigned char b_unused;
};

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8, unsigned ftid);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, nrv_uint *, unsigned);

static void unpackExtent(Extent *const xi, Extent *const xo, f_expand *const f_decompress, f_unfilter *f_unf)
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
               int const j = (*f_decompress)(
                  (const unsigned char *)xi->buf, h.sz_cpr, (unsigned char *)xo->buf, &out_len, h.b_method);
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);
               if (h.b_ftid != 0 && f_unf) {
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

static void upx_bzero(char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

typedef struct {
     unsigned magic;
     unsigned nfat_arch;
} Fat_header;
typedef struct {
     unsigned cputype;
     unsigned cpusubtype;
     unsigned offset;
     unsigned size;
     unsigned align;
} Fat_arch;
enum e8 { FAT_MAGIC = 0xcafebabe };
enum e9 { CPU_TYPE_I386 = 7, CPU_TYPE_POWERPC = 0x00000012, CPU_TYPE_POWERPC64 = 0x01000012 };

typedef struct {
     unsigned magic;
     unsigned cputype;
     unsigned cpysubtype;
     unsigned filetype;
     unsigned ncmds;
     unsigned sizeofcmds;
     unsigned flags;
} Mach_header;
enum e0 { MH_MAGIC = 0xfeedface };
enum e2 { MH_EXECUTE = 2 };
enum e3 { MH_NOUNDEFS = 1 };

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
} Mach_load_command;
enum e4 { LC_SEGMENT = 0x1, LC_THREAD = 0x4, LC_UNIXTHREAD = 0x5, LC_LOAD_DYLINKER = 0xe };

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     char segname[16];
     unsigned vmaddr;
     unsigned vmsize;
     unsigned fileoff;
     unsigned filesize;
     unsigned maxprot;
     unsigned initprot;
     unsigned nsects;
     unsigned flags;
} Mach_segment_command;
enum e5 { VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4 };

typedef struct {
     unsigned srr0;
     unsigned srr1;
     unsigned r0, r1, r2, r3, r4, r5, r6, r7;
     unsigned r8, r9, r10, r11, r12, r13, r14, r15;
     unsigned r16, r17, r18, r19, r20, r21, r22, r23;
     unsigned r24, r25, r26, r27, r28, r29, r30, r31;

     unsigned cr;
     unsigned xer;
     unsigned lr;
     unsigned ctr;
     unsigned mq;

     unsigned vrsave;
} Mach_ppcle_thread_state64;

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     unsigned flavor;
     unsigned count;
     Mach_ppcle_thread_state64 state;
} Mach_thread_command;
enum e6 { PPC_THREAD_STATE = 1 };
enum e7 { PPC_THREAD_STATE_COUNT = sizeof(Mach_ppcle_thread_state64) / 4 };

typedef union {
     unsigned long offset;
     char * ptr;
} Mach_lc_str;

#define MAP_FIXED 0x10
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x1000
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4

extern char *mmap(char *, size_t, unsigned, unsigned, int, off_t_upx_stub);
ssize_t pread(int, void *, size_t, off_t_upx_stub);

static Mach_ppcle_thread_state64 const *do_xmap(Mach_header const *const mhdr,
                                                off_t_upx_stub const fat_offset,
                                                Extent *const xi,
                                                int const fdi,
                                                Mach_header ** mhdrpp,
                                                f_expand *const f_decompress,
                                                f_unfilter *const f_unf)
{
     Mach_segment_command const * sc = (Mach_segment_command const *)(1 + mhdr);
     Mach_ppcle_thread_state64 const *entry = 0;
     unsigned j;

     for (j = 0; j < mhdr->ncmds;
          ++j, (sc = (Mach_segment_command const *)(void const *)(sc->cmdsize + (char const *)sc)))
          if (LC_SEGMENT == sc->cmd) {
               Extent xo;
               size_t mlen = xo.size = sc->filesize;
               char * addr = xo.buf = (char *)(long)sc->vmaddr;
               char * haddr = sc->vmsize + addr;
               size_t frag = (long)addr & ~PAGE_MASK;
               addr -= frag;
               mlen += frag;

               if (0 != mlen
                   && addr
                         != mmap(addr,
                                 mlen,
                                 VM_PROT_READ | VM_PROT_WRITE,
                                 MAP_FIXED | MAP_PRIVATE | ((xi || 0 == sc->filesize) ? MAP_ANON : 0),
                                 ((0 == sc->filesize) ? -1 : fdi),
                                 sc->fileoff + fat_offset)) {
                    err_exit(8);
               }
               if (xi && 0 != sc->filesize) {
                    if (0 == sc->fileoff) {
                         *mhdrpp = (Mach_header *)(void *)addr;
                    }
                    unpackExtent(xi, &xo, f_decompress, f_unf);
               }

               frag = (-mlen) & ~PAGE_MASK;
               bzero(mlen + addr, frag);
               if (0 != mlen && 0 != mprotect(addr, mlen, sc->initprot)) {
                    err_exit(10);
                    ERR_LAB
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    if (addr != mmap(addr, haddr - addr, sc->initprot, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0)) {
                         err_exit(9);
                    }
               }
          }
          else if (LC_UNIXTHREAD == sc->cmd || LC_THREAD == sc->cmd) {
               Mach_thread_command const *const thrc = (Mach_thread_command const *)sc;
               if (PPC_THREAD_STATE == thrc->flavor && PPC_THREAD_STATE_COUNT == thrc->count) {
                    entry = &thrc->state;
               }
          }
     return entry;
}

Mach_ppcle_thread_state64 const *upx_main(struct l_info const *const li,
                                          size_t volatile sz_compressed,
                                          Mach_header *const mhdr,
                                          size_t const sz_mhdr,
                                          f_expand *const f_decompress,
                                          f_unfilter *const f_unf,
                                          Mach_header **const mhdrpp)
{
     Mach_ppcle_thread_state64 const *entry;
     off_t_upx_stub fat_offset = 0;
     Extent xi, xo, xi0;
     xi.buf = CONST_CAST(char *, 1 + (struct p_info const *)(1 + li));
     xi.size = sz_compressed - (sizeof(struct l_info) + sizeof(struct p_info));
     xo.buf = (char *)mhdr;
     xo.size = ((struct b_info const *)(void const *)xi.buf)->sz_unc;
     xi0 = xi;

     unpackExtent(&xi, &xo, f_decompress, 0);

     entry = do_xmap(mhdr, fat_offset, &xi0, -1, mhdrpp, f_decompress, f_unf);

     {
          Mach_load_command const *lc = (Mach_load_command const *)(1 + mhdr);
          unsigned j;

          for (j = 0; j < mhdr->ncmds;
               ++j, (lc = (Mach_load_command const *)(void const *)(lc->cmdsize + (char const *)lc)))
               if (LC_LOAD_DYLINKER == lc->cmd) {
                    char const *const dyld_name
                       = ((Mach_lc_str const *)(void const *)(1 + lc))->offset + (char const *)lc;
                    int const fdi = open(dyld_name, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
               fat:
                    if ((ssize_t)sz_mhdr != pread(fdi, (void *)mhdr, sz_mhdr, fat_offset)) {
                         ERR_LAB
                         err_exit(19);
                    }
                    switch (mhdr->magic) {
                         case MH_MAGIC:
                              break;
                         case FAT_MAGIC: {

                              Fat_header const *const fh = (Fat_header const *)mhdr;
                              Fat_arch const * fa = (Fat_arch const *)(1 + fh);
                              for (j = 0; j < fh->nfat_arch; ++j, ++fa) {
                                   if (CPU_TYPE_POWERPC == fa->cputype) {
                                        fat_offset = fa->offset;
                                        goto fat;
                                   }
                              }
                         } break;
                    }
                    entry = do_xmap(mhdr, fat_offset, 0, fdi, 0, 0, 0);
                    close(fdi);
                    break;
               }
     }

     return entry;
}
