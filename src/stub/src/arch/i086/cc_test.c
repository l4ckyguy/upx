#if 0 && defined(__WATCOMC__)
#define __cdecl __watcall
#endif

typedef short int16_t;
typedef unsigned short uint16_t;
typedef long int32_t;
typedef unsigned long uint32_t;

#if 1

typedef char __huge * hptr;
typedef long hptrdiff_t;
typedef unsigned long hsize_t;
#elif 1

typedef char __far * hptr;
typedef long hptrdiff_t;
typedef unsigned long hsize_t;
#else

typedef char __near * hptr;
typedef short hptrdiff_t;
typedef unsigned short hsize_t;
#endif

hptr __cdecl pia(hptr a, hsize_t d)
{
     return a + d;
}
hptr __cdecl pia1(hptr a)
{
     return a + 1;
}

hptr __cdecl pis(hptr a, hsize_t d)
{
     return a - d;
}
hptr __cdecl pis1(hptr a)
{
     return a - 1;
}

hptrdiff_t __cdecl pts(hptr a, hptr b)
{
     return a - b;
}

int __cdecl ptc_eq(hptr a, hptr b)
{
     return a == b;
}
int __cdecl ptc_ne(hptr a, hptr b)
{
     return a != b;
}
int __cdecl ptc_lt(hptr a, hptr b)
{
     return a < b;
}
int __cdecl ptc_le(hptr a, hptr b)
{
     return a <= b;
}
int __cdecl ptc_gt(hptr a, hptr b)
{
     return a > b;
}
int __cdecl ptc_ge(hptr a, hptr b)
{
     return a >= b;
}

uint32_t __cdecl u4m(uint32_t a, uint32_t b)
{
     return a * b;
}
uint32_t __pascal u4m_p(uint32_t a, uint32_t b)
{
     return b * a;
}

int32_t __cdecl i4m(int32_t a, int32_t b)
{
     return a * b;
}
int32_t __pascal i4m_p(int32_t a, int32_t b)
{
     return b * a;
}

uint16_t __cdecl u2m(uint16_t a, uint16_t b)
{
     return a * b;
}
int16_t __cdecl i2m(int16_t a, int16_t b)
{
     return a * b;
}
uint32_t __cdecl u2m4(uint16_t a, uint16_t b)
{
     return a * b;
}
int32_t __cdecl i2m4(int16_t a, int16_t b)
{
     return a * b;
}

uint16_t __cdecl u2shl8(uint16_t a)
{
     return a << 8;
}
uint32_t __cdecl u4shl8(uint32_t a)
{
     return a << 8;
}
uint16_t __cdecl u2shl12(uint16_t a)
{
     return a << 12;
}
uint32_t __cdecl u4shl12(uint32_t a)
{
     return a << 12;
}
uint32_t __cdecl u4shl16(uint32_t a)
{
     return a << 16;
}
uint32_t __cdecl u4shl24(uint32_t a)
{
     return a << 24;
}
uint16_t __cdecl u2shlv(uint16_t a, unsigned v)
{
     return a << v;
}
uint32_t __cdecl u4shlv(uint32_t a, unsigned v)
{
     return a << v;
}

void __pascal p4nshlv_v(unsigned char v, uint32_t __near *a)
{
     *a <<= v;
}
void __pascal p4fshlv_v(unsigned char v, uint32_t __far *a)
{
     *a <<= v;
}
uint32_t __pascal p4nshlv(unsigned char v, uint32_t __near *a)
{
     return *a <<= v;
}
uint32_t __pascal p4fshlv(unsigned char v, uint32_t __far *a)
{
     return *a <<= v;
}

hptrdiff_t __cdecl hptr2int(hptr a)
{
     return (hptrdiff_t)a;
}
hptr __cdecl int2hptr(hptrdiff_t a)
{
     return (hptr)a;
}
