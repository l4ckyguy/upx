#ifndef __AHSHIFT

#define __AHSHIFT 12
#define __AHINCR (1 << __AHSHIFT)

.macro M_PIA_small add ax, bx adc cx,
   0
#if 0



        mov bx, cx
        mov cl, __AHSHIFT
        shl bx, cl
        add dx, bx
#else

   mov bl,
   cl mov cl, __AHSHIFT - 8 shl bl, cl add dh,
   bl
#endif
      .endm

      .macro M_PIA_fast add ax,
   bx adc cx,
   0

   shl cl shl cl shl cl shl cl add dh,
   cl.endm

      .macro M_PIA1_small

         local L1 inc ax jnes L1

            add dh,
   __AHINCR >> 8 L1
   :.endm

       .macro M_PIA1_fast

          add ax,
   1 sbb bl, bl and bl, __AHINCR >> 8 add dh,
   bl.endm

#if 0

.macro M_PIS
        sub ax, bx
        adc cx, 0
        mov bx, cx
        mov cl, __AHSHIFT
        shl bx, cl
        sub dx, bx
.endm
#endif

      .macro M_PTS
#if 0



        sub ax, bx
        sbb dx, cx
#endif
      .endm

      .macro M_PTC

         local L1 cmp dx,
   cx jnes L1 cmp ax,
   bx L1
   :.endm

       .macro M_PTC_JNE l cmp ax,
   bx jnes l cmp dx,
   cx jnes
      l.endm

         .macro M_U4M_dxax_00bx

            mov cx,
   ax mov ax, dx mul bx xchg ax,
   cx

      mul bx

         add dx,
   cx.endm

      .macro M_U4M_dxax_00bx_ptr

         mov cx,
   ax mov ax, dx mul word ptr[bx] xchg ax,
   cx

      mul word ptr[bx]

   add dx,
   cx.endm

      .macro M_U4M_axcx_00bx

         mul bx xchg ax,
   cx

      mul bx

         add dx,
   cx.endm

      .macro M_U4M_dxax_0x0600
#if 0



        mov bx, 0x300
        M_U4M_dxax_00bx
        shl ax
        rcl dx
#elif 0

         mov bx,
   0x600 M_U4M_dxax_00bx
#else

         shl ax rcl dx mov cx,
   dx mov bx, ax shl ax rcl dx add ax, bx adc dx,
   cx M_shld_8
#endif
      .endm

      .macro M_shld_8

         mov dh,
   dl mov dl, ah mov ah, al xor al,
   al.endm

      .macro M_shld_disi_8_bxcx
#if 0



        local L1
        mov cx, 8
L1: shl si
        rcl di
        loop L1
#else

         mov bx,
   di mov cx, si mov bh, bl mov bl, ch mov ch, cl xor cl, cl mov di, bx mov si,
   cx
#endif
      .endm

      .macro M_shld_diax_8_bxcx
#if 0



        local L1
        mov cx, 8
L1: shl ax
        rcl di
        loop L1
#else

         mov bx,
   di mov bh, bl mov bl, ah mov ah, al xor al, al mov di,
   bx
#endif
      .endm

      .macro M_shld_8_bp h l mov dx,
   word ptr[bp + h] mov ax, word ptr[bp + l] M_shld_8 mov word ptr[bp + h], dx mov word ptr[bp + l],
   ax.endm

      .macro M_shld_00_15 r1 mov r1,
   ax shl dx, cl shl ax, cl sub cl, 16 neg cl shr r1, cl or dx,
   r1.endm

      .macro M_shld_16_32 sub cl,
   16 shl ax, cl mov dx, ax xor ax,
   ax.endm

      .macro M_shld r1 local L1,
   L2 cmp cl,
   16 jaes L1

      M_shld_00_15 r1 jmps L2 L1 :

   M_shld_16_32 L2
   :.endm

       .macro M_shrd_11_small

          mov cl,
   11 mov bx, dx shr ax, cl shr dx, cl mov cl, 5 shl bx, cl or ax,
   bx.endm

      .macro M_shrd_11_fast

         mov al,
   ah mov ah, dl mov dl, dh xor dh,
   dh shr dx rcr ax shr dx rcr ax shr dx rcr
      ax.endm

         .macro M_shrd_11_bp_small h l mov dx,
   word ptr[bp + h] mov ax, word ptr[bp + l] M_shrd_11_small mov word ptr[bp + h], dx mov word ptr[bp + l],
   ax.endm

      .macro M_shrd_11_bp_fast h l mov dx,
   word ptr[bp + h] mov ax, word ptr[bp + l] M_shrd_11_fast mov word ptr[bp + h], dx mov word ptr[bp + l],
   ax.endm

      .macro M_shrd_11_disi_bp_small h l mov dx,
   di mov ax, si M_shrd_11_small mov word ptr[bp + h], dx mov word ptr[bp + l],
   ax.endm

      .macro M_shrd_11_disi_bp_fast h l mov dx,
   di mov ax, si M_shrd_11_fast mov word ptr[bp + h], dx mov word ptr[bp + l], ax.endm

#endif

#undef M_PIA
#undef M_PIA1
#undef M_shrd_11
#undef M_shrd_11_bp
#undef M_shrd_11_disi_bp

#if defined(FAST)
#define M_PIA M_PIA_fast
#define M_PIA1 M_PIA1_fast
#define M_shrd_11 M_shrd_11_fast
#define M_shrd_11_bp M_shrd_11_bp_fast
#define M_shrd_11_disi_bp M_shrd_11_disi_bp_fast
#elif defined(SMALL)
#define M_PIA M_PIA_small
#define M_PIA1 M_PIA1_small
#define M_shrd_11 M_shrd_11_small
#define M_shrd_11_bp M_shrd_11_bp_small
#define M_shrd_11_disi_bp M_shrd_11_disi_bp_small
#else
#error
#endif
