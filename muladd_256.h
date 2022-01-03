#define MULADD_256_ASM(s_,d_,w_,c_)                      \
 asm ( "ldmia  %[s]!, { r8, r9, r10 } \n\t"              \
       "ldmia  %[d], { r5, r6, r7 }   \n\t"              \
       "umull  r4, r8, %[w], r8       \n\t"              \
       "adds   r5, r5, r4             \n\t"              \
       "adcs   r6, r6, r8             \n\t"              \
       "umull  r4, r8, %[w], r9       \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r6, r6, r4             \n\t"              \
       "adcs   r7, r7, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r10      \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r7, r7, r4             \n\t"              \
       "stmia  %[d]!, { r5, r6, r7 }  \n\t"              \
       "ldmia  %[s]!, { r8, r9, r10 } \n\t"              \
       "ldmia  %[d], { r5, r6, r7 }   \n\t"              \
       "adcs   r5, r5, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r8       \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r5, r5, r4             \n\t"              \
       "adcs   r6, r6, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r9       \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r6, r6, r4             \n\t"              \
       "adcs   r7, r7, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r10      \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r7, r7, r4             \n\t"              \
       "stmia  %[d]!, { r5, r6, r7 }  \n\t"              \
       "ldmia  %[s]!, { r8, r9 }      \n\t"              \
       "ldmia  %[d], { r5, r6 }       \n\t"              \
       "adcs   r5, r5, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r8       \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r5, r5, r4             \n\t"              \
       "adcs   r6, r6, %[c]           \n\t"              \
       "umull  r4, r8, %[w], r9       \n\t"              \
       "adc    %[c], r8, #0           \n\t"              \
       "adds   r6, r6, r4             \n\t"              \
       "adc    %[c], %[c], #0         \n\t"              \
       "stmia  %[d]!, { r5, r6 }"                        \
       : [s] "=&r" (s_), [d] "=&r" (d_), [c] "=&r" (c_)  \
       : "[s]" (s_), "[d]" (d_), [w] "r" (w_)            \
       : "r4", "r5", "r6", "r7", "r8", "r9", "r10",      \
         "memory", "cc" )

#define MULADD_256(s__,d__,w__,c__) do { \
  MULADD_256_ASM(s__,d__,w__,c__);	 \
  *d__ = c__;                            \
} while (0)
