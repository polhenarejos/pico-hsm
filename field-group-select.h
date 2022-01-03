#define CONCAT0(a,b) a##b
#define CONCAT1(a,b) CONCAT0(a,b)
#define CONCAT2(a,b,c) CONCAT1(a,b##c)
#define CONCAT3(a,b,c) CONCAT2(a,b,c)

#define FUNC(func) CONCAT1(func##_,FIELD)
#define MFNC(func) CONCAT3(mod,FIELD,_##func)
