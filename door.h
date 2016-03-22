struct callstack;

extern void* door_arg_basic();
extern void door_arg_get(struct callstack* callstack, void* ptr);
extern void door_arg_ref(struct callstack* callstack, void** ptr, size_t *size);
extern int door_arg_pass(void* ptr, size_t size);
extern int door_arg_passstatic(void* ptr, unsigned long count, size_t size);
extern int door_arg_passcount(void* ptr, unsigned long count, size_t size);
extern int door_arg_passcount2(void* ptr, unsigned long maxcount, unsigned long* actualcount, size_t size);
extern void door_arg_passback(struct callstack* callstack);
extern void door_return(struct callstack* callstack);
extern void door_initialize(void);
extern void door_getcallbuffer(char** buffer, unsigned int* size);
extern void door_setcallbuffer(struct callstack *callstack);
extern void door_verify(void);
extern void door_marshall_complexarray(void *ptr, long unsigned count, size_t size, int ptr_offset, int len_offset);
extern void door_unmarshall_complexarray(void *ptr, long unsigned *count, size_t size, int ptr_offset, int len_offset);

#define door_ARG(ARG) door_arg_pass(&ARG, sizeof(ARG))
#define door_REF(ARG) door_arg_pass(ARG, sizeof(*ARG))
#define door_STRING(ARG) door_arg_passcount(ARG,strlen(ARG)+1,sizeof(char))
#define door_ARRAY(ARG,COUNT) door_arg_passcount(ARG,COUNT,sizeof(*ARG))
#define door_ARRAY2(ARG,COUNTPTR) door_arg_passcount2(ARG,*COUNTPTR,COUNTPTR,sizeof(*ARG))
#define door_ARRAY3(ARG,MAXCOUNT,ACTUALCOUNTPTR) door_arg_passcount2(ARG,MAXCOUNT,ACTUALCOUNTPTR,sizeof(*ARG))
#define door_GET(TYPE) (*(TYPE*)door_arg_basic())
#define door_OBJ(TYPE) ((TYPE)door_arg_basic())
