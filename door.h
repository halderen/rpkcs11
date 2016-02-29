struct callstack;

extern void door_arg_get(struct callstack* callstack, void* ptr);
extern void door_arg_ref(struct callstack* callstack, void** ptr, size_t *size);
extern void* door_arg_basic(struct callstack* callstack);
extern int door_arg_pass(void* ptr, size_t size);
extern int door_arg_passcount2(void* ptr, unsigned long* array, size_t size);
extern void door_arg_passback(struct callstack* callstack);
extern void door_return(struct callstack* callstack);
extern void door_initialize(void);
extern void door_getcallbuffer(char** buffer, unsigned int* size);
extern void door_setcallbuffer(struct callstack *callstack);

#define door_ARG(ARG) door_arg_pass(&ARG, sizeof(ARG))
#define door_REF(ARG) door_arg_pass(ARG, sizeof(*ARG))
#define door_STRING(ARG) door_arg_passcount(ARG,strlen(ARG)+1,sizeof(char))
#define door_ARRAY(ARG,COUNT) door_arg_passcount(ARG,COUNT,sizeof(*ARG))
#define door_ARRAY2(ARG,COUNTPTR) door_arg_passcount2(ARG,COUNTPTR,sizeof(*ARG))
#define door_GET(TYPE) (*((TYPE)*)door_arg_basic((void*)input.arguments_val))
#define door_OBJ(TYPE) ((TYPE)door_arg_basic((void*)input.arguments_val))
