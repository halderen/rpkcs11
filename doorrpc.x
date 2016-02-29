typedef opaque arguments<>;

program DOORRPCPROG {
        version DOORRPCVERS {
            void DOORRPCPROC_NULL(void) =  0;
            arguments DOORRPCPROC_CALL(string, arguments) = 1;
        } = 1;
} = 200493;
