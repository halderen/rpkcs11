typedef opaque arguments<>;

program DOORRPCPROG {
        version DOORRPCVERS {
            void DOORRPCPROC_NULL(void) =  0;
            arguments DOORRPCPROC_CALL(string, arguments) = 1;
        } = 1;
} = 200493;

#ifdef RPC_SVC
%extern int dispatcher(void);
%void doorrpcprog_1(struct svc_req *rqstp, register SVCXPRT *transp);
%int
%dispatcher(void)
%{
%    register SVCXPRT *transp;
%    pmap_unset(DOORRPCPROG, DOORRPCVERS);
%    if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
%        return 1;
%    }
%    if (!svc_register(transp, DOORRPCPROG, DOORRPCVERS, doorrpcprog_1, IPPROTO_UDP)) {
%        return 2;
%    }
%    if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
%        return 3;
%    }
%    if (!svc_register(transp, DOORRPCPROG, DOORRPCVERS, doorrpcprog_1, IPPROTO_TCP)) {
%        return 4;
%    }
%    svc_run();
%    return 0;
%}
#endif
