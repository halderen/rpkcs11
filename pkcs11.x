typedef unsigned long ck_rv_t;
typedef unsigned long ck_flags_t;
typedef unsigned long ck_notification_t;
typedef unsigned long ck_slot_id_t;
typedef unsigned long ck_session_handle_t;
typedef unsigned long ck_user_type_t;
typedef unsigned long ck_state_t;
typedef unsigned long ck_object_handle_t;
typedef unsigned long ck_object_class_t;
typedef unsigned long ck_hw_feature_type_t;
typedef unsigned long ck_key_type_t;
typedef unsigned long ck_certificate_type_t;
typedef unsigned long ck_attribute_type_t;
typedef unsigned long ck_mechanism_type_t;

struct ck_version
{
  unsigned char major;
  unsigned char minor;
};

struct ck_info
{
  struct ck_version cryptoki_version;
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  unsigned char library_description[32];
  struct ck_version library_version;
  ck_rv_t result;
};

struct ck_slot_info
{
  unsigned char slot_description<64>;
  unsigned char manufacturer_id<32>;
  ck_flags_t flags;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
};

struct ck_token_info
{
  unsigned char label<32>;
  unsigned char manufacturer_id<32>;
  unsigned char model[16];
  unsigned char serial_number<16>;
  ck_flags_t flags;
  unsigned long max_session_count;
  unsigned long session_count;
  unsigned long max_rw_session_count;
  unsigned long rw_session_count;
  unsigned long max_pin_len;
  unsigned long min_pin_len;
  unsigned long total_public_memory;
  unsigned long free_public_memory;
  unsigned long total_private_memory;
  unsigned long free_private_memory;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
  unsigned char utc_time<16>;
};

struct ck_session_info
{
  ck_slot_id_t slot_id;
  ck_state_t state;
  ck_flags_t flags;
  unsigned long device_error;
};

struct ck_attribute
{
  ck_attribute_type_t type;
  opaque value<>;
  unsigned long value_len;
};

struct ck_date
{
  unsigned char year<4>;
  unsigned char month<2>;
  unsigned char day<2>;
};

struct ck_mechanism
{
  ck_mechanism_type_t mechanism;
  opaque parameter<>;
  unsigned long parameter_len;
};

struct ck_mechanism_info
{
  unsigned long min_key_size;
  unsigned long max_key_size;
  ck_flags_t flags;
};

struct slotlist
{
    int count;
    ck_slot_id_t slots<3>;
    ck_rv_t result;
};

typedef opaque reserved<>;

program PKCSPROG {
        version PKCSVERS {
                void                PKCSPROC_NULL(void) = 0;
                ck_rv_t             PKCSPROC_INITIALIZE(reserved init_args) = 1;
                ck_rv_t             PKCSPROC_FINALIZE(reserved reserved) = 2;
                struct ck_info      PKCSPROC_GETINFO() = 3;
                slotlist            PKCSPROC_GETSLOTLIST(unsigned char token_present) = 5;
        } = 1;
} = 200492;

#ifdef RPC_SVC
%extern int dispatcher(void);
%void pkcsprog_1(struct svc_req *rqstp, register SVCXPRT *transp);
%int
%dispatcher(void)
%{
%    register SVCXPRT *transp;
%    pmap_unset(PKCSPROG, PKCSVERS);
%    if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
%        return 1;
%    }
%    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_UDP)) {
%        return 2;
%    }
%    if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
%        return 3;
%    }
%    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_TCP)) {
%        return 4;
%    }
%    svc_run();
%}
#endif
