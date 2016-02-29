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
  unsigned char slot_description[64];
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
};

struct ck_token_info
{
  unsigned char label[32];
  unsigned char manufacturer_id[32];
  unsigned char model[16];
  unsigned char serial_number[16];
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
  unsigned char utc_time[16];
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
  unsigned char year[4];
  unsigned char month[2];
  unsigned char day[2];
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
    ck_slot_id_t slots<>;
    ck_rv_t result;
};
struct slotinfo
{
    ck_slot_info info;
    ck_rv_t result;
};
struct tokeninfo
{
    ck_token_info info;
    ck_rv_t result;
};
struct slotevent
{
    ck_slot_id_t slot;
    ck_rv_t result;
};
struct mechlist
{
    ck_mechanism_type_t mechs<>;
    ck_rv_t result;
};
struct mechinfo
{
    struct ck_mechanism_info info;
    ck_rv_t result;
};
struct sessionresult
{
    ck_session_handle_t session;
    ck_rv_t result;
};
struct sessioninfo
{
    struct ck_session_info info;
    ck_rv_t result;
};

typedef opaque reserved<>;
typedef unsigned char buffer<>;

program PKCSPROG {
        version PKCSVERS {
                void                PKCSPROC_NULL(void)                                                          =  0;
                ck_rv_t             PKCSPROC_INITIALIZE(reserved init_args)                                      =  1;
                ck_rv_t             PKCSPROC_FINALIZE(reserved reserved)                                         =  2;
                struct ck_info      PKCSPROC_GETINFO()                                                           =  3;
                slotlist            PKCSPROC_GETSLOTLIST(unsigned char token_present)                            =  5;
                slotinfo            PKCSPROC_GETSLOTINFO(ck_slot_id_t slot_id)                                   =  6;
                tokeninfo           PKCSPROC_GETTOKENINFO(ck_slot_id_t slot_id)                                  =  7;
                slotevent           PKCSPROC_WAITFORSLOTEVENT(ck_flags_t flags, reserved)                        =  8;
                mechlist            PKCSPROC_GETMECHANISMLIST(ck_slot_id_t slot_id)                              =  9;
                mechinfo            PKCSPROC_GETMECHANISMINFO(ck_slot_id_t slot_id, ck_mechanism_type_t type)    = 10;
                ck_rv_t             PKCSPROC_INITTOKEN(ck_slot_id_t slot_id, buffer pin, string label)           = 11;
                ck_rv_t             PKCSPROC_INITPIN(ck_session_handle_t session, buffer pin)                    = 12;
                ck_rv_t             PKCSPROC_SETPIN(ck_session_handle_t session, buffer old_pin, buffer new_pin) = 13;
                sessionresult       PKCSPROC_OPENSESSION(ck_slot_id_t slot_id, ck_flags_t flags)                 = 14;
                ck_rv_t             PKCSPROC_CLOSESESSION(ck_session_handle_t session)                           = 15;
                ck_rv_t             PKCSPROC_CLOSEALLSESSIONS(ck_slot_id_t slot_id)                              = 16;
                sessioninfo         PKCSPROC_GETSESSIONINFO(ck_session_handle_t session)                         = 17;

#ifdef NOTDEFINED
GetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long *operation_state_len) = 18;
SetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long operation_state_len, ck_object_handle_t encryption_key, ck_object_handle_t authentiation_key) = 19;
Login(ck_session_handle_t session, ck_user_type_t user_type, unsigned char *pin, unsigned long pin_len) = 20;
Logout(ck_session_handle_t session) = 21;
CreateObject(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *object) = 22;
CopyObject(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *new_object) = 23;
DestroyObject(ck_session_handle_t session, ck_object_handle_t object) = 24;
GetObjectSize(ck_session_handle_t session, ck_object_handle_t object, unsigned long *size) = 25;
GetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) = 26;
SetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) = 27;
FindObjectsInit(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count) = 28;
FindObjects(ck_session_handle_t session, ck_object_handle_t *object, unsigned long max_object_count, unsigned long *object_count) = 29;
FindObjectsFinal(ck_session_handle_t session) = 30;
EncryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 31;
Encrypt(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) = 32;
EncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) = 33;
EncryptFinal(ck_session_handle_t session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) = 34;
DecryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 35;
Decrypt(ck_session_handle_t session, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) = 36;
DecryptUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) = 37;
DecryptFinal(ck_session_handle_t session, unsigned char *last_part, unsigned long *last_part_len) = 38;
DigestInit(ck_session_handle_t session, struct ck_mechanism *mechanism) = 39;
Digest(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) = 40;
DigestUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) = 41;
DigestKey(ck_session_handle_t session, ck_object_handle_t key) = 42;
DigestFinal(ck_session_handle_t session, unsigned char *digest, unsigned long *digest_len) = 43;
SignInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 44;
Sign(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) = 45;
SignUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) = 46;
SignFinal(ck_session_handle_t session, unsigned char *signature, unsigned long *signature_len) = 47;
SignRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 48;
SignRecover(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) = 49;
VerifyInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 50;
Verify(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len) = 51;
VerifyUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) = 52;
VerifyFinal(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len) = 53;
VerifyRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) = 54;
VerifyRecover(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char *data, unsigned long *data_len) = 55;
DigestEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) = 56;
DecryptDigestUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) = 57;
SignEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) = 58;
DecryptVerifyUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) = 59;
GenerateKey(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *key) = 60;
GenerateKeyPair(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *public_key_template, unsigned long public_key_attribute_count, struct ck_attribute *private_key_template, unsigned long private_key_attribute_count, ck_object_handle_t *public_key, ck_object_handle_t *private_key) = 61;
WrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t wrapping_key, ck_object_handle_t key, unsigned char *wrapped_key, unsigned long *wrapped_key_len) = 62;
UnwrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t unwrapping_key, unsigned char *wrapped_key, unsigned long wrapped_key_len, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) = 63;
DeriveKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t base_key, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) = 64;
SeedRandom(ck_session_handle_t session, unsigned char *seed, unsigned long seed_len) = 65;
GenerateRandom(ck_session_handle_t session, unsigned char *random_data, unsigned long random_len) = 66;
GetFunctionStatus(ck_session_handle_t session) = 67;
CancelFunction(ck_session_handle_t session) = 68;
#endif
        } = 1;
} = 200492;
