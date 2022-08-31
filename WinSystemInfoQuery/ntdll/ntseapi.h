
/*++ BUILD Version: 0003    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    ntseapi.h

Abstract:

    This module contains the Security APIs and any public data
    structures needed to call these APIs.

    This module should be included by including "nt.h".

--*/

#ifndef _NTSEAPI_
#define _NTSEAPI_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif


    ////////////////////////////////////////////////////////////////////////
    //                                                                    //
    //                      Pointers to Opaque data types                 //
    //                                                                    //
    ////////////////////////////////////////////////////////////////////////

    //
    // Some of these data types may have related data types defined elsewhere
    // in this file.
    //

    // begin_ntddk begin_wdm begin_nthal begin_ntifs
    //
    //  Define an access token from a programmer's viewpoint.  The structure is
    //  completely opaque and the programer is only allowed to have pointers
    //  to tokens.
    //

    typedef PVOID PACCESS_TOKEN;            // winnt

    //
    // Pointer to a SECURITY_DESCRIPTOR  opaque data type.
    //

    typedef PVOID PSECURITY_DESCRIPTOR;     // winnt

    //
    // Define a pointer to the Security ID data type (an opaque data type)
    //

    typedef PVOID PSID;     // winnt

    // end_ntddk end_wdm end_nthal end_ntifs


    // begin_winnt
    ////////////////////////////////////////////////////////////////////////
    //                                                                    //
    //                             ACCESS MASK                            //
    //                                                                    //
    ////////////////////////////////////////////////////////////////////////

    //
    //  Define the access mask as a longword sized structure divided up as
    //  follows:
    //
    //       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
    //       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
    //      +---------------+---------------+-------------------------------+
    //      |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
    //      |R|W|E|A|     |S|               |                               |
    //      +-+-------------+---------------+-------------------------------+
    //
    //      typedef struct _ACCESS_MASK {
    //          USHORT SpecificRights;
    //          UCHAR StandardRights;
    //          UCHAR AccessSystemAcl : 1;
    //          UCHAR Reserved : 3;
    //          UCHAR GenericAll : 1;
    //          UCHAR GenericExecute : 1;
    //          UCHAR GenericWrite : 1;
    //          UCHAR GenericRead : 1;
    //      } ACCESS_MASK;
    //      typedef ACCESS_MASK *PACCESS_MASK;
    //
    //  but to make life simple for programmer's we'll allow them to specify
    //  a desired access mask by simply OR'ing together mulitple single rights
    //  and treat an access mask as a ULONG.  For example
    //
    //      DesiredAccess = DELETE | READ_CONTROL
    //
    //  So we'll declare ACCESS_MASK as ULONG
    //

    // begin_ntddk begin_wdm begin_nthal begin_ntifs
    typedef ULONG ACCESS_MASK;
    typedef ACCESS_MASK* PACCESS_MASK;

    // end_winnt end_wdm end_ntddk end_nthal end_ntifs

    // begin_winnt

    ////////////////////////////////////////////////////////////////////////
    //                                                                    //
    //              Security Id     (SID)                                 //
    //                                                                    //
    ////////////////////////////////////////////////////////////////////////
    //
    //
    // Pictorially the structure of an SID is as follows:
    //
    //         1   1   1   1   1   1
    //         5   4   3   2   1   0   9   8   7   6   5   4   3   2   1   0
    //      +---------------------------------------------------------------+
    //      |      SubAuthorityCount        |Reserved1 (SBZ)|   Revision    |
    //      +---------------------------------------------------------------+
    //      |                   IdentifierAuthority[0]                      |
    //      +---------------------------------------------------------------+
    //      |                   IdentifierAuthority[1]                      |
    //      +---------------------------------------------------------------+
    //      |                   IdentifierAuthority[2]                      |
    //      +---------------------------------------------------------------+
    //      |                                                               |
    //      +- -  -  -  -  -  -  -  SubAuthority[]  -  -  -  -  -  -  -  - -+
    //      |                                                               |
    //      +---------------------------------------------------------------+
    //
    //


    // begin_ntifs

#ifndef SID_IDENTIFIER_AUTHORITY_DEFINED
#define SID_IDENTIFIER_AUTHORITY_DEFINED
    typedef struct _SID_IDENTIFIER_AUTHORITY
    {
        UCHAR Value[ 6 ];
    } SID_IDENTIFIER_AUTHORITY, * PSID_IDENTIFIER_AUTHORITY;
#endif


#ifndef SID_DEFINED
#define SID_DEFINED
    typedef struct _SID
    {
        UCHAR Revision;
        UCHAR SubAuthorityCount;
        SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    #ifdef MIDL_PASS
        [ size_is( SubAuthorityCount ) ] ULONG SubAuthority[ * ];
    #else // MIDL_PASS
        ULONG SubAuthority[ ANYSIZE_ARRAY ];
    #endif // MIDL_PASS
    } SID, * PISID;
#endif

#define SID_REVISION                     (1)    // Current revision level
#define SID_MAX_SUB_AUTHORITIES          (15)
#define SID_RECOMMENDED_SUB_AUTHORITIES  (1)    // Will change to around 6


    //
    //                                  COMPOUND ACE
    //
    //       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
    //       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
    //      +---------------+-------+-------+---------------+---------------+
    //      |    AceFlags   | Resd  |Inherit|    AceSize    |     AceType   |
    //      +---------------+-------+-------+---------------+---------------+
    //      |                              Mask                             |
    //      +-------------------------------+-------------------------------+
    //      |     Compound ACE Type         |        Reserved (SBZ)         |
    //      +-------------------------------+-------------------------------+
    //      |                                                               |
    //      +                                                               +
    //      |                                                               |
    //      +                              Sid                              +
    //      |                                                               |
    //      +                                                               +
    //      |                                                               |
    //      +---------------------------------------------------------------+
    //



    typedef struct _COMPOUND_ACCESS_ALLOWED_ACE
    {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        USHORT CompoundAceType;
        USHORT Reserved;
        ULONG SidStart;
    } COMPOUND_ACCESS_ALLOWED_ACE;

    typedef COMPOUND_ACCESS_ALLOWED_ACE* PCOMPOUND_ACCESS_ALLOWED_ACE;

    //
    // Currently defined Compound ACE types
    //

#define COMPOUND_ACE_IMPERSONATION  1


//
// ** ** ** ** ** ** ** ** ** ** NOTE ** ** ** ** ** ** ** ** ** ** ** ** **
//
//          Any additions or deletions to the following list
//          of privileges must have corresponding changes made
//          in the following files:
//          - ntos\se\seglobal.c
//          - ds\security\base\lsa\msprivs\msprivs.rc
//          - ds\security\base\lsa\server\dspolicy\dbpriv.c
//
// ** ** ** ** ** ** ** ** ** ** NOTE ** ** ** ** ** ** ** ** ** ** ** ** **
//


// begin_winnt

#define SE_CREATE_TOKEN_NAME              TEXT("SeCreateTokenPrivilege")
#define SE_ASSIGNPRIMARYTOKEN_NAME        TEXT("SeAssignPrimaryTokenPrivilege")
#define SE_LOCK_MEMORY_NAME               TEXT("SeLockMemoryPrivilege")
#define SE_INCREASE_QUOTA_NAME            TEXT("SeIncreaseQuotaPrivilege")
#define SE_UNSOLICITED_INPUT_NAME         TEXT("SeUnsolicitedInputPrivilege")
#define SE_MACHINE_ACCOUNT_NAME           TEXT("SeMachineAccountPrivilege")
#define SE_TCB_NAME                       TEXT("SeTcbPrivilege")
#define SE_SECURITY_NAME                  TEXT("SeSecurityPrivilege")
#define SE_TAKE_OWNERSHIP_NAME            TEXT("SeTakeOwnershipPrivilege")
#define SE_LOAD_DRIVER_NAME               TEXT("SeLoadDriverPrivilege")
#define SE_SYSTEM_PROFILE_NAME            TEXT("SeSystemProfilePrivilege")
#define SE_SYSTEMTIME_NAME                TEXT("SeSystemtimePrivilege")
#define SE_PROF_SINGLE_PROCESS_NAME       TEXT("SeProfileSingleProcessPrivilege")
#define SE_INC_BASE_PRIORITY_NAME         TEXT("SeIncreaseBasePriorityPrivilege")
#define SE_CREATE_PAGEFILE_NAME           TEXT("SeCreatePagefilePrivilege")
#define SE_CREATE_PERMANENT_NAME          TEXT("SeCreatePermanentPrivilege")
#define SE_BACKUP_NAME                    TEXT("SeBackupPrivilege")
#define SE_RESTORE_NAME                   TEXT("SeRestorePrivilege")
#define SE_SHUTDOWN_NAME                  TEXT("SeShutdownPrivilege")
#define SE_DEBUG_NAME                     TEXT("SeDebugPrivilege")
#define SE_AUDIT_NAME                     TEXT("SeAuditPrivilege")
#define SE_SYSTEM_ENVIRONMENT_NAME        TEXT("SeSystemEnvironmentPrivilege")
#define SE_CHANGE_NOTIFY_NAME             TEXT("SeChangeNotifyPrivilege")
#define SE_REMOTE_SHUTDOWN_NAME           TEXT("SeRemoteShutdownPrivilege")
#define SE_UNDOCK_NAME                    TEXT("SeUndockPrivilege")
#define SE_SYNC_AGENT_NAME                TEXT("SeSyncAgentPrivilege")
#define SE_ENABLE_DELEGATION_NAME         TEXT("SeEnableDelegationPrivilege")
#define SE_MANAGE_VOLUME_NAME             TEXT("SeManageVolumePrivilege")
#define SE_IMPERSONATE_NAME               TEXT("SeImpersonatePrivilege")
#define SE_CREATE_GLOBAL_NAME             TEXT("SeCreateGlobalPrivilege")
// end_winnt

// begin_wdm begin_ntddk begin_ntifs
//
// These must be converted to LUIDs before use.
//

#define SE_MIN_WELL_KNOWN_PRIVILEGE       (2L)
#define SE_CREATE_TOKEN_PRIVILEGE         (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   (3L)
#define SE_LOCK_MEMORY_PRIVILEGE          (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE       (5L)

// end_wdm
//
// Unsolicited Input is obsolete and unused.
//

#define SE_UNSOLICITED_INPUT_PRIVILEGE    (6L)

// begin_wdm
#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_UNDOCK_PRIVILEGE               (25L)
#define SE_SYNC_AGENT_PRIVILEGE           (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE    (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE        (28L)
#define SE_IMPERSONATE_PRIVILEGE          (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE        (30L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE       (SE_CREATE_GLOBAL_PRIVILEGE)



    typedef enum _PROXY_CLASS
    {
        ProxyFull,
        ProxyService,
        ProxyTree,
        ProxyDirectory
    } PROXY_CLASS, * PPROXY_CLASS;


    typedef struct _SECURITY_TOKEN_PROXY_DATA
    {
        ULONG Length;
        PROXY_CLASS ProxyClass;
        UNICODE_STRING PathInfo;
        ACCESS_MASK ContainerMask;
        ACCESS_MASK ObjectMask;
    } SECURITY_TOKEN_PROXY_DATA, * PSECURITY_TOKEN_PROXY_DATA;

    typedef struct _SECURITY_TOKEN_AUDIT_DATA
    {
        ULONG Length;
        ACCESS_MASK GrantMask;
        ACCESS_MASK DenyMask;
    } SECURITY_TOKEN_AUDIT_DATA, * PSECURITY_TOKEN_AUDIT_DATA;

    //
    // Advanced Quality of Service
    //

    typedef struct _SECURITY_ADVANCED_QUALITY_OF_SERVICE
    {
        ULONG Length;
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
        BOOLEAN EffectiveOnly;
        PSECURITY_TOKEN_PROXY_DATA ProxyData;
        PSECURITY_TOKEN_AUDIT_DATA AuditData;
    } SECURITY_ADVANCED_QUALITY_OF_SERVICE, * PSECURITY_ADVANCED_QUALITY_OF_SERVICE;


    ////////////////////////////////////////////////////////////////////////
    //                                                                    //
    //                    Flags for NtFilerToken                          //
    //                                                                    //
    ////////////////////////////////////////////////////////////////////////

#define DISABLE_MAX_PRIVILEGE   0x1 // winnt
#define SANDBOX_INERT           0x2 // winnt


////////////////////////////////////////////////////////////////////////
//                                                                    //
//                    General Security definitions                    //
//                                                                    //
////////////////////////////////////////////////////////////////////////

//
// Security information associated with objects.
// Used for query operations.
//
// This will be extended in the future to include mandatory access control.
//

// begin_winnt begin_wdm begin_ntddk begin_nthal begin_ntifs

    typedef ULONG SECURITY_INFORMATION, * PSECURITY_INFORMATION;

#define OWNER_SECURITY_INFORMATION       (0x00000001L)
#define GROUP_SECURITY_INFORMATION       (0x00000002L)
#define DACL_SECURITY_INFORMATION        (0x00000004L)
#define SACL_SECURITY_INFORMATION        (0x00000008L)

#define PROTECTED_DACL_SECURITY_INFORMATION     (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION     (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION   (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION   (0x10000000L)

    // end_winnt end_wdm end_ntddk end_nthal end_ntifs


    //
    // used for password manipulations
    //


    typedef struct _SECURITY_SEED_AND_LENGTH
    {
        UCHAR Length;
        UCHAR Seed;
    } SECURITY_SEED_AND_LENGTH, * PSECURITY_SEED_AND_LENGTH;


    ////////////////////////////////////////////////////////////////////////
    //                                                                    //
    //                      Security System Service Defnitions            //
    //                                                                    //
    ////////////////////////////////////////////////////////////////////////

    //
    //  Security check system services
    //

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheck(
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in HANDLE ClientToken,
            __in ACCESS_MASK DesiredAccess,
            __in PGENERIC_MAPPING GenericMapping,
            __out_bcount( *PrivilegeSetLength ) PPRIVILEGE_SET PrivilegeSet,
            __inout PULONG PrivilegeSetLength,
            __out PACCESS_MASK GrantedAccess,
            __out PNTSTATUS AccessStatus
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckByType(
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in_opt PSID PrincipalSelfSid,
            __in HANDLE ClientToken,
            __in ACCESS_MASK DesiredAccess,
            __in_ecount( ObjectTypeListLength ) POBJECT_TYPE_LIST ObjectTypeList,
            __in ULONG ObjectTypeListLength,
            __in PGENERIC_MAPPING GenericMapping,
            __out_bcount( *PrivilegeSetLength ) PPRIVILEGE_SET PrivilegeSet,
            __inout PULONG PrivilegeSetLength,
            __out PACCESS_MASK GrantedAccess,
            __out PNTSTATUS AccessStatus
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckByTypeResultList(
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in_opt PSID PrincipalSelfSid,
            __in HANDLE ClientToken,
            __in ACCESS_MASK DesiredAccess,
            __in_ecount( ObjectTypeListLength ) POBJECT_TYPE_LIST ObjectTypeList,
            __in ULONG ObjectTypeListLength,
            __in PGENERIC_MAPPING GenericMapping,
            __out_bcount( *PrivilegeSetLength ) PPRIVILEGE_SET PrivilegeSet,
            __inout PULONG PrivilegeSetLength,
            __out_ecount( ObjectTypeListLength ) PACCESS_MASK GrantedAccess,
            __out_ecount( ObjectTypeListLength ) PNTSTATUS AccessStatus
        );



    ///////////////////////////////////////////////////////////////////////
    //                                                                   //
    //               Token Object System Services                        //
    //                                                                   //
    ///////////////////////////////////////////////////////////////////////


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateToken(
            __out PHANDLE TokenHandle,
            __in ACCESS_MASK DesiredAccess,
            __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
            __in TOKEN_TYPE TokenType,
            __in PLUID AuthenticationId,
            __in PLARGE_INTEGER ExpirationTime,
            __in PTOKEN_USER User,
            __in PTOKEN_GROUPS Groups,
            __in PTOKEN_PRIVILEGES Privileges,
            __in_opt PTOKEN_OWNER Owner,
            __in PTOKEN_PRIMARY_GROUP PrimaryGroup,
            __in_opt PTOKEN_DEFAULT_DACL DefaultDacl,
            __in PTOKEN_SOURCE TokenSource
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCompareTokens(
            __in HANDLE FirstTokenHandle,
            __in HANDLE SecondTokenHandle,
            __out PBOOLEAN Equal
        );

    // begin_ntifs

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenThreadToken(
            __in HANDLE ThreadHandle,
            __in ACCESS_MASK DesiredAccess,
            __in BOOLEAN OpenAsSelf,
            __out PHANDLE TokenHandle
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenThreadTokenEx(
            __in HANDLE ThreadHandle,
            __in ACCESS_MASK DesiredAccess,
            __in BOOLEAN OpenAsSelf,
            __in ULONG HandleAttributes,
            __out PHANDLE TokenHandle
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenProcessToken(
            __in HANDLE ProcessHandle,
            __in ACCESS_MASK DesiredAccess,
            __out PHANDLE TokenHandle
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenProcessTokenEx(
            __in HANDLE ProcessHandle,
            __in ACCESS_MASK DesiredAccess,
            __in ULONG HandleAttributes,
            __out PHANDLE TokenHandle
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtDuplicateToken(
            __in HANDLE ExistingTokenHandle,
            __in ACCESS_MASK DesiredAccess,
            __in POBJECT_ATTRIBUTES ObjectAttributes,
            __in BOOLEAN EffectiveOnly,
            __in TOKEN_TYPE TokenType,
            __out PHANDLE NewTokenHandle
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtFilterToken(
            __in HANDLE ExistingTokenHandle,
            __in ULONG Flags,
            __in_opt PTOKEN_GROUPS SidsToDisable,
            __in_opt PTOKEN_PRIVILEGES PrivilegesToDelete,
            __in_opt PTOKEN_GROUPS RestrictedSids,
            __out PHANDLE NewTokenHandle
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtImpersonateAnonymousToken(
            __in HANDLE ThreadHandle
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtQueryInformationToken(
            __in HANDLE TokenHandle,
            __in TOKEN_INFORMATION_CLASS TokenInformationClass,
            __out_bcount_part_opt( TokenInformationLength, *ReturnLength ) PVOID TokenInformation,
            __in ULONG TokenInformationLength,
            __out PULONG ReturnLength
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtSetInformationToken(
            __in HANDLE TokenHandle,
            __in TOKEN_INFORMATION_CLASS TokenInformationClass,
            __in_bcount( TokenInformationLength ) PVOID TokenInformation,
            __in ULONG TokenInformationLength
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAdjustPrivilegesToken(
            __in HANDLE TokenHandle,
            __in BOOLEAN DisableAllPrivileges,
            __in_opt PTOKEN_PRIVILEGES NewState,
            __in_opt ULONG BufferLength,
            __out_bcount_part_opt( BufferLength, *ReturnLength ) PTOKEN_PRIVILEGES PreviousState,
            __out_opt PULONG ReturnLength
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAdjustGroupsToken(
            __in HANDLE TokenHandle,
            __in BOOLEAN ResetToDefault,
            __in PTOKEN_GROUPS NewState,
            __in_opt ULONG BufferLength,
            __out_bcount_part_opt( BufferLength, *ReturnLength ) PTOKEN_GROUPS PreviousState,
            __out PULONG ReturnLength
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtPrivilegeCheck(
            __in HANDLE ClientToken,
            __inout PPRIVILEGE_SET RequiredPrivileges,
            __out PBOOLEAN Result
        );


    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckAndAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in PUNICODE_STRING ObjectTypeName,
            __in PUNICODE_STRING ObjectName,
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in ACCESS_MASK DesiredAccess,
            __in PGENERIC_MAPPING GenericMapping,
            __in BOOLEAN ObjectCreation,
            __out PACCESS_MASK GrantedAccess,
            __out PNTSTATUS AccessStatus,
            __out PBOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckByTypeAndAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in PUNICODE_STRING ObjectTypeName,
            __in PUNICODE_STRING ObjectName,
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in_opt PSID PrincipalSelfSid,
            __in ACCESS_MASK DesiredAccess,
            __in AUDIT_EVENT_TYPE AuditType,
            __in ULONG Flags,
            __in_ecount_opt( ObjectTypeListLength ) POBJECT_TYPE_LIST ObjectTypeList,
            __in ULONG ObjectTypeListLength,
            __in PGENERIC_MAPPING GenericMapping,
            __in BOOLEAN ObjectCreation,
            __out PACCESS_MASK GrantedAccess,
            __out PNTSTATUS AccessStatus,
            __out PBOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckByTypeResultListAndAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in PUNICODE_STRING ObjectTypeName,
            __in PUNICODE_STRING ObjectName,
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in_opt PSID PrincipalSelfSid,
            __in ACCESS_MASK DesiredAccess,
            __in AUDIT_EVENT_TYPE AuditType,
            __in ULONG Flags,
            __in_ecount_opt( ObjectTypeListLength ) POBJECT_TYPE_LIST ObjectTypeList,
            __in ULONG ObjectTypeListLength,
            __in PGENERIC_MAPPING GenericMapping,
            __in BOOLEAN ObjectCreation,
            __out_ecount( ObjectTypeListLength ) PACCESS_MASK GrantedAccess,
            __out_ecount( ObjectTypeListLength ) PNTSTATUS AccessStatus,
            __out PBOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in HANDLE ClientToken,
            __in PUNICODE_STRING ObjectTypeName,
            __in PUNICODE_STRING ObjectName,
            __in PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in_opt PSID PrincipalSelfSid,
            __in ACCESS_MASK DesiredAccess,
            __in AUDIT_EVENT_TYPE AuditType,
            __in ULONG Flags,
            __in_ecount_opt( ObjectTypeListLength ) POBJECT_TYPE_LIST ObjectTypeList,
            __in ULONG ObjectTypeListLength,
            __in PGENERIC_MAPPING GenericMapping,
            __in BOOLEAN ObjectCreation,
            __out_ecount( ObjectTypeListLength ) PACCESS_MASK GrantedAccess,
            __out_ecount( ObjectTypeListLength ) PNTSTATUS AccessStatus,
            __out PBOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtOpenObjectAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in PUNICODE_STRING ObjectTypeName,
            __in PUNICODE_STRING ObjectName,
            __in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
            __in HANDLE ClientToken,
            __in ACCESS_MASK DesiredAccess,
            __in ACCESS_MASK GrantedAccess,
            __in_opt PPRIVILEGE_SET Privileges,
            __in BOOLEAN ObjectCreation,
            __in BOOLEAN AccessGranted,
            __out PBOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtPrivilegeObjectAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in HANDLE ClientToken,
            __in ACCESS_MASK DesiredAccess,
            __in PPRIVILEGE_SET Privileges,
            __in BOOLEAN AccessGranted
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCloseObjectAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in BOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtDeleteObjectAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in_opt PVOID HandleId,
            __in BOOLEAN GenerateOnClose
        );

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtPrivilegedServiceAuditAlarm(
            __in PUNICODE_STRING SubsystemName,
            __in PUNICODE_STRING ServiceName,
            __in HANDLE ClientToken,
            __in PPRIVILEGE_SET Privileges,
            __in BOOLEAN AccessGranted
        );

    // end_ntifs

#ifdef __cplusplus
}
#endif

#endif // _NTSEAPI_

