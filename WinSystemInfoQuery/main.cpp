#include "sysinfo/sysinfo.hpp"
#include "tokeninfo/tokeninfo.hpp"

#define NT_FUNC_FAILURE( s, n ) \
    do {                                                        \
        if( !NT_SUCCESS( s ) )                                  \
        {                                                       \
            fmt::println( "Failed {}: {}!", n, s );             \
            exit(1);                                            \
        }                                                       \
    }                                                           \
    while(0)

int main( int argc, char* argv[] )
{
    BOOLEAN old;
    NTSTATUS status;

    status = RtlAdjustPrivilege( SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old );
    status |= RtlAdjustPrivilege( SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old );

    if( !NT_SUCCESS( status ) )
    {
        fmt::println( "Failed to adjust privilege levels!" );
    }

    fmt::println( "NtQuerySystemInformation playground" );

    /*
     * ----------------------------------------------
     * SystemHandleInformation
     * ----------------------------------------------
     */

    /*SystemHandleInformationQuery handleinfo_query;

    NT_FUNC_FAILURE( handleinfo_query.exec(), "SystemHandleInformationQuery" );

    handleinfo_query.print_info();*/

    /*
     * ----------------------------------------------
     * SystemModuleInformation
     * ----------------------------------------------
     */

     //SystemModuleInformationQuery moduleinfo_query;

     //NT_FUNC_FAILURE( moduleinfo_query.exec(), "SystemModuleInformationQuery" );

     //moduleinfo_query.print_info();

    /*
     * ----------------------------------------------
     * SystemExtendedProcessInformation
     * ----------------------------------------------
     */

     //SystemExtendedProcessInformationQuery processinfo_ex_query;

     //NT_FUNC_FAILURE( processinfo_ex_query.exec(), "SystemExtendedProcessInformationQuery" );

     //processinfo_ex_query.print_info();

    /*
     * ----------------------------------------------
     * SystemProcessInformation
     * ----------------------------------------------
     */

     //SystemProcessInformationQuery processinfo_query;

     //NT_FUNC_FAILURE( processinfo_query.exec(), "SystemProcessInformationQuery" );

     //processinfo_query.print_info();

    /*
     * ----------------------------------------------
     * SystemPageFileInformation
     * ----------------------------------------------
     */

     //SystemPageFileInfomationQuery pagefileinfo_query;

     //NT_FUNC_FAILURE( pagefileinfo_query.exec(), "SystemPageFileInfomationQuery" );

     //pagefileinfo_query.print_info();

    /*
     * ----------------------------------------------
     * TokenPrivilleges
     * ----------------------------------------------
     */

    HANDLE token_handle;

    NT_FUNC_FAILURE( 
        NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &token_handle ), 
        "Failed to get token" 
    );

    TokenPrivilegesQuery token_priv_query( token_handle );

    NT_FUNC_FAILURE( token_priv_query.exec(), "TokenPrivilegesQuery" );

    token_priv_query.print_info();
}