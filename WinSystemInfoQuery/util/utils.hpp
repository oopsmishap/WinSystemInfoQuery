#pragma once
#include <Windows.h>
#include <string>

namespace utils
{
    std::string get_luid_name( LUID* luid )
    {
        std::string ret_string = "";
        DWORD retSize = 0;

        LookupPrivilegeNameA( nullptr, luid, nullptr, &retSize );
        if( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
        {
            char* name = ( char* )LocalAlloc( LPTR, retSize );
            if( name && LookupPrivilegeNameA( nullptr, luid, name, &retSize ) )
            {
                ret_string = name;
            }
        }

        return ret_string;
    }
}