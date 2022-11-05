#pragma once

#include <Windows.h>
#include <vector>
#include "ntdll/ntdll.h"

template< class T >
class WinTokenInfoQuery
{
private:
    bool                        _initialised;
    std::vector< uint8_t >      _buffer;
    HANDLE                      _token_handle;
    TOKEN_INFORMATION_CLASS     _ti;

public:
    WinTokenInfoQuery( TOKEN_INFORMATION_CLASS tokeninfo_class, HANDLE token_handle ) :
        _initialised( false ),
        _ti( tokeninfo_class ),
        _token_handle( token_handle )
    {}

    NTSTATUS exec()
    {
        NTSTATUS status;
        ULONG return_size;

        // set up an initial buffer size
        ULONG buffer_size = ( ULONG )max( _buffer.size(), 0x1000 );

        // loop until the output buffer size is correct
        do
        {
            // reserve the buffer size
            _buffer.reserve( buffer_size );

            // carry out the query
            status = NtQueryInformationToken(
                _token_handle,
                _ti,
                _buffer.data(),
                buffer_size,
                &return_size
            );

            // if status returns invalid buffer size then we set
            // buffer size to the return size then loop through again
            if( status == STATUS_INFO_LENGTH_MISMATCH )
            {
                buffer_size = return_size;
            }
        }
        while( status == STATUS_INFO_LENGTH_MISMATCH );

        // set init to output of NT_SUCCESS
        _initialised = NT_SUCCESS( status );

        return status;
    }

    T* get()
    {
        return _initialised ? ( T* )_buffer.data() : nullptr;
    }
};