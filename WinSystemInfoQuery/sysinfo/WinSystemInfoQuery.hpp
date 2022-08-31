#pragma once

#include <Windows.h>
#include <vector>
#include "ntdll/ntdll.h"

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm

// base class to setup NtQuerySystemInformation
// class template input is the output structure of the query
// input of the class is the enum class ID of the query carried out
template< class T >
class WinSystemInfoQuery
{
private:
    bool                        _initialised;
    SYSTEM_INFORMATION_CLASS    _si;
    std::vector< uint8_t >      _buffer;

public:
    WinSystemInfoQuery( SYSTEM_INFORMATION_CLASS sysinfo_class ) :
        _initialised( false ),
        _si( sysinfo_class )
    {}

    //************************************
    // Method:      exec
    // FullName:    WinSystemInfoQuery<T>::exec
    // Access:      public 
    // Returns:     NTSTATUS
    // Qualifier:  
    // Description: Collects the given system info class and stores within buffer
    //************************************
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
            status = NtQuerySystemInformation(
                _si,
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

    //************************************
    // Method:      get
    // FullName:    WinSystemInfoQuery<T>::get
    // Access:      public 
    // Returns:     T* or nullptr
    // Qualifier:  
    // Description: simple template get function that will return the buffer as the template buffer
    //************************************
    T* get()
    {
        return _initialised ? ( T* )_buffer.data() : nullptr;
    }
};