#pragma once

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm

class SystemProcessInformationQuery :
    public WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION>
{
public:
    SystemProcessInformationQuery() :
        WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION>
        ( SYSTEMINFOCLASS::SystemProcessInformation )
    {}

    //************************************
    // Method:      get_proc_id
    // FullName:    SystemProcessInformationQuery::get_proc_id
    // Access:      public 
    // Returns:     PVOID
    // Qualifier:  
    // Parameter:   const std::wstring & name
    // Description: Gets process UniqueProcessId given process name
    //************************************
    PVOID get_proc_id( const std::wstring& name )
    {
        auto* buffer = get();

        while( buffer->NextEntryOffset )
        {
            if( !buffer->ImageName.Buffer )
            {
                buffer = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >(
                    reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset );

                continue;
            }

            if( name == buffer->ImageName.Buffer )
            {
                return buffer->UniqueProcessId;
            }

            buffer = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >(
                reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset );
        }
    }

    //************************************
    // Method:      print_info
    // FullName:    SystemProcessInformationQuery::print_info
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: Prints UniqueProcessId & ImageName for each process
    //************************************
    void print_info()
    {
        auto* buffer = get();

        while( buffer->NextEntryOffset )
        {
            if( !buffer->ImageName.Buffer )
            {
                buffer = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >(
                    reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset );

                continue;
            }

            fmt::println( L"{}", ( wchar_t* )buffer->ImageName.Buffer );
            fmt::println( "- UniqueProcessId: {}", uint64_t( buffer->UniqueProcessId ) );
            fmt::println( "" );

            buffer = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION >(
                reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset );
        }
    }
};