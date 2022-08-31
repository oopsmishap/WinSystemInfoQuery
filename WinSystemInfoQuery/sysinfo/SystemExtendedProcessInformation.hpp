#pragma once

class SystemExtendedProcessInformationQuery :
    public WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION_EX>
{
public:
    SystemExtendedProcessInformationQuery() :
        WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION_EX>
        ( SYSTEMINFOCLASS::SystemExtendedProcessInformation )
    {}

    //************************************
    // Method:      print_info
    // FullName:    SystemExtendedProcessInformationQuery::print_info
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: Prints out some, not all, of PSYSTEM_PROCESS_INFORMATION_EX struct
    //************************************
    void print_info()
    {
        auto* buffer = get();

        while( buffer->NextEntryOffset )
        {
            if( buffer->ImageName.Buffer == NULL )
            {
                buffer = reinterpret_cast< PSYSTEM_PROCESS_INFORMATION_EX >(
                    reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset );

                continue;
            }

            fmt::println( L"{}", ( wchar_t* )buffer->ImageName.Buffer );
            fmt::println( "- UniqueProcessId:  {}", ( uint64_t )buffer->UniqueProcessId );
            fmt::println( "- SessionId:        {}", buffer->SessionId );
            fmt::println( "- HandleCount:      {}", buffer->HandleCount );
            fmt::println( "- Parent Pid:       {}", ( uint64_t )buffer->InheritedFromUniqueProcessId );
            fmt::println( "- UniqueProcessKey: {}", buffer->UniqueProcessKey );
            fmt::println( "- PeakVirtualSize:  {}", ( void* )buffer->PeakVirtualSize );
            fmt::println( "- VirtualSize:      {}", ( void* )buffer->VirtualSize );
            fmt::println( "- NumberOfThreads:  {}", buffer->NumberOfThreads );

            for( auto i = 0u; i < buffer->NumberOfThreads; i++ )
            {
                auto thread = buffer->Threads[ i ];
                fmt::println( "-- Thread:                            {}", i );
                fmt::println( "-- ThreadInfo.ClientId.UniqueThread:  {}", ( uint64_t )thread.ThreadInfo.ClientId.UniqueThread );
                fmt::println( "-- ThreadInfo.ClientId.UniqueProcess: {}", ( uint64_t )thread.ThreadInfo.ClientId.UniqueProcess );
            }

            fmt::println( "" );

            buffer = ( PSYSTEM_PROCESS_INFORMATION_EX )(
                ( BYTE* )buffer + buffer->NextEntryOffset );
        }
    }
};