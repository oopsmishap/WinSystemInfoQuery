#pragma once

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm?ts=0,79

class SystemHandleInformationQuery :
    public WinSystemInfoQuery<SYSTEM_HANDLE_INFORMATION>
{
public:
    SystemHandleInformationQuery() :
        WinSystemInfoQuery<SYSTEM_HANDLE_INFORMATION>
        ( SYSTEMINFOCLASS::SystemHandleInformation )
    {}

    //************************************
    // Method:      get_eprocess
    // FullName:    SystemHandleInformationQuery::get_eprocess
    // Access:      public 
    // Returns:     PVOID
    // Qualifier:  
    // Parameter:   USHORT pid
    // Description: *Should* get EProcess address of given pid
    //              (testing on win11, ObjectTypeIndex values might of changed)
    //************************************
    void* get_eprocess( USHORT pid )
    {
        auto* buffer = get();

        for( auto i = 0u; i < buffer->NumberOfHandles; i++ )
        {
            auto handle = buffer->Handles[ i ];

            if( pid == handle.UniqueProcessId && handle.ObjectTypeIndex == SYSTEM_HANDLE_TYPE::PROCESS )
            {
                return handle.Object;
            }
        }

        return nullptr;
    }

    //************************************
    // Method:      print_info
    // FullName:    SystemHandleInformationQuery::print_info
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: Prints all info on all handles
    //************************************
    void print_info()
    {
        auto buffer = get();

        for( auto i = 0u; i < buffer->NumberOfHandles; i++ )
        {
            auto handle = buffer->Handles[ i ];

            fmt::println( "UniqueProcessId: {}", uint64_t( handle.UniqueProcessId ) );
            fmt::println( "- ObjectTypeIndex:  {}", uint8_t( handle.ObjectTypeIndex ) );
            fmt::println( "- HandleAttributes: {}", uint8_t( handle.HandleAttributes ) );
            fmt::println( "- HandleValue:      {:#x}", uint16_t( handle.HandleValue ) );
            fmt::println( "- Object:           {}", handle.Object );
            fmt::println( "- GrantedAccess:    {:#x}", uint32_t( handle.GrantedAccess ) );
            fmt::println( "" );
        }
    }

    //************************************
    // Method:      print_eprocesses
    // FullName:    SystemHandleInformationQuery::print_eprocesses
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: *Should* print all EProcess's addresses
    //              (testing on win11, ObjectTypeIndex values might of changed)
    //************************************
    void print_eprocesses()
    {
        auto buffer = get();

        for( auto i = 0u; i < buffer->NumberOfHandles; i++ )
        {
            auto handle = buffer->Handles[ i ];

            if( handle.ObjectTypeIndex != SYSTEM_HANDLE_TYPE::PROCESS )
                continue;

            fmt::println( "UniqueProcessId: {}", uint64_t( handle.UniqueProcessId ) );
            fmt::println( "- ObjectTypeIndex:  {}", uint8_t( handle.ObjectTypeIndex ) );
            fmt::println( "- HandleAttributes: {}", uint8_t( handle.HandleAttributes ) );
            fmt::println( "- HandleValue:      {:#x}", uint16_t( handle.HandleValue ) );
            fmt::println( "- EProcess:         {}", handle.Object );
            fmt::println( "- GrantedAccess:    {:#x}", uint32_t( handle.GrantedAccess ) );
            fmt::println( "" );
        }
    }

    //************************************
    // Method:      print_own_eprocess
    // FullName:    SystemHandleInformationQuery::print_own_eprocess
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: *Should* print EProcess addresses of current process
    //              (testing on win11, ObjectTypeIndex values might of changed)
    //************************************
    void print_own_eprocess()
    {
        auto buffer = get();
        auto pid = GetCurrentProcessId();
        auto own_handle = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );

        for( auto i = 0u; i < buffer->NumberOfHandles; i++ )
        {
            auto handle = buffer->Handles[ i ];

            if( handle.UniqueProcessId != static_cast< USHORT >( pid ) )
                continue;

            fmt::println( "UniqueProcessId: {}", uint64_t( handle.UniqueProcessId ) );
            fmt::println( "- CreatorBackTraceIndex: {}", uint16_t( handle.CreatorBackTraceIndex ) );
            fmt::println( "- ObjectTypeIndex:       {}", uint8_t( handle.ObjectTypeIndex ) );
            fmt::println( "- HandleAttributes:      {}", uint8_t( handle.HandleAttributes ) );
            fmt::println( "- HandleValue:           {:#x}", uint16_t( handle.HandleValue ) );
            fmt::println( "- EProcess:              {}", handle.Object );
            fmt::println( "- GrantedAccess:         {:#x}", uint32_t( handle.GrantedAccess ) );
            fmt::println( "" );
        }
    }
};