#pragma once

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/pagefile.htm

class SystemPageFileInfomationQuery :
    public WinSystemInfoQuery<SYSTEM_PAGEFILE_INFORMATION>
{
public:
    SystemPageFileInfomationQuery() :
        WinSystemInfoQuery<SYSTEM_PAGEFILE_INFORMATION>
        ( SYSTEMINFOCLASS::SystemPageFileInformation )
    {}

    //************************************
    // Method:      print_info
    // FullName:    SystemPageFileInfomationQuery::print_info
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: Prints info about Page Files
    //************************************
    void print_info()
    {
        auto* buffer = get();

        do
        {
            fmt::println( L"{}", ( wchar_t* )buffer->PageFileName.Buffer );
            fmt::println( "- TotalSize:       {:#x}", buffer->TotalSize );
            fmt::println( "- PeakUsage:       {:#x}", buffer->PeakUsage );
            fmt::println( "- TotalInUse:      {:#x}", buffer->TotalInUse );
            fmt::println( "- NextEntryOffset: {:#x}", buffer->NextEntryOffset );

            if( buffer->NextEntryOffset == 0 )
                break;
        }
        while( buffer = reinterpret_cast< PSYSTEM_PAGEFILE_INFORMATION >(
            reinterpret_cast< uint8_t* >( buffer ) + buffer->NextEntryOffset ) );
    }
};