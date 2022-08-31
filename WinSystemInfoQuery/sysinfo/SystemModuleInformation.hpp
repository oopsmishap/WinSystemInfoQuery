#pragma once

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/process_modules.htm
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/rtl/ldrreloc/process_module_information.htm

class SystemModuleInformationQuery :
    public WinSystemInfoQuery<RTL_PROCESS_MODULES>
{
public:
    SystemModuleInformationQuery() :
        WinSystemInfoQuery<RTL_PROCESS_MODULES>
        ( SYSTEMINFOCLASS::SystemModuleInformation )
    {}

    //************************************
    // Method:      find_module
    // FullName:    SystemModuleInformationQuery::find_module
    // Access:      public 
    // Returns:     bool
    // Qualifier:  
    // Parameter:   const std::string & name
    // Parameter:   RTL_PROCESS_MODULE_INFORMATION & info_out
    // Description: Find a certain module and get info of module back
    //************************************
    bool find_module
    (
        const std::string& name,
        RTL_PROCESS_MODULE_INFORMATION& info_out
    )
    {
        auto* buffer = get();

        for( auto i = 0u; i < buffer->NumberOfModules; i++ )
        {
            auto* info = &buffer->Modules[ i ];
            auto* file_name = info->FullPathName + info->OffsetToFileName;

            if( name == reinterpret_cast< char* >( file_name ) )
            {
                info_out = *info;
                return true;
            }
        }

        return false;
    }

    //************************************
    // Method:      print_info
    // FullName:    SystemModuleInformationQuery::print_info
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Description: Prints all info of all modules
    //************************************
    void print_info()
    {
        auto* buffer = get();

        for( auto i = 0u; i < buffer->NumberOfModules; i++ )
        {
            auto* info = &buffer->Modules[ i ];

            auto* file_name = info->FullPathName + info->OffsetToFileName;

            fmt::println( "{}", ( char* )file_name );
            fmt::println( "- file path:   {}", ( char* )info->FullPathName );
            fmt::println( "- mapped base: {}", fmt::ptr( info->MappedBase ) );
            fmt::println( "- image base:  {}", fmt::ptr( info->ImageBase ) );
            fmt::println( "- image size:  {:#x}", info->ImageSize );
            fmt::println( "- flags:       {:#x}", info->Flags );
            fmt::println( "" );
        }
    }
};