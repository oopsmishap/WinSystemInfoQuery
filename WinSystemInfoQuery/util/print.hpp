#pragma once
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/xchar.h>

namespace fmt
{
    //************************************
    // Method:      println
    // FullName:    fmt::println
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Parameter:   format_string<Args...> & & fmt_str
    // Parameter:   Args & & ... args
    // Description: Wrapper function for print to append newline
    //************************************
    template <typename... Args>
    void println( fmt::format_string<Args...>&& fmt_str, Args&&... args )
    {
        fmt::print( "{}\n", fmt::format(
            std::forward<fmt::format_string<Args...>>( fmt_str ), std::forward<Args>( args )... ) );
    }


    //************************************
    // Method:      println
    // FullName:    fmt::println
    // Access:      public 
    // Returns:     void
    // Qualifier:  
    // Parameter:   wformat_string<Args...> & & fmt_str
    // Parameter:   Args & & ... args
    // Description: Wrapper function for print to append newline
    //************************************
    template <typename... Args>
    void println( fmt::wformat_string<Args...>&& fmt_str, Args&&... args )
    {
        fmt::print( L"{}\n", fmt::format(
            std::forward<fmt::wformat_string<Args...>>( fmt_str ), std::forward<Args>( args )... ) );
    }
}