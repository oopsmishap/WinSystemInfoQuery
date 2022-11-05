#pragma once

class TokenPrivilegesQuery :
    public WinTokenInfoQuery<TOKEN_PRIVILEGES>
{
public:
    TokenPrivilegesQuery( HANDLE token_handle ) :
        WinTokenInfoQuery<TOKEN_PRIVILEGES>
        ( TOKEN_INFORMATION_CLASS::TokenPrivileges, token_handle )
    {}

    void print_info()
    {
        auto buffer = get();

        for( auto i = 0u; i < buffer->PrivilegeCount; i++ )
        {
            auto* priv = &buffer->Privileges[ i ];

            auto name = utils::get_luid_name( &priv->Luid );
            
            fmt::println( "Luid Name: {}", name );
            fmt::println( " - Attributes: {}", priv->Attributes );
            uint64_t luid = ( ( uint64_t )priv->Luid.HighPart << 32 ) | priv->Luid.LowPart;
            fmt::println( " - Luid: 0x{:x}", luid );
        }
    }
};