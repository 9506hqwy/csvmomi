namespace CsVmomi;

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

internal class TokenSecurityTokenProvider : SecurityTokenProvider
{
    private readonly SecurityToken token;

    internal TokenSecurityTokenProvider(SecurityToken token)
    {
        this.token = token;
    }

    protected override SecurityToken GetTokenCore(TimeSpan timeout)
    {
        return this.token;
    }
}
