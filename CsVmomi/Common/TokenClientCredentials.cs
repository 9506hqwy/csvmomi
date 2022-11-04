namespace CsVmomi;

using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Description;

internal class TokenClientCredentials : ClientCredentials
{
    internal TokenClientCredentials(SecurityToken token)
        : base()
    {
        this.Token = token;
    }

    protected TokenClientCredentials(TokenClientCredentials other)
        : base(other)
    {
        this.Token = other.Token;
    }

    internal SecurityToken Token { get; }

    public override SecurityTokenManager CreateSecurityTokenManager()
    {
        return new TokenClientCredentialsSecurityTokenManager(this);
    }

    protected override ClientCredentials CloneCore()
    {
        return new TokenClientCredentials(this);
    }
}
