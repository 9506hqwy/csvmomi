namespace CsVmomi;

using System.IdentityModel.Selectors;
using System.ServiceModel;

internal class TokenClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager
{
    internal TokenClientCredentialsSecurityTokenManager(TokenClientCredentials clientCredentials)
        : base(clientCredentials)
    {
    }

    public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
    {
        var credentials = this.ClientCredentials as TokenClientCredentials;
        return new TokenSecurityTokenProvider(credentials!.Token);
    }
}
