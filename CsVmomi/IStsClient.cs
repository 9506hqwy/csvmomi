namespace CsVmomi;

using StsService;

public interface IStsClient
{
    public Uri Uri { get; }

    public string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Issue(RequestSecurityTokenType requestSecurityToken);

    System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Renew(RequestSecurityTokenType requestSecurityToken);

    System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Validate(RequestSecurityTokenType requestSecurityToken);

    System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Challenge(RequestSecurityTokenResponseType requestSecurityTokenResponse);
}
