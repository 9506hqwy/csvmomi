namespace CsVmomi;

using StsService;
using System.ServiceModel.Channels;

public class StsClient : IStsClient
{
    private readonly STSService_PortTypeClient inner;

    internal StsClient(STSService_PortTypeClient inner)
    {
        this.inner = inner;
    }

    public Uri Uri => this.inner.Endpoint.Address.Uri;

    public string? GetCookie(string name)
    {
        return this.GetCookie()?
            .OfType<System.Net.Cookie>()
            .FirstOrDefault(c => c.Name == name)?
            .Value;
    }

    public System.Net.CookieCollection? GetCookie()
    {
        return this.inner.InnerChannel.GetProperty<IHttpCookieContainerManager>()?
            .CookieContainer
            .GetCookies(this.Uri);
    }

    public void SetCookie(System.Net.CookieCollection? cookie)
    {
        var container = this.inner.InnerChannel
            .GetProperty<IHttpCookieContainerManager>()!
            .CookieContainer;

        foreach (var c in cookie.OfType<System.Net.Cookie>())
        {
            container.Add(new System.Net.Cookie(c.Name, c.Value, this.Uri.AbsolutePath, this.Uri.Host));
        }
    }

    public async System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Issue(RequestSecurityTokenType requestSecurityToken)
    {
        var res = await this.inner.IssueAsync(requestSecurityToken);
        return res.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse;
    }

    public async System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Renew(RequestSecurityTokenType requestSecurityToken)
    {
        var res = await this.inner.RenewAsync(requestSecurityToken);
        return res.RequestSecurityTokenResponse;
    }

    public async System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Validate(RequestSecurityTokenType requestSecurityToken)
    {
        var res = await this.inner.ValidateAsync(requestSecurityToken);
        return res.RequestSecurityTokenResponse;
    }

    public async System.Threading.Tasks.Task<RequestSecurityTokenResponseType> Challenge(RequestSecurityTokenResponseType requestSecurityTokenResponse)
    {
        var res = await this.inner.ChallengeAsync(requestSecurityTokenResponse);
        return res.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse;
    }
}
