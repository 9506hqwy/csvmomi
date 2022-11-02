namespace CsVmomi;

using StsService;
using System.Xml;

public static class Sso
{
    public static async System.Threading.Tasks.Task<RequestSecurityTokenResponseType> GetBearerToken(
        Session session,
        TimeSpan duration)
    {
        var requestSecurityToken = Sso.CreateIssueRequest(duration);
        return await session.StsClient!.Issue(requestSecurityToken);
    }

    private static RequestSecurityTokenType CreateIssueRequest(TimeSpan duration)
    {
        var created = DateTime.UtcNow;
        var expires = created.Add(duration);

        return new RequestSecurityTokenType
        {
            TokenType = TokenTypeEnum.urnoasisnamestcSAML20assertion,
            TokenTypeSpecified = true,
            RequestType = RequestTypeEnum.httpdocsoasisopenorgwssxwstrust200512Issue,
            Lifetime = new LifetimeType
            {
                Created = new AttributedDateTime
                {
                    Value = XmlConvert.ToString(created, "yyy-MM-ddTHH:mm:ss.fffZ"),
                },
                Expires = new AttributedDateTime
                {
                    Value = XmlConvert.ToString(expires, "yyy-MM-ddTHH:mm:ss.fffZ"),
                },
            },
            KeyType = KeyTypeEnum.httpdocsoasisopenorgwssxwstrust200512Bearer,
            KeyTypeSpecified = true,
            SignatureAlgorithm = SignatureAlgorithmEnum.httpwwww3org200104xmldsigmorersasha256,
            SignatureAlgorithmSpecified = true,
        };
    }
}
