namespace CsVmomi;

using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;

internal class SessionCookieMessageInspector : IClientMessageInspector
{
    private readonly string? sessionCookie;

    internal SessionCookieMessageInspector(string? sessionCookie)
    {
        this.sessionCookie = sessionCookie;
    }

    public void AfterReceiveReply(ref Message reply, object correlationState)
    {
    }

    public object? BeforeSendRequest(ref Message request, IClientChannel channel)
    {
        if (!string.IsNullOrWhiteSpace(this.sessionCookie))
        {
            request.Headers.Add(MessageHeader.CreateHeader(
                "vcSessionCookie",
                string.Empty,
                this.sessionCookie));
        }

        return null;
    }
}
