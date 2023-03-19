namespace CsVmomi;

using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

internal class SessionCookieBehavior : IEndpointBehavior
{
    private readonly string? sessionCookie;

    internal SessionCookieBehavior(string? sessionCookie)
    {
        this.sessionCookie = sessionCookie;
    }

    public void AddBindingParameters(
        ServiceEndpoint serviceEndpoint,
        BindingParameterCollection bindingParameters)
    {
    }

    public void ApplyClientBehavior(
        ServiceEndpoint serviceEndpoint,
        ClientRuntime behavior)
    {
        behavior.ClientMessageInspectors.Add(
            new SessionCookieMessageInspector(this.sessionCookie));
    }

    public void ApplyDispatchBehavior(
        ServiceEndpoint serviceEndpoint,
        EndpointDispatcher endpointDispatcher)
    {
    }

    public void Validate(ServiceEndpoint serviceEndpoint)
    {
    }
}
