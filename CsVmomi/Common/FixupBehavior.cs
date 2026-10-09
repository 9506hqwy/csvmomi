namespace CsVmomi;

using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

public class FixupBehavior : IEndpointBehavior
{
    private readonly MessageToolBox tool;

    internal FixupBehavior(MessageToolBox tool)
    {
        this.tool = tool;
    }

    public void AddBindingParameters(
        ServiceEndpoint endpoint,
        BindingParameterCollection bindingParameters)
    {
    }

    public void ApplyClientBehavior(
        ServiceEndpoint endpoint,
        ClientRuntime clientRuntime)
    {
        clientRuntime.ClientMessageInspectors.Add(
            new FixupMessageInspector(this.tool));
    }

    public void ApplyDispatchBehavior(
        ServiceEndpoint endpoint,
        EndpointDispatcher endpointDispatcher)
    {
    }

    public void Validate(ServiceEndpoint endpoint)
    {
    }
}
