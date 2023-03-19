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
        ServiceEndpoint serviceEndpoint,
        BindingParameterCollection bindingParameters)
    {
    }

    public void ApplyClientBehavior(
        ServiceEndpoint serviceEndpoint,
        ClientRuntime behavior)
    {
        behavior.ClientMessageInspectors.Add(
            new FixupMessageInspector(this.tool));
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
