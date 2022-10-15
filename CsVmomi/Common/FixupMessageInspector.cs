namespace CsVmomi;

using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.Xml;

public class FixupMessageInspector : IClientMessageInspector
{
    private readonly MessageToolBox tool;

    internal FixupMessageInspector(MessageToolBox tool)
    {
        this.tool = tool;
    }

    public void AfterReceiveReply(ref Message reply, object correlationState)
    {
        if (this.tool.Fixup == null)
        {
            return;
        }

        var tmp = reply;
        using (tmp)
        {
            var source = this.ConvertToByteFrom(tmp);
            var destination = this.tool.Fixup(source);

            reply = this.CreateMessageFrom(destination, tmp);
        }
    }

    public object? BeforeSendRequest(ref Message request, IClientChannel channel)
    {
        return null;
    }

    private byte[] ConvertToByteFrom(Message message)
    {
        using var mem = new MemoryStream();

        using (var writer = XmlWriter.Create(mem))
        {
            message.WriteMessage(writer);
            writer.Flush();
        }

        return mem.ToArray();
    }

    private Message CreateMessageFrom(byte[] envelope, Message source)
    {
        // not close.
        var mem = new MemoryStream(envelope);
        var reader = XmlReader.Create(mem);
        var newMessage = Message.CreateMessage(reader, int.MaxValue, source.Version);
        newMessage.Properties.Clear();
        newMessage.Properties.CopyProperties(source.Properties);
        return newMessage;
    }
}
