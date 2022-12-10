namespace VimService
{
    using System.Xml.Serialization;

    [XmlTypeAttribute(Namespace = "urn:vim25")]
    public enum HttpNfcLeaseState
    {
        initializing,
        ready,
        done,
        error,
    }
}
