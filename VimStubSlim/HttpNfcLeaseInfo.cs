namespace VimService
{
    using System.Xml.Serialization;

    public partial class HttpNfcLeaseInfo : DynamicData
    {
        [XmlElementAttribute(Order = 6)]
        public HttpNfcLeaseState leaseState { get; set; }
    }
}
