namespace CsVmomi.Test;

using System.Text;

[TestClass]
public class SessionTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (this.session != null)
        {
            this.session.SessionManager!.Logout().Wait();
        }
    }

    [TestMethod]
    public void MessageToolBox()
    {
        string? envelope = null;
        this.session.MessageToolBox.Fixup = (source) =>
        {
            envelope = Encoding.UTF8.GetString(source);
            return source;
        };
        Assert.IsNotNull(this.session.RootFolder.FindFirst<Datacenter>().Result);
        Assert.IsNotNull(envelope);
    }

    [TestMethod]
    public void EamServiceContent()
    {
        this.session.SetEamClient();
        Assert.IsNotNull(this.session.EsxAgentManager);
    }

    [TestMethod]
    public void PbmServiceContent()
    {
        this.session.SetPbmClient().Wait();
        Assert.IsNotNull(this.session.PbmAboutInfo);
        Assert.IsNotNull(this.session.PbmCapabilityMetadataManager);
        Assert.IsNotNull(this.session.PbmComplianceManager);
        Assert.IsNotNull(this.session.PbmPlacementSolver);
        Assert.IsNotNull(this.session.PbmProfileManager);
        Assert.IsNotNull(this.session.PbmReplicationManager);
        Assert.IsNotNull(this.session.PbmSessionManager);
    }

    [TestMethod]
    public void SmsServiceInstance()
    {
        this.session.SetSmsClient();
        Assert.IsNotNull(this.session.SmsServiceInstance);
    }

    [TestMethod]
    public void SoapSessionId()
    {
        Assert.IsNotNull(this.session.SoapSessionId);
    }

    [TestMethod]
    public void VslmServiceContent()
    {
        this.session.SetVslmClient().Wait();
        Assert.IsNotNull(this.session.VslmAboutInfo);
        Assert.IsNotNull(this.session.VslmSessionManager);
        Assert.IsNotNull(this.session.VslmStorageLifecycleManager);
        Assert.IsNotNull(this.session.VslmVStorageObjectManager);
    }
}
