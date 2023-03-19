namespace CsVmomi.Test;

[TestClass]
public class EsxAgentManagerTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
        this.session.SetEamClient();
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
    [Ignore]
    public void GetPropertyAgency()
    {
        var agencies = this.session.EsxAgentManager!.GetPropertyAgency().Result;
        Assert.IsNotNull(agencies);
    }

    [TestMethod]
    [Ignore]
    public void GetPropertyIssue()
    {
        var issues = this.session.EsxAgentManager!.GetPropertyIssue().Result;
        Assert.IsNotNull(issues);
    }

    [TestMethod]
    public void QueryAgency()
    {
        var agencies = this.session.EsxAgentManager!.QueryAgency().Result;
        Assert.IsNotNull(agencies);
    }

    [TestMethod]
    public void ScanForUnknownAgentVm()
    {
        this.session.EsxAgentManager!.ScanForUnknownAgentVm().Wait();
    }

    [TestMethod]
    public void SetMaintenanceModePolicy()
    {
        this.session.EsxAgentManager!.SetMaintenanceModePolicy("singleHost").Wait();
    }
}
