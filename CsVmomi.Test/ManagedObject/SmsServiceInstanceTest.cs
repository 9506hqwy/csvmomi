namespace CsVmomi.Test;

[TestClass]
public class SmsServiceInstanceTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
        this.session.SetSmsClient();
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
    public void QueryAboutInfo()
    {
        var info = this.session.SmsServiceInstance!.QueryAboutInfo().Result;
        Assert.IsNotNull(info);
    }

    [TestMethod]
    public void QueryStorageManager()
    {
        var manager = this.session.SmsServiceInstance!.QueryStorageManager().Result;
        Assert.IsNotNull(manager);
    }
}
