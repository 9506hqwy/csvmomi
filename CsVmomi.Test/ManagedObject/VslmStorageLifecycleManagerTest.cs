namespace CsVmomi.Test;

[TestClass]
public class VslmStorageLifecycleManagerTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
        this.session.SetVslmClient().Wait();
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
    public void VslmQueryDatastoreInfo()
    {
        var ds = this.session.RootFolder.FindFirst<Datastore>().Result;
        var info = ds!.GetPropertyInfo().Result;
        var results = this.session.VslmStorageLifecycleManager!.VslmQueryDatastoreInfo(info.url).Result;
        Assert.IsNotNull(results);
    }

    [TestMethod]
    public void VslmSyncDatastore()
    {
        var ds = this.session.RootFolder.FindFirst<Datastore>().Result;
        var info = ds!.GetPropertyInfo().Result;
        this.session.VslmStorageLifecycleManager!.VslmSyncDatastore(info.url, false, null).Wait();
    }
}
