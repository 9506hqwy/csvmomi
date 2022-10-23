namespace CsVmomi.Test;

using System.ServiceModel;
using System.Text;

[TestClass]
public class FixupTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
        this.session.MessageToolBox.Fixup = null;
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (this.session != null)
        {
            this.session.MessageToolBox.Fixup = null;
            this.session.SessionManager!.Logout().Wait();
        }
    }

    [TestMethod]
    public void FixupNamespaceNotPreserve()
    {
        var vm = this.session.RootFolder.FindFirst<VirtualMachine>().Result;

        var host = vm!.FindFirstUpper<HostSystem>().Result;
        var configManager = host!.GetPropertyConfigManager().Result;
        var system = ManagedObject.Create<HostDatastoreSystem>(configManager.datastoreSystem, this.session);

        var ds = vm!.FindFirstUpper<Datastore>().Result;

        this.session.MessageToolBox.Fixup = Fixup.FixupNamespaceNotPreserve();

        try
        {
            system!.RemoveDatastore(ds!).Wait();
            Assert.Fail();
        }
        catch (AggregateException e) when (e.InnerException is FaultException<VimService.ResourceInUse> fault)
        {
            var inUse = fault.Detail;
            Assert.IsNotNull(inUse.name);

            var msg = inUse.faultMessage?.FirstOrDefault();
            if (msg != null)
            {
                foreach (var arg in msg.arg)
                {
                    Assert.IsNotNull(arg.key);
                    Assert.IsTrue(arg.value is string);
                }
            }
        }
    }
}
