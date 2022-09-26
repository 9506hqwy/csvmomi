namespace CsVmomi.Test;

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
    public void PropertyCollector()
    {
        var mo = this.session.PropertyCollector;
        Assert.IsNotNull(mo);

        var filter = mo.GetPropertyFilter().Result;
        Assert.IsNotNull(filter);
    }

    [TestMethod]
    public void RootFolder()
    {
        var root = this.session.RootFolder;
        Assert.IsNotNull(root);

        var rootName = root.GetPropertyName().Result;
        Assert.AreEqual("root", rootName);

        var children = root.GetPropertyChildEntity().Result;
        Assert.IsNotNull(children);
    }
}
