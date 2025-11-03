namespace CsVmomi.Test;

[TestClass]
public class PbmComplianceManagerTest
{
    private Session session = null!;

    [TestInitialize]
    public void Initialize()
    {
        this.session = Session.Get(new Uri("https://192.168.0.1/sdk")).Result;
        this.session.SessionManager!.Login("root", "password").Wait();
        this.session.SetPbmClient().Wait();
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
    public void PbmCheckCompliance()
    {
        var entities = this.GetAllVmEntities().Result;
        var results = this.session.PbmComplianceManager!.PbmCheckCompliance(entities, null).Result;
        Assert.IsNotNull(results);
    }

    [TestMethod]
    public void PbmCheckRollupCompliance()
    {
        var entities = this.GetAllVmEntities().Result;
        var results = this.session.PbmComplianceManager!.PbmCheckRollupCompliance(entities).Result;
        Assert.IsNotNull(results);
    }

    [TestMethod]
    public void PbmFetchComplianceResult()
    {
        var entities = this.GetAllVmEntities().Result;
        var results = this.session.PbmComplianceManager!.PbmFetchComplianceResult(entities, null).Result;
        Assert.IsNotNull(results);
    }

    [TestMethod]
    public void PbmFetchRollupComplianceResult()
    {
        var entities = this.GetAllVmEntities().Result;
        var results = this.session.PbmComplianceManager!.PbmFetchRollupComplianceResult(entities).Result;
        Assert.IsNotNull(results);
    }

    [TestMethod]
    public void PbmQueryByRollupComplianceStatus()
    {
        var results = this.session.PbmComplianceManager!.PbmQueryByRollupComplianceStatus("compliant").Result;
        Assert.IsNotNull(results);
    }

    private async System.Threading.Tasks.Task<VirtualMachine[]> GetAllVm()
    {
        var result = new List<VirtualMachine>();

        await foreach (var vm in this.session.RootFolder.Enumerate<VirtualMachine>())
        {
            result.Add(vm);
        }

        return [.. result];
    }

    private async System.Threading.Tasks.Task<PbmService.PbmServerObjectRef[]> GetAllVmEntities()
    {
        var vms = await this.GetAllVm();
        return [.. vms.Select(v =>
        {
            return new PbmService.PbmServerObjectRef
            {
                key = v.VimReference.Value,
                objectType = "virtualMachine",
                serverUuid = this.session.About.instanceUuid,
            };
        })];
    }
}
