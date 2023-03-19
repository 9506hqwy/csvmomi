namespace CsVmomi;

using EamService;

#pragma warning disable SA1402 // File may only contain a single type

public partial class Agency : EamObject
{
    protected Agency(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Agent[]?> GetPropertyAgent()
    {
        var agent = await this.GetProperty<ManagedObjectReference[]>("agent");
        return agent?
            .Select(r => ManagedObject.Create<Agent>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<AgencyConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<AgencyConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyOwner()
    {
        var obj = await this.GetProperty<string>("owner");
        return obj;
    }

    public async System.Threading.Tasks.Task<EamObjectRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<EamObjectRuntimeInfo>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertySolutionId()
    {
        var obj = await this.GetProperty<string>("solutionId");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Issue?> AddIssue(Issue issue)
    {
        return await this.Session.EamClient!.AddIssue(this.EamReference, issue);
    }

    public async System.Threading.Tasks.Task Agency_Disable()
    {
        await this.Session.EamClient!.Agency_Disable(this.EamReference);
    }

    public async System.Threading.Tasks.Task Agency_Enable()
    {
        await this.Session.EamClient!.Agency_Enable(this.EamReference);
    }

    public async System.Threading.Tasks.Task<EamObjectRuntimeInfo?> AgencyQueryRuntime()
    {
        return await this.Session.EamClient!.AgencyQueryRuntime(this.EamReference);
    }

    public async System.Threading.Tasks.Task DestroyAgency()
    {
        await this.Session.EamClient!.DestroyAgency(this.EamReference);
    }

    public async System.Threading.Tasks.Task<Agent[]?> QueryAgent()
    {
        var res = await this.Session.EamClient!.QueryAgent(this.EamReference);
        return res?.Select(r => ManagedObject.Create<Agent>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<AgencyConfigInfo?> QueryConfig()
    {
        return await this.Session.EamClient!.QueryConfig(this.EamReference);
    }

    public async System.Threading.Tasks.Task<string?> QuerySolutionId()
    {
        return await this.Session.EamClient!.QuerySolutionId(this.EamReference);
    }

    public async System.Threading.Tasks.Task<Agent?> RegisterAgentVm(VirtualMachine agentVm)
    {
        var res = await this.Session.EamClient!.RegisterAgentVm(this.EamReference, agentVm.EamReference);
        return ManagedObject.Create<Agent>(res, this.Session);
    }

    public async System.Threading.Tasks.Task Uninstall()
    {
        await this.Session.EamClient!.Uninstall(this.EamReference);
    }

    public async System.Threading.Tasks.Task UnregisterAgentVm(VirtualMachine agentVm)
    {
        await this.Session.EamClient!.UnregisterAgentVm(this.EamReference, agentVm.EamReference);
    }

    public async System.Threading.Tasks.Task Update(AgencyConfigInfo config)
    {
        await this.Session.EamClient!.Update(this.EamReference, config);
    }
}

public partial class Agent : EamObject
{
    protected Agent(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<AgentConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<AgentConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<AgentRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<AgentRuntimeInfo>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<AgentConfigInfo?> AgentQueryConfig()
    {
        return await this.Session.EamClient!.AgentQueryConfig(this.EamReference);
    }

    public async System.Threading.Tasks.Task<AgentRuntimeInfo?> AgentQueryRuntime()
    {
        return await this.Session.EamClient!.AgentQueryRuntime(this.EamReference);
    }

    public async System.Threading.Tasks.Task MarkAsAvailable()
    {
        await this.Session.EamClient!.MarkAsAvailable(this.EamReference);
    }
}

public partial class EamObject : ManagedObject
{
    protected EamObject(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Issue[]?> QueryIssue(int[]? issueKey)
    {
        return await this.Session.EamClient!.QueryIssue(this.EamReference, issueKey);
    }

    public async System.Threading.Tasks.Task<int[]?> Resolve(int[] issueKey)
    {
        return await this.Session.EamClient!.Resolve(this.EamReference, issueKey);
    }

    public async System.Threading.Tasks.Task ResolveAll()
    {
        await this.Session.EamClient!.ResolveAll(this.EamReference);
    }
}

public partial class EamTask : ManagedObject
{
    protected EamTask(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class EsxAgentManager : EamObject
{
    protected EsxAgentManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Agency[]?> GetPropertyAgency()
    {
        var agency = await this.GetProperty<ManagedObjectReference[]>("agency");
        return agency?
            .Select(r => ManagedObject.Create<Agency>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Issue[]?> GetPropertyIssue()
    {
        var obj = await this.GetProperty<Issue[]>("issue");
        return obj;
    }

    public async System.Threading.Tasks.Task<Agency?> CreateAgency(AgencyConfigInfo agencyConfigInfo, string initialGoalState)
    {
        var res = await this.Session.EamClient!.CreateAgency(this.EamReference, agencyConfigInfo, initialGoalState);
        return ManagedObject.Create<Agency>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string?> GetMaintenanceModePolicy()
    {
        return await this.Session.EamClient!.GetMaintenanceModePolicy(this.EamReference);
    }

    public async System.Threading.Tasks.Task<Agency[]?> QueryAgency()
    {
        var res = await this.Session.EamClient!.QueryAgency(this.EamReference);
        return res?.Select(r => ManagedObject.Create<Agency>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task ScanForUnknownAgentVm()
    {
        await this.Session.EamClient!.ScanForUnknownAgentVm(this.EamReference);
    }

    public async System.Threading.Tasks.Task SetMaintenanceModePolicy(string policy)
    {
        await this.Session.EamClient!.SetMaintenanceModePolicy(this.EamReference, policy);
    }
}

#pragma warning restore SA1402 // File may only contain a single type
