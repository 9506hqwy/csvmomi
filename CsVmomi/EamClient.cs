namespace CsVmomi;

using System.ServiceModel.Channels;
using EamService;

#pragma warning disable IDE0058 // Expression value is never used

public class EamClient : IEamClient
{
    private readonly EamPortTypeClient inner;

    internal EamClient(EamPortTypeClient inner)
    {
        this.inner = inner;
    }

    public Uri Uri => this.inner.Endpoint.Address.Uri;

    public string? GetCookie(string name)
    {
        return this.GetCookie()?
            .OfType<System.Net.Cookie>()
            .FirstOrDefault(c => c.Name == name)?
            .Value;
    }

    public System.Net.CookieCollection? GetCookie()
    {
        return this.inner.InnerChannel.GetProperty<IHttpCookieContainerManager>()?
            .CookieContainer
            .GetCookies(this.Uri);
    }

    public void SetCookie(System.Net.CookieCollection? cookie)
    {
        if (cookie == null)
        {
            return;
        }

        var container = this.inner.InnerChannel
            .GetProperty<IHttpCookieContainerManager>()!
            .CookieContainer;

        foreach (var c in cookie.OfType<System.Net.Cookie>())
        {
            container.Add(new System.Net.Cookie(c.Name, c.Value, this.Uri.AbsolutePath, this.Uri.Host));
        }
    }

    public async System.Threading.Tasks.Task<Issue?> AddIssue(ManagedObjectReference self, Issue issue)
    {
        var req = new AddIssueRequestType
        {
            _this = self,
            issue = issue,
        };

        var res = await this.inner.AddIssueAsync(req).ConfigureAwait(false);

        return res.AddIssueResponse.returnval;
    }

    public async System.Threading.Tasks.Task Agency_Disable(ManagedObjectReference self)
    {
        var req = new Agency_DisableRequestType
        {
            _this = self,
        };

        await this.inner.Agency_DisableAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task Agency_Enable(ManagedObjectReference self)
    {
        var req = new Agency_EnableRequestType
        {
            _this = self,
        };

        await this.inner.Agency_EnableAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<EamObjectRuntimeInfo?> AgencyQueryRuntime(ManagedObjectReference self)
    {
        var req = new AgencyQueryRuntimeRequestType
        {
            _this = self,
        };

        var res = await this.inner.AgencyQueryRuntimeAsync(req).ConfigureAwait(false);

        return res.AgencyQueryRuntimeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<AgentConfigInfo?> AgentQueryConfig(ManagedObjectReference self)
    {
        var req = new AgentQueryConfigRequestType
        {
            _this = self,
        };

        var res = await this.inner.AgentQueryConfigAsync(req).ConfigureAwait(false);

        return res.AgentQueryConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<AgentRuntimeInfo?> AgentQueryRuntime(ManagedObjectReference self)
    {
        var req = new AgentQueryRuntimeRequestType
        {
            _this = self,
        };

        var res = await this.inner.AgentQueryRuntimeAsync(req).ConfigureAwait(false);

        return res.AgentQueryRuntimeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateAgency(ManagedObjectReference self, AgencyConfigInfo agencyConfigInfo, string initialGoalState)
    {
        var req = new CreateAgencyRequestType
        {
            _this = self,
            agencyConfigInfo = agencyConfigInfo,
            initialGoalState = initialGoalState,
        };

        var res = await this.inner.CreateAgencyAsync(req).ConfigureAwait(false);

        return res.CreateAgencyResponse.returnval;
    }

    public async System.Threading.Tasks.Task DestroyAgency(ManagedObjectReference self)
    {
        var req = new DestroyAgencyRequestType
        {
            _this = self,
        };

        await this.inner.DestroyAgencyAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> GetMaintenanceModePolicy(ManagedObjectReference self)
    {
        var req = new GetMaintenanceModePolicyRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetMaintenanceModePolicyAsync(req).ConfigureAwait(false);

        return res.GetMaintenanceModePolicyResponse.returnval;
    }

    public async System.Threading.Tasks.Task MarkAsAvailable(ManagedObjectReference self)
    {
        var req = new MarkAsAvailableRequestType
        {
            _this = self,
        };

        await this.inner.MarkAsAvailableAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryAgency(ManagedObjectReference self)
    {
        var req = new QueryAgencyRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryAgencyAsync(req).ConfigureAwait(false);

        return res.QueryAgencyResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryAgent(ManagedObjectReference self)
    {
        var req = new QueryAgentRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryAgentAsync(req).ConfigureAwait(false);

        return res.QueryAgentResponse1;
    }

    public async System.Threading.Tasks.Task<AgencyConfigInfo?> QueryConfig(ManagedObjectReference self)
    {
        var req = new QueryConfigRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryConfigAsync(req).ConfigureAwait(false);

        return res.QueryConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<Issue[]?> QueryIssue(ManagedObjectReference self, int[]? issueKey)
    {
        var req = new QueryIssueRequestType
        {
            _this = self,
            issueKey = issueKey,
        };

        var res = await this.inner.QueryIssueAsync(req).ConfigureAwait(false);

        return res.QueryIssueResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QuerySolutionId(ManagedObjectReference self)
    {
        var req = new QuerySolutionIdRequestType
        {
            _this = self,
        };

        var res = await this.inner.QuerySolutionIdAsync(req).ConfigureAwait(false);

        return res.QuerySolutionIdResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RegisterAgentVm(ManagedObjectReference self, ManagedObjectReference agentVm)
    {
        var req = new RegisterAgentVmRequestType
        {
            _this = self,
            agentVm = agentVm,
        };

        var res = await this.inner.RegisterAgentVmAsync(req).ConfigureAwait(false);

        return res.RegisterAgentVmResponse.returnval;
    }

    public async System.Threading.Tasks.Task<int[]?> Resolve(ManagedObjectReference self, int[] issueKey)
    {
        var req = new ResolveRequestType
        {
            _this = self,
            issueKey = issueKey,
        };

        var res = await this.inner.ResolveAsync(req).ConfigureAwait(false);

        return res.ResolveResponse1;
    }

    public async System.Threading.Tasks.Task ResolveAll(ManagedObjectReference self)
    {
        var req = new ResolveAllRequestType
        {
            _this = self,
        };

        await this.inner.ResolveAllAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ScanForUnknownAgentVm(ManagedObjectReference self)
    {
        var req = new ScanForUnknownAgentVmRequestType
        {
            _this = self,
        };

        await this.inner.ScanForUnknownAgentVmAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetMaintenanceModePolicy(ManagedObjectReference self, string policy)
    {
        var req = new SetMaintenanceModePolicyRequestType
        {
            _this = self,
            policy = policy,
        };

        await this.inner.SetMaintenanceModePolicyAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task Uninstall(ManagedObjectReference self)
    {
        var req = new UninstallRequestType
        {
            _this = self,
        };

        await this.inner.UninstallAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnregisterAgentVm(ManagedObjectReference self, ManagedObjectReference agentVm)
    {
        var req = new UnregisterAgentVmRequestType
        {
            _this = self,
            agentVm = agentVm,
        };

        await this.inner.UnregisterAgentVmAsync(req).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task Update(ManagedObjectReference self, AgencyConfigInfo config)
    {
        var req = new UpdateRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateAsync(req).ConfigureAwait(false);
    }

}

#pragma warning restore IDE0058 // Expression value is never used
