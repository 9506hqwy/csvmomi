namespace CsVmomi;

using EamService;

public interface IEamClient
{
    Uri Uri { get; }

    string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task<Issue?> AddIssue(ManagedObjectReference self, Issue issue);

    System.Threading.Tasks.Task Agency_Disable(ManagedObjectReference self);

    System.Threading.Tasks.Task Agency_Enable(ManagedObjectReference self);

    System.Threading.Tasks.Task<EamObjectRuntimeInfo?> AgencyQueryRuntime(ManagedObjectReference self);

    System.Threading.Tasks.Task<AgentConfigInfo?> AgentQueryConfig(ManagedObjectReference self);

    System.Threading.Tasks.Task<AgentRuntimeInfo?> AgentQueryRuntime(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateAgency(ManagedObjectReference self, AgencyConfigInfo agencyConfigInfo, string initialGoalState);

    System.Threading.Tasks.Task DestroyAgency(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> GetMaintenanceModePolicy(ManagedObjectReference self);

    System.Threading.Tasks.Task MarkAsAvailable(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryAgency(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryAgent(ManagedObjectReference self);

    System.Threading.Tasks.Task<AgencyConfigInfo?> QueryConfig(ManagedObjectReference self);

    System.Threading.Tasks.Task<Issue[]?> QueryIssue(ManagedObjectReference self, int[]? issueKey);

    System.Threading.Tasks.Task<string?> QuerySolutionId(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> RegisterAgentVm(ManagedObjectReference self, ManagedObjectReference agentVm);

    System.Threading.Tasks.Task<int[]?> Resolve(ManagedObjectReference self, int[] issueKey);

    System.Threading.Tasks.Task ResolveAll(ManagedObjectReference self);

    System.Threading.Tasks.Task ScanForUnknownAgentVm(ManagedObjectReference self);

    System.Threading.Tasks.Task SetMaintenanceModePolicy(ManagedObjectReference self, string policy);

    System.Threading.Tasks.Task Uninstall(ManagedObjectReference self);

    System.Threading.Tasks.Task UnregisterAgentVm(ManagedObjectReference self, ManagedObjectReference agentVm);

    System.Threading.Tasks.Task Update(ManagedObjectReference self, AgencyConfigInfo config);

}
