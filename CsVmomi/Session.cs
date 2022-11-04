namespace CsVmomi;

using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;

public class Session
{
    private const string SessionCookieName = "vmware_soap_session";

    private readonly ServiceContent vimServiceContent;

    private PbmService.PbmServiceInstanceContent? pbmServiceContent;

    private VslmService.VslmServiceInstanceContent? vslmServiceContent;

    private Session(IVimClient client, ServiceContent serviceContent)
    {
        this.VimClient = client;
        this.vimServiceContent = serviceContent;
    }

    public MessageToolBox MessageToolBox { get; set; } = new MessageToolBox();

    public string? SoapSessionId => this.VimClient.GetCookie(Session.SessionCookieName)?.Trim('"');

    public AboutInfo About => this.vimServiceContent.about;

    public HostLocalAccountManager? AccountManager => ManagedObject.Create<HostLocalAccountManager>(this.vimServiceContent.accountManager, this);

    public AlarmManager? AlarmManager => ManagedObject.Create<AlarmManager>(this.vimServiceContent.alarmManager, this);

    public AuthorizationManager? AuthorizationManager => ManagedObject.Create<AuthorizationManager>(this.vimServiceContent.authorizationManager, this);

    public CertificateManager? CertificateManager => ManagedObject.Create<CertificateManager>(this.vimServiceContent.certificateManager, this);

    public ClusterProfileManager? ClusterProfileManager => ManagedObject.Create<ClusterProfileManager>(this.vimServiceContent.clusterProfileManager, this);

    public ProfileComplianceManager? ComplianceManager => ManagedObject.Create<ProfileComplianceManager>(this.vimServiceContent.complianceManager, this);

    public CryptoManager? CryptoManager => ManagedObject.Create<CryptoManager>(this.vimServiceContent.cryptoManager, this);

    public CustomFieldsManager? CustomFieldsManager => ManagedObject.Create<CustomFieldsManager>(this.vimServiceContent.customFieldsManager, this);

    public CustomizationSpecManager? CustomizationSpecManager => ManagedObject.Create<CustomizationSpecManager>(this.vimServiceContent.customizationSpecManager, this);

    public DatastoreNamespaceManager? DatastoreNamespaceManager => ManagedObject.Create<DatastoreNamespaceManager>(this.vimServiceContent.datastoreNamespaceManager, this);

    public DiagnosticManager? DiagnosticManager => ManagedObject.Create<DiagnosticManager>(this.vimServiceContent.diagnosticManager, this);

    public DistributedVirtualSwitchManager? DvSwitchManager => ManagedObject.Create<DistributedVirtualSwitchManager>(this.vimServiceContent.dvSwitchManager, this);

    public EventManager? EventManager => ManagedObject.Create<EventManager>(this.vimServiceContent.eventManager, this);

    public ExtensionManager? ExtensionManager => ManagedObject.Create<ExtensionManager>(this.vimServiceContent.extensionManager, this);

    public FailoverClusterConfigurator? FailoverClusterConfigurator => ManagedObject.Create<FailoverClusterConfigurator>(this.vimServiceContent.failoverClusterConfigurator, this);

    public FailoverClusterManager? FailoverClusterManager => ManagedObject.Create<FailoverClusterManager>(this.vimServiceContent.failoverClusterManager, this);

    public FileManager? FileManager => ManagedObject.Create<FileManager>(this.vimServiceContent.fileManager, this);

    public VirtualMachineGuestCustomizationManager? GuestCustomizationManager => ManagedObject.Create<VirtualMachineGuestCustomizationManager>(this.vimServiceContent.guestCustomizationManager, this);

    public GuestOperationsManager? GuestOperationsManager => ManagedObject.Create<GuestOperationsManager>(this.vimServiceContent.guestOperationsManager, this);

    public HealthUpdateManager? HealthUpdateManager => ManagedObject.Create<HealthUpdateManager>(this.vimServiceContent.healthUpdateManager, this);

    public HostProfileManager? HostProfileManager => ManagedObject.Create<HostProfileManager>(this.vimServiceContent.hostProfileManager, this);

    public HostSpecificationManager? HostSpecManager => ManagedObject.Create<HostSpecificationManager>(this.vimServiceContent.hostSpecManager, this);

    public IoFilterManager? IoFilterManager => ManagedObject.Create<IoFilterManager>(this.vimServiceContent.ioFilterManager, this);

    public IpPoolManager? IpPoolManager => ManagedObject.Create<IpPoolManager>(this.vimServiceContent.ipPoolManager, this);

    public LicenseManager? LicenseManager => ManagedObject.Create<LicenseManager>(this.vimServiceContent.licenseManager, this);

    public LocalizationManager? LocalizationManager => ManagedObject.Create<LocalizationManager>(this.vimServiceContent.localizationManager, this);

    public OverheadMemoryManager? OverheadMemoryManager => ManagedObject.Create<OverheadMemoryManager>(this.vimServiceContent.overheadMemoryManager, this);

    public OvfManager? OvfManager => ManagedObject.Create<OvfManager>(this.vimServiceContent.ovfManager, this);

    public PerformanceManager? PerfManager => ManagedObject.Create<PerformanceManager>(this.vimServiceContent.perfManager, this);

    public PropertyCollector PropertyCollector => ManagedObject.Create<PropertyCollector>(this.vimServiceContent.propertyCollector, this)!;

    public Folder RootFolder => ManagedObject.Create<Folder>(this.vimServiceContent.rootFolder, this)!;

    public ScheduledTaskManager? ScheduledTaskManager => ManagedObject.Create<ScheduledTaskManager>(this.vimServiceContent.scheduledTaskManager, this);

    public SearchIndex? SearchIndex => ManagedObject.Create<SearchIndex>(this.vimServiceContent.searchIndex, this);

    public ServiceManager? ServiceManager => ManagedObject.Create<ServiceManager>(this.vimServiceContent.serviceManager, this);

    public SessionManager? SessionManager => ManagedObject.Create<SessionManager>(this.vimServiceContent.sessionManager, this);

    public OptionManager? Setting => ManagedObject.Create<OptionManager>(this.vimServiceContent.setting, this);

    public SiteInfoManager? SiteInfoManager => ManagedObject.Create<SiteInfoManager>(this.vimServiceContent.siteInfoManager, this);

    public HostSnmpSystem? SnmpSystem => ManagedObject.Create<HostSnmpSystem>(this.vimServiceContent.snmpSystem, this);

    public StorageQueryManager? StorageQueryManager => ManagedObject.Create<StorageQueryManager>(this.vimServiceContent.storageQueryManager, this);

    public StorageResourceManager? StorageResourceManager => ManagedObject.Create<StorageResourceManager>(this.vimServiceContent.storageResourceManager, this);

    public TaskManager? TaskManager => ManagedObject.Create<TaskManager>(this.vimServiceContent.taskManager, this);

    public TenantTenantManager? TenantManager => ManagedObject.Create<TenantTenantManager>(this.vimServiceContent.tenantManager, this);

    public UserDirectory? UserDirectory => ManagedObject.Create<UserDirectory>(this.vimServiceContent.userDirectory, this);

    public ViewManager? ViewManager => ManagedObject.Create<ViewManager>(this.vimServiceContent.viewManager, this);

    public VirtualDiskManager? VirtualDiskManager => ManagedObject.Create<VirtualDiskManager>(this.vimServiceContent.virtualDiskManager, this);

    public VirtualizationManager? VirtualizationManager => ManagedObject.Create<VirtualizationManager>(this.vimServiceContent.virtualizationManager, this);

    public VirtualMachineCompatibilityChecker? VmCompatibilityChecker => ManagedObject.Create<VirtualMachineCompatibilityChecker>(this.vimServiceContent.vmCompatibilityChecker, this);

    public VirtualMachineProvisioningChecker? VmProvisioningChecker => ManagedObject.Create<VirtualMachineProvisioningChecker>(this.vimServiceContent.vmProvisioningChecker, this);

    public VStorageObjectManagerBase? VStorageObjectManager => ManagedObject.Create<VStorageObjectManagerBase>(this.vimServiceContent.vStorageObjectManager, this);

    public PbmService.PbmAboutInfo? PbmAboutInfo => this.pbmServiceContent?.aboutInfo;

    public PbmCapabilityMetadataManager? PbmCapabilityMetadataManager => ManagedObject.Create<PbmCapabilityMetadataManager>(this.pbmServiceContent?.capabilityMetadataManager, this);

    public PbmComplianceManager? PbmComplianceManager => ManagedObject.Create<PbmComplianceManager>(this.pbmServiceContent?.complianceManager, this);

    public PbmPlacementSolver? PbmPlacementSolver => ManagedObject.Create<PbmPlacementSolver>(this.pbmServiceContent?.placementSolver, this);

    public PbmProfileProfileManager? PbmProfileManager => ManagedObject.Create<PbmProfileProfileManager>(this.pbmServiceContent?.profileManager, this);

    public PbmReplicationManager? PbmReplicationManager => ManagedObject.Create<PbmReplicationManager>(this.pbmServiceContent?.replicationManager, this);

    public PbmSessionManager? PbmSessionManager => ManagedObject.Create<PbmSessionManager>(this.pbmServiceContent?.sessionManager, this);

    public EsxAgentManager? EsxAgentManager { get; private set; }

    public SmsServiceInstance? SmsServiceInstance { get; private set; }

    public VslmService.VslmAboutInfo? VslmAboutInfo => this.vslmServiceContent?.aboutInfo;

    public VslmSessionManager? VslmSessionManager => ManagedObject.Create<VslmSessionManager>(this.vslmServiceContent?.sessionManager, this);

    public VslmStorageLifecycleManager? VslmStorageLifecycleManager => ManagedObject.Create<VslmStorageLifecycleManager>(this.vslmServiceContent?.storageLifecycleManager, this);

    public VslmVStorageObjectManager? VslmVStorageObjectManager => ManagedObject.Create<VslmVStorageObjectManager>(this.vslmServiceContent?.vStorageObjectManager, this);

    internal IEamClient? EamClient { get; set; }

    internal IPbmClient? PbmClient { get; set; }

    internal ISmsClient? SmsClient { get; set; }

    internal IStsClient? StsClient { get; set; }

    internal IVimClient VimClient { get; }

    internal IVslmClient? VslmClient { get; set; }

    public static async System.Threading.Tasks.Task<Session> Get(Uri url)
    {
        var binding = Session.GetBinding();

        var endpoint = new EndpointAddress(url);

        var inner = new VimPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };

        var tool = new MessageToolBox();
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(tool));

        var session = await Session.Get(inner);
        session.MessageToolBox = tool;

        return session;
    }

    public static async System.Threading.Tasks.Task<Session> Get(VimPortTypeClient inner)
    {
        return await Session.Get(new VimClient(inner));
    }

    public static async System.Threading.Tasks.Task<Session> Get(IVimClient client)
    {
        var mor = new ManagedObjectReference
        {
            type = "ServiceInstance",
            Value = "ServiceInstance",
        };
        var serviceContent = await client.RetrieveServiceContent(mor);

        return new Session(client, serviceContent!);
    }

    public void SetEamClient()
    {
        var builder = new UriBuilder(this.VimClient.Uri);
        builder.Path = "eam/sdk";

        var binding = Session.GetBinding();

        var endpoint = new EndpointAddress(builder.Uri);

        var inner = new EamService.EamPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(this.MessageToolBox));

        this.SetEamClient(inner);
    }

    public void SetEamClient(EamService.EamPortTypeClient inner)
    {
        this.SetEamClient(new EamClient(inner));
    }

    public void SetEamClient(IEamClient client)
    {
        this.EamClient = client;
        this.EamClient.SetCookie(this.VimClient.GetCookie());

        var mor = new EamService.ManagedObjectReference
        {
            type = "EsxAgentManager",
            Value = "EsxAgentManager",
        };
        this.EsxAgentManager = ManagedObject.Create<EsxAgentManager>(mor, this);
    }

    public System.Threading.Tasks.Task SetPbmClient()
    {
        var builder = new UriBuilder(this.VimClient.Uri);
        builder.Path = "pbm";

        var binding = Session.GetBinding();

        var endpoint = new EndpointAddress(builder.Uri);

        var inner = new PbmService.PbmPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(this.MessageToolBox));
        inner.Endpoint.EndpointBehaviors.Add(new SessionCookieBehavior(this.SoapSessionId));

        return this.SetPbmClient(inner);
    }

    public System.Threading.Tasks.Task SetPbmClient(PbmService.PbmPortTypeClient inner)
    {
        return this.SetPbmClient(new PbmClient(inner));
    }

    public async System.Threading.Tasks.Task SetPbmClient(IPbmClient client)
    {
        this.PbmClient = client;

        var mor = new PbmService.ManagedObjectReference
        {
            type = "PbmServiceInstance",
            Value = "ServiceInstance",
        };
        this.pbmServiceContent = await client.PbmRetrieveServiceContent(mor);
    }

    public void SetSmsClient()
    {
        var builder = new UriBuilder(this.VimClient.Uri);
        builder.Path = "sms/sdk";

        var binding = Session.GetBinding();

        var endpoint = new EndpointAddress(builder.Uri);

        var inner = new SmsService.SmsPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(this.MessageToolBox));
        inner.Endpoint.EndpointBehaviors.Add(new SessionCookieBehavior(this.SoapSessionId));

        this.SetSmsClient(inner);
    }

    public void SetSmsClient(SmsService.SmsPortTypeClient inner)
    {
        this.SetSmsClient(new SmsClient(inner));
    }

    public void SetSmsClient(ISmsClient client)
    {
        this.SmsClient = client;

        var mor = new SmsService.ManagedObjectReference
        {
            type = "SmsServiceInstance",
            Value = "ServiceInstance",
        };
        this.SmsServiceInstance = ManagedObject.Create<SmsServiceInstance>(mor, this);
    }

    public void SetStsClient(string username, string password)
    {
        var builder = new UriBuilder(this.VimClient.Uri);
        builder.Path = "sts/STSService";

        var binding = Session.GetStsBinding();

        var endpoint = new EndpointAddress(builder.Uri);

        var inner = new StsService.STSService_PortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        inner.ClientCredentials.UserName.UserName = username;
        inner.ClientCredentials.UserName.Password = password;

        this.SetStsClient(inner);
    }

    public void SetStsClient(StsService.STSService_PortTypeClient inner)
    {
        this.SetStsClient(new StsClient(inner));
    }

    public void SetStsClient(IStsClient client)
    {
        this.StsClient = client;
    }

    public System.Threading.Tasks.Task SetVslmClient()
    {
        var builder = new UriBuilder(this.VimClient.Uri);
        builder.Path = "vslm/sdk";

        var binding = Session.GetBinding();

        var endpoint = new EndpointAddress(builder.Uri);

        var inner = new VslmService.VslmPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(this.MessageToolBox));
        inner.Endpoint.EndpointBehaviors.Add(new SessionCookieBehavior(this.SoapSessionId));

        return this.SetVslmClient(inner);
    }

    public System.Threading.Tasks.Task SetVslmClient(VslmService.VslmPortTypeClient inner)
    {
        return this.SetVslmClient(new VslmClient(inner));
    }

    public async System.Threading.Tasks.Task SetVslmClient(IVslmClient client)
    {
        this.VslmClient = client;

        var mor = new VslmService.ManagedObjectReference
        {
            type = "VslmServiceInstance",
            Value = "ServiceInstance",
        };
        this.vslmServiceContent = await client.RetrieveContent(mor);
    }

    internal static async System.Threading.Tasks.Task<Session> Get(Uri url, SecurityToken token)
    {
        // https://learn.microsoft.com/ja-jp/dotnet/framework/wcf/samples/saml-token-provider
        var binding = Session.GetStsBinding();

        var endpoint = new EndpointAddress(url);

        var inner = new VimPortTypeClient(binding, endpoint);
        inner.ChannelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
        inner.ChannelFactory.Endpoint.EndpointBehaviors.Add(new TokenClientCredentials(token));
        inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
        {
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };

        var tool = new MessageToolBox();
        inner.Endpoint.EndpointBehaviors.Add(new FixupBehavior(tool));

        var session = await Session.Get(inner);
        session.MessageToolBox = tool;

        return session;
    }

    private static BasicHttpBinding GetBinding()
    {
        return new BasicHttpBinding
        {
            AllowCookies = true,
            BypassProxyOnLocal = true,
            MaxBufferPoolSize = int.MaxValue,
            MaxBufferSize = int.MaxValue,
            MaxReceivedMessageSize = int.MaxValue,
            MessageEncoding = WSMessageEncoding.Text,
            Security = new BasicHttpSecurity
            {
                Mode = BasicHttpSecurityMode.Transport,
                Transport = new HttpTransportSecurity
                {
                    ClientCredentialType = HttpClientCredentialType.None,
                    ProxyCredentialType = HttpProxyCredentialType.None,
                },
            },
            TextEncoding = Encoding.UTF8,
            TransferMode = TransferMode.Buffered,
            UseDefaultWebProxy = false,

            // タイムアウト
            OpenTimeout = TimeSpan.FromSeconds(300),
            SendTimeout = TimeSpan.FromSeconds(300),
            ReceiveTimeout = TimeSpan.FromSeconds(1800),
            CloseTimeout = TimeSpan.FromSeconds(300),
        };
    }

    private static CustomBinding GetStsBinding()
    {
        var binding = Session.GetBinding();

        // https://learn.microsoft.com/ja-jp/dotnet/framework/wcf/feature-details/security-protocols#311-usernameovertransport
        binding.Security.Message = new BasicHttpMessageSecurity
        {
            ClientCredentialType = BasicHttpMessageCredentialType.UserName,
        };
        binding.Security.Mode = BasicHttpSecurityMode.TransportWithMessageCredential;

        // https://learn.microsoft.com/ja-jp/dotnet/framework/wcf/extending/how-to-customize-a-system-provided-binding
        var customBinding = new CustomBinding(binding);
        var security = customBinding.Elements.OfType<SecurityBindingElement>().FirstOrDefault();
        if (security != null)
        {
            // security.EnableUnsecuredResponse = true;
            security.GetType().GetProperty("EnableUnsecuredResponse").SetValue(security, true);
        }

        return customBinding;
    }
}
