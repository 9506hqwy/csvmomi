using CsVmomi;
using VimService;

try
{
    await Work(args);
}
catch (Exception e)
{
    await Console.Error.WriteLineAsync(string.Format("{0}", e));
}

async System.Threading.Tasks.Task Work(string[] args)
{
    if (args.Length != 4)
    {
        await Console.Error.WriteLineAsync("ExportVm URL USERNAME PASSWORD VM");
        return;
    }

    if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
    {
        await Console.Error.WriteLineAsync("URL is invalid format.");
        return;
    }

    var session = await Session.Get(url);
    session.MessageToolBox.Fixup = Fixup.FixupNamespaceNotPreserve();
    await session.SessionManager!.Login(args[1], args[2]);
    try
    {
        var vm = await session.RootFolder.FindByName<VirtualMachine>(args[3]);
        if (vm == null)
        {
            throw new Exception($"Not found virtual machine `{args[3]}`.");
        }

        var vmName = await vm.GetPropertyName();

        var nfc = await vm.ExportVm();
        try
        {
            var info = await nfc!.GetPropertyInfo();
            if (info == null || info.deviceUrl == null || info.deviceUrl.Length == 0)
            {
                return;
            }

            using var http = CreateHttpClient();
            var map = new Dictionary<string, string>();
            foreach (var deviceUrl in info.deviceUrl)
            {
                var fileUrl = new Uri(deviceUrl.url.Replace("*", url.Host));
                var fileName = fileUrl.AbsolutePath.Split('/').Last();

                var res = await http.GetAsync(fileUrl);
                res.EnsureSuccessStatusCode();

                await res.Content.CopyToAsync(File.Create(fileName));
                map.Add(deviceUrl.key, fileName);
            }

            var manifests = await nfc.HttpNfcLeaseGetManifest();
            using var mf = new StreamWriter($"{vmName}.mf");
            var ovfFiles = new List<OvfFile>();
            foreach (var manifest in manifests!)
            {
                var fileName = map[manifest.key];
                await mf.WriteAsync($"SHA1({fileName})= {manifest.sha1}");
                ovfFiles.Add(new OvfFile
                {
                    capacity = manifest.capacity,
                    capacitySpecified = true,
                    deviceId = manifest.key,
                    path = fileName,
                    size = manifest.size,
                });
            }

            await nfc!.HttpNfcLeaseComplete();

            var options = await session.OvfManager!.GetPropertyOvfExportOption();

            var cdp = new OvfCreateDescriptorParams
            {
                exportOption = options!.Select(o => o.option).ToArray(),
                ovfFiles = ovfFiles.ToArray(),
            };
            var ovf = await session.OvfManager!.CreateDescriptor(vm, cdp);

            if (ovf!.error != null)
            {
                foreach (var error in ovf.error)
                {
                    await Console.Out.WriteLineAsync(error.localizedMessage);
                }
            }

            if (ovf.warning != null)
            {
                foreach (var warning in ovf.warning)
                {
                    await Console.Out.WriteLineAsync(warning.localizedMessage);
                }
            }

            File.WriteAllText($"{vmName}.ovf", ovf.ovfDescriptor);

            await Console.Out.WriteLineAsync("Success.");
        }
        catch (Exception e)
        {
            var fault = new LocalizedMethodFault
            {
                fault = new MethodFault(),
                localizedMessage = e.Message,
            };
            await nfc!.HttpNfcLeaseAbort(fault);

            throw;
        }
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

HttpClient CreateHttpClient()
{
    var handler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (req, cert, chain, errors) => true,
    };

    var http = new HttpClient(handler, true);
    return http;
}
