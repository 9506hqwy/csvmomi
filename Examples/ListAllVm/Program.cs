namespace Examples
{
    using System;
    using System.Linq;
    using CsVmomi;
    using VimService;

    internal class ListAllVm
    {
        internal static async System.Threading.Tasks.Task Main(string[] args)
        {
            try
            {
                await ListAllVm.Work(args);
            }
            catch (Exception e)
            {
                await Console.Error.WriteLineAsync(string.Format("{0}", e));
            }
        }

        private static async System.Threading.Tasks.Task Work(string[] args)
        {
            if (args.Length != 3)
            {
                await Console.Error.WriteLineAsync("ListAllVm URL USERNAME PASSWORD");
                return;
            }

            if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
            {
                await Console.Error.WriteLineAsync("URL is invalid format.");
                return;
            }

            var session = await Session.Get(url);
            await session.SessionManager.Login(args[1], args[2], null);
            try
            {
                var view = await session.ViewManager.CreateContainerView(
                       session.RootFolder,
                       new[] { "vim.VirtualMachine" },
                       true);

                var objs = await view.GetPropertyView();
                var vms = objs.Cast<VirtualMachine>().ToArray();

                foreach (var vm in vms)
                {
                    await ListAllVm.PrintVm(session, vm);
                }
            }
            finally
            {
                await session.SessionManager.Logout();
            }
        }

        private static async System.Threading.Tasks.Task PrintVm(Session session, VirtualMachine vm)
        {
            var pathSet = new[] { "name", "summary" };
            var content = await session.PropertyCollector.RetrieveProperties(vm, false, pathSet, false);

            var name = content.propSet.First(p => p.name == "name").val as string;
            var summary = content.propSet.First(p => p.name == "summary").val as VirtualMachineSummary;

            await Console.Out.WriteLineAsync(String.Format("Name          : {0}", name));
            await Console.Out.WriteLineAsync(String.Format("Template      : {0}", summary.config.template));
            await Console.Out.WriteLineAsync(String.Format("Path          : {0}", summary.config.vmPathName));
            await Console.Out.WriteLineAsync(String.Format("Guest         : {0}", summary.config.guestFullName));
            await Console.Out.WriteLineAsync(String.Format("Instance UUID : {0}", summary.config.instanceUuid));
            await Console.Out.WriteLineAsync(String.Format("BIOS UUID     : {0}", summary.config.uuid));
            await Console.Out.WriteLineAsync();
        }
    }
}
