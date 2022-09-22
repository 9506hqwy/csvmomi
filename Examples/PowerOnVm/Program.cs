namespace Examples
{
    using System;
    using System.Linq;
    using CsVmomi;

    internal class PowerOnVm
    {
        internal static async System.Threading.Tasks.Task Main(string[] args)
        {
            try
            {
                await PowerOnVm.Work(args);
            }
            catch (Exception e)
            {
                await Console.Error.WriteLineAsync(string.Format("{0}", e));
            }
        }

        private static async System.Threading.Tasks.Task Work(string[] args)
        {
            if (args.Length != 4)
            {
                await Console.Error.WriteLineAsync("PowerOnVm URL USERNAME PASSWORD VMNAME");
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
                var vm = await PowerOnVm.FindVm(session, args[3]);
                var task = await vm.PowerOnVM_Task(null);
                await PowerOnVm.WaitForTask(task);

                await Console.Out.WriteLineAsync("Success.");
            }
            finally
            {
                await session.SessionManager.Logout();
            }
        }

        private static async System.Threading.Tasks.Task<VirtualMachine> FindVm(Session session, string vmname)
        {
            var view = await session.ViewManager.CreateContainerView(
                   session.RootFolder,
                   new[] { "vim.VirtualMachine" },
                   true);

            var objs = await view.GetPropertyView();
            var vms = objs.Cast<VirtualMachine>().ToArray();

            foreach (var vm in vms)
            {
                var name = await vm.GetPropertyName();
                if (name.ToLowerInvariant() == vmname.ToLowerInvariant())
                {
                    return vm;
                }
            }

            throw new Exception($"Not found virtual machine `{vmname}`.");
        }

        private static async System.Threading.Tasks.Task WaitForTask(Task task)
        {
            var info = await task.GetPropertyInfo();
            while (true)
            {
                if (info.state == VimService.TaskInfoState.error ||
                    info.state == VimService.TaskInfoState.success)
                {
                    break;
                }

                await System.Threading.Tasks.Task.Delay(3000);

                info = await task.GetPropertyInfo();
            }

            if (info.state == VimService.TaskInfoState.error)
            {
                throw new Exception(info.error.localizedMessage);
            }
        }
    }
}
