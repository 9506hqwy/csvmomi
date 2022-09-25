namespace CsVmomi
{
    using System.Linq;
    using VimService;

    internal static class ObjectContentExtension
    {
        internal static T GetPropertyValue<T>(this ObjectContent self, string pathSet)
        {
            return (T)self.propSet.FirstOrDefault(p => p.name == pathSet)?.val ?? default(T);
        }
    }
}
