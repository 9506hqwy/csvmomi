namespace CsVmomi;

internal static class ObjectContentExtension
{
    internal static T? GetPropertyValue<T>(this ObjectContent self, string pathSet)
    {
        return (T?)self.propSet?.FirstOrDefault(p => p.name == pathSet)?.val ?? default;
    }
}
