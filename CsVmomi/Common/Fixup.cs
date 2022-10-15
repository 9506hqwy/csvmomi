namespace CsVmomi;

using System.Text;

public static class Fixup
{
    public static Func<byte[], byte[]> FixupNamespaceNotPreserve()
    {
        // デシリアライズ時にエラー「名前空間プレフィックス 'xsd' は定義されていません。」が
        // 発生するため簡易的に名前空間を追加して回避する。
        // https://github.com/dotnet/wcf/issues/2541
        return (source) =>
        {
            var envelope = Encoding.UTF8.GetString(source).Replace(
                "xsi:type=\"xsd:string\"",
                "xsi:type=\"xsd:string\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"");
            return Encoding.UTF8.GetBytes(envelope);
        };
    }
}
