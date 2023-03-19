# CsVmomi

This library is vSphere Management API C# bindings for .NET Standard 2.0.

This package is ManagedObject implementation class built on API bindings, and is added some utility functions.
ManagedObject class is generated from [Reference Guide](https://developer.vmware.com/web/sdk/8.0/vsphere-management).

## Examples

see [Examples](./Examples) directory.

## API bindings

see [Lib](./Lib) directory pre-gnerated by [csvmomi-lib](https://github.com/9506hqwy/csvmomi-lib).

## Notes

If use .Net Framework,
need to add [Microsoft.Bcl.AsyncInterfaces](https://www.nuget.org/packages/Microsoft.Bcl.AsyncInterfaces/) package reference
because of using async stream in [CsVmomi](./CsVmomi) package.

If use .Net 6.0, need to use .Net 6.0.11 or later,
see [Allow for null XmlSerialziers when loading pre-gen from mappings](https://github.com/dotnet/runtime/pull/75638).

## References

- [Announcing deprecation of vSphere Management SDK for .Net (C#) (87965)](https://kb.vmware.com/s/article/87965)
