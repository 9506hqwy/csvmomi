# CsVmomi

This library is vSphere Management API C# bindings for .NET 8.0 or .NET Framework 4.7.2 or later.

This package is ManagedObject implementation class built on API bindings, and is added some utility functions.
ManagedObject class is generated from [Reference Guide](https://developer.broadcom.com/sdks/vcf-api-specification/latest/).

## Examples

see [Examples](./Examples) directory.

## API bindings

see [Packages](./Packages) directory pre-gnerated by [csvmomi-lib](https://github.com/9506hqwy/csvmomi-lib).

## Notes

If use .Net 6.0, need to use .Net 6.0.11 or later,
see [Allow for null XmlSerialziers when loading pre-gen from mappings](https://github.com/dotnet/runtime/pull/75638).

## References

- [Announcing deprecation of vSphere Management SDK for .Net (C#) (87965)](https://kb.vmware.com/s/article/87965)
- [vcf-api-specs](https://github.com/vmware/vcf-api-specs)
