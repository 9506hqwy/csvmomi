# CsVmomi

This library is vSphere Management API C# bindings for .NET Standard 2.0.

This repository includes some packages.

- [EamService](./EamService)

  This package is vSphere ESX Agent Manager API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil),
  and pre-generated XML serializer by using [dotnet-svcutil.xmlserializer](https://www.nuget.org/packages/dotnet-svcutil.xmlserializer).

- [PbmService](./PbmService)

  This package is VMware Storage Policy API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil),
  and pre-generated XML serializer by using [dotnet-svcutil.xmlserializer](https://www.nuget.org/packages/dotnet-svcutil.xmlserializer).

- [SmsService](./SmsService)

  This package is vCenter Storage Monitoring Service API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil),
  and pre-generated XML serializer by using [dotnet-svcutil.xmlserializer](https://www.nuget.org/packages/dotnet-svcutil.xmlserializer).

- [StsService](./StsService)

  This package is vCenter Single Sign-On API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil).

- [VimService](./VimService)

  This package is vSphere Web Services API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil),
  and pre-generated XML serializer by using [dotnet-svcutil.xmlserializer](https://www.nuget.org/packages/dotnet-svcutil.xmlserializer).

- [VslmService](./VslmService)

  This package is Virtual Storage Lifecycle Management API C# bindings.
  This package is stub that generated from WSDL by using [dotnet-svcuti](https://www.nuget.org/packages/dotnet-svcutil),
  and pre-generated XML serializer by using [dotnet-svcutil.xmlserializer](https://www.nuget.org/packages/dotnet-svcutil.xmlserializer).

- [CsVmomi](./CsVmomi)

  This package is ManagedObject implementation class built on C# bindings, and is added some utility functions.
  ManagedObject class is generated from Reference Guide.

## Examples

see [Examples](./Examples) directory.

## Notes

If use .Net Framework,
need to add [Microsoft.Bcl.AsyncInterfaces](https://www.nuget.org/packages/Microsoft.Bcl.AsyncInterfaces/) package reference
because of using async stream in [CsVmomi](./CsVmomi) package.

If use .Net 6.0, need to use .Net 6.0.11 or later,
see [Allow for null XmlSerialziers when loading pre-gen from mappings](https://github.com/dotnet/runtime/pull/75638).

## References

- [Announcing deprecation of vSphere Management SDK for .Net (C#) (87965)](https://kb.vmware.com/s/article/87965)
