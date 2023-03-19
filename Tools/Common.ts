import { join } from "https://deno.land/std/path/mod.ts";
import { DOMParser } from "https://deno.land/x/deno_dom/deno-dom-wasm.ts";

// constant

export const excludeManagedObjectMethod = [];

export const fixMethodName = {
  "QueryBackingStoragePool": "QueryAssociatedBackingStoragePool",
}

export const fixTypes = {
  "abort": {
    "MethodFault": "LocalizedMethodFault",
  },
  "queryFaultToleranceCompatibility": {
    "MethodFault[]": "LocalizedMethodFault[]",
  },
  "queryFaultToleranceCompatibilityEx": {
    "MethodFault[]": "LocalizedMethodFault[]",
  },
  "setState": {
    "MethodFault": "LocalizedMethodFault",
  },
  "validateStoragePodConfig": {
    "MethodFault": "LocalizedMethodFault",
  },
};

export const simpleTypes = [
  "SimpleCommandEncoding",
];

export const csStructureTypes = [
  "bool",
  "DateTime",
  "int",
  "long",
  // VimService enum.
  "VirtualMachineMovePriority",
  "VirtualMachinePowerState",
];

const parser = new DOMParser();

// class

export class ManagedObject {
  name: null | string;
  baseTy: null | string;
  properties: ManagedObjectProperty[];
  methods: ManagedObjectMethod[];

  constructor() {
    this.properties = [];
    this.methods = [];
  }
}

export class ManagedObjectMethod {
  name: null | string;
  returnTy: null | TypeDeclare;
  parameters: ManagedObjectMethodParameter[];

  constructor() {
    this.parameters = [];
  }
}

export class ManagedObjectMethodParameter {
  name: null | string;
  ty: null | TypeDeclare;
  mandatory: boolean;
}

export class ManagedObjectMethodRef {
  name: null | string;
  clsName: null | string;
  id: null | string;
}

export class ManagedObjectProperty {
  name: null | string;
  ty: null | TypeDeclare;
  mandatory: boolean;
}

export class TypeDeclare {
  local: null | string;
  remote: null | string;
}

// function

export function convertType(source: string): string {
  if (source == "xsd:boolean") {
    return "bool";
  } else if (source == "xsd:boolean[]") {
    return "bool[]";
  } else if (source == "xsd:byte") {
    return "byte";
  } else if (source == "xsd:byte[]") {
    return "byte[]";
  } else if (source == "xsd:string") {
    return "string";
  } else if (source == "xsd:string[]") {
    return "string[]";
  } else if (source == "xsd:int") {
    return "int";
  } else if (source == "xsd:int[]") {
    return "int[]";
  } else if (source == "xsd:long") {
    return "long";
  } else if (source == "xsd:long[]") {
    return "long[]";
  } else if (source == "xsd:anyType") {
    return "object";
  } else if (source == "xsd:dateTime") {
    return "DateTime";
  } else if (source == "xsd:dateTime[]") {
    return "DateTime[]";
  } else if (source == "xsd:base64Binary") {
    return "byte[]";
  } else if (simpleTypes.includes(source)) {
    return "string";
  } else {
    return source;
  }
}

export function findExtends(document: HTMLDocument): null | string {
  for (const dt of document.querySelectorAll<HTMLElement>("dl dt")) {
    if (dt.innerText.trim() == "Extends") {
      return dt.nextElementSibling.innerText.trim();
    }
  }

  return null;
}

export function findMethod(
  reference: ManagedObjectMethodRef,
  document: HTMLDocument,
): ManagedObjectMethod {
  const method = new ManagedObjectMethod();
  method.name = reference.name;
  method.returnTy = findMethodReturnTy(reference, document);
  method.parameters = findMethodArgument(reference, document);
  return method;
}

export function findMethodArgument(
  reference: ManagedObjectMethodRef,
  document: HTMLDocument,
): ManagedObjectMethodParameter[] {
  const sec = document.querySelector<HTMLAnchorElement>(`a#${reference.id}`);

  let p = sec;
  const KEYWORD = "Parameters";
  while ((p = p.nextElementSibling) && p.innerText.trim() != KEYWORD) {
    for (const child of p.querySelectorAll("p.table-title")) {
      if (child.innerText.trim() == KEYWORD) {
        p = child.previousElementSibling;
        break;
      }
    }
  }

  if (!p) {
    return [];
  }

  const table = p.nextElementSibling;

  const params = [];
  const parameters = table.querySelectorAll<HTMLTableRowElement>(
    "tr:not(:first-child)",
  );
  for (const parameter of parameters) {
    const nameElem = parameter.querySelector<HTMLElement>("td:nth-child(1)");
    if (nameElem == null) {
      continue;
    }

    const arg = new ManagedObjectMethodParameter();
    arg.name = nameElem.querySelector("strong").innerText.trim();
    arg.ty = findPropertyType(reference.id, parameter, 2);
    arg.mandatory =
      Array.from(nameElem.querySelectorAll("span")).findIndex((s) =>
        s.getAttribute("title") == "Need not be set"
      ) < 0;

    params.push(arg);
  }

  return params;
}

export function findMethodReturnTy(
  reference: ManagedObjectMethodRef,
  document: HTMLDocument,
): null | TypeDeclare {
  const sec = document.querySelector<HTMLAnchorElement>(`a#${reference.id}`);

  let p = sec;
  const KEYWORD = "Return Value";
  while ((p = p.nextElementSibling) && p.innerText.trim() != KEYWORD) {
    for (const child of p.querySelectorAll("p.table-title")) {
      if (child.innerText.trim() == KEYWORD) {
        p = child.previousElementSibling;
        break;
      }
    }
  }

  if (!p) {
    return null;
  }

  const table = p.nextElementSibling;
  const ty = findPropertyType(reference.id, table, 1);
  if (ty.local == "None") {
    return null;
  }

  return ty;
}

export function findPropertyName(
  property: HTMLTableRowElement,
): null | [string, boolean] {
  const propNameElem = property.querySelector<HTMLTableCellElement>(
    "td:nth-child(1)",
  );
  if (propNameElem == null) {
    return null;
  }

  const nameElem = propNameElem.querySelector<HTMLAnchorElement>("a");
  if (nameElem == null) {
    return null;
  }

  const propName = nameElem.getAttribute("id");
  if (propName == null) {
    return null;
  }

  const mandatory =
    Array.from(propNameElem.querySelectorAll("span")).findIndex((s) =>
      s.getAttribute("title") == "May not be present"
    ) < 0;

  return [propName.trim(), mandatory];
}

export function findPropertyType(
  methodId: string,
  property: HTMLTableRowElement,
  index: number,
): TypeDeclare {
  const propTypeElem = property.querySelector<HTMLTableCellElement>(
    `td:nth-child(${index})`,
  );

  const decl = new TypeDeclare();

  const anchors = propTypeElem.querySelectorAll<HTMLAnchorElement>("a");
  const typeStrings = propTypeElem.innerText.trim().split(' ');
  if (anchors.length == 2) {
      decl.local = anchors[1].innerText.trim();
      decl.remote = anchors[0].innerText.trim();
  } else if (typeStrings.length > 1) {
    decl.local = typeStrings[typeStrings.length - 1].trim();
    decl.remote = typeStrings[0].trim();
    if (decl.local.slice(-2) == '[]' && decl.remote.slice(-2) != '[]') {
      decl.remote += '[]';
    }
  } else if (anchors.length == 1) {
    const ty = anchors[0].innerText.trim();
    decl.local = ty;
    decl.remote = ty;
  } else {
    const ty = propTypeElem.innerText.trim();
    decl.local = ty;
    decl.remote = ty;
  }

  if (methodId in fixTypes && decl.local in fixTypes[methodId]) {
    decl.local = fixTypes[methodId][decl.local];
  }

  if (methodId in fixTypes && decl.remote in fixTypes[methodId]) {
    decl.remote = fixTypes[methodId][decl.remote];
  }

  if (decl.local.indexOf('.') > 0) {
    decl.local = decl.local.split('.')[1];
  }

  if (decl.remote.indexOf('.') > 0) {
    decl.remote = decl.remote.split('.')[1];
  }

  return decl;
}

export async function getCls(
  directory: string,
  methods: ManagedObjectMethodRef[],
): { [key: string]: HTMLDocument } {
  const cls = {};

  for (const method of methods) {
    if (method.clsName in cls) {
      continue;
    }

    const html = await Deno.readTextFile(join(directory, method.clsName));
    const document = parser.parseFromString(html, "text/html");
    cls[method.clsName] = document;
  }

  return cls;
}

export async function getManagedMethodRefs1(
  directory: string,
): ManagedObjectMethodRef[] {
  const methods = [];

  const html = await Deno.readTextFile(join(directory, "index-methods.html"));
  const document = parser.parseFromString(html, "text/html");
  for (const method of document.querySelectorAll<HTMLElement>("div nobr")) {
    const names = method.querySelectorAll<HTMLAnchorElement>("a");

    const m = new ManagedObjectMethodRef();
    m.name = names[0].innerText.trim();
    m.clsName = names[1].getAttribute("href");
    m.id = names[0].getAttribute("href").split("#")[1];

    if (m.name in fixMethodName) {
      m.name = fixMethodName[m.name];
    }

    methods.push(m);
  }

  return methods;
}

export async function getManagedMethodRefs2(
  directory: string,
): { [key: string]: ManagedObjectMethodRef } {
  const methods = {};

  const html = await Deno.readTextFile(join(directory, "index-methods.html"));
  const document = parser.parseFromString(html, "text/html");
  for (const method of document.querySelectorAll<HTMLElement>("div nobr")) {
    const names = method.querySelectorAll<HTMLAnchorElement>("a");

    const className = names[1].innerText.trim();
    if (!(className in methods)) {
      methods[className] = [];
    }

    const m = new ManagedObjectMethodRef();
    m.name = names[0].innerText.trim();
    m.clsName = names[1].getAttribute("href");
    m.id = names[0].getAttribute("href").split("#")[1];

    if (m.name in fixMethodName) {
      m.name = fixMethodName[m.name];
    }

    methods[className].push(m);
  }

  return methods;
}

export async function getManagedObjects(
  directory: string,
  methods: { [key: string]: ManagedObjectMethodRef },
): ManagedObject[] {
  const objs = [];

  const html = await Deno.readTextFile(join(directory, "index-mo_types.html"));
  const document = parser.parseFromString(html, "text/html");
  for (
    const ref of document.querySelectorAll<HTMLAnchorElement>("div nobr a")
  ) {
    const className = ref.getAttribute("title");
    const data = await Deno.readTextFile(
      join(directory, ref.getAttribute("href")),
    );
    const doc = parser.parseFromString(data, "text/html");
    const obj = convertManagedObject(className, methods[className] || [], doc);
    objs.push(obj);
  }

  return objs;
}

export function toCapitalCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function convertManagedObject(
  name: string,
  methods: ManagedObjectMethodRef[],
  document: HTMLDocument,
): ManagedObject {
  const mo = new ManagedObject();

  mo.name = name;
  mo.baseTy = findExtends(document);

  const properties =
    document.querySelector<HTMLParagraphElement>(".table-title")
      .nextElementSibling;
  for (
    const property of properties.querySelectorAll<HTMLTableRowElement>(
      "tr:not(:first-child)",
    )
  ) {
    const propName = findPropertyName(property);
    if (propName == null) {
      continue;
    }

    const prop = new ManagedObjectProperty();
    prop.name = propName[0];
    prop.ty = findPropertyType(name, property, 2);
    prop.mandatory = propName[1];

    mo.properties.push(prop);
  }

  for (const ref of methods) {
    if (excludeManagedObjectMethod.includes(ref.id)) {
      continue;
    }

    const method = findMethod(ref, document);
    mo.methods.push(method);
  }

  return mo;
}
