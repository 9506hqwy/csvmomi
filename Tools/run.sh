#!/bin/bash

set -euo pipefail

VERSION="9.1.0.0"
SPEC_URL="https://github.com/vmware/vcf-api-specs.git"

TOOL=$(cd "$(dirname "$0")"; pwd)
SRC=${TOOL}/../CsVmomi/

WORKDIR=$(mktemp -d)
trap 'rm -rf ${WORKDIR}' EXIT

pushd "${WORKDIR}"

git clone --depth 1 --branch "${VERSION}" "${SPEC_URL}"

mkdir -p eam
unzip -d eam vcf-api-specs/documentation/vsphere/wsdl/eam/eam_apiref.zip
EAM_REF_GUIDE=${WORKDIR}/eam

mkdir -p pbm
unzip -d pbm vcf-api-specs/documentation/vsphere/wsdl/pbm/pbm_apiref.zip
PBM_REF_GUIDE=${WORKDIR}/pbm

mkdir -p sms
unzip -d sms vcf-api-specs/documentation/vsphere/wsdl/sms/sms_apiref.zip
SMS_REF_GUIDE=${WORKDIR}/sms

mkdir -p vim
unzip -d vim vcf-api-specs/documentation/vsphere/wsdl/vim/vim25_api_ref.zip
VIM_REF_GUIDE=${WORKDIR}/vim

mkdir -p vslm
unzip -d vslm vcf-api-specs/documentation/vsphere/wsdl/vslm/vslm_apiref.zip
VSLM_REF_GUIDE=${WORKDIR}/vslm

deno run --allow-read "${TOOL}/GenEamImplementation.ts" "${EAM_REF_GUIDE}" > "${SRC}EamClient.cs"
deno run --allow-read "${TOOL}/GenEamInterface.ts" "${EAM_REF_GUIDE}" > "${SRC}IEamClient.cs"
deno run --allow-read "${TOOL}/GenEamManagedObject.ts" "${EAM_REF_GUIDE}" > "${SRC}ManagedObject/GeneratedEam.cs"

deno run --allow-read "${TOOL}/GenPbmImplementation.ts" "${PBM_REF_GUIDE}" > "${SRC}PbmClient.cs"
deno run --allow-read "${TOOL}/GenPbmInterface.ts" "${PBM_REF_GUIDE}" > "${SRC}IPbmClient.cs"
deno run --allow-read "${TOOL}/GenPbmManagedObject.ts" "${PBM_REF_GUIDE}" > "${SRC}ManagedObject/GeneratedPbm.cs"

deno run --allow-read "${TOOL}/GenSmsImplementation.ts" "${SMS_REF_GUIDE}" > "${SRC}SmsClient.cs"
deno run --allow-read "${TOOL}/GenSmsInterface.ts" "${SMS_REF_GUIDE}" > "${SRC}ISmsClient.cs"
deno run --allow-read "${TOOL}/GenSmsManagedObject.ts" "${SMS_REF_GUIDE}" > "${SRC}ManagedObject/GeneratedSms.cs"

deno run --allow-read "${TOOL}/GenVimImplementation.ts" "${VIM_REF_GUIDE}" > "${SRC}VimClient.cs"
deno run --allow-read "${TOOL}/GenVimInterface.ts" "${VIM_REF_GUIDE}" > "${SRC}IVimClient.cs"
deno run --allow-read "${TOOL}/GenVimManagedObject.ts" "${VIM_REF_GUIDE}" > "${SRC}ManagedObject/GeneratedVim.cs"

deno run --allow-read "${TOOL}/GenVslmImplementation.ts" "${VSLM_REF_GUIDE}" > "${SRC}VslmClient.cs"
deno run --allow-read "${TOOL}/GenVslmInterface.ts" "${VSLM_REF_GUIDE}" > "${SRC}IVslmClient.cs"
deno run --allow-read "${TOOL}/GenVslmManagedObject.ts" "${VSLM_REF_GUIDE}" > "${SRC}ManagedObject/GeneratedVslm.cs"

popd
