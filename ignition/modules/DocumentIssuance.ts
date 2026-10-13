import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const DocumentIssuanceModule = buildModule("DocumentIssuanceModule", (m) => {
  const documentIssuance = m.contract("DocumentIssuanceConsortium");

  return { documentIssuance };
});

export default DocumentIssuanceModule;
