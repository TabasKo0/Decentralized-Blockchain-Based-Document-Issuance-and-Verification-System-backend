import { RelayerService } from './relayer.service';

export class RelayService extends RelayerService {
  async issueDocumentOnChain(docHash: string, citizenAddress: string, docType: string) {
    return this.issueDocument(docHash, citizenAddress, docType);
  }

  async revokeDocumentOnChain(docHash: string) {
    return this.revokeDocument(docHash);
  }
}
