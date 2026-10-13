import { PinataService, pinata } from './pinata.service';

export { pinata };

export class IpfsService {
  static async uploadPayload(payload: any): Promise<string> {
    return PinataService.pinJSONToIPFS(payload);
  }

  static async fetchPayload(cid: string): Promise<any> {
    return PinataService.fetchFromIPFS(cid);
  }
}
