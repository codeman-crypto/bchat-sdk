import { Buffer } from 'buffer';
import { Transport } from './Transport.js';
import { SendMessageParams, Snode } from '../types.js';
import { BchatRpc } from '../snode/bchatRpc.js';

const DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000;

export class DirectTransport implements Transport {
  constructor(private rpc: BchatRpc) {}

  store(params: SendMessageParams, target: Snode) {
    const rpcParams = {
      pubKey: params.recipientPubKey,
      ttl: `${params.ttlMs ?? DEFAULT_TTL_MS}`,
      timestamp: `${params.timestampMs ?? Date.now()}`,
      // storage_rpc `data` is always base64. A string payload used to be
      // forwarded verbatim, so calling the transport directly with text sent
      // an unparseable body to the snode.
      data: Buffer.from(
        typeof params.payload === 'string' ? Buffer.from(params.payload, 'utf8') : params.payload
      ).toString('base64'),
      isSyncMessage: params.isSyncMessage,
      messageId: params.messageId,
      namespace: params.namespace ?? 0,
    };
    return this.rpc.call({ method: 'store', params: rpcParams, targetNode: target });
  }

  retrieve(params: any, target: Snode) {
    return this.rpc.call({ method: 'retrieve', params, targetNode: target });
  }
}
