import { describe, expect, it } from 'vitest';
import { BchatProtocolEncryption, BELDEX_ADDRESS_LENGTH } from '../BchatProtocolEncryption';
import { ProtoWriter } from '../protobuf';
import {
  CallMessageType,
  decodeCallMessage,
  decodeContent,
  encodeCallContent,
  encodeCallMessage,
} from '../wire';
import { createAccount } from '../../account';

const UUID = '6f1c1c52-0d0b-4a6e-9a55-0c4b1f0f6a11';

const provider = async () => {
  const account = await createAccount();
  return {
    account,
    enc: new BchatProtocolEncryption({
      ed25519: account.ed25519,
      beldexAddress: 'bxc'.padEnd(BELDEX_ADDRESS_LENGTH.mainnet, 'A'),
      network: 'mainnet',
    }),
  };
};

describe('call messages on the wire', () => {
  it('round-trips an offer', () => {
    const sdp = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n';
    const back = decodeCallMessage(
      encodeCallMessage({ type: CallMessageType.OFFER, uuid: UUID, sdps: [sdp] }).finish()
    );
    expect(back).toEqual({ type: 1, uuid: UUID, sdps: [sdp], sdpMLineIndexes: [], sdpMids: [] });
  });

  it('keeps a batch of ICE candidates aligned, including media index 0', () => {
    const call = {
      type: CallMessageType.ICE_CANDIDATES,
      uuid: UUID,
      sdps: ['candidate:1 1 udp 1 10.0.0.1 5000 typ relay', 'candidate:2 1 udp 1 10.0.0.2 5001 typ relay'],
      sdpMLineIndexes: [0, 1],
      sdpMids: ['audio', 'video'],
    };
    expect(decodeCallMessage(encodeCallMessage(call).finish())).toEqual(call);
  });

  it('reads media indexes a sender wrote in packed form', () => {
    const packed = new ProtoWriter()
      .uint(1, CallMessageType.ICE_CANDIDATES)
      .bytes(3, new Uint8Array([0, 1, 0xac, 0x02])) // 0, 1, 300
      .string(5, UUID)
      .finish();
    expect(decodeCallMessage(packed).sdpMLineIndexes).toEqual([0, 1, 300]);
  });

  it('a pre-offer and an end of call carry only the type and the call id', () => {
    for (const type of [CallMessageType.PRE_OFFER, CallMessageType.END_CALL]) {
      const decoded = decodeContent(encodeCallContent({ type, uuid: UUID }));
      expect(decoded.kind).toBe('call');
      expect(decoded.call).toEqual({ type, uuid: UUID, sdps: [], sdpMLineIndexes: [], sdpMids: [] });
    }
  });
});

describe('call messages through BchatProtocolEncryption', () => {
  it('delivers an answer with the sender authenticated', async () => {
    const alice = await provider();
    const bob = await provider();
    const sealed = await alice.enc.encryptCallForRecipient(
      { type: CallMessageType.ANSWER, uuid: UUID, sdps: ['v=0\r\n'] },
      bob.account.bchatId
    );
    const opened = await bob.enc.decryptEnvelope(
      sealed,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    expect(opened?.kind).toBe('call');
    expect(opened?.senderBchatId).toBe(alice.account.bchatId);
    expect(opened?.call).toMatchObject({ type: 2, uuid: UUID, sdps: ['v=0\r\n'] });
    expect(opened?.body).toBeUndefined();
  });
});
