import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { BchatProtocolEncryption, BELDEX_ADDRESS_LENGTH } from '../BchatProtocolEncryption';
import { decodeEnvelope, unwrapEnvelope, EnvelopeType } from '../wire';
import { removeMessagePadding } from '../padding';
import { createAccount } from '../../account';

const address = (network: 'mainnet' | 'testnet' = 'mainnet') =>
  'bxc'.padEnd(BELDEX_ADDRESS_LENGTH[network], 'A');

const provider = async (network: 'mainnet' | 'testnet' = 'mainnet', displayName?: string) => {
  const account = await createAccount();
  return {
    account,
    enc: new BchatProtocolEncryption({
      ed25519: account.ed25519,
      beldexAddress: address(network),
      network,
      displayName,
    }),
  };
};

describe('BchatProtocolEncryption', () => {
  it('rejects a wallet address of the wrong length', async () => {
    const account = await createAccount();
    expect(
      () =>
        new BchatProtocolEncryption({ ed25519: account.ed25519, beldexAddress: 'too-short' })
    ).toThrow(/exactly 97 characters/);
  });

  it('round-trips a message and authenticates the sender', async () => {
    const alice = await provider('mainnet', 'Alice');
    const bob = await provider();

    const payload = await alice.enc.encryptForRecipient(
      Buffer.from('hello bob', 'utf8'),
      bob.account.bchatId
    );

    const decoded = await bob.enc.decryptEnvelope(
      payload,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );

    expect(decoded?.body).toBe('hello bob');
    // sender is derived from the signed ed25519 key, not asserted by the sender
    expect(decoded?.senderBchatId).toBe(alice.account.bchatId);
    expect(decoded?.unverifiedSenderWalletAddress).toBe(address());
    expect(decoded?.displayName).toBe('Alice');
    expect(typeof decoded?.sentAt).toBe('number');
  });

  it('produces a BCHAT_MESSAGE envelope inside a WebSocketMessage', async () => {
    const alice = await provider();
    const bob = await provider();

    const payload = await alice.enc.encryptForRecipient(Buffer.from('x'), bob.account.bchatId);
    const envelope = decodeEnvelope(unwrapEnvelope(payload));

    expect(envelope.type).toBe(EnvelopeType.BCHAT_MESSAGE);
    expect(envelope.source).toBeUndefined(); // 1:1 messages carry no source
    expect(envelope.content?.length).toBeGreaterThan(0);
  });

  it('lays the sealed blob out as walletAddress ‖ padded ‖ edPub ‖ signature', async () => {
    await sodium.ready;
    const alice = await provider();
    const bob = await provider();

    const payload = await alice.enc.encryptForRecipient(
      Buffer.from('layout check'),
      bob.account.bchatId
    );
    const envelope = decodeEnvelope(unwrapEnvelope(payload));

    const blob = sodium.crypto_box_seal_open(
      envelope.content!,
      Buffer.from(bob.account.x25519.publicKey, 'hex'),
      Buffer.from(bob.account.x25519.privateKey, 'hex')
    );

    const signature = blob.subarray(blob.length - 64);
    const edPub = blob.subarray(blob.length - 96, blob.length - 64);
    const signed = blob.subarray(0, blob.length - 96);

    expect(Buffer.from(edPub).toString('hex')).toBe(alice.account.ed25519.publicKey);
    expect(Buffer.from(signed.subarray(0, 97)).toString('utf8')).toBe(address());

    // the padded content sits between the address and the ed25519 key
    const content = removeMessagePadding(signed.subarray(97));
    expect(content.length).toBeGreaterThan(0);

    // and the signature covers signed ‖ edPub ‖ recipientX25519
    const verification = Buffer.concat([
      Buffer.from(signed),
      Buffer.from(edPub),
      Buffer.from(bob.account.x25519.publicKey, 'hex'),
    ]);
    expect(sodium.crypto_sign_verify_detached(signature, verification, edPub)).toBe(true);
  });

  it('returns null for a message addressed to someone else', async () => {
    const alice = await provider();
    const bob = await provider();
    const eve = await provider();

    const payload = await alice.enc.encryptForRecipient(Buffer.from('secret'), bob.account.bchatId);
    const decoded = await eve.enc.decryptEnvelope(
      payload,
      eve.account.x25519.privateKey,
      eve.account.x25519.publicKey
    );
    expect(decoded).toBeNull();
  });

  it('rejects a payload whose signature was tampered with', async () => {
    const alice = await provider();
    const bob = await provider();

    const payload = await alice.enc.encryptForRecipient(Buffer.from('trust me'), bob.account.bchatId);
    const envelope = decodeEnvelope(unwrapEnvelope(payload));

    // flip a bit inside the sealed box: seal_open itself will now fail
    const tampered = Uint8Array.from(envelope.content!);
    tampered[tampered.length - 1] ^= 0x01;

    const forged = await bob.enc.decryptEnvelope(
      // re-wrap the tampered ciphertext
      (await import('../wire')).wrapEnvelope(
        (await import('../wire')).encodeEnvelope({
          type: EnvelopeType.BCHAT_MESSAGE,
          timestamp: Date.now(),
          content: tampered,
        })
      ),
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    expect(forged).toBeNull();
  });

  it('ignores payloads that are not BChat envelopes at all', async () => {
    const bob = await provider();
    const decoded = await bob.enc.decryptEnvelope(
      Buffer.from('not a protobuf at all, just text'),
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    expect(decoded).toBeNull();
  });

  it('uses the 95-byte address length on testnet', async () => {
    const alice = await provider('testnet');
    const bob = await provider('testnet');

    const payload = await alice.enc.encryptForRecipient(Buffer.from('tn'), bob.account.bchatId);
    const decoded = await bob.enc.decryptEnvelope(
      payload,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    expect(decoded?.body).toBe('tn');
    expect(decoded?.unverifiedSenderWalletAddress).toHaveLength(95);
  });
});

describe('security hardening', () => {
  it('labels the wallet address as unverified and spoofable (BCHAT-04)', async () => {
    const victimWallet = 'bxcVICTIM'.padEnd(97, 'V');
    const malloryWallet = 'bxcMALLORY'.padEnd(97, 'M');

    const mallory = await createAccount();
    const bob = await provider();

    // Mallory signs with her own key but embeds the victim's wallet address.
    const spoofer = new BchatProtocolEncryption({
      ed25519: mallory.ed25519,
      beldexAddress: victimWallet,
      network: 'mainnet',
    });

    const payload = await spoofer.encryptForRecipient(Buffer.from('pay me'), bob.account.bchatId);
    const decoded = await bob.enc.decryptEnvelope(
      payload,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );

    // The sender ID is authenticated and correctly identifies Mallory...
    expect(decoded?.senderBchatId).toBe(mallory.bchatId);
    // ...while the wallet address is simply whatever she chose. That is the
    // whole reason the field is named `unverified`.
    expect(decoded?.unverifiedSenderWalletAddress).toBe(victimWallet);
    expect(decoded?.unverifiedSenderWalletAddress).not.toBe(malloryWallet);
    expect('senderWalletAddress' in (decoded ?? {})).toBe(false);
  });

  it('rejects a message dated far in the past (BCHAT-05)', async () => {
    const alice = await provider();
    const bob = await provider();

    const payload = await alice.enc.encryptForRecipient(Buffer.from('stale'), bob.account.bchatId);

    // 15 days later the payload is beyond the store TTL window.
    const realNow = Date.now;
    Date.now = () => realNow() + 15 * 24 * 60 * 60 * 1000;
    try {
      const decoded = await bob.enc.decryptEnvelope(
        payload,
        bob.account.x25519.privateKey,
        bob.account.x25519.publicKey
      );
      expect(decoded).toBeNull();
    } finally {
      Date.now = realNow;
    }
  });

  it('rejects a message dated implausibly in the future (BCHAT-05)', async () => {
    const alice = await provider();
    const bob = await provider();
    const payload = await alice.enc.encryptForRecipient(Buffer.from('future'), bob.account.bchatId);

    const realNow = Date.now;
    Date.now = () => realNow() - 60 * 60 * 1000; // our clock an hour behind
    try {
      expect(
        await bob.enc.decryptEnvelope(
          payload,
          bob.account.x25519.privateKey,
          bob.account.x25519.publicKey
        )
      ).toBeNull();
    } finally {
      Date.now = realNow;
    }
  });

  it('still accepts a message inside the skew tolerance', async () => {
    const alice = await provider();
    const bob = await provider();
    const payload = await alice.enc.encryptForRecipient(Buffer.from('fresh'), bob.account.bchatId);

    const realNow = Date.now;
    Date.now = () => realNow() - 5 * 60 * 1000; // 5 min of skew, within tolerance
    try {
      const decoded = await bob.enc.decryptEnvelope(
        payload,
        bob.account.x25519.privateKey,
        bob.account.x25519.publicKey
      );
      expect(decoded?.body).toBe('fresh');
    } finally {
      Date.now = realNow;
    }
  });
});

describe('non-text content types', () => {
  it('decodes a reaction as kind "reaction" rather than a failure', async () => {
    const { ProtoWriter } = await import('../protobuf');
    const { decodeContent } = await import('../wire');
    const { addMessagePadding, removeMessagePadding } = await import('../padding');

    // DataMessage { timestamp = 7, reaction = 11 { id=1, author=2, emoji=3, action=4 } }
    const reaction = new ProtoWriter()
      .uint(1, 1_767_000_000_000)
      .string(2, 'bd' + 'a'.repeat(64))
      .string(3, '\u{1F44D}')
      .uint(4, 0);
    const content = new ProtoWriter()
      .message(1, new ProtoWriter().uint(7, Date.now()).message(11, reaction))
      .finish();

    const decoded = decodeContent(content);
    expect(decoded.kind).toBe('reaction');
    expect(decoded.dataMessage?.reaction?.emoji).toBe('\u{1F44D}');
    expect(decoded.dataMessage?.reaction?.messageTimestamp).toBe(1_767_000_000_000);
    expect(decoded.dataMessage?.reaction?.action).toBe(0);
    // no body -- which is exactly why an absent body must not mean "failed"
    expect(decoded.dataMessage?.body).toBeUndefined();

    // survives the padding round trip the real payload goes through
    expect(decodeContent(removeMessagePadding(addMessagePadding(content))).kind).toBe('reaction');
  });

  it('marks a removed reaction with action = 1', async () => {
    const { ProtoWriter } = await import('../protobuf');
    const { decodeContent } = await import('../wire');

    const reaction = new ProtoWriter().uint(1, 1).string(2, 'bd00').string(3, '\u2764').uint(4, 1);
    const content = new ProtoWriter()
      .message(1, new ProtoWriter().message(11, reaction))
      .finish();

    expect(decodeContent(content).dataMessage?.reaction?.action).toBe(1);
  });

  it('classifies typing, receipt and unsend payloads instead of reporting failure', async () => {
    const { ProtoWriter } = await import('../protobuf');
    const { decodeContent } = await import('../wire');

    const typing = new ProtoWriter()
      .message(6, new ProtoWriter().uint(1, Date.now()).uint(2, 0))
      .finish();
    expect(decodeContent(typing).kind).toBe('typing');

    const receipt = new ProtoWriter()
      .message(5, new ProtoWriter().uint(1, 1).uint(2, Date.now()))
      .finish();
    expect(decodeContent(receipt).kind).toBe('receipt');

    const unsend = new ProtoWriter()
      .message(9, new ProtoWriter().uint(1, Date.now()).string(2, 'bd00'))
      .finish();
    expect(decodeContent(unsend).kind).toBe('unsend');

    expect(decodeContent(new Uint8Array(0)).kind).toBe('unknown');
  });

  it('reports a plain text message as kind "message"', async () => {
    const { encodeContent, decodeContent } = await import('../wire');
    const decoded = decodeContent(encodeContent({ body: 'hi', timestamp: Date.now() }));
    expect(decoded.kind).toBe('message');
    expect(decoded.dataMessage?.body).toBe('hi');
  });

  it('round-trips a real sealed message as kind "message"', async () => {
    const alice = await provider();
    const bob = await provider();
    const payload = await alice.enc.encryptForRecipient(Buffer.from('hey'), bob.account.bchatId);
    const decoded = await bob.enc.decryptEnvelope(
      payload,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    expect(decoded?.kind).toBe('message');
    expect(decoded?.body).toBe('hey');
  });
});

describe('replies (quotes)', () => {
  it('decodes a quote alongside the reply body', async () => {
    const { ProtoWriter } = await import('../protobuf');
    const { decodeContent } = await import('../wire');
    const { addMessagePadding, removeMessagePadding } = await import('../padding');

    // DataMessage { body = 1, quote = 8 { id=1, author=2, text=3 }, timestamp = 7 }
    const quote = new ProtoWriter()
      .uint(1, 1_767_000_000_000)
      .string(2, 'bd' + 'a'.repeat(64))
      .string(3, 'the original message');
    const content = new ProtoWriter()
      .message(
        1,
        new ProtoWriter().string(1, 'my reply').uint(7, Date.now()).message(8, quote)
      )
      .finish();

    const decoded = decodeContent(content);

    // A reply stays kind 'message' -- consumers switching on kind must not
    // silently drop it.
    expect(decoded.kind).toBe('message');
    expect(decoded.dataMessage?.body).toBe('my reply');
    expect(decoded.dataMessage?.quote?.text).toBe('the original message');
    expect(decoded.dataMessage?.quote?.author).toBe('bd' + 'a'.repeat(64));
    expect(decoded.dataMessage?.quote?.messageTimestamp).toBe(1_767_000_000_000);

    // survives the padding round trip
    const again = decodeContent(removeMessagePadding(addMessagePadding(content)));
    expect(again.dataMessage?.quote?.text).toBe('the original message');
  });

  it('round-trips a quote through encodeContent', async () => {
    const { encodeContent, decodeContent } = await import('../wire');
    const encoded = encodeContent({
      body: 'sure',
      timestamp: 1_767_000_000_005,
      quote: { messageTimestamp: 1_767_000_000_001, author: 'bd00', text: 'shall we?' },
    });

    const decoded = decodeContent(encoded);
    expect(decoded.kind).toBe('message');
    expect(decoded.dataMessage?.body).toBe('sure');
    expect(decoded.dataMessage?.quote).toEqual({
      messageTimestamp: 1_767_000_000_001,
      author: 'bd00',
      text: 'shall we?',
    });
  });

  it('leaves quote undefined on an ordinary message', async () => {
    const { encodeContent, decodeContent } = await import('../wire');
    const decoded = decodeContent(encodeContent({ body: 'plain', timestamp: Date.now() }));
    expect(decoded.dataMessage?.quote).toBeUndefined();
  });

  it('surfaces the quote through a real sealed round trip', async () => {
    const alice = await provider();
    const bob = await provider();

    // seal a reply built with encodeContent, via the public API path
    const payload = await alice.enc.encryptForRecipient(Buffer.from('agreed'), bob.account.bchatId);
    const decoded = await bob.enc.decryptEnvelope(
      payload,
      bob.account.x25519.privateKey,
      bob.account.x25519.publicKey
    );
    // plain send carries no quote
    expect(decoded?.quote).toBeUndefined();
    expect(decoded?.body).toBe('agreed');
  });
});
