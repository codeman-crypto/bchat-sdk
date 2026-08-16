/**
 * The BChat protobuf messages this SDK needs, encoded by hand.
 *
 * Field numbers are taken from bchat-desktop's protos/SignalService.proto.
 * BChat's Envelope differs from Session's: it has no `sourceDevice`, and adds
 * `isBnsHolder = 9`.
 */
import { Buffer } from 'buffer';
import {
  ProtoWriter,
  allBytes,
  allNumbers,
  decodeFields,
  firstBytes,
  firstFixed64,
  firstNumber,
  firstString,
} from './protobuf.js';

export const EnvelopeType = {
  BCHAT_MESSAGE: 6,
  CLOSED_GROUP_MESSAGE: 7,
} as const;

export const WebSocketMessageType = {
  UNKNOWN: 0,
  REQUEST: 1,
  RESPONSE: 2,
} as const;

// ---------------------------------------------------------------- DataMessage

export type LokiProfile = { displayName?: string; profilePicture?: string };

export const ReactionAction = { REACT: 0, REMOVE: 1 } as const;

/** DataMessage.Reaction: id = 1, author = 2, emoji = 3, action = 4 */
export type Reaction = {
  /** sent-timestamp of the message being reacted to */
  messageTimestamp?: number;
  author?: string;
  emoji?: string;
  /** 0 = react, 1 = remove */
  action?: number;
};

/**
 * DataMessage.Quote: id = 1, author = 2, text = 3, attachments = 4.
 *
 * A reply is an ordinary text message that additionally carries a Quote naming
 * the message being replied to.
 */
export type Quote = {
  /** sent-timestamp of the message being replied to; identifies it */
  messageTimestamp?: number;
  /** BChat ID of the quoted message's author */
  author?: string;
  /** the quoted excerpt, as the replying client chose to render it */
  text?: string;
};

/** DataMessage.Flags */
export const DataMessageFlags = { EXPIRATION_TIMER_UPDATE: 2 } as const;

/** AttachmentPointer.Flags */
export const AttachmentFlags = { VOICE_MESSAGE: 1 } as const;

/**
 * AttachmentPointer: id = 1 (fixed64), contentType = 2, key = 3, size = 4,
 * digest = 6, fileName = 7, flags = 8, width = 9, height = 10, caption = 11,
 * url = 101.
 *
 * The SDK does not download or decrypt attachment bodies; this is metadata
 * only, so a client can say "a 1.2 MB image arrived" instead of showing an
 * empty message.
 */
export type AttachmentPointer = {
  id?: string;
  contentType?: string;
  size?: number;
  fileName?: string;
  caption?: string;
  url?: string;
  width?: number;
  height?: number;
  /** true when AttachmentFlags.VOICE_MESSAGE is set */
  isVoiceMessage?: boolean;
};

/** DataMessage.Preview: url = 1, title = 2, image = 3 */
export type LinkPreview = { url?: string; title?: string };

/** DataMessage.OpenGroupInvitation: url = 1, name = 3 */
export type OpenGroupInvitation = { url?: string; name?: string };

/** DataMessage.Payment: amount = 1, txnId = 3 */
export type Payment = { amount?: string; txnId?: string };

/** DataMessage.SharedContact: address = 1, name = 2 */
export type SharedContact = { address?: string; name?: string };

export type DataMessage = {
  body?: string;
  timestamp?: number;
  profile?: LokiProfile;
  reaction?: Reaction;
  quote?: Quote;
  attachments?: AttachmentPointer[];
  previews?: LinkPreview[];
  openGroupInvitation?: OpenGroupInvitation;
  payment?: Payment;
  sharedContact?: SharedContact;
  /** seconds; 0 disables disappearing messages */
  expireTimer?: number;
  /** true when this message only announces a disappearing-timer change */
  isExpirationTimerUpdate?: boolean;
  /**
   * Set on a message we sent from another device, mirrored to our own mailbox.
   * Its value is the real recipient, so a client should not show it as inbound.
   */
  syncTarget?: string;
  /** the message targets a closed group, which this SDK does not support */
  hasGroupContext?: boolean;
};

/** DataMessage: body = 1, timestamp = 7, profile = 101 */
export function encodeDataMessage(message: DataMessage): ProtoWriter {
  const writer = new ProtoWriter().string(1, message.body).uint(7, message.timestamp);

  if (message.quote) {
    const quote = new ProtoWriter()
      .uint(1, message.quote.messageTimestamp)
      .string(2, message.quote.author)
      .string(3, message.quote.text);
    writer.message(8, quote);
  }

  if (message.profile) {
    // LokiProfile: displayName = 1, profilePicture = 2
    const profile = new ProtoWriter()
      .string(1, message.profile.displayName)
      .string(2, message.profile.profilePicture);
    writer.message(101, profile);
  }

  return writer;
}

export function decodeDataMessage(buf: Uint8Array): DataMessage {
  const fields = decodeFields(buf);
  const profileBytes = firstBytes(fields, 101);
  const profileFields = profileBytes ? decodeFields(profileBytes) : undefined;

  const reactionBytes = firstBytes(fields, 11);
  const reactionFields = reactionBytes ? decodeFields(reactionBytes) : undefined;

  const quoteBytes = firstBytes(fields, 8);
  const quoteFields = quoteBytes ? decodeFields(quoteBytes) : undefined;

  const attachments = allBytes(fields, 2).map(decodeAttachmentPointer);
  const previews = allBytes(fields, 10).map(buf => {
    const f = decodeFields(buf);
    return { url: firstString(f, 1), title: firstString(f, 2) };
  });

  const invitationBytes = firstBytes(fields, 102);
  const paymentBytes = firstBytes(fields, 106);
  const contactBytes = firstBytes(fields, 107);
  const flags = firstNumber(fields, 4) ?? 0;

  return {
    body: firstString(fields, 1),
    timestamp: firstNumber(fields, 7),
    quote: quoteFields
      ? {
          messageTimestamp: firstNumber(quoteFields, 1),
          author: firstString(quoteFields, 2),
          text: firstString(quoteFields, 3),
        }
      : undefined,
    profile: profileFields
      ? {
          displayName: firstString(profileFields, 1),
          profilePicture: firstString(profileFields, 2),
        }
      : undefined,
    reaction: reactionFields
      ? {
          messageTimestamp: firstNumber(reactionFields, 1),
          author: firstString(reactionFields, 2),
          emoji: firstString(reactionFields, 3),
          action: firstNumber(reactionFields, 4) ?? ReactionAction.REACT,
        }
      : undefined,
    attachments: attachments.length ? attachments : undefined,
    previews: previews.length ? previews : undefined,
    openGroupInvitation: invitationBytes
      ? (() => {
          const f = decodeFields(invitationBytes);
          return { url: firstString(f, 1), name: firstString(f, 3) };
        })()
      : undefined,
    payment: paymentBytes
      ? (() => {
          const f = decodeFields(paymentBytes);
          return { amount: firstString(f, 1), txnId: firstString(f, 3) };
        })()
      : undefined,
    sharedContact: contactBytes
      ? (() => {
          const f = decodeFields(contactBytes);
          return { address: firstString(f, 1), name: firstString(f, 2) };
        })()
      : undefined,
    expireTimer: firstNumber(fields, 5),
    isExpirationTimerUpdate:
      (flags & DataMessageFlags.EXPIRATION_TIMER_UPDATE) !== 0 || undefined,
    syncTarget: firstString(fields, 105),
    hasGroupContext: fields.has(3) || fields.has(104) || undefined,
  };
}

export function decodeAttachmentPointer(buf: Uint8Array): AttachmentPointer {
  const f = decodeFields(buf);
  const flags = firstNumber(f, 8) ?? 0;
  return {
    id: firstFixed64(f, 1),
    contentType: firstString(f, 2),
    size: firstNumber(f, 4),
    fileName: firstString(f, 7),
    caption: firstString(f, 11),
    url: firstString(f, 101),
    width: firstNumber(f, 9),
    height: firstNumber(f, 10),
    isVoiceMessage: (flags & AttachmentFlags.VOICE_MESSAGE) !== 0 || undefined,
  };
}

// -------------------------------------------------------------------- Content

/** Content: dataMessage = 1 */
export function encodeContent(dataMessage: DataMessage): Uint8Array {
  return new ProtoWriter().message(1, encodeDataMessage(dataMessage)).finish();
}

/**
 * Which Content variant arrived. Only `dataMessage` carries text, so anything
 * else legitimately has no body — reporting those as "could not be decrypted"
 * confuses a successful decode with a failure.
 */
export type ContentKind =
  | 'message'
  | 'reaction'
  | 'call'
  | 'receipt'
  | 'typing'
  | 'configuration'
  | 'dataExtraction'
  | 'unsend'
  | 'messageRequestResponse'
  | 'unknown';

export const TypingAction = { STARTED: 0, STOPPED: 1 } as const;
export const ReceiptType = { READ: 1 } as const;
export const DataExtractionType = { SCREENSHOT: 1, MEDIA_SAVED: 2 } as const;

/** TypingMessage: timestamp = 1, action = 2 */
export type TypingMessage = { timestamp?: number; action?: number };
/** ReceiptMessage: type = 1, timestamp = 2 (repeated) */
export type ReceiptMessage = { type?: number; timestamps: number[] };
/** Unsend: timestamp = 1, author = 2 — a request to delete a sent message */
export type UnsendRequest = { timestamp?: number; author?: string };
/** DataExtractionNotification: type = 1, timestamp = 2 */
export type DataExtractionNotification = { type?: number; timestamp?: number };
/** MessageRequestResponse: isApproved = 1 */
export type MessageRequestResponse = { isApproved?: boolean };
/** CallMessage: type = 1, uuid = 5 */
export type CallMessage = { type?: number; uuid?: string };

export type DecodedContent = {
  kind: ContentKind;
  dataMessage?: DataMessage;
  typing?: TypingMessage;
  receipt?: ReceiptMessage;
  unsend?: UnsendRequest;
  dataExtraction?: DataExtractionNotification;
  messageRequestResponse?: MessageRequestResponse;
  call?: CallMessage;
};

export function decodeContent(buf: Uint8Array): DecodedContent {
  const fields = decodeFields(buf);
  const dataMessageBytes = firstBytes(fields, 1);

  if (dataMessageBytes) {
    const dataMessage = decodeDataMessage(dataMessageBytes);
    return {
      // A reply, an attachment, a payment and a plain line of text are all
      // `message`: they are DataMessages a client should surface. Only a
      // reaction gets its own kind, because it annotates another message
      // rather than being one.
      kind: dataMessage.reaction ? 'reaction' : 'message',
      dataMessage,
    };
  }

  const call = firstBytes(fields, 3);
  if (call) {
    const f = decodeFields(call);
    return { kind: 'call', call: { type: firstNumber(f, 1), uuid: firstString(f, 5) } };
  }

  const receipt = firstBytes(fields, 5);
  if (receipt) {
    const f = decodeFields(receipt);
    return {
      kind: 'receipt',
      receipt: { type: firstNumber(f, 1), timestamps: allNumbers(f, 2) },
    };
  }

  const typing = firstBytes(fields, 6);
  if (typing) {
    const f = decodeFields(typing);
    return {
      kind: 'typing',
      typing: { timestamp: firstNumber(f, 1), action: firstNumber(f, 2) },
    };
  }

  if (fields.has(7)) return { kind: 'configuration' };

  const extraction = firstBytes(fields, 8);
  if (extraction) {
    const f = decodeFields(extraction);
    return {
      kind: 'dataExtraction',
      dataExtraction: { type: firstNumber(f, 1), timestamp: firstNumber(f, 2) },
    };
  }

  const unsend = firstBytes(fields, 9);
  if (unsend) {
    const f = decodeFields(unsend);
    return {
      kind: 'unsend',
      unsend: { timestamp: firstNumber(f, 1), author: firstString(f, 2) },
    };
  }

  const request = firstBytes(fields, 10);
  if (request) {
    const f = decodeFields(request);
    return {
      kind: 'messageRequestResponse',
      messageRequestResponse: { isApproved: firstNumber(f, 1) === 1 },
    };
  }

  return { kind: 'unknown' };
}

// ------------------------------------------------------------------- Envelope

export type Envelope = {
  type: number;
  source?: string;
  timestamp: number;
  content?: Uint8Array;
  isBnsHolder?: boolean;
};

/** Envelope: type = 1, source = 2, timestamp = 5, content = 8, isBnsHolder = 9 */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  return new ProtoWriter()
    .uint(1, envelope.type)
    .string(2, envelope.source)
    .uint(5, envelope.timestamp)
    .bytes(8, envelope.content)
    .bool(9, envelope.isBnsHolder)
    .finish();
}

export function decodeEnvelope(buf: Uint8Array): Envelope {
  const fields = decodeFields(buf);
  const type = firstNumber(fields, 1);
  const timestamp = firstNumber(fields, 5);
  if (type === undefined) throw new Error('envelope: missing required field `type`');

  return {
    type,
    source: firstString(fields, 2),
    timestamp: timestamp ?? 0,
    content: firstBytes(fields, 8),
    isBnsHolder: firstNumber(fields, 9) === 1,
  };
}

// ----------------------------------------------------------- WebSocketMessage

/**
 * Storage-node payloads are an Envelope wrapped in a WebSocketMessage. Desktop
 * calls this "an outdated practice" in a comment but still does it, so
 * interoperable clients have to as well.
 *
 * WebSocketRequestMessage: verb = 1, path = 2, body = 3, id = 4, headers = 5
 * WebSocketMessage:        type = 1, request = 2, response = 3
 */
export function wrapEnvelope(envelopeBytes: Uint8Array): Uint8Array {
  const request = new ProtoWriter()
    .string(1, 'PUT')
    .string(2, '/api/v1/message')
    .bytes(3, envelopeBytes);

  return new ProtoWriter()
    .uint(1, WebSocketMessageType.REQUEST)
    .message(2, request)
    .finish();
}

/**
 * Returns the Envelope bytes from a stored payload.
 *
 * Accepts both the WebSocketMessage wrapper and a bare Envelope, since not
 * every client on the network wraps.
 */
export function unwrapEnvelope(payload: Uint8Array): Uint8Array {
  try {
    const fields = decodeFields(payload);
    const type = firstNumber(fields, 1);
    const request = firstBytes(fields, 2);
    if (type === WebSocketMessageType.REQUEST && request) {
      const body = firstBytes(decodeFields(request), 3);
      if (body) return body;
    }
  } catch {
    // fall through: treat it as a bare envelope
  }
  return payload;
}

export const utf8 = (s: string) => Buffer.from(s, 'utf8');
