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
  decodeFields,
  firstBytes,
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

export type DataMessage = {
  body?: string;
  timestamp?: number;
  profile?: LokiProfile;
  reaction?: Reaction;
  quote?: Quote;
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

/** Content field numbers, from bchat-desktop's SignalService.proto. */
const CONTENT_FIELDS: Array<[number, ContentKind]> = [
  [3, 'call'],
  [5, 'receipt'],
  [6, 'typing'],
  [7, 'configuration'],
  [8, 'dataExtraction'],
  [9, 'unsend'],
  [10, 'messageRequestResponse'],
];

export function decodeContent(buf: Uint8Array): {
  dataMessage?: DataMessage;
  kind: ContentKind;
} {
  const fields = decodeFields(buf);
  const dataMessageBytes = firstBytes(fields, 1);

  if (dataMessageBytes) {
    const dataMessage = decodeDataMessage(dataMessageBytes);
    return {
      dataMessage,
      kind: dataMessage.reaction ? 'reaction' : 'message',
    };
  }

  for (const [field, kind] of CONTENT_FIELDS) {
    if (fields.has(field)) return { kind };
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
