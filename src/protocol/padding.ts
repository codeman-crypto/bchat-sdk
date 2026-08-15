/**
 * Message padding, ported byte-for-byte from bchat-desktop
 * (ts/bchat/crypto/BufferPadding.ts).
 *
 * A padded buffer ends with 0x80 followed by any number of 0x00, and the whole
 * thing is rounded up to a multiple of 160 bytes so that message length leaks
 * less about the content.
 */
const PADDING_BYTE = 0x00;
const TERMINATOR = 0x80;
const BLOCK = 160;

function getPaddedMessageLength(originalLength: number): number {
  const messageLengthWithTerminator = originalLength + 1;
  let messagePartCount = Math.floor(messageLengthWithTerminator / BLOCK);
  if (messageLengthWithTerminator % BLOCK !== 0) messagePartCount += 1;
  return messagePartCount * BLOCK;
}

export function addMessagePadding(messageBuffer: Uint8Array): Uint8Array {
  const plaintext = new Uint8Array(getPaddedMessageLength(messageBuffer.byteLength + 1) - 1);
  plaintext.set(messageBuffer);
  plaintext[messageBuffer.byteLength] = TERMINATOR;
  return plaintext;
}

export function removeMessagePadding(paddedData: Uint8Array): Uint8Array {
  for (let i = paddedData.length - 1; i >= 0; i -= 1) {
    if (paddedData[i] === TERMINATOR) {
      return paddedData.subarray(0, i);
    }
    if (paddedData[i] !== PADDING_BYTE) {
      // Unpadded payload -- desktop lets these through rather than failing.
      return paddedData;
    }
  }
  throw new Error('Invalid padding');
}
