export const b64ToBytes = (b64: string) =>
  Uint8Array.from(atob(b64), c => c.charCodeAt(0));

export function plainTextToBase64(str: string): string {
  // Prima converti la stringa in Uint8Array (bytes UTF-8)
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);

  // Poi converti i bytes in una stringa "binary" per btoa (che lavora su ASCII)
  let binary = '';
  bytes.forEach((b) => binary += String.fromCharCode(b));

  // Ora usa btoa per ottenere Base64
  return btoa(binary);
}
// Utility to convert a hex string to Uint8Array
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Hex string must have even length');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, 2), 16);
  }
  return bytes;
}
export function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder(); // Usa TextEncoder per UTF-8
  return encoder.encode(str); // encode ritorna un Uint8Array, prendi il buffer sottostante
}

export function uint8ArrayToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder(); // UTF-8 per default
  return decoder.decode(bytes);
}

// Utility to convert ArrayBuffer → uppercase hex string
export function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}