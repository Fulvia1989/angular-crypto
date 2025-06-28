import { Injectable } from '@angular/core';
import { b64ToBytes, bufferToHex, hexToBytes, stringToUint8Array } from './crypto.utils';

/** Implementing Crypto Web API */


@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private chiaveDiAccesso : string = '';
  constructor(
  ) { }

  async getKey(password:string, salt:string, hmac = true){
    const iters = hmac ? 50_000 : 250_000;
    const keyHex = await this.pbkdf2Sha256Hex(password, salt, iters);
  }

  /**
 * Derives a 32‑byte key using PBKDF2‑SHA256 and returns it as a hex string.
 *
 * @param password     Passphrase in clear text
 * @param saltB64      Salt in Base64
 * @param iterations   Number of iterations (e.g. 50 000 or 250 000)
 * @returns            64‑char hex string (lowercase)
 */

  async pbkdf2Sha256Hex(
  password: string,
  saltB64: string,
  iterations: number
  ): Promise<string> {
    const salt = b64ToBytes(saltB64);
    const enc  = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      keyMaterial,
      256 // 32 bytes * 8 = 256 bits
    );

    return bufferToHex(bits);
    
  }

  /**
 * Calculates HMAC‑SHA‑256 of a message using a key in hex format.
 * Equivalent to Node: createHmac('sha256', keyHex).update(msg).digest('hex').toUpperCase()
 *
 * @param msg      Message to authenticate (string or Uint8Array)
 * @param keyHex   Key as hex string (e.g. "aabbcc…")
 * @returns        Upper‑case hex string of HMAC
 */

  async hmacSha256Hex(
  msg: string | Uint8Array,
  keyHex: string
  ): Promise<string> {
    const msgBytes = typeof msg === 'string' ? new TextEncoder().encode(msg) : msg;
    const keyBytes = hexToBytes(keyHex);

    // Import key for HMAC‑SHA‑256
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Sign and produce ArrayBuffer
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgBytes);
    return bufferToHex(signature); // already uppercase
  }

  async encryptAES(text:string, key:string, IV:string, salt:string) : Promise<string> {
      const buffer = stringToUint8Array(text);
      //const b64iv = plainTextToBase64(IV);
      const b64iv = IV;
      //const b64salt = plainTextToBase64(salt);
      const b64salt = salt;
      let encrypt = this.encrypt(buffer, key, b64iv, b64salt);
      return encrypt


  }

  async decryptAES(crypt_text:string, key:string, IV:string, salt:string) : Promise<string> {
       //const b64iv = plainTextToBase64(IV);
      const b64iv = IV;
      //const b64salt = plainTextToBase64(salt);
      const b64salt = salt;

      let decrypt_text = this.decryptAesGcmBase64(crypt_text, key, b64iv, salt);
      return decrypt_text
    
  }

/**
 * Decripta un payload cifrato in AES-256-GCM con tag finale di 16 byte
 *
 * @param encDataB64  cipherText||tag in Base64
 * @param masterKey   passphrase in chiaro   (se si usa PBKDF2)
 *                    └- oppure chiave AES a 32 byte codificata Base64
 * @param ivB64       IV (12 byte) in Base64
 * @param saltB64     SALT in Base64 (se presente → usa PBKDF2, altrimenti
 *                    interpreta `masterKey` come chiave AES già pronta)
 * @return            testo in chiaro (UTF-8)
 */
  async decryptAesGcmBase64(
  encDataB64: string,
  masterKey: string,
  ivB64: string,
  saltB64?: string
): Promise<string> {

    /* 1 — decodifica i parametri ------------------------------------------------ */
  const cipherAndTag = b64ToBytes(encDataB64);   // contiene già tag in coda
  const iv           = b64ToBytes(ivB64);        // 96 bit             (12 B)

  /* 2 — ottieni la CryptoKey AES-GCM a 256 bit ------------------------------- */
  let aesKey: CryptoKey;

  if (saltB64) {
    /* ▶ Caso A: deriva la chiave con PBKDF2-SHA-256 */
    const salt        = b64ToBytes(saltB64);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(masterKey), // passphrase in chiaro
      'PBKDF2',
      false,
      ['deriveKey']
    );
    console.log(keyMaterial);

    aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  } else {
    /* ▶ Caso B: la chiave è già un Base64 da 32 byte */
    const rawKey = b64ToBytes(masterKey);        // 256 bit
    aesKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  /* 3 — decripta ------------------------------------------------------------- */
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },                     // tagLength=128 bit di default
    aesKey,
    cipherAndTag                                  // cipherText||tag
  );

  /* 4 — torna il testo UTF-8 -------------------------------------------------- */
  return new TextDecoder().decode(plainBuf);
  }



  async encrypt(plaintext:Uint8Array, passphrase:string, base64Iv:string ,base64Salt:string){

     // 1. converte costanti
  const salt = Uint8Array.from(atob(base64Salt), c => c.charCodeAt(0));
  const iv   = Uint8Array.from(atob(base64Iv),   c => c.charCodeAt(0));

  // 2. ricava il “materiale chiave” dal passphrase
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );

  // 3. deriva chiave AES-256 con PBKDF2-SHA256 (250 000 iterazioni)
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt']
  );

  // 4. cifra con AES-GCM
  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintext
  );

  // 5. ritorna (cipherText || tag) in Base64, compatibile con Node 17+
  return btoa(String.fromCharCode(...new Uint8Array(cipherBuf)));
  }

  async sha1Hash(message:string){
    const encoder = new TextEncoder();
  const data = encoder.encode(message);

  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  // Convert bytes to hex string
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return hashHex;
   }

}
