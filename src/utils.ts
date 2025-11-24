export function fromBase64Url(base64url: string) {
  const base64 = base64url.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    '=',
  );
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export function toHex(bytes: Uint8Array) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}
