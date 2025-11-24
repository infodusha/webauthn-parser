import { expect, test } from 'bun:test';

import { parseClient } from '../../src';

test('clientDataJSON', () => {
  const clientDataJSON =
    '7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2241514944222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303330222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2f796162506578227d';

  const collectedClientData = parseClient(Uint8Array.fromHex(clientDataJSON));

  expect(collectedClientData.type).toBe('webauthn.create');
  expect(collectedClientData.challenge).toEqual(new Uint8Array([1, 2, 3]));
  expect(collectedClientData.origin).toBe('http://localhost:3030');
});
