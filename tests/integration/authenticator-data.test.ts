import { expect, test } from "bun:test";

import { parseAuthenticatorData } from "../../src";

test("authenticatorData", () => {
  const authenticatorData =
    "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97635d00000000fbfc3007154e4ecc8c0b6e020557d7bd0014f67c2c1aa5c54e243eeeaa4c0de36d9e3205d985a5010203262001215820580b3439a0f5f9b2fcfea1eb89c77561684eb6d78345d8cffc91f997e360c5cf225820adcc13f9d817e09212eae65d57a756e110c8db6cafe5d28ca794dbc36d259ebf";

  const authenticatorDataResult = parseAuthenticatorData(
    Uint8Array.fromHex(authenticatorData)
  );

  expect(authenticatorDataResult.rpIdHash.byteLength).toBe(32);

  expect(authenticatorDataResult.flags.userPresent).toBe(true);
  expect(authenticatorDataResult.flags.userVerified).toBe(true);
  expect(authenticatorDataResult.flags.backupEligibility).toBe(true);
  expect(authenticatorDataResult.flags.backupState).toBe(true);
  expect(authenticatorDataResult.flags.attestedData).toBe(true);
  expect(authenticatorDataResult.flags.extensionData).toBe(false);

  expect(authenticatorDataResult.signCount).toBe(0);

  expect(authenticatorDataResult.attestedCredentialData).toBeDefined();
  expect(authenticatorDataResult.attestedCredentialData?.aaguid).toBe(
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
  );

  expect(
    authenticatorDataResult.attestedCredentialData?.credentialId.byteLength
  ).toBe(20);

  expect(
    authenticatorDataResult.attestedCredentialData?.publicKey.byteLength
  ).toBe(65);
});
