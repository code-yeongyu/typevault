import {
  decodeSecretKey,
  encodeSecretKey,
  type Identity,
  type PublicKey,
  publicKeyOf,
  seal,
  type SecretKey,
  unseal,
} from './crypto'
import { fromUtf8, utf8 } from './encoding'
import { TypeVaultError } from './errors'

export type WrapHolder =
  | { readonly kind: 'owner' }
  | { readonly kind: 'tier'; readonly tier: string; readonly gen: number }
  | { readonly kind: 'member'; readonly name: string }

/** Vault-relative path (always `/`-separated) of a tier key sealed to a holder: the owner, an including tier, a member. */
export function wrapPath(tier: string, gen: number, holder: WrapHolder): string {
  const dir = `tiers/${tier}/${gen}`
  switch (holder.kind) {
    case 'owner':
      return `${dir}/owner.age`
    case 'tier':
      return `${dir}/${holder.tier}.${holder.gen}.age`
    case 'member':
      return `${dir}/members/${holder.name}.age`
  }
}

export const ownerWrapPath = (member: string): string => `owner/${member}.age`

export const samePublic = (a: PublicKey, b: PublicKey): boolean =>
  a.recipient === b.recipient && a.signPublic === b.signPublic

export const sealWrap = (key: SecretKey, recipients: readonly string[]): Promise<Uint8Array> =>
  seal(recipients, utf8(encodeSecretKey(key)))

/**
 * Opens a sealed key, keeping it only when it matches the public key it should be. Wraps aren't signed and recipients
 * are public, so a planted or foreign wrap yields undefined instead of an error.
 */
export async function openWrap(
  sealed: Uint8Array,
  holders: readonly Identity[],
  expected: PublicKey,
): Promise<SecretKey | undefined> {
  const key = await unseal(holders, sealed)
    .then((bytes) => decodeSecretKey(fromUtf8(bytes)))
    .catch((error: unknown) => {
      if (error instanceof TypeVaultError) return undefined
      throw error
    })
  if (key === undefined) return undefined
  return samePublic(await publicKeyOf(key), expected) ? key : undefined
}
