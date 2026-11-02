// Declarations of the Expo modules this package calls, so that it compiles without installing them: Expo and React
// Native belong to the app that uses the package. Each block lists only what the sources use, with the signatures of
// the published declarations of expo-secure-store 58.0.2, expo-crypto 58.0.7 and @animo-id/expo-secure-environment
// 0.3.0. The compiler does not emit this file and no exported type refers to it.

declare module 'expo-secure-store' {
  export type KeychainAccessibilityConstant = number;
  export type SecureStoreOptions = {
    keychainService?: string;
    requireAuthentication?: boolean;
    requireConfirmation?: boolean;
    authenticationPrompt?: string;
    keychainAccessible?: KeychainAccessibilityConstant;
    accessGroup?: string;
  };
  export const WHEN_UNLOCKED_THIS_DEVICE_ONLY: KeychainAccessibilityConstant;
  export function getItemAsync(key: string, options?: SecureStoreOptions): Promise<string | null>;
  export function setItemAsync(key: string, value: string, options?: SecureStoreOptions): Promise<void>;
  export function deleteItemAsync(key: string, options?: SecureStoreOptions): Promise<void>;
}

declare module 'expo-crypto' {
  // The published signature takes every integer typed array; the sources pass a Uint8Array.
  export function getRandomValues<T extends Uint8Array>(typedArray: T): T;
}

declare module '@animo-id/expo-secure-environment' {
  export type UserAuthenticationMethod = 'biometric' | 'deviceCredential';
  export type KeyStorage = 'strongBox' | 'trustedEnvironment' | 'software';
  export interface UserAuthenticationOptions {
    methods?: [UserAuthenticationMethod, ...UserAuthenticationMethod[]];
    invalidateOnBiometricChange?: boolean;
    validitySeconds?: number;
  }
  export interface GenerateKeypairOptions {
    userAuthentication?: UserAuthenticationOptions | false;
    minimumKeyStorage?: KeyStorage;
    preferStrongBox?: boolean;
  }
  export interface AuthenticationPrompt {
    title?: string;
    subtitle?: string;
    cancel?: string;
  }
  export interface SignOptions {
    prompt?: AuthenticationPrompt;
  }
  export interface IsSecureEnvironmentSupportedOptions {
    minimumKeyStorage?: KeyStorage;
  }
  export function isSecureEnvironmentSupported(options?: IsSecureEnvironmentSupportedOptions): boolean;
  export function generateKeypair(keyId: string, options?: GenerateKeypairOptions): Promise<void>;
  /** The public key in compressed form, 33 bytes. */
  export function getPublicBytesForKeyId(keyId: string): Promise<Uint8Array>;
  /** ECDSA over SHA-256 of the message, as the raw signature r and s, 64 bytes. */
  export function sign(keyId: string, message: Uint8Array, options?: SignOptions): Promise<Uint8Array>;
  export function deleteKey(keyId: string): Promise<void>;
}
