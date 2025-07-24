import { OAuthMetadata } from '@modelcontextprotocol/sdk/shared/auth.js'

/**
 * Internal type for storing OAuth state in localStorage during the popup flow.
 * @internal
 */
export interface StoredState {
  expiry: number
  metadata?: OAuthMetadata // Optional: might not be needed if auth() rediscovers
  serverUrlHash: string
  authSessionId?: string // Add session ID for localStorage polling
  // Add provider options needed on callback:
  providerOptions: {
    serverUrl: string
    storageKeyPrefix: string
    clientName: string
    clientUri: string
    callbackUrl: string
  }
}

/**
 * Type for auth results stored in localStorage for polling
 * @internal
 */
export interface AuthResult {
  success: boolean
  error?: string
  timestamp: number
  expiry: number
}
