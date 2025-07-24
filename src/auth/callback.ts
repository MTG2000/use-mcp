// callback.ts
import { auth } from '@modelcontextprotocol/sdk/client/auth.js'
import { BrowserOAuthClientProvider } from './browser-provider.js' // Adjust path
import { StoredState, AuthResult } from './types.js' // Adjust path, ensure definition includes providerOptions

/**
 * Handles the OAuth callback using the SDK's auth() function.
 * Assumes it's running on the page specified as the callbackUrl.
 */
export async function onMcpAuthorization() {
  const queryParams = new URLSearchParams(window.location.search)
  const code = queryParams.get('code')
  const state = queryParams.get('state')
  const error = queryParams.get('error')
  const errorDescription = queryParams.get('error_description')

  const logPrefix = '[mcp-callback]' // Generic prefix, or derive from stored state later
  console.log(`${logPrefix} Handling callback...`, { code, state, error, errorDescription })

  let provider: BrowserOAuthClientProvider | null = null
  let storedStateData: StoredState | null = null
  const stateKey = state ? `mcp:auth:state_${state}` : null // Reconstruct state key prefix assumption

  try {
    // --- Basic Error Handling ---
    if (error) {
      throw new Error(`OAuth error: ${error} - ${errorDescription || 'No description provided.'}`)
    }
    if (!code) {
      throw new Error('Authorization code not found in callback query parameters.')
    }
    if (!state || !stateKey) {
      throw new Error('State parameter not found or invalid in callback query parameters.')
    }

    // --- Retrieve Stored State & Provider Options ---
    const storedStateJSON = localStorage.getItem(stateKey)
    if (!storedStateJSON) {
      throw new Error(`Invalid or expired state parameter "${state}". No matching state found in storage.`)
    }
    try {
      storedStateData = JSON.parse(storedStateJSON) as StoredState
    } catch (e) {
      throw new Error('Failed to parse stored OAuth state.')
    }

    // Validate expiry
    if (!storedStateData.expiry || storedStateData.expiry < Date.now()) {
      localStorage.removeItem(stateKey) // Clean up expired state
      throw new Error('OAuth state has expired. Please try initiating authentication again.')
    }

    // Ensure provider options are present
    if (!storedStateData.providerOptions) {
      throw new Error('Stored state is missing required provider options.')
    }
    const { serverUrl, ...providerOptions } = storedStateData.providerOptions

    // --- Instantiate Provider ---
    console.log(`${logPrefix} Re-instantiating provider for server: ${serverUrl}`)
    provider = new BrowserOAuthClientProvider(serverUrl, providerOptions)

    // --- Call SDK Auth Function ---
    console.log(`${logPrefix} Calling SDK auth() to exchange code...`)
    // The SDK auth() function will internally:
    // 1. Use provider.clientInformation()
    // 2. Use provider.codeVerifier()
    // 3. Call exchangeAuthorization()
    // 4. Use provider.saveTokens() on success
    const authResult = await auth(provider, { serverUrl, authorizationCode: code })

    if (authResult === 'AUTHORIZED') {
      console.log(`${logPrefix} Authorization successful via SDK auth(). Writing result to localStorage...`)

      // Write success result to localStorage for polling
      if (storedStateData.authSessionId) {
        const authResultKey = `${storedStateData.providerOptions.storageKeyPrefix}:auth_result_${storedStateData.authSessionId}`
        const authResultData: AuthResult = {
          success: true,
          timestamp: Date.now(),
          expiry: Date.now() + 1000 * 60 * 5, // Result expires in 5 minutes
        }
        localStorage.setItem(authResultKey, JSON.stringify(authResultData))
        console.log(`${logPrefix} Auth result written to localStorage: ${authResultKey}`)
      } else {
        console.warn(`${logPrefix} No authSessionId found in stored state, cannot write to localStorage for polling`)
      }

      // Try postMessage as fallback (for compatibility if window.opener exists)
      if (window.opener && !window.opener.closed) {
        try {
          window.opener.postMessage({ type: 'mcp_auth_callback', success: true }, window.location.origin)
          console.log(`${logPrefix} Also sent postMessage to opener as fallback`)
        } catch (e) {
          console.log(`${logPrefix} PostMessage fallback failed (expected if opener is nullified):`, e)
        }
      }

      // Close the popup after a short delay to ensure localStorage write completes
      setTimeout(() => {
        window.close()
      }, 100)

      // Clean up state ONLY on success and after writing result
      localStorage.removeItem(stateKey)
    } else {
      // This case shouldn't happen if `authorizationCode` is provided to `auth()`
      console.warn(`${logPrefix} SDK auth() returned unexpected status: ${authResult}`)
      throw new Error(`Unexpected result from authentication library: ${authResult}`)
    }
  } catch (err) {
    console.error(`${logPrefix} Error during OAuth callback handling:`, err)
    const errorMessage = err instanceof Error ? err.message : String(err)

    // Write error result to localStorage for polling
    if (storedStateData?.authSessionId) {
      const authResultKey = `${storedStateData.providerOptions.storageKeyPrefix}:auth_result_${storedStateData.authSessionId}`
      const authResultData: AuthResult = {
        success: false,
        error: errorMessage,
        timestamp: Date.now(),
        expiry: Date.now() + 1000 * 60 * 5, // Result expires in 5 minutes
      }
      localStorage.setItem(authResultKey, JSON.stringify(authResultData))
      console.log(`${logPrefix} Auth error written to localStorage: ${authResultKey}`)
    } else {
      console.warn(`${logPrefix} No authSessionId found in stored state, cannot write error to localStorage for polling`)
    }

    // Try postMessage as fallback (for compatibility)
    if (window.opener && !window.opener.closed) {
      try {
        window.opener.postMessage({ type: 'mcp_auth_callback', success: false, error: errorMessage }, window.location.origin)
        console.log(`${logPrefix} Also sent error postMessage to opener as fallback`)
      } catch (e) {
        console.log(`${logPrefix} PostMessage fallback failed (expected if opener is nullified):`, e)
      }
    }

    // Display error in the callback window
    try {
      document.body.innerHTML = `
            <div style="font-family: sans-serif; padding: 20px;">
            <h1>Authentication Error</h1>
            <p style="color: red; background-color: #ffebeb; border: 1px solid red; padding: 10px; border-radius: 4px;">
                ${errorMessage}
            </p>
            <p>You can close this window or <a href="#" onclick="window.close(); return false;">click here to close</a>.</p>
            <pre style="font-size: 0.8em; color: #555; margin-top: 20px; white-space: pre-wrap;">${
              err instanceof Error ? err.stack : ''
            }</pre>
            </div>
        `
    } catch (displayError) {
      console.error(`${logPrefix} Could not display error in callback window:`, displayError)
    }
    // Clean up potentially invalid state on error
    if (stateKey) {
      localStorage.removeItem(stateKey)
    }
    // Clean up potentially dangling verifier or last_auth_url if auth failed badly
    // Note: saveTokens should clean these on success
    if (provider) {
      localStorage.removeItem(provider.getKey('code_verifier'))
      localStorage.removeItem(provider.getKey('last_auth_url'))
    }
  }
}
