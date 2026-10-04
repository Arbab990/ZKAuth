import {
  LoginFailedError,
  RateLimitError,
  RegistrationError,
  ServerProofMismatchError,
  ServerUnavailableError,
  fetchPublicKey,
  login,
  register,
  verifyToken,
} from "zkauth-client"

export {
  LoginFailedError,
  RateLimitError,
  RegistrationError,
  ServerProofMismatchError,
  ServerUnavailableError,
  fetchPublicKey,
  login,
  register,
  verifyToken,
}

export function getBaseUrl() {
  return import.meta.env.VITE_API_URL || "http://localhost:5000"
}
