/**
 * Client-side crypto bridge re-exporting shared/crypto.
 * Ensures the browser and Express server use the exact same hash computation and validation logic.
 */
export {
  canonicalJson,
  sha256,
  computeEventHash,
  verifyHashChain,
  GENESIS_PREV_HASH,
  formatHash
} from '../../shared/crypto';
export type {
  EventHashInput,
  VerificationResult
} from '../../shared/crypto';
