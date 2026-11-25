// Reads a password from stdin (first line) and prints its scrypt hash for BRAIN_PASSWORD_HASH.
// Usage: printf '%s\n' "$PW" | node tools/hash-password.mjs
import { hashPassword } from '../src/auth.mjs';

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  const pw = input.split(/\r?\n/)[0];
  if (!pw || pw.length < 12) {
    console.error('Password must be at least 12 characters.');
    process.exit(2);
  }
  console.log(hashPassword(pw));
});
