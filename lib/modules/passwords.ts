// Bcrypt
import { compareSync } from 'bcrypt';

// Argon2 support
import { hash, verify } from 'argon2';

export async function Compare(hash: string, password: string): Promise<{ algo: 'argon2' | 'bcrypt'; valid: boolean } | boolean> {
  if (hash.startsWith('$2')) return compareSync(password, hash) ? { algo: 'bcrypt', valid: true } : false;
  else if (hash.startsWith('$argon2')) return (await verify(hash, password)) ? { algo: 'argon2', valid: true } : false;
  else return false;
}

export async function Hash(password: string): Promise<string> {
  const hashPassword = await hash(password);
  return hashPassword;
}
