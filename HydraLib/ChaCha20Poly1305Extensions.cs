using System;
using System.Security.Cryptography;

namespace HydraLib.Cryptography.Extensions
{
    /// <summary>
    /// Provides extension methods for ChaCha20Poly1305 to simplify encryption and decryption operations.
    /// </summary>
    public static class ChaCha20Poly1305Extensions
    {
        /// <summary>
        /// Encrypts data using ChaCha20Poly1305 authenticated encryption.
        /// </summary>
        /// <param name="algorithm">The ChaCha20Poly1305 algorithm instance</param>
        /// <param name="nonce">Nonce for encryption (must be 12 bytes)</param>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="associatedData">Optional associated data for authenticated encryption</param>
        /// <returns>Encrypted data including authentication tag</returns>
        /// <exception cref="ArgumentNullException">Thrown if required parameters are null</exception>
        /// <exception cref="ArgumentException">Thrown if nonce has an invalid length</exception>
        public static byte[] Encrypt(this ChaCha20Poly1305 algorithm, byte[] nonce, byte[] plaintext, byte[] associatedData = null)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be exactly 12 bytes for ChaCha20Poly1305", nameof(nonce));

            // Create output buffer for ciphertext + tag
            byte[] ciphertext = new byte[plaintext.Length + 16]; // 16 bytes for auth tag

            // Perform the encryption
            algorithm.Encrypt(nonce, plaintext, ciphertext, associatedData);

            return ciphertext;
        }

        /// <summary>
        /// Decrypts data using ChaCha20Poly1305 authenticated decryption.
        /// </summary>
        /// <param name="algorithm">The ChaCha20Poly1305 algorithm instance</param>
        /// <param name="nonce">Nonce used for encryption (must be 12 bytes)</param>
        /// <param name="ciphertext">Data to decrypt (includes authentication tag)</param>
        /// <param name="associatedData">Optional associated data for authenticated decryption</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown if required parameters are null</exception>
        /// <exception cref="ArgumentException">Thrown if nonce has an invalid length</exception>
        /// <exception cref="CryptographicException">Thrown if authentication fails</exception>
        public static byte[] Decrypt(this ChaCha20Poly1305 algorithm, byte[] nonce, byte[] ciphertext, byte[] associatedData = null)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be exactly 12 bytes for ChaCha20Poly1305", nameof(nonce));

            if (ciphertext.Length < 16) // 16 bytes minimum for the auth tag
                throw new ArgumentException("Ciphertext is too short to be valid ChaCha20Poly1305 ciphertext", nameof(ciphertext));

            // Create output buffer for plaintext
            byte[] plaintext = new byte[ciphertext.Length - 16]; // subtract auth tag size

            try
            {
                // Perform the decryption
                algorithm.Decrypt(nonce, ciphertext, plaintext, associatedData);
                return plaintext;
            }
            catch (CryptographicException)
            {
                // Authentication failed - rethrow to maintain the expected behavior
                throw;
            }
        }

        /// <summary>
        /// Attempts to decrypt data using ChaCha20Poly1305 without throwing exceptions.
        /// </summary>
        /// <param name="algorithm">The ChaCha20Poly1305 algorithm instance</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="ciphertext">Data to decrypt</param>
        /// <param name="associatedData">Optional associated data for authentication</param>
        /// <param name="plaintext">When successful, contains the decrypted data</param>
        /// <returns>True if decryption succeeds, false otherwise</returns>
        public static bool TryDecrypt(this ChaCha20Poly1305 algorithm, byte[] nonce, byte[] ciphertext, byte[] associatedData, out byte[] plaintext)
        {
            plaintext = null;

            try
            {
                plaintext = Decrypt(algorithm, nonce, ciphertext, associatedData);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}