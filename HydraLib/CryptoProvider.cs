using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using HydraLib.Core;
using HydraLib.Cryptography;
using HydraLib.Cryptography.Extensions;

namespace HydraLib.Cryptography
{
    /// <summary>
    /// Provides cryptographic operations for the multi-layer encryption system.
    /// Implements ChaCha20-Poly1305 authenticated encryption with secure key management.
    /// </summary>
    public class CryptoProvider : IDisposable
    {
        #region Fields

        private readonly byte[] _key;
        private readonly bool _ownsKey;
        private bool _disposed = false;

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new instance of CryptoProvider with the specified key.
        /// </summary>
        /// <param name="key">The 32-byte encryption key</param>
        /// <param name="ownsKey">Whether the provider should securely dispose the key when finished</param>
        /// <exception cref="ArgumentNullException">Thrown if key is null</exception>
        /// <exception cref="ArgumentException">Thrown if key length is invalid</exception>
        public CryptoProvider(byte[] key, bool ownsKey = true)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes (256 bits) for ChaCha20", nameof(key));

            // Create a defensive copy of the key
            _key = new byte[key.Length];
            Buffer.BlockCopy(key, 0, _key, 0, key.Length);
            _ownsKey = ownsKey;
        }

        /// <summary>
        /// Creates a new instance of CryptoProvider with a randomly generated key.
        /// </summary>
        /// <returns>A new CryptoProvider with a secure random key</returns>
        public static CryptoProvider CreateWithRandomKey()
        {
            byte[] key = SecurityUtilities.GenerateRandomBytes(32);
            return new CryptoProvider(key, true);
        }

        #endregion

        #region Encryption Methods

        /// <summary>
        /// Encrypts data using ChaCha20-Poly1305 authenticated encryption.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="nonce">12-byte nonce for encryption</param>
        /// <param name="associatedData">Optional associated data for authenticated encryption</param>
        /// <returns>Encrypted data with authentication tag</returns>
        /// <exception cref="ArgumentNullException">Thrown if data or nonce is null</exception>
        /// <exception cref="ArgumentException">Thrown if nonce length is invalid</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public byte[] Encrypt(byte[] data, byte[] nonce, byte[] associatedData = null)
        {
            ThrowIfDisposed();

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be 12 bytes (96 bits) for ChaCha20-Poly1305", nameof(nonce));

            try
            {
                using var algorithm = new ChaCha20Poly1305(_key);
                return algorithm.Encrypt(nonce, data, associatedData);
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Encryption failed", ex);
            }
        }

        /// <summary>
        /// Encrypts data using ChaCha20-Poly1305 with a randomly generated nonce.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="associatedData">Optional associated data for authenticated encryption</param>
        /// <returns>Encrypted package containing nonce and ciphertext</returns>
        /// <exception cref="ArgumentNullException">Thrown if data is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public EncryptedPackage EncryptWithRandomNonce(byte[] data, byte[] associatedData = null)
        {
            ThrowIfDisposed();

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            // Generate a secure random nonce
            byte[] nonce = SecurityUtilities.GenerateRandomBytes(12);

            try
            {
                byte[] ciphertext = Encrypt(data, nonce, associatedData);
                return new EncryptedPackage(nonce, ciphertext, associatedData != null);
            }
            catch (Exception)
            {
                // Ensure nonce is cleared if encryption fails
                SecurityUtilities.SecureZeroMemory(nonce);
                throw;
            }
        }

        /// <summary>
        /// Encrypts data using ChaCha20-Poly1305 with a derived nonce.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="nonceDerivationData">Data to use for nonce derivation</param>
        /// <param name="associatedData">Optional associated data for authenticated encryption</param>
        /// <returns>Encrypted package containing nonce and ciphertext</returns>
        /// <exception cref="ArgumentNullException">Thrown if data is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public EncryptedPackage EncryptWithDerivedNonce(byte[] data, byte[] nonceDerivationData, byte[] associatedData = null)
        {
            ThrowIfDisposed();

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (nonceDerivationData == null)
                throw new ArgumentNullException(nameof(nonceDerivationData));

            // Derive nonce from key and provided data
            byte[] nonce = KeyDerivation.DeriveNonce(_key, nonceDerivationData);

            try
            {
                byte[] ciphertext = Encrypt(data, nonce, associatedData);
                return new EncryptedPackage(nonce, ciphertext, associatedData != null);
            }
            catch (Exception)
            {
                // Ensure nonce is cleared if encryption fails
                SecurityUtilities.SecureZeroMemory(nonce);
                throw;
            }
        }

        #endregion

        #region Decryption Methods

        /// <summary>
        /// Decrypts data using ChaCha20-Poly1305 authenticated decryption.
        /// </summary>
        /// <param name="ciphertext">Data to decrypt</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="associatedData">Optional associated data for authenticated decryption</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown if ciphertext or nonce is null</exception>
        /// <exception cref="ArgumentException">Thrown if nonce length is invalid</exception>
        /// <exception cref="CryptographicException">Thrown if authentication fails</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] associatedData = null)
        {
            ThrowIfDisposed();

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be 12 bytes (96 bits) for ChaCha20-Poly1305", nameof(nonce));

            try
            {
                using var algorithm = new ChaCha20Poly1305(_key);
                return algorithm.Decrypt(nonce, ciphertext, associatedData);
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Decryption failed: Authentication tag verification failed", ex);
            }
        }

        /// <summary>
        /// Decrypts data from an encrypted package.
        /// </summary>
        /// <param name="package">Encrypted package containing nonce and ciphertext</param>
        /// <param name="associatedData">Optional associated data for authenticated decryption</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown if package is null</exception>
        /// <exception cref="CryptographicException">Thrown if authentication fails</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public byte[] Decrypt(EncryptedPackage package, byte[] associatedData = null)
        {
            ThrowIfDisposed();

            if (package == null)
                throw new ArgumentNullException(nameof(package));

            return Decrypt(package.Ciphertext, package.Nonce, associatedData);
        }

        /// <summary>
        /// Attempts to decrypt data with authentication in a constant-time manner.
        /// </summary>
        /// <param name="ciphertext">Data to decrypt</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="associatedData">Optional associated data for authenticated decryption</param>
        /// <param name="plaintext">When successful, contains the decrypted data</param>
        /// <returns>True if decryption successful, false otherwise</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public bool TryDecrypt(byte[] ciphertext, byte[] nonce, byte[] associatedData, out byte[] plaintext)
        {
            ThrowIfDisposed();

            plaintext = null;

            try
            {
                plaintext = Decrypt(ciphertext, nonce, associatedData);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        /// <summary>
        /// Attempts to decrypt data from an encrypted package.
        /// </summary>
        /// <param name="package">Encrypted package containing nonce and ciphertext</param>
        /// <param name="associatedData">Optional associated data for authenticated decryption</param>
        /// <param name="plaintext">When successful, contains the decrypted data</param>
        /// <returns>True if decryption successful, false otherwise</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public bool TryDecrypt(EncryptedPackage package, byte[] associatedData, out byte[] plaintext)
        {
            ThrowIfDisposed();

            plaintext = null;

            if (package == null)
                return false;

            return TryDecrypt(package.Ciphertext, package.Nonce, associatedData, out plaintext);
        }

        #endregion

        #region Stream Methods

        /// <summary>
        /// Encrypts a stream using ChaCha20-Poly1305 with chunked processing.
        /// </summary>
        /// <param name="inputStream">Stream to encrypt</param>
        /// <param name="outputStream">Stream to write encrypted data to</param>
        /// <param name="baseNonce">Base nonce for encryption (will be modified for each chunk)</param>
        /// <param name="chunkSize">Size of chunks to process</param>
        /// <returns>Task representing the asynchronous operation</returns>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
        /// <exception cref="ArgumentException">Thrown if nonce length is invalid</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, byte[] baseNonce, int chunkSize = 1048576)
        {
            ThrowIfDisposed();

            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (baseNonce == null)
                throw new ArgumentNullException(nameof(baseNonce));

            if (baseNonce.Length != 12)
                throw new ArgumentException("Base nonce must be 12 bytes (96 bits) for ChaCha20-Poly1305", nameof(baseNonce));

            if (chunkSize <= 0)
                throw new ArgumentException("Chunk size must be positive", nameof(chunkSize));

            try
            {
                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                long position = 0;
                byte[] chunkNonce = new byte[12];

                // Write the base nonce to the output stream
                await outputStream.WriteAsync(baseNonce, 0, baseNonce.Length);

                using var algorithm = new ChaCha20Poly1305(_key);

                while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    // Create chunk-specific nonce by XORing the base nonce with the position
                    Buffer.BlockCopy(baseNonce, 0, chunkNonce, 0, 12);
                    XorPositionIntoNonce(chunkNonce, position);

                    // Create chunk-specific associated data using the position
                    byte[] chunkAssociatedData = BitConverter.GetBytes(position);

                    // Encrypt the chunk
                    byte[] chunkData = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, chunkData, 0, bytesRead);
                    byte[] encryptedChunk = algorithm.Encrypt(chunkNonce, chunkData, chunkAssociatedData);

                    // Write the encrypted chunk size and data
                    byte[] chunkSizeBytes = BitConverter.GetBytes(encryptedChunk.Length);
                    await outputStream.WriteAsync(chunkSizeBytes, 0, chunkSizeBytes.Length);
                    await outputStream.WriteAsync(encryptedChunk, 0, encryptedChunk.Length);

                    position++;

                    // Clear sensitive data
                    SecurityUtilities.SecureZeroMemory(chunkData);
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Stream encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypts a stream encrypted with EncryptStreamAsync.
        /// </summary>
        /// <param name="inputStream">Stream containing encrypted data</param>
        /// <param name="outputStream">Stream to write decrypted data to</param>
        /// <returns>Task representing the asynchronous operation</returns>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
        /// <exception cref="CryptographicException">Thrown if decryption or authentication fails</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the provider has been disposed</exception>
        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream)
        {
            ThrowIfDisposed();

            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            try
            {
                // Read the base nonce from the input stream
                byte[] baseNonce = new byte[12];
                int bytesRead = await inputStream.ReadAsync(baseNonce, 0, baseNonce.Length);

                if (bytesRead != baseNonce.Length)
                    throw new CryptographicException("Failed to read base nonce from stream");

                byte[] chunkNonce = new byte[12];
                long position = 0;

                using var algorithm = new ChaCha20Poly1305(_key);
                byte[] chunkSizeBytes = new byte[4]; // 4 bytes for Int32

                while (true)
                {
                    // Read the encrypted chunk size
                    bytesRead = await inputStream.ReadAsync(chunkSizeBytes, 0, chunkSizeBytes.Length);

                    if (bytesRead == 0)
                        break; // End of stream

                    if (bytesRead != chunkSizeBytes.Length)
                        throw new CryptographicException("Failed to read chunk size from stream");

                    int encryptedChunkSize = BitConverter.ToInt32(chunkSizeBytes, 0);

                    if (encryptedChunkSize <= 0 || encryptedChunkSize > 2097152) // 2MB sanity check
                        throw new CryptographicException("Invalid chunk size in encrypted stream");

                    // Read the encrypted chunk
                    byte[] encryptedChunk = new byte[encryptedChunkSize];
                    bytesRead = await inputStream.ReadAsync(encryptedChunk, 0, encryptedChunk.Length);

                    if (bytesRead != encryptedChunk.Length)
                        throw new CryptographicException("Failed to read complete chunk from stream");

                    // Create chunk-specific nonce by XORing the base nonce with the position
                    Buffer.BlockCopy(baseNonce, 0, chunkNonce, 0, 12);
                    XorPositionIntoNonce(chunkNonce, position);

                    // Create chunk-specific associated data using the position
                    byte[] chunkAssociatedData = BitConverter.GetBytes(position);

                    // Decrypt the chunk
                    byte[] decryptedChunk = algorithm.Decrypt(chunkNonce, encryptedChunk, chunkAssociatedData);

                    // Write the decrypted chunk
                    await outputStream.WriteAsync(decryptedChunk, 0, decryptedChunk.Length);

                    position++;

                    // Clear sensitive data
                    SecurityUtilities.SecureZeroMemory(decryptedChunk);
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Stream decryption failed", ex);
            }
        }

        /// <summary>
        /// XORs a 64-bit position value into a nonce.
        /// </summary>
        /// <param name="nonce">Nonce to modify</param>
        /// <param name="position">Position value to XOR</param>
        private static void XorPositionIntoNonce(byte[] nonce, long position)
        {
            byte[] positionBytes = BitConverter.GetBytes(position);
            for (int i = 0; i < Math.Min(8, nonce.Length); i++)
            {
                nonce[i] ^= positionBytes[i];
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Throws an ObjectDisposedException if this provider has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        /// <summary>
        /// Verifies if the specified key has the correct length for this provider.
        /// </summary>
        /// <param name="key">Key to verify</param>
        /// <returns>True if the key is valid, false otherwise</returns>
        public static bool IsValidKey(byte[] key)
        {
            return key != null && key.Length == 32;
        }

        /// <summary>
        /// Verifies if the specified nonce has the correct length for this provider.
        /// </summary>
        /// <param name="nonce">Nonce to verify</param>
        /// <returns>True if the nonce is valid, false otherwise</returns>
        public static bool IsValidNonce(byte[] nonce)
        {
            return nonce != null && nonce.Length == 12;
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Releases resources used by this provider.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases resources used by this provider.
        /// </summary>
        /// <param name="disposing">Whether this method is being called from Dispose()</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing && _ownsKey)
                {
                    // Securely clear the key from memory
                    SecurityUtilities.SecureZeroMemory(_key);
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer to ensure resources are released.
        /// </summary>
        ~CryptoProvider()
        {
            Dispose(false);
        }

        #endregion
    }

    /// <summary>
    /// Represents an encrypted package containing a nonce and ciphertext.
    /// </summary>
    public class EncryptedPackage
    {
        /// <summary>
        /// Gets the nonce used for encryption.
        /// </summary>
        public byte[] Nonce { get; }

        /// <summary>
        /// Gets the encrypted ciphertext.
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Gets whether associated data was used for encryption.
        /// </summary>
        public bool UsesAssociatedData { get; }

        /// <summary>
        /// Creates a new instance of the EncryptedPackage class.
        /// </summary>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="ciphertext">Encrypted ciphertext</param>
        /// <param name="usesAssociatedData">Whether associated data was used</param>
        /// <exception cref="ArgumentNullException">Thrown if nonce or ciphertext is null</exception>
        public EncryptedPackage(byte[] nonce, byte[] ciphertext, bool usesAssociatedData = false)
        {
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
            Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
            UsesAssociatedData = usesAssociatedData;
        }

        /// <summary>
        /// Creates a binary representation of this encrypted package.
        /// </summary>
        /// <returns>Byte array containing the serialized package</returns>
        public byte[] ToByteArray()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Write version
            writer.Write((byte)1);

            // Write flags
            writer.Write((byte)(UsesAssociatedData ? 1 : 0));

            // Write nonce
            writer.Write(Nonce.Length);
            writer.Write(Nonce);

            // Write ciphertext
            writer.Write(Ciphertext.Length);
            writer.Write(Ciphertext);

            return ms.ToArray();
        }

        /// <summary>
        /// Creates an encrypted package from a binary representation.
        /// </summary>
        /// <param name="data">Serialized package data</param>
        /// <returns>Deserialized encrypted package</returns>
        /// <exception cref="ArgumentNullException">Thrown if data is null</exception>
        /// <exception cref="ArgumentException">Thrown if data is not a valid package</exception>
        public static EncryptedPackage FromByteArray(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (data.Length < 7) // Minimum length: version (1) + flags (1) + nonce length (4) + nonce (1 min)
                throw new ArgumentException("Data too short to be a valid encrypted package", nameof(data));

            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            try
            {
                // Read version
                byte version = reader.ReadByte();
                if (version != 1)
                    throw new ArgumentException($"Unsupported package version: {version}", nameof(data));

                // Read flags
                byte flags = reader.ReadByte();
                bool usesAssociatedData = (flags & 1) != 0;

                // Read nonce
                int nonceLength = reader.ReadInt32();
                if (nonceLength != 12)
                    throw new ArgumentException("Invalid nonce length in package", nameof(data));

                byte[] nonce = reader.ReadBytes(nonceLength);

                // Read ciphertext
                int ciphertextLength = reader.ReadInt32();
                if (ciphertextLength <= 0 || ms.Position + ciphertextLength > ms.Length)
                    throw new ArgumentException("Invalid ciphertext length in package", nameof(data));

                byte[] ciphertext = reader.ReadBytes(ciphertextLength);

                return new EncryptedPackage(nonce, ciphertext, usesAssociatedData);
            }
            catch (EndOfStreamException)
            {
                throw new ArgumentException("Truncated encrypted package data", nameof(data));
            }
        }
    }
}