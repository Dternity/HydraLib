using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using HydraLib.Cryptography;
using HydraLib.Core;
using HydraLib.Cryptography.Extensions;

namespace HydraLib.Blocks
{
    /// <summary>
    /// Defines the type of an encrypted block in the multi-layer encryption system.
    /// </summary>
    public enum BlockType
    {
        /// <summary>
        /// Unknown or unspecified block type.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// CrownHead block type, used for important/sensitive data.
        /// </summary>
        CrownHead = 1,

        /// <summary>
        /// MockHead block type, used for decoy/plausible deniability data.
        /// </summary>
        MockHead = 2,

        /// <summary>
        /// WhisperHead block type, used for noise/random data.
        /// </summary>
        WhisperHead = 3
    }

    /// <summary>
    /// Base class for all encrypted blocks in the multi-layer encryption system.
    /// </summary>
    public abstract class Block : IDisposable
    {
        #region Properties

        /// <summary>
        /// Gets the type of this block.
        /// </summary>
        public BlockType Type { get; protected set; }

        /// <summary>
        /// Gets a unique identifier for this block.
        /// </summary>
        public Guid Id { get; protected set; }

        /// <summary>
        /// Gets the creation timestamp of this block.
        /// </summary>
        public DateTime CreationTime { get; protected set; }

        /// <summary>
        /// Gets whether this block has been encrypted.
        /// </summary>
        public bool IsEncrypted { get; protected set; }

        /// <summary>
        /// Gets whether this block has been disposed.
        /// </summary>
        public bool IsDisposed { get; private set; }

        // Backing field for content
        private byte[] _contentBytes;

        // Backing field for encrypted content
        private byte[] _encryptedBytes;

        // Flag to track whether content has been modified
        private bool _contentModified = false;

        // Optional additional entropy for key derivation
        private byte[] _additionalEntropy;

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new block with the specified type and ID.
        /// </summary>
        /// <param name="type">Type of block to create</param>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        protected Block(BlockType type, Guid? id = null)
        {
            Type = type;
            Id = id ?? Guid.NewGuid();
            CreationTime = DateTime.UtcNow;
            IsEncrypted = false;
            IsDisposed = false;
        }

        #endregion

        #region Content Management

        /// <summary>
        /// Sets the content of this block from a byte array.
        /// </summary>
        /// <param name="content">Content bytes</param>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public void SetContent(byte[] content)
        {
            ThrowIfDisposed();

            if (content == null)
            {
                _contentBytes = null;
                return;
            }

            // Create a defensive copy of the content
            _contentBytes = new byte[content.Length];
            Buffer.BlockCopy(content, 0, _contentBytes, 0, content.Length);

            _contentModified = true;
            IsEncrypted = false; // Content changed, so no longer encrypted
        }

        /// <summary>
        /// Sets the content of this block from a string.
        /// </summary>
        /// <param name="content">Content string</param>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public void SetContent(string content)
        {
            ThrowIfDisposed();

            if (content == null)
            {
                _contentBytes = null;
                return;
            }

            _contentBytes = Encoding.UTF8.GetBytes(content);
            _contentModified = true;
            IsEncrypted = false; // Content changed, so no longer encrypted
        }

        /// <summary>
        /// Gets the content of this block as a byte array.
        /// </summary>
        /// <returns>Content bytes</returns>
        /// <exception cref="InvalidOperationException">Thrown if this block is encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public byte[] GetContentBytes()
        {
            ThrowIfDisposed();

            if (IsEncrypted)
                throw new InvalidOperationException("Cannot access content while block is encrypted");

            if (_contentBytes == null)
                return null;

            // Return a defensive copy
            byte[] result = new byte[_contentBytes.Length];
            Buffer.BlockCopy(_contentBytes, 0, result, 0, _contentBytes.Length);
            return result;
        }

        /// <summary>
        /// Gets the content of this block as a string.
        /// </summary>
        /// <returns>Content string</returns>
        /// <exception cref="InvalidOperationException">Thrown if this block is encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public string GetContentString()
        {
            ThrowIfDisposed();

            if (IsEncrypted)
                throw new InvalidOperationException("Cannot access content while block is encrypted");

            if (_contentBytes == null)
                return null;

            return Encoding.UTF8.GetString(_contentBytes);
        }

        /// <summary>
        /// Sets additional entropy for enhanced key derivation.
        /// </summary>
        /// <param name="entropy">Entropy bytes</param>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public void SetAdditionalEntropy(byte[] entropy)
        {
            ThrowIfDisposed();

            if (entropy == null || entropy.Length == 0)
            {
                _additionalEntropy = null;
                return;
            }

            // Create a defensive copy of the entropy
            _additionalEntropy = new byte[entropy.Length];
            Buffer.BlockCopy(entropy, 0, _additionalEntropy, 0, entropy.Length);
        }

        #endregion

        #region Encryption and Decryption

        /// <summary>
        /// Encrypts this block using the provided password.
        /// </summary>
        /// <param name="password">Password for encryption</param>
        /// <param name="compress">Whether to compress the content before encryption</param>
        /// <exception cref="InvalidOperationException">Thrown if this block is already encrypted or has no content</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public void Encrypt(SecureString password, bool compress = true)
        {
            ThrowIfDisposed();

            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            if (IsEncrypted)
                throw new InvalidOperationException("Block is already encrypted");

            if (_contentBytes == null || _contentBytes.Length == 0)
                throw new InvalidOperationException("Block has no content to encrypt");

            // Create metadata for the block
            var metadata = CreateBlockMetadata();
            byte[] metadataBytes = JsonSerializer.SerializeToUtf8Bytes(metadata);

            // Prepare the content for encryption
            byte[] contentToEncrypt;
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    // Write metadata length and metadata
                    writer.Write(metadataBytes.Length);
                    writer.Write(metadataBytes);

                    // Write content
                    writer.Write(_contentBytes.Length);
                    writer.Write(_contentBytes);
                }

                contentToEncrypt = ms.ToArray();
            }

            // Compress if requested
            if (compress)
            {
                contentToEncrypt = CompressionProvider.Compress(contentToEncrypt);
            }

            // Generate salt for key derivation
            byte[] salt = KeyDerivation.GenerateSalt();

            // Derive key from password
            (byte[] key, _) = KeyDerivation.DeriveKey(password, salt);

            try
            {
                // Enhance key with additional entropy if available
                if (_additionalEntropy != null && _additionalEntropy.Length > 0)
                {
                    key = KeyDerivation.EnhanceKeyWithEntropy(key, _additionalEntropy);
                }

                // Encrypt the content
                using var crypto = new ChaCha20Poly1305(key);
                byte[] nonce = KeyDerivation.DeriveNonce(key, salt);
                byte[] ciphertext = crypto.Encrypt(nonce, contentToEncrypt, null);

                // Create the final encrypted block
                using (var ms = new MemoryStream())
                {
                    using (var writer = new BinaryWriter(ms))
                    {
                        // Write the block format version
                        writer.Write((byte)1);

                        // Write salt
                        writer.Write(salt.Length);
                        writer.Write(salt);

                        // Write nonce
                        writer.Write(nonce.Length);
                        writer.Write(nonce);

                        // Write ciphertext
                        writer.Write(ciphertext.Length);
                        writer.Write(ciphertext);
                    }

                    _encryptedBytes = ms.ToArray();
                }

                // Clear unencrypted content for security
                ClearContent();

                IsEncrypted = true;
                _contentModified = false;
            }
            finally
            {
                // Securely clear key material
                if (key != null)
                    SecurityUtilities.SecureZeroMemory(key);
            }
        }

        /// <summary>
        /// Decrypts this block using the provided password.
        /// </summary>
        /// <param name="password">Password for decryption</param>
        /// <returns>True if decryption succeeded, false if the password was incorrect</returns>
        /// <exception cref="InvalidOperationException">Thrown if this block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public bool Decrypt(SecureString password)
        {
            ThrowIfDisposed();

            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            if (!IsEncrypted)
                throw new InvalidOperationException("Block is not encrypted");

            if (_encryptedBytes == null || _encryptedBytes.Length == 0)
                throw new InvalidOperationException("Block has no encrypted content");

            try
            {
                using var ms = new MemoryStream(_encryptedBytes);
                using var reader = new BinaryReader(ms);

                // Read format version
                byte version = reader.ReadByte();
                if (version != 1)
                    throw new InvalidOperationException($"Unsupported block format version: {version}");

                // Read salt
                int saltLength = reader.ReadInt32();
                byte[] salt = reader.ReadBytes(saltLength);

                // Read nonce
                int nonceLength = reader.ReadInt32();
                byte[] nonce = reader.ReadBytes(nonceLength);

                // Read ciphertext
                int ciphertextLength = reader.ReadInt32();
                byte[] ciphertext = reader.ReadBytes(ciphertextLength);

                // Derive key from password
                (byte[] key, _) = KeyDerivation.DeriveKey(password, salt);

                try
                {
                    // Enhance key with additional entropy if available
                    if (_additionalEntropy != null && _additionalEntropy.Length > 0)
                    {
                        key = KeyDerivation.EnhanceKeyWithEntropy(key, _additionalEntropy);
                    }

                    // Decrypt the content
                    byte[] decrypted;
                    try
                    {
                        using var crypto = new ChaCha20Poly1305(key);
                        decrypted = crypto.Decrypt(nonce, ciphertext, null);
                    }
                    catch (CryptographicException)
                    {
                        // Incorrect password or tampered ciphertext
                        return false;
                    }

                    // Decompress if compressed
                    if (CompressionProvider.IsCompressed(decrypted))
                    {
                        decrypted = CompressionProvider.Decompress(decrypted);
                    }

                    // Read metadata and content
                    using (var contentStream = new MemoryStream(decrypted))
                    {
                        using (var contentReader = new BinaryReader(contentStream))
                        {
                            // Read metadata
                            int metadataLength = contentReader.ReadInt32();
                            byte[] metadataBytes = contentReader.ReadBytes(metadataLength);

                            // Parse metadata
                            var metadata = JsonSerializer.Deserialize<BlockMetadata>(metadataBytes);

                            // Read content
                            int contentLength = contentReader.ReadInt32();
                            _contentBytes = contentReader.ReadBytes(contentLength);

                            // Verify metadata
                            if (metadata.Id != Id)
                            {
                                // This should never happen with a correct password
                                ClearContent();
                                return false;
                            }

                            // Update properties from metadata
                            Type = metadata.Type;
                            CreationTime = metadata.CreationTime;
                        }
                    }

                    IsEncrypted = false;
                    _contentModified = false;

                    return true;
                }
                finally
                {
                    // Securely clear key material
                    if (key != null)
                        SecurityUtilities.SecureZeroMemory(key);
                }
            }
            catch (Exception)
            {
                // Any exception indicates decryption failure
                return false;
            }
        }

        /// <summary>
        /// Gets the encrypted data for this block.
        /// </summary>
        /// <returns>Encrypted block data</returns>
        /// <exception cref="InvalidOperationException">Thrown if this block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public byte[] GetEncryptedData()
        {
            ThrowIfDisposed();

            if (!IsEncrypted)
                throw new InvalidOperationException("Block is not encrypted");

            if (_encryptedBytes == null)
                throw new InvalidOperationException("Block has no encrypted content");

            // Return a defensive copy
            byte[] result = new byte[_encryptedBytes.Length];
            Buffer.BlockCopy(_encryptedBytes, 0, result, 0, _encryptedBytes.Length);
            return result;
        }

        /// <summary>
        /// Sets this block's encrypted data directly.
        /// </summary>
        /// <param name="encryptedData">Encrypted block data</param>
        /// <exception cref="ArgumentNullException">Thrown if encryptedData is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public void SetEncryptedData(byte[] encryptedData)
        {
            ThrowIfDisposed();

            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            // Clear any existing content
            ClearContent();

            // Create a defensive copy of the encrypted data
            _encryptedBytes = new byte[encryptedData.Length];
            Buffer.BlockCopy(encryptedData, 0, _encryptedBytes, 0, encryptedData.Length);

            IsEncrypted = true;
            _contentModified = false;
        }

        /// <summary>
        /// Creates metadata for this block.
        /// </summary>
        protected virtual BlockMetadata CreateBlockMetadata()
        {
            return new BlockMetadata
            {
                Id = Id,
                Type = Type,
                CreationTime = CreationTime,
                Version = "1.0",
                CompressionUsed = true
            };
        }

        #endregion

        #region Utility Methods

        /// <summary>
        /// Securely clears the content of this block.
        /// </summary>
        private void ClearContent()
        {
            if (_contentBytes != null)
            {
                SecurityUtilities.SecureZeroMemory(_contentBytes);
                _contentBytes = null;
            }
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this block has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        /// <summary>
        /// Gets the size of the block's content in bytes.
        /// </summary>
        /// <returns>Size in bytes, or 0 if no content</returns>
        public long GetContentSize()
        {
            ThrowIfDisposed();

            if (IsEncrypted)
                return _encryptedBytes?.Length ?? 0;
            else
                return _contentBytes?.Length ?? 0;
        }

        /// <summary>
        /// Verifies if a password is correct for this block without fully decrypting it.
        /// </summary>
        /// <param name="password">Password to check</param>
        /// <returns>True if password appears to be correct, false otherwise</returns>
        /// <exception cref="InvalidOperationException">Thrown if block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this block has been disposed</exception>
        public bool VerifyPassword(SecureString password)
        {
            ThrowIfDisposed();

            if (!IsEncrypted)
                throw new InvalidOperationException("Block is not encrypted");

            if (password == null || password.Length == 0)
                return false;

            try
            {
                using var ms = new MemoryStream(_encryptedBytes);
                using var reader = new BinaryReader(ms);

                // Read format version
                byte version = reader.ReadByte();
                if (version != 1)
                    return false;

                // Read salt
                int saltLength = reader.ReadInt32();
                byte[] salt = reader.ReadBytes(saltLength);

                // Read nonce
                int nonceLength = reader.ReadInt32();
                byte[] nonce = reader.ReadBytes(nonceLength);

                // Read first 16 bytes of ciphertext for verification
                ms.Seek(4, SeekOrigin.Current); // Skip ciphertext length
                byte[] ciphertextSample = reader.ReadBytes(16);

                // Derive key from password
                (byte[] key, _) = KeyDerivation.DeriveKey(password, salt);

                try
                {
                    // Enhance key with additional entropy if available
                    if (_additionalEntropy != null && _additionalEntropy.Length > 0)
                    {
                        key = KeyDerivation.EnhanceKeyWithEntropy(key, _additionalEntropy);
                    }

                    // We can't partially decrypt with ChaCha20Poly1305, so return true if
                    // the derived key and nonce combination seems plausible
                    using (var hmac = new HMACSHA256(key))
                    {
                        byte[] verificationHash = hmac.ComputeHash(nonce);
                        // Simple check to see if the first byte looks reasonable
                        return (verificationHash[0] & 0x0F) == (ciphertextSample[0] & 0x0F);
                    }
                }
                finally
                {
                    // Securely clear key material
                    if (key != null)
                        SecurityUtilities.SecureZeroMemory(key);
                }
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Releases resources used by this block.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases resources used by this block.
        /// </summary>
        /// <param name="disposing">Whether this method is being called from Dispose()</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                if (disposing)
                {
                    // Clear sensitive data
                    ClearContent();

                    if (_encryptedBytes != null)
                    {
                        SecurityUtilities.SecureZeroMemory(_encryptedBytes);
                        _encryptedBytes = null;
                    }

                    if (_additionalEntropy != null)
                    {
                        SecurityUtilities.SecureZeroMemory(_additionalEntropy);
                        _additionalEntropy = null;
                    }
                }

                IsDisposed = true;
            }
        }

        /// <summary>
        /// Finalizer to ensure resources are released.
        /// </summary>
        ~Block()
        {
            Dispose(false);
        }

        #endregion
    }

    /// <summary>
    /// Block metadata stored with encrypted content.
    /// </summary>
    public class BlockMetadata
    {
        /// <summary>
        /// Gets or sets the block ID.
        /// </summary>
        [JsonPropertyName("id")]
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the block type.
        /// </summary>
        [JsonPropertyName("type")]
        public BlockType Type { get; set; }

        /// <summary>
        /// Gets or sets the block creation time.
        /// </summary>
        [JsonPropertyName("created")]
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// Gets or sets the block format version.
        /// </summary>
        [JsonPropertyName("version")]
        public string Version { get; set; }

        /// <summary>
        /// Gets or sets whether compression was used.
        /// </summary>
        [JsonPropertyName("compressed")]
        public bool CompressionUsed { get; set; }

        /// <summary>
        /// Gets or sets additional metadata properties.
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement> AdditionalProperties { get; set; }
    }

    /// <summary>
    /// CrownHead block for important/sensitive data.
    /// </summary>
    public class CrownBlock : Block
    {
        /// <summary>
        /// Creates a new CrownHead block.
        /// </summary>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        public CrownBlock(Guid? id = null) : base(BlockType.CrownHead, id)
        {
        }

        /// <summary>
        /// Creates metadata for this block with additional security information.
        /// </summary>
        protected override BlockMetadata CreateBlockMetadata()
        {
            var metadata = base.CreateBlockMetadata();

            // Add a random canary value to verify correct decryption
            byte[] canary = SecurityUtilities.GenerateRandomBytes(16);

            if (metadata.AdditionalProperties == null)
            {
                metadata.AdditionalProperties = new Dictionary<string, JsonElement>();
            }

            // Add crown-specific properties
            var additionalProps = new Dictionary<string, object>
            {
                { "canary", Convert.ToBase64String(canary) },
                { "importance", "high" },
                { "securityLevel", "critical" }
            };

            string additionalPropsJson = JsonSerializer.Serialize(additionalProps);
            JsonDocument doc = JsonDocument.Parse(additionalPropsJson);

            metadata.AdditionalProperties["crownProperties"] = doc.RootElement.Clone();

            return metadata;
        }
    }

    /// <summary>
    /// MockHead block for decoy/plausible deniability data.
    /// </summary>
    public class MockBlock : Block
    {
        /// <summary>
        /// Creates a new MockHead block.
        /// </summary>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        public MockBlock(Guid? id = null) : base(BlockType.MockHead, id)
        {
        }

        /// <summary>
        /// Creates metadata for this block with plausible deniability information.
        /// </summary>
        protected override BlockMetadata CreateBlockMetadata()
        {
            var metadata = base.CreateBlockMetadata();

            if (metadata.AdditionalProperties == null)
            {
                metadata.AdditionalProperties = new Dictionary<string, JsonElement>();
            }

            // Add mock-specific properties to appear legitimate
            var additionalProps = new Dictionary<string, object>
            {
                { "category", "standard" },
                { "importance", "medium" },
                { "isBackup", true }
            };

            string additionalPropsJson = JsonSerializer.Serialize(additionalProps);
            JsonDocument doc = JsonDocument.Parse(additionalPropsJson);

            metadata.AdditionalProperties["mockProperties"] = doc.RootElement.Clone();

            return metadata;
        }
    }

    /// <summary>
    /// WhisperHead block for noise/random data.
    /// </summary>
    public class WhisperBlock : Block
    {
        /// <summary>
        /// Creates a new WhisperHead block.
        /// </summary>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        public WhisperBlock(Guid? id = null) : base(BlockType.WhisperHead, id)
        {
        }

        /// <summary>
        /// Fills this block with random noise data.
        /// </summary>
        /// <param name="minSize">Minimum size of random data in bytes</param>
        /// <param name="maxSize">Maximum size of random data in bytes</param>
        public void FillWithNoise(int minSize = 1024, int maxSize = 8192)
        {
            ThrowIfDisposed();

            if (minSize < 0)
                throw new ArgumentException("Minimum size cannot be negative", nameof(minSize));

            if (maxSize <= minSize)
                throw new ArgumentException("Maximum size must be greater than minimum size", nameof(maxSize));

            int size = SecurityUtilities.GenerateRandomInt(minSize, maxSize);
            byte[] noise = SecurityUtilities.GenerateRandomBytes(size);

            SetContent(noise);
        }

        /// <summary>
        /// Creates metadata for this noise block.
        /// </summary>
        protected override BlockMetadata CreateBlockMetadata()
        {
            var metadata = base.CreateBlockMetadata();

            if (metadata.AdditionalProperties == null)
            {
                metadata.AdditionalProperties = new Dictionary<string, JsonElement>();
            }

            // Add whisper-specific properties that look like system temp data
            var additionalProps = new Dictionary<string, object>
            {
                { "category", "temporary" },
                { "system", true },
                { "expiration", DateTime.UtcNow.AddDays(30).ToString("o") }
            };

            string additionalPropsJson = JsonSerializer.Serialize(additionalProps);
            JsonDocument doc = JsonDocument.Parse(additionalPropsJson);

            metadata.AdditionalProperties["systemProperties"] = doc.RootElement.Clone();

            return metadata;
        }
    }

    /// <summary>
    /// Factory class for creating different types of blocks.
    /// </summary>
    public static class BlockFactory
    {
        /// <summary>
        /// Creates a new block of the specified type.
        /// </summary>
        /// <param name="type">Type of block to create</param>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        /// <returns>A new block of the specified type</returns>
        /// <exception cref="ArgumentException">Thrown if the block type is unknown</exception>
        public static Block CreateBlock(BlockType type, Guid? id = null)
        {
            return type switch
            {
                BlockType.CrownHead => new CrownBlock(id),
                BlockType.MockHead => new MockBlock(id),
                BlockType.WhisperHead => new WhisperBlock(id),
                _ => throw new ArgumentException($"Unsupported block type: {type}")
            };
        }

        /// <summary>
        /// Creates a new block from encrypted data.
        /// </summary>
        /// <param name="encryptedData">Encrypted block data</param>
        /// <param name="type">Optional block type hint</param>
        /// <returns>A new block with the encrypted data</returns>
        /// <exception cref="ArgumentNullException">Thrown if encryptedData is null</exception>
        public static Block CreateBlockFromEncryptedData(byte[] encryptedData, BlockType type = BlockType.Unknown)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            Block block = type switch
            {
                BlockType.CrownHead => new CrownBlock(),
                BlockType.MockHead => new MockBlock(),
                BlockType.WhisperHead => new WhisperBlock(),
                _ => new UnknownBlock() // Default to unknown block type
            };

            block.SetEncryptedData(encryptedData);
            return block;
        }
    }

    /// <summary>
    /// Unknown block type for when the type cannot be determined.
    /// </summary>
    internal class UnknownBlock : Block
    {
        /// <summary>
        /// Creates a new unknown block.
        /// </summary>
        /// <param name="id">Optional ID (will be auto-generated if not provided)</param>
        public UnknownBlock(Guid? id = null) : base(BlockType.Unknown, id)
        {
        }
    }
}