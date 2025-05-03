using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using HydraLib.Blocks;
using HydraLib.Core;

namespace HydraLib.Container
{
    /// <summary>
    /// Provides metadata information for encrypted containers.
    /// Contains version, integrity verification, and block accounting without revealing sensitive details.
    /// </summary>
    public class ContainerMetadata
    {
        #region Properties

        /// <summary>
        /// Gets or sets the format version of the container.
        /// </summary>
        [JsonPropertyName("version")]
        public string Version { get; set; } = "1.0";

        /// <summary>
        /// Gets or sets a unique identifier for this container.
        /// </summary>
        [JsonPropertyName("id")]
        public Guid Id { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Gets or sets the creation timestamp of this container.
        /// </summary>
        [JsonPropertyName("created")]
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the number of blocks in this container.
        /// </summary>
        [JsonPropertyName("blockCount")]
        public int BlockCount { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the container uses compression.
        /// </summary>
        [JsonPropertyName("compressed")]
        public bool UsesCompression { get; set; } = true;

        /// <summary>
        /// Gets or sets the encryption algorithm used for the container.
        /// </summary>
        [JsonPropertyName("encryptionAlgorithm")]
        public string EncryptionAlgorithm { get; set; } = "ChaCha20Poly1305";

        /// <summary>
        /// Gets or sets the KDF algorithm used for password-based key derivation.
        /// </summary>
        [JsonPropertyName("kdfAlgorithm")]
        public string KdfAlgorithm { get; set; } = "PBKDF2-SHA512";

        /// <summary>
        /// Gets or sets a value indicating whether the container has been modified.
        /// </summary>
        [JsonPropertyName("modified")]
        public DateTime LastModified { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets a value indicating whether integrity verification is used.
        /// </summary>
        [JsonPropertyName("useIntegrityVerification")]
        public bool UseIntegrityVerification { get; set; } = true;

        /// <summary>
        /// Gets or sets the integrity verification method.
        /// </summary>
        [JsonPropertyName("integrityMethod")]
        public string IntegrityMethod { get; set; } = "HMAC-SHA256";

        /// <summary>
        /// Gets or sets the HMAC of all block identifiers for integrity verification.
        /// Will be null until container is finalized.
        /// </summary>
        [JsonPropertyName("blockIntegrityHash")]
        public string BlockIntegrityHash { get; set; }

        /// <summary>
        /// Gets or sets the total size of the container in bytes.
        /// </summary>
        [JsonPropertyName("totalSize")]
        public long TotalSize { get; set; }

        /// <summary>
        /// Gets or sets container flags.
        /// </summary>
        [JsonPropertyName("flags")]
        public ContainerFlags Flags { get; set; } = ContainerFlags.None;

        /// <summary>
        /// Gets or sets additional metadata properties.
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement> AdditionalProperties { get; set; }

        // Private field for integrity key
        [JsonIgnore]
        private byte[] _integrityKey;

        #endregion

        #region Creation Methods

        /// <summary>
        /// Creates a new instance of the ContainerMetadata class.
        /// </summary>
        public ContainerMetadata()
        {
            // Generate integrity key for container verification
            _integrityKey = SecurityUtilities.GenerateRandomBytes(32);
        }

        /// <summary>
        /// Creates a new instance of the ContainerMetadata class with the specified ID.
        /// </summary>
        /// <param name="id">The container ID</param>
        public ContainerMetadata(Guid id) : this()
        {
            Id = id;
        }

        #endregion

        #region Block Management

        /// <summary>
        /// Registers a block with this container metadata.
        /// </summary>
        /// <param name="block">Block to register</param>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        public void RegisterBlock(Block block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            BlockCount++;
            LastModified = DateTime.UtcNow;

            // Update container flags based on block type
            UpdateFlagsForBlock(block.Type);
        }

        /// <summary>
        /// Updates the container flags based on the block type.
        /// </summary>
        /// <param name="blockType">Type of block being added</param>
        private void UpdateFlagsForBlock(BlockType blockType)
        {
            switch (blockType)
            {
                case BlockType.CrownHead:
                    Flags |= ContainerFlags.HasCrownHeads;
                    break;

                case BlockType.MockHead:
                    Flags |= ContainerFlags.HasMockHeads;
                    break;

                case BlockType.WhisperHead:
                    Flags |= ContainerFlags.HasWhisperHeads;
                    break;
            }
        }

        #endregion

        #region Integrity Verification

        /// <summary>
        /// Calculates the integrity hash for a list of blocks.
        /// </summary>
        /// <param name="blocks">List of blocks to generate the integrity hash for</param>
        /// <returns>Base64-encoded integrity hash</returns>
        /// <exception cref="ArgumentNullException">Thrown if blocks is null</exception>
        public string CalculateIntegrityHash(IEnumerable<Block> blocks)
        {
            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            // Create HMAC using the integrity key
            using var hmac = new HMACSHA256(_integrityKey);

            // Build a data structure with block IDs and types
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Write container ID and version
            writer.Write(Id.ToByteArray());
            writer.Write(Version);

            // Write block information
            foreach (var block in blocks)
            {
                // Write block ID and type
                writer.Write(block.Id.ToByteArray());
                writer.Write((int)block.Type);

                // Include block size
                writer.Write(block.GetContentSize());
            }

            // Calculate HMAC
            byte[] hash = hmac.ComputeHash(ms.ToArray());
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Finalizes this container metadata with integrity information.
        /// </summary>
        /// <param name="blocks">List of blocks in the container</param>
        /// <param name="totalSize">Total size of the container in bytes</param>
        /// <exception cref="ArgumentNullException">Thrown if blocks is null</exception>
        public void Finalize(IEnumerable<Block> blocks, long totalSize)
        {
            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            // Calculate and store integrity hash
            BlockIntegrityHash = CalculateIntegrityHash(blocks);

            // Update size information
            TotalSize = totalSize;

            // Update modified timestamp
            LastModified = DateTime.UtcNow;
        }

        /// <summary>
        /// Verifies the integrity of the container.
        /// </summary>
        /// <param name="blocks">List of blocks to verify</param>
        /// <returns>True if integrity is verified, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if blocks is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the container has not been finalized</exception>
        public bool VerifyIntegrity(IEnumerable<Block> blocks)
        {
            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            if (string.IsNullOrEmpty(BlockIntegrityHash))
                throw new InvalidOperationException("Container has not been finalized with integrity information");

            // Calculate current integrity hash
            string currentHash = CalculateIntegrityHash(blocks);

            // Compare with stored hash
            return string.Equals(currentHash, BlockIntegrityHash, StringComparison.Ordinal);
        }

        /// <summary>
        /// Gets the integrity key for this container.
        /// </summary>
        /// <returns>Copy of the integrity key</returns>
        public byte[] GetIntegrityKey()
        {
            if (_integrityKey == null)
                return null;

            // Return a defensive copy
            byte[] result = new byte[_integrityKey.Length];
            Buffer.BlockCopy(_integrityKey, 0, result, 0, _integrityKey.Length);
            return result;
        }

        /// <summary>
        /// Sets the integrity key for this container.
        /// </summary>
        /// <param name="key">Integrity key</param>
        /// <exception cref="ArgumentNullException">Thrown if key is null</exception>
        public void SetIntegrityKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            // Create a defensive copy
            _integrityKey = new byte[key.Length];
            Buffer.BlockCopy(key, 0, _integrityKey, 0, key.Length);
        }

        #endregion

        #region Serialization

        /// <summary>
        /// Serializes this container metadata to JSON.
        /// </summary>
        /// <returns>JSON string representation</returns>
        public string ToJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };

            return JsonSerializer.Serialize(this, options);
        }

        /// <summary>
        /// Deserializes container metadata from JSON.
        /// </summary>
        /// <param name="json">JSON string to deserialize</param>
        /// <returns>Deserialized container metadata</returns>
        /// <exception cref="ArgumentNullException">Thrown if json is null</exception>
        /// <exception cref="JsonException">Thrown if deserialization fails</exception>
        public static ContainerMetadata FromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            return JsonSerializer.Deserialize<ContainerMetadata>(json, options);
        }

        /// <summary>
        /// Serializes this container metadata to a binary format.
        /// </summary>
        /// <returns>Binary representation</returns>
        public byte[] ToBinary()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Write signature and version
            writer.Write(Encoding.UTF8.GetBytes("MLENC"));
            writer.Write(Encoding.UTF8.GetBytes(Version));

            // Write container ID
            writer.Write(Id.ToByteArray());

            // Write timestamps
            writer.Write(CreationTime.ToBinary());
            writer.Write(LastModified.ToBinary());

            // Write block count and size
            writer.Write(BlockCount);
            writer.Write(TotalSize);

            // Write flags
            writer.Write((int)Flags);

            // Write algorithm info
            writer.Write(EncryptionAlgorithm);
            writer.Write(KdfAlgorithm);

            // Write integrity info
            writer.Write(UseIntegrityVerification);

            if (UseIntegrityVerification)
            {
                writer.Write(IntegrityMethod);

                if (!string.IsNullOrEmpty(BlockIntegrityHash))
                {
                    writer.Write(true); // Has integrity hash
                    writer.Write(BlockIntegrityHash);
                }
                else
                {
                    writer.Write(false); // No integrity hash
                }

                // Write integrity key
                if (_integrityKey != null)
                {
                    writer.Write(true); // Has integrity key
                    writer.Write(_integrityKey.Length);
                    writer.Write(_integrityKey);
                }
                else
                {
                    writer.Write(false); // No integrity key
                }
            }

            // Write compression flag
            writer.Write(UsesCompression);

            // Write additional properties as JSON
            string additionalPropsJson = JsonSerializer.Serialize(AdditionalProperties);
            byte[] additionalPropsBytes = Encoding.UTF8.GetBytes(additionalPropsJson);
            writer.Write(additionalPropsBytes.Length);
            writer.Write(additionalPropsBytes);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes container metadata from a binary format.
        /// </summary>
        /// <param name="data">Binary data to deserialize</param>
        /// <returns>Deserialized container metadata</returns>
        /// <exception cref="ArgumentNullException">Thrown if data is null</exception>
        /// <exception cref="ArgumentException">Thrown if data is not valid container metadata</exception>
        public static ContainerMetadata FromBinary(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            // Read and verify signature
            byte[] signatureBytes = reader.ReadBytes(5);
            string signature = Encoding.UTF8.GetString(signatureBytes);

            if (signature != "MLENC")
                throw new ArgumentException("Invalid container metadata signature", nameof(data));

            // Read version
            byte[] versionBytes = reader.ReadBytes(3);
            string version = Encoding.UTF8.GetString(versionBytes);

            // Create result object
            var result = new ContainerMetadata
            {
                Version = version
            };

            // Read container ID
            result.Id = new Guid(reader.ReadBytes(16));

            // Read timestamps
            result.CreationTime = DateTime.FromBinary(reader.ReadInt64());
            result.LastModified = DateTime.FromBinary(reader.ReadInt64());

            // Read block count and size
            result.BlockCount = reader.ReadInt32();
            result.TotalSize = reader.ReadInt64();

            // Read flags
            result.Flags = (ContainerFlags)reader.ReadInt32();

            // Read algorithm info
            result.EncryptionAlgorithm = reader.ReadString();
            result.KdfAlgorithm = reader.ReadString();

            // Read integrity info
            result.UseIntegrityVerification = reader.ReadBoolean();

            if (result.UseIntegrityVerification)
            {
                result.IntegrityMethod = reader.ReadString();

                bool hasIntegrityHash = reader.ReadBoolean();
                if (hasIntegrityHash)
                {
                    result.BlockIntegrityHash = reader.ReadString();
                }

                // Read integrity key
                bool hasIntegrityKey = reader.ReadBoolean();
                if (hasIntegrityKey)
                {
                    int keyLength = reader.ReadInt32();
                    result._integrityKey = reader.ReadBytes(keyLength);
                }
            }

            // Read compression flag
            result.UsesCompression = reader.ReadBoolean();

            // Read additional properties
            int additionalPropsLength = reader.ReadInt32();
            byte[] additionalPropsBytes = reader.ReadBytes(additionalPropsLength);
            string additionalPropsJson = Encoding.UTF8.GetString(additionalPropsBytes);

            if (!string.IsNullOrEmpty(additionalPropsJson))
            {
                result.AdditionalProperties = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(additionalPropsJson);
            }

            return result;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Gets a display-friendly version of this container metadata.
        /// </summary>
        /// <param name="includeIntegrityInfo">Whether to include integrity information</param>
        /// <returns>Display-friendly metadata</returns>
        public Dictionary<string, string> GetDisplayInfo(bool includeIntegrityInfo = false)
        {
            var result = new Dictionary<string, string>
            {
                { "Container ID", Id.ToString() },
                { "Version", Version },
                { "Created", CreationTime.ToString() },
                { "Last Modified", LastModified.ToString() },
                { "Block Count", BlockCount.ToString() },
                { "Total Size", FormatByteSize(TotalSize) },
                { "Encryption Algorithm", EncryptionAlgorithm },
                { "KDF Algorithm", KdfAlgorithm },
                { "Compression", UsesCompression ? "Enabled" : "Disabled" }
            };

            // Add block type information based on flags
            if ((Flags & ContainerFlags.HasCrownHeads) != 0)
                result.Add("Contains CrownHeads", "Yes");

            if ((Flags & ContainerFlags.HasMockHeads) != 0)
                result.Add("Contains MockHeads", "Yes");

            if ((Flags & ContainerFlags.HasWhisperHeads) != 0)
                result.Add("Contains WhisperHeads", "Yes");

            // Add integrity information if requested
            if (includeIntegrityInfo && UseIntegrityVerification)
            {
                result.Add("Integrity Method", IntegrityMethod);

                if (!string.IsNullOrEmpty(BlockIntegrityHash))
                {
                    result.Add("Integrity Hash", BlockIntegrityHash);
                }
            }

            return result;
        }

        /// <summary>
        /// Formats a byte size to a user-friendly string.
        /// </summary>
        /// <param name="bytes">Number of bytes</param>
        /// <returns>Formatted size string</returns>
        private static string FormatByteSize(long bytes)
        {
            string[] suffix = { "B", "KB", "MB", "GB", "TB" };
            int i;
            double dblBytes = bytes;

            for (i = 0; i < suffix.Length && bytes >= 1024; i++, bytes /= 1024)
            {
                dblBytes = bytes / 1024.0;
            }

            return $"{dblBytes:0.##} {suffix[i]}";
        }

        #endregion
    }

    /// <summary>
    /// Flags describing container properties and features.
    /// </summary>
    [Flags]
    public enum ContainerFlags
    {
        /// <summary>
        /// No flags set.
        /// </summary>
        None = 0,

        /// <summary>
        /// Container has CrownHead blocks.
        /// </summary>
        HasCrownHeads = 1,

        /// <summary>
        /// Container has MockHead blocks.
        /// </summary>
        HasMockHeads = 2,

        /// <summary>
        /// Container has WhisperHead blocks.
        /// </summary>
        HasWhisperHeads = 4,

        /// <summary>
        /// Container uses hardware acceleration.
        /// </summary>
        UsesHardwareAcceleration = 8,

        /// <summary>
        /// Container uses sparse files for noise blocks.
        /// </summary>
        UsesSparseFiles = 16,

        /// <summary>
        /// Container has been modified.
        /// </summary>
        Modified = 32,

        /// <summary>
        /// Container has been verified.
        /// </summary>
        Verified = 64,

        /// <summary>
        /// Container has custom properties.
        /// </summary>
        HasCustomProperties = 128,

        /// <summary>
        /// Container uses strong timing protection.
        /// </summary>
        UsesTimingProtection = 256
    }
}