using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using HydraLib.Blocks;
using HydraLib.Security;


namespace HydraLib.Serialization
{
    /// <summary>
    /// Provides serialization and deserialization capabilities for blocks.
    /// Handles format compatibility and secure conversion between different representations.
    /// </summary>
    public static class BlockSerializer
    {
        #region Block Binary Format

        // Block format signature
        private static readonly byte[] BlockSignature = Encoding.UTF8.GetBytes("MLBLK");

        // Current block format version
        private const byte CurrentFormatVersion = 1;

        #endregion

        #region Binary Serialization

        /// <summary>
        /// Serializes a block to a binary format.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <returns>Serialized block data</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        public static byte[] SerializeBlock(Block block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (!block.IsEncrypted)
                throw new InvalidOperationException("Block must be encrypted for serialization");

            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Write block signature
            writer.Write(BlockSignature);

            // Write format version
            writer.Write(CurrentFormatVersion);

            // Write block type
            writer.Write((int)block.Type);

            // Write block ID
            writer.Write(block.Id.ToByteArray());

            // Write creation time
            writer.Write(block.CreationTime.ToBinary());

            // Write encrypted data
            byte[] encryptedData = block.GetEncryptedData();
            writer.Write(encryptedData.Length);
            writer.Write(encryptedData);

            // Calculate block hash for integrity verification
            using var sha256 = SHA256.Create();
            byte[] blockHash = sha256.ComputeHash(encryptedData);

            // Write hash
            writer.Write(blockHash.Length);
            writer.Write(blockHash);

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializes a block from binary data.
        /// </summary>
        /// <param name="data">Serialized block data</param>
        /// <returns>Deserialized block</returns>
        /// <exception cref="ArgumentNullException">Thrown if data is null</exception>
        /// <exception cref="ArgumentException">Thrown if data is too short</exception>
        /// <exception cref="InvalidDataException">Thrown if the data is not a valid serialized block</exception>
        public static Block DeserializeBlock(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (data.Length < BlockSignature.Length + 1 + 4 + 16 + 8)
                throw new ArgumentException("Data too short to be a valid serialized block", nameof(data));

            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            try
            {
                // Read and verify signature
                byte[] signature = reader.ReadBytes(BlockSignature.Length);

                // Verify signature
                for (int i = 0; i < BlockSignature.Length; i++)
                {
                    if (signature[i] != BlockSignature[i])
                        throw new InvalidDataException("Invalid block signature");
                }

                // Read format version
                byte formatVersion = reader.ReadByte();

                if (formatVersion > CurrentFormatVersion)
                    throw new InvalidDataException($"Unsupported block format version: {formatVersion}");

                // Read block type
                BlockType blockType = (BlockType)reader.ReadInt32();

                // Read block ID
                Guid blockId = new Guid(reader.ReadBytes(16));

                // Read creation time
                DateTime creationTime = DateTime.FromBinary(reader.ReadInt64());

                // Read encrypted data
                int encryptedDataLength = reader.ReadInt32();
                byte[] encryptedData = reader.ReadBytes(encryptedDataLength);

                // Read hash
                int hashLength = reader.ReadInt32();
                byte[] storedHash = reader.ReadBytes(hashLength);

                // Verify hash
                using var sha256 = SHA256.Create();
                byte[] calculatedHash = sha256.ComputeHash(encryptedData);

                // Verify hash in constant time to prevent timing attacks
                if (!CryptographicOperations.FixedTimeEquals(storedHash, calculatedHash))
                    throw new InvalidDataException("Block hash verification failed");

                // Create block based on type
                Block block = BlockFactory.CreateBlock(blockType, blockId);

                // Set creation time through reflection (bypassing read-only property)
                typeof(Block).GetProperty("CreationTime").SetValue(block, creationTime);

                // Set encrypted data
                block.SetEncryptedData(encryptedData);

                return block;
            }
            catch (EndOfStreamException)
            {
                throw new InvalidDataException("Unexpected end of block data");
            }
        }

        /// <summary>
        /// Serializes a block to a file.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <param name="filePath">Path to save the serialized block</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentNullException">Thrown if block or filePath is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="IOException">Thrown if the file cannot be written</exception>
        public static void SerializeBlockToFile(Block block, string filePath, bool overwrite = false)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (File.Exists(filePath) && !overwrite)
                throw new InvalidOperationException("File exists and overwrite is not enabled");

            byte[] serializedData = SerializeBlock(block);

            try
            {
                File.WriteAllBytes(filePath, serializedData);
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to write serialized block to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Deserializes a block from a file.
        /// </summary>
        /// <param name="filePath">Path to the serialized block file</param>
        /// <returns>Deserialized block</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file does not contain a valid serialized block</exception>
        public static Block DeserializeBlockFromFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("Block file not found", filePath);

            try
            {
                byte[] serializedData = File.ReadAllBytes(filePath);
                return DeserializeBlock(serializedData);
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is InvalidDataException))
            {
                throw new InvalidDataException($"Failed to read serialized block from file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Serializes a block asynchronously to a stream.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <param name="stream">Stream to write the serialized block to</param>
        /// <exception cref="ArgumentNullException">Thrown if block or stream is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="IOException">Thrown if the stream cannot be written</exception>
        public static async Task SerializeBlockToStreamAsync(Block block, Stream stream)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (!stream.CanWrite)
                throw new ArgumentException("Stream must be writable", nameof(stream));

            byte[] serializedData = SerializeBlock(block);

            try
            {
                await stream.WriteAsync(serializedData, 0, serializedData.Length);
                await stream.FlushAsync();
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to write serialized block to stream: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Deserializes a block asynchronously from a stream.
        /// </summary>
        /// <param name="stream">Stream containing the serialized block</param>
        /// <returns>Deserialized block</returns>
        /// <exception cref="ArgumentNullException">Thrown if stream is null</exception>
        /// <exception cref="ArgumentException">Thrown if the stream cannot be read</exception>
        /// <exception cref="InvalidDataException">Thrown if the stream does not contain a valid serialized block</exception>
        public static async Task<Block> DeserializeBlockFromStreamAsync(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            if (!stream.CanRead)
                throw new ArgumentException("Stream must be readable", nameof(stream));

            try
            {
                // Read the entire stream into memory
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms);
                ms.Position = 0;

                byte[] serializedData = ms.ToArray();
                return DeserializeBlock(serializedData);
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is InvalidDataException))
            {
                throw new InvalidDataException($"Failed to read serialized block from stream: {ex.Message}", ex);
            }
        }

        #endregion

        #region JSON Serialization

        /// <summary>
        /// Serializes a block's metadata to JSON.
        /// Note: This does not include the encrypted content, only metadata.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <returns>JSON string representing the block's metadata</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        public static string SerializeBlockMetadataToJson(Block block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            var metadata = new BlockMetadataInfo
            {
                Id = block.Id,
                Type = block.Type,
                CreationTime = block.CreationTime,
                IsEncrypted = block.IsEncrypted,
                ContentSize = block.GetContentSize()
            };

            // Calculate hash if encrypted
            if (block.IsEncrypted)
            {
                metadata.ContentHash = IntegrityVerifier.CalculateBlockHash(block);
            }

            return JsonSerializer.Serialize(metadata, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }

        /// <summary>
        /// Serializes a block to a secure JSON format that includes the encrypted content.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <returns>JSON string representing the block</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        public static string SerializeBlockToJson(Block block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (!block.IsEncrypted)
                throw new InvalidOperationException("Block must be encrypted for serialization");

            var blockData = new BlockJsonData
            {
                Id = block.Id,
                Type = block.Type,
                CreationTime = block.CreationTime,
                EncryptedData = Convert.ToBase64String(block.GetEncryptedData()),
                ContentHash = IntegrityVerifier.CalculateBlockHash(block)
            };

            return JsonSerializer.Serialize(blockData, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }

        /// <summary>
        /// Deserializes a block from a JSON string.
        /// </summary>
        /// <param name="json">JSON string representing the block</param>
        /// <returns>Deserialized block</returns>
        /// <exception cref="ArgumentNullException">Thrown if json is null</exception>
        /// <exception cref="JsonException">Thrown if the JSON is invalid</exception>
        /// <exception cref="InvalidDataException">Thrown if the JSON does not represent a valid block</exception>
        public static Block DeserializeBlockFromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            try
            {
                var blockData = JsonSerializer.Deserialize<BlockJsonData>(json);

                if (blockData == null)
                    throw new InvalidDataException("Invalid block JSON data");

                if (string.IsNullOrEmpty(blockData.EncryptedData))
                    throw new InvalidDataException("Missing encrypted data");

                // Decode base64 encrypted data
                byte[] encryptedData;
                try
                {
                    encryptedData = Convert.FromBase64String(blockData.EncryptedData);
                }
                catch (FormatException)
                {
                    throw new InvalidDataException("Invalid Base64 encoded encrypted data");
                }

                // Create block based on type
                Block block = BlockFactory.CreateBlock(blockData.Type, blockData.Id);

                // Set creation time through reflection (bypassing read-only property)
                typeof(Block).GetProperty("CreationTime").SetValue(block, blockData.CreationTime);

                // Set encrypted data
                block.SetEncryptedData(encryptedData);

                // Verify hash if provided
                if (!string.IsNullOrEmpty(blockData.ContentHash))
                {
                    string calculatedHash = IntegrityVerifier.CalculateBlockHash(block);

                    if (calculatedHash != blockData.ContentHash)
                        throw new InvalidDataException("Block hash verification failed");
                }

                return block;
            }
            catch (JsonException ex)
            {
                throw new JsonException($"Failed to parse block JSON: {ex.Message}", ex);
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is JsonException || ex is InvalidDataException))
            {
                throw new InvalidDataException($"Failed to deserialize block from JSON: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Serializes a block to a JSON file.
        /// </summary>
        /// <param name="block">Block to serialize</param>
        /// <param name="filePath">Path to save the serialized block</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentNullException">Thrown if block or filePath is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="IOException">Thrown if the file cannot be written</exception>
        public static void SerializeBlockToJsonFile(Block block, string filePath, bool overwrite = false)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (File.Exists(filePath) && !overwrite)
                throw new InvalidOperationException("File exists and overwrite is not enabled");

            string json = SerializeBlockToJson(block);

            try
            {
                File.WriteAllText(filePath, json);
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to write serialized block to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Deserializes a block from a JSON file.
        /// </summary>
        /// <param name="filePath">Path to the serialized block file</param>
        /// <returns>Deserialized block</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file does not contain a valid serialized block</exception>
        public static Block DeserializeBlockFromJsonFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("Block file not found", filePath);

            try
            {
                string json = File.ReadAllText(filePath);
                return DeserializeBlockFromJson(json);
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException || ex is JsonException || ex is InvalidDataException))
            {
                throw new InvalidDataException($"Failed to read serialized block from file: {ex.Message}", ex);
            }
        }

        #endregion

        #region Format Conversion

        /// <summary>
        /// Converts a block from one serialization format to another.
        /// </summary>
        /// <param name="sourceFile">Source file path</param>
        /// <param name="destinationFile">Destination file path</param>
        /// <param name="sourceFormat">Source file format</param>
        /// <param name="destinationFormat">Destination file format</param>
        /// <param name="overwrite">Whether to overwrite an existing destination file</param>
        /// <exception cref="ArgumentNullException">Thrown if sourceFile or destinationFile is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the source file does not exist</exception>
        /// <exception cref="InvalidOperationException">Thrown if the destination file exists and overwrite is false</exception>
        /// <exception cref="InvalidDataException">Thrown if the source file is not a valid serialized block</exception>
        /// <exception cref="IOException">Thrown if the destination file cannot be written</exception>
        public static void ConvertBlockFormat(
            string sourceFile,
            string destinationFile,
            BlockSerializationFormat sourceFormat,
            BlockSerializationFormat destinationFormat,
            bool overwrite = false)
        {
            if (string.IsNullOrEmpty(sourceFile))
                throw new ArgumentNullException(nameof(sourceFile));

            if (string.IsNullOrEmpty(destinationFile))
                throw new ArgumentNullException(nameof(destinationFile));

            if (!File.Exists(sourceFile))
                throw new FileNotFoundException("Source file not found", sourceFile);

            if (File.Exists(destinationFile) && !overwrite)
                throw new InvalidOperationException("Destination file exists and overwrite is not enabled");

            // Deserialize from source format
            Block block;

            switch (sourceFormat)
            {
                case BlockSerializationFormat.Binary:
                    block = DeserializeBlockFromFile(sourceFile);
                    break;

                case BlockSerializationFormat.Json:
                    block = DeserializeBlockFromJsonFile(sourceFile);
                    break;

                default:
                    throw new ArgumentException($"Unsupported source format: {sourceFormat}", nameof(sourceFormat));
            }

            // Serialize to destination format
            switch (destinationFormat)
            {
                case BlockSerializationFormat.Binary:
                    SerializeBlockToFile(block, destinationFile, overwrite);
                    break;

                case BlockSerializationFormat.Json:
                    SerializeBlockToJsonFile(block, destinationFile, overwrite);
                    break;

                default:
                    throw new ArgumentException($"Unsupported destination format: {destinationFormat}", nameof(destinationFormat));
            }
        }

        /// <summary>
        /// Detects the serialization format of a file.
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        /// <returns>Detected serialization format</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file format cannot be detected</exception>
        public static BlockSerializationFormat DetectFileFormat(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            try
            {
                // Read first bytes to check for binary signature
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

                byte[] signature = new byte[BlockSignature.Length];
                int bytesRead = fs.Read(signature, 0, signature.Length);

                if (bytesRead == BlockSignature.Length)
                {
                    bool isBinary = true;

                    for (int i = 0; i < BlockSignature.Length; i++)
                    {
                        if (signature[i] != BlockSignature[i])
                        {
                            isBinary = false;
                            break;
                        }
                    }

                    if (isBinary)
                        return BlockSerializationFormat.Binary;
                }

                // Check if it's JSON by trying to parse it
                string content = File.ReadAllText(filePath);

                try
                {
                    using var document = JsonDocument.Parse(content);

                    // Check if it has expected properties
                    if (document.RootElement.TryGetProperty("Id", out _) &&
                        document.RootElement.TryGetProperty("Type", out _) &&
                        document.RootElement.TryGetProperty("EncryptedData", out _))
                    {
                        return BlockSerializationFormat.Json;
                    }
                }
                catch (JsonException)
                {
                    // Not JSON
                }

                throw new InvalidDataException("Unable to detect file format");
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException || ex is InvalidDataException))
            {
                throw new InvalidDataException($"Failed to detect file format: {ex.Message}", ex);
            }
        }

        #endregion

        #region Helper Types

        /// <summary>
        /// Represents a block's metadata for JSON serialization.
        /// </summary>
        private class BlockMetadataInfo
        {
            /// <summary>
            /// Gets or sets the block ID.
            /// </summary>
            public Guid Id { get; set; }

            /// <summary>
            /// Gets or sets the block type.
            /// </summary>
            public BlockType Type { get; set; }

            /// <summary>
            /// Gets or sets the block creation time.
            /// </summary>
            public DateTime CreationTime { get; set; }

            /// <summary>
            /// Gets or sets whether the block is encrypted.
            /// </summary>
            public bool IsEncrypted { get; set; }

            /// <summary>
            /// Gets or sets the size of the block's content.
            /// </summary>
            public long ContentSize { get; set; }

            /// <summary>
            /// Gets or sets the hash of the block's content.
            /// </summary>
            public string ContentHash { get; set; }
        }

        /// <summary>
        /// Represents a block for JSON serialization.
        /// </summary>
        private class BlockJsonData
        {
            /// <summary>
            /// Gets or sets the block ID.
            /// </summary>
            public Guid Id { get; set; }

            /// <summary>
            /// Gets or sets the block type.
            /// </summary>
            public BlockType Type { get; set; }

            /// <summary>
            /// Gets or sets the block creation time.
            /// </summary>
            public DateTime CreationTime { get; set; }

            /// <summary>
            /// Gets or sets the encrypted data as Base64.
            /// </summary>
            public string EncryptedData { get; set; }

            /// <summary>
            /// Gets or sets the hash of the encrypted content.
            /// </summary>
            public string ContentHash { get; set; }
        }

        #endregion
    }

    /// <summary>
    /// Represents the serialization format of a block.
    /// </summary>
    public enum BlockSerializationFormat
    {
        /// <summary>
        /// Binary serialization format.
        /// </summary>
        Binary = 0,

        /// <summary>
        /// JSON serialization format.
        /// </summary>
        Json = 1
    }
}