using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HydraLib.Blocks;
using HydraLib.Container;
using HydraLib.Security;

namespace HydraLib
{
    /// <summary>
    /// Manages encrypted containers in the multi-layer encryption system.
    /// Provides high-level operations for container creation, loading, saving, and block management.
    /// </summary>
    public class ContainerManager : IDisposable
    {
        #region Fields and Properties

        private ContainerMetadata _metadata;
        private readonly List<Block> _blocks = new List<Block>();
        private readonly Dictionary<Guid, string> _blockHashes = new Dictionary<Guid, string>();
        private bool _modified = false;
        private bool _disposed = false;
        private string _filePath;

        /// <summary>
        /// Gets the metadata for this container.
        /// </summary>
        public ContainerMetadata Metadata => _metadata;

        /// <summary>
        /// Gets the number of blocks in this container.
        /// </summary>
        public int BlockCount => _blocks.Count;

        /// <summary>
        /// Gets whether this container has been modified since it was last saved.
        /// </summary>
        public bool IsModified => _modified;

        /// <summary>
        /// Gets the file path of this container, or null if it has not been saved.
        /// </summary>
        public string FilePath => _filePath;

        /// <summary>
        /// Gets whether this container has been disposed.
        /// </summary>
        public bool IsDisposed => _disposed;

        /// <summary>
        /// Gets a summary of the container contents.
        /// </summary>
        public ContainerSummary Summary
        {
            get
            {
                ThrowIfDisposed();

                var summary = new ContainerSummary
                {
                    Id = _metadata.Id,
                    CreationTime = _metadata.CreationTime,
                    LastModified = _metadata.LastModified,
                    TotalBlocks = _blocks.Count,
                    FilePath = _filePath
                };

                // Count block types
                foreach (var block in _blocks)
                {
                    switch (block.Type)
                    {
                        case BlockType.CrownHead:
                            summary.CrownHeadCount++;
                            break;
                        case BlockType.MockHead:
                            summary.MockHeadCount++;
                            break;
                        case BlockType.WhisperHead:
                            summary.WhisperHeadCount++;
                            break;
                    }
                }

                // Calculate sizes
                summary.TotalSize = _blocks.Sum(b => b.GetContentSize());

                return summary;
            }
        }

        #endregion

        #region Constructor and Factory Methods

        /// <summary>
        /// Creates a new instance of the ContainerManager class.
        /// </summary>
        /// <param name="metadata">Optional container metadata</param>
        /// <exception cref="ArgumentNullException">Thrown if metadata is null</exception>
        public ContainerManager(ContainerMetadata metadata = null)
        {
            _metadata = metadata ?? new ContainerMetadata();
        }

        /// <summary>
        /// Creates a new container with the specified configuration.
        /// </summary>
        /// <param name="crownHeadCount">Number of CrownHead blocks to create</param>
        /// <param name="mockHeadCount">Number of MockHead blocks to create</param>
        /// <param name="whisperHeadCount">Number of WhisperHead blocks to create</param>
        /// <param name="useIntegrityVerification">Whether to enable integrity verification</param>
        /// <param name="compressContent">Whether to compress content before encryption</param>
        /// <returns>A new container manager</returns>
        public static ContainerManager CreateContainer(
            int crownHeadCount = 1,
            int mockHeadCount = 2,
            int whisperHeadCount = 3,
            bool useIntegrityVerification = true,
            bool compressContent = true)
        {
            var metadata = new ContainerMetadata
            {
                UseIntegrityVerification = useIntegrityVerification,
                UsesCompression = compressContent
            };

            var container = new ContainerManager(metadata);

            // Create CrownHead blocks
            for (int i = 0; i < crownHeadCount; i++)
            {
                container.AddBlock(new CrownBlock());
            }

            // Create MockHead blocks
            for (int i = 0; i < mockHeadCount; i++)
            {
                container.AddBlock(new MockBlock());
            }

            // Create WhisperHead blocks
            for (int i = 0; i < whisperHeadCount; i++)
            {
                var block = new WhisperBlock();
                block.FillWithNoise();
                container.AddBlock(block);
            }

            // Randomize block order
            container.RandomizeBlockOrder();

            return container;
        }

        /// <summary>
        /// Loads a container from a file.
        /// </summary>
        /// <param name="filePath">Path to the container file</param>
        /// <returns>Loaded container manager</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file is not a valid container</exception>
        public static async Task<ContainerManager> LoadContainerAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("Container file not found", filePath);

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var container = await LoadContainerFromStreamAsync(fileStream);
                container._filePath = filePath;
                return container;
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException))
            {
                throw new InvalidDataException($"Failed to load container from file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Loads a container from a stream.
        /// </summary>
        /// <param name="stream">Stream containing container data</param>
        /// <returns>Loaded container manager</returns>
        /// <exception cref="ArgumentNullException">Thrown if stream is null</exception>
        /// <exception cref="InvalidDataException">Thrown if the stream does not contain a valid container</exception>
        public static async Task<ContainerManager> LoadContainerFromStreamAsync(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                using var reader = new BinaryReader(stream, Encoding.UTF8, true);

                // Read and verify container signature
                byte[] signature = reader.ReadBytes(5);
                if (Encoding.UTF8.GetString(signature) != "MLENC")
                    throw new InvalidDataException("Invalid container signature");

                // Read metadata length
                int metadataLength = reader.ReadInt32();

                // Read metadata
                byte[] metadataBytes = reader.ReadBytes(metadataLength);
                var metadata = ContainerMetadata.FromBinary(metadataBytes);

                var container = new ContainerManager(metadata);

                // Read block count
                int blockCount = reader.ReadInt32();

                // Read blocks
                for (int i = 0; i < blockCount; i++)
                {
                    // Read block length
                    int blockLength = reader.ReadInt32();

                    // Read block data
                    byte[] blockData = reader.ReadBytes(blockLength);

                    // Create block from encrypted data
                    var block = BlockFactory.CreateBlockFromEncryptedData(blockData);

                    // Add block to container
                    container.AddBlock(block);

                    // Calculate block hash for integrity verification
                    if (metadata.UseIntegrityVerification)
                    {
                        string blockHash = IntegrityVerifier.CalculateBlockHash(block);
                        container._blockHashes[block.Id] = blockHash;
                    }

                    // Allow for UI updates by yielding execution
                    await Task.Yield();
                }

                container._modified = false;

                return container;
            }
            catch (Exception ex) when (!(ex is ArgumentNullException))
            {
                throw new InvalidDataException($"Failed to load container from stream: {ex.Message}", ex);
            }
        }

        #endregion

        #region Container Operations

        /// <summary>
        /// Saves this container to a file.
        /// </summary>
        /// <param name="filePath">Path to save the container to</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the file exists and overwrite is false</exception>
        /// <exception cref="IOException">Thrown if an I/O error occurs</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task SaveContainerAsync(string filePath, bool overwrite = false)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (File.Exists(filePath) && !overwrite)
                throw new InvalidOperationException("File exists and overwrite is not enabled");

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
                await SaveContainerToStreamAsync(fileStream);

                _filePath = filePath;
                _modified = false;
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is InvalidOperationException || ex is ObjectDisposedException))
            {
                throw new IOException($"Failed to save container to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Saves this container to a stream.
        /// </summary>
        /// <param name="stream">Stream to save the container to</param>
        /// <exception cref="ArgumentNullException">Thrown if stream is null</exception>
        /// <exception cref="IOException">Thrown if an I/O error occurs</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task SaveContainerToStreamAsync(Stream stream)
        {
            ThrowIfDisposed();

            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                // Update container metadata
                _metadata.LastModified = DateTime.UtcNow;
                _metadata.BlockCount = _blocks.Count;

                // Finalize container with integrity information if enabled
                if (_metadata.UseIntegrityVerification)
                {
                    _metadata.Finalize(_blocks, CalculateTotalSize());

                    // Update block hashes
                    _blockHashes.Clear();
                    foreach (var block in _blocks)
                    {
                        _blockHashes[block.Id] = IntegrityVerifier.CalculateBlockHash(block);
                    }
                }

                using var writer = new BinaryWriter(stream, Encoding.UTF8, true);

                // Write container signature
                writer.Write(Encoding.UTF8.GetBytes("MLENC"));

                // Write metadata
                byte[] metadataBytes = _metadata.ToBinary();
                writer.Write(metadataBytes.Length);
                writer.Write(metadataBytes);

                // Write block count
                writer.Write(_blocks.Count);

                // Write blocks
                foreach (var block in _blocks)
                {
                    if (!block.IsEncrypted)
                        throw new InvalidOperationException($"Block {block.Id} is not encrypted");

                    byte[] blockData = block.GetEncryptedData();

                    // Write block length
                    writer.Write(blockData.Length);

                    // Write block data
                    writer.Write(blockData);

                    // Allow for UI updates by yielding execution
                    await Task.Yield();
                }

                // Ensure all data is written
                await stream.FlushAsync();

                _modified = false;
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is ObjectDisposedException))
            {
                throw new IOException($"Failed to save container to stream: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Verifies the integrity of this container.
        /// </summary>
        /// <returns>Integrity verification result</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IntegrityResult VerifyIntegrity()
        {
            ThrowIfDisposed();

            // Only verify if integrity verification is enabled
            if (!_metadata.UseIntegrityVerification)
                return new IntegrityResult(IntegrityStatus.NotEnabled, "Integrity verification is not enabled for this container");

            return IntegrityVerifier.VerifyContainerIntegrity(_metadata, _blocks);
        }

        /// <summary>
        /// Performs a deep integrity verification of this container.
        /// </summary>
        /// <returns>Detailed integrity verification result</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task<DetailedIntegrityResult> VerifyIntegrityDeepAsync()
        {
            ThrowIfDisposed();

            return await IntegrityVerifier.PerformDeepIntegrityVerificationAsync(_metadata, _blocks, _blockHashes);
        }

        /// <summary>
        /// Generates an integrity report for this container.
        /// </summary>
        /// <returns>Integrity report</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task<IntegrityReport> GenerateIntegrityReportAsync()
        {
            ThrowIfDisposed();

            return await IntegrityVerifier.GenerateIntegrityReportAsync(_metadata, _blocks);
        }

        /// <summary>
        /// Randomizes the order of blocks in this container.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public void RandomizeBlockOrder()
        {
            ThrowIfDisposed();

            // Create a cryptographically secure random shuffling
            Random random = new Random();
            byte[] buffer = new byte[4];

            int n = _blocks.Count;
            while (n > 1)
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(buffer);
                }

                int k = BitConverter.ToInt32(buffer, 0) % n;
                if (k < 0) k += n;
                n--;

                var value = _blocks[k];
                _blocks[k] = _blocks[n];
                _blocks[n] = value;
            }

            _modified = true;
        }

        /// <summary>
        /// Calculates the total size of all blocks in this container.
        /// </summary>
        /// <returns>Total size in bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public long CalculateTotalSize()
        {
            ThrowIfDisposed();

            return _blocks.Sum(b => b.GetContentSize());
        }

        #endregion

        #region Block Management

        /// <summary>
        /// Adds a block to this container.
        /// </summary>
        /// <param name="block">Block to add</param>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public void AddBlock(Block block)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            _blocks.Add(block);
            _metadata.RegisterBlock(block);
            _modified = true;
        }

        /// <summary>
        /// Removes a block from this container.
        /// </summary>
        /// <param name="block">Block to remove</param>
        /// <returns>True if the block was removed, false if it was not found</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public bool RemoveBlock(Block block)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            bool removed = _blocks.Remove(block);

            if (removed)
            {
                // Remove block hash if it exists
                _blockHashes.Remove(block.Id);
                _modified = true;
            }

            return removed;
        }

        /// <summary>
        /// Removes a block from this container by ID.
        /// </summary>
        /// <param name="blockId">ID of the block to remove</param>
        /// <returns>True if the block was removed, false if it was not found</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public bool RemoveBlock(Guid blockId)
        {
            ThrowIfDisposed();

            var block = _blocks.FirstOrDefault(b => b.Id == blockId);

            if (block != null)
            {
                return RemoveBlock(block);
            }

            return false;
        }

        /// <summary>
        /// Gets a block by ID.
        /// </summary>
        /// <param name="blockId">ID of the block to get</param>
        /// <returns>The block, or null if not found</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public Block GetBlock(Guid blockId)
        {
            ThrowIfDisposed();

            return _blocks.FirstOrDefault(b => b.Id == blockId);
        }

        /// <summary>
        /// Gets all blocks in this container.
        /// </summary>
        /// <returns>All blocks</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IReadOnlyList<Block> GetAllBlocks()
        {
            ThrowIfDisposed();

            return _blocks.AsReadOnly();
        }

        /// <summary>
        /// Gets blocks of a specific type.
        /// </summary>
        /// <param name="type">Type of blocks to get</param>
        /// <returns>Blocks of the specified type</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IEnumerable<Block> GetBlocksByType(BlockType type)
        {
            ThrowIfDisposed();

            return _blocks.Where(b => b.Type == type);
        }

        /// <summary>
        /// Gets the number of blocks of a specific type.
        /// </summary>
        /// <param name="type">Type of blocks to count</param>
        /// <returns>Number of blocks of the specified type</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public int GetBlockCount(BlockType type)
        {
            ThrowIfDisposed();

            return _blocks.Count(b => b.Type == type);
        }

        /// <summary>
        /// Gets CrownHead blocks.
        /// </summary>
        /// <returns>CrownHead blocks</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IEnumerable<Block> GetCrownHeadBlocks()
        {
            ThrowIfDisposed();

            return _blocks.Where(b => b.Type == BlockType.CrownHead);
        }

        /// <summary>
        /// Gets MockHead blocks.
        /// </summary>
        /// <returns>MockHead blocks</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IEnumerable<Block> GetMockHeadBlocks()
        {
            ThrowIfDisposed();

            return _blocks.Where(b => b.Type == BlockType.MockHead);
        }

        /// <summary>
        /// Gets WhisperHead blocks.
        /// </summary>
        /// <returns>WhisperHead blocks</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public IEnumerable<Block> GetWhisperHeadBlocks()
        {
            ThrowIfDisposed();

            return _blocks.Where(b => b.Type == BlockType.WhisperHead);
        }

        #endregion

        #region Block Encryption/Decryption

        /// <summary>
        /// Encrypts a block with the specified password.
        /// </summary>
        /// <param name="block">Block to encrypt</param>
        /// <param name="password">Password for encryption</param>
        /// <param name="compress">Whether to compress the content before encryption</param>
        /// <param name="additionalEntropy">Optional additional entropy for key derivation</param>
        /// <exception cref="ArgumentNullException">Thrown if block or password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is already encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public void EncryptBlock(Block block, SecureString password, bool compress = true, byte[] additionalEntropy = null)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            // Set additional entropy if provided
            if (additionalEntropy != null)
            {
                block.SetAdditionalEntropy(additionalEntropy);
            }

            // Encrypt the block
            block.Encrypt(password, compress);

            // Update block hash if integrity verification is enabled
            if (_metadata.UseIntegrityVerification)
            {
                _blockHashes[block.Id] = IntegrityVerifier.CalculateBlockHash(block);
            }

            _modified = true;
        }

        /// <summary>
        /// Attempts to decrypt a block with the specified password.
        /// </summary>
        /// <param name="block">Block to decrypt</param>
        /// <param name="password">Password for decryption</param>
        /// <returns>True if decryption succeeded, false if the password was incorrect</returns>
        /// <exception cref="ArgumentNullException">Thrown if block or password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public bool DecryptBlock(Block block, SecureString password)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            bool success = block.Decrypt(password);

            if (success)
            {
                _modified = true;
            }

            return success;
        }

        /// <summary>
        /// Verifies if a password is correct for a block without fully decrypting it.
        /// </summary>
        /// <param name="block">Block to verify</param>
        /// <param name="password">Password to check</param>
        /// <returns>True if the password appears to be correct, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if block or password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public bool VerifyBlockPassword(Block block, SecureString password)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            return block.VerifyPassword(password);
        }

        /// <summary>
        /// Checks if a block can be decrypted with any of the provided passwords.
        /// </summary>
        /// <param name="block">Block to check</param>
        /// <param name="passwords">Passwords to try</param>
        /// <returns>The index of the first password that works, or -1 if none work</returns>
        /// <exception cref="ArgumentNullException">Thrown if block or passwords is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public int FindWorkingPassword(Block block, IList<SecureString> passwords)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (passwords == null)
                throw new ArgumentNullException(nameof(passwords));

            for (int i = 0; i < passwords.Count; i++)
            {
                if (VerifyBlockPassword(block, passwords[i]))
                {
                    return i;
                }
            }

            return -1;
        }

        #endregion

        #region Entropy Enhancement

        /// <summary>
        /// Collects system entropy for use in encryption operations.
        /// </summary>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public byte[] CollectSystemEntropy(int size = 32)
        {
            ThrowIfDisposed();

            return EntropyCollector.CollectSystemEntropy(size);
        }

        /// <summary>
        /// Collects user entropy for use in encryption operations.
        /// </summary>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="targetSamples">Number of user input samples to collect</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task<byte[]> CollectUserEntropyAsync(
            IProgress<int> callback = null,
            int targetSamples = 32,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return await EntropyCollector.CollectUserEntropyAsync(callback, targetSamples, cancellationToken);
        }

        /// <summary>
        /// Collects hardware entropy for use in encryption operations.
        /// </summary>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public byte[] CollectHardwareEntropy(int size = 32)
        {
            ThrowIfDisposed();

            return EntropyCollector.CollectHardwareEntropy(size);
        }

        /// <summary>
        /// Collects combined entropy from multiple sources.
        /// </summary>
        /// <param name="includeUserEntropy">Whether to include user entropy</param>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Combined entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task<byte[]> CollectCombinedEntropyAsync(
            bool includeUserEntropy = true,
            IProgress<string> callback = null,
            int size = 32,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return await EntropyCollector.CollectCombinedEntropyAsync(includeUserEntropy, callback, size, cancellationToken);
        }

        #endregion

        #region Export and Import

        /// <summary>
        /// Exports a block to a file.
        /// </summary>
        /// <param name="block">Block to export</param>
        /// <param name="filePath">Path to save the block to</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentNullException">Thrown if block or filePath is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="IOException">Thrown if an I/O error occurs</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public async Task ExportBlockAsync(Block block, string filePath, bool overwrite = false)
        {
            ThrowIfDisposed();

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!block.IsEncrypted)
                throw new InvalidOperationException("Block must be encrypted for export");

            if (File.Exists(filePath) && !overwrite)
                throw new InvalidOperationException("File exists and overwrite is not enabled");

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
                using var writer = new BinaryWriter(fileStream);

                // Write block signature
                writer.Write(Encoding.UTF8.GetBytes("MLBLK"));

                // Write block data
                byte[] blockData = block.GetEncryptedData();
                writer.Write(blockData.Length);
                writer.Write(blockData);

                // Write block ID
                writer.Write(block.Id.ToByteArray());

                // Write block type
                writer.Write((int)block.Type);

                // Write timestamp
                writer.Write(block.CreationTime.ToBinary());

                // Ensure all data is written
                await fileStream.FlushAsync();
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is InvalidOperationException || ex is ObjectDisposedException))
            {
                throw new IOException($"Failed to export block to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Imports a block from a file.
        /// </summary>
        /// <param name="filePath">Path to the block file</param>
        /// <returns>Imported block</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file is not a valid block</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public Block ImportBlock(string filePath)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException("Block file not found", filePath);

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var reader = new BinaryReader(fileStream);

                // Read and verify block signature
                byte[] signature = reader.ReadBytes(5);
                if (Encoding.UTF8.GetString(signature) != "MLBLK")
                    throw new InvalidDataException("Invalid block signature");

                // Read block data
                int blockLength = reader.ReadInt32();
                byte[] blockData = reader.ReadBytes(blockLength);

                // Read block ID if available
                Guid blockId = Guid.Empty;
                BlockType blockType = BlockType.Unknown;

                if (fileStream.Position < fileStream.Length - 15) // At least enough for GUID
                {
                    blockId = new Guid(reader.ReadBytes(16));

                    // Read block type if available
                    if (fileStream.Position < fileStream.Length - 3) // At least enough for int
                    {
                        blockType = (BlockType)reader.ReadInt32();
                    }
                }

                // Create block from encrypted data
                Block block = blockId != Guid.Empty
                    ? BlockFactory.CreateBlock(blockType, blockId)
                    : BlockFactory.CreateBlockFromEncryptedData(blockData, blockType);

                // Set encrypted data
                block.SetEncryptedData(blockData);

                // Add block to container
                AddBlock(block);

                // Update block hash if integrity verification is enabled
                if (_metadata.UseIntegrityVerification)
                {
                    _blockHashes[block.Id] = IntegrityVerifier.CalculateBlockHash(block);
                }

                return block;
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException || ex is ObjectDisposedException))
            {
                throw new InvalidDataException($"Failed to import block from file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Exports this container's metadata to a string.
        /// </summary>
        /// <returns>JSON string representation of the metadata</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public string ExportMetadataToJson()
        {
            ThrowIfDisposed();

            return _metadata.ToJson();
        }

        /// <summary>
        /// Imports metadata from a JSON string.
        /// </summary>
        /// <param name="json">JSON string representation of the metadata</param>
        /// <exception cref="ArgumentNullException">Thrown if json is null</exception>
        /// <exception cref="JsonException">Thrown if the JSON is invalid</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this container has been disposed</exception>
        public void ImportMetadataFromJson(string json)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(json))
                throw new ArgumentNullException(nameof(json));

            _metadata = ContainerMetadata.FromJson(json);
            _modified = true;
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Releases all resources used by this container manager.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases resources used by this container manager.
        /// </summary>
        /// <param name="disposing">Whether this method is being called from Dispose()</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose all blocks
                    foreach (var block in _blocks)
                    {
                        block.Dispose();
                    }

                    // Clear collections
                    _blocks.Clear();
                    _blockHashes.Clear();
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this container manager has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        /// <summary>
        /// Finalizer to ensure resources are released.
        /// </summary>
        ~ContainerManager()
        {
            Dispose(false);
        }

        #endregion
    }

    /// <summary>
    /// Provides a summary of a container's contents.
    /// </summary>
    public class ContainerSummary
    {
        /// <summary>
        /// Gets or sets the container ID.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the container creation time.
        /// </summary>
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// Gets or sets the container's last modification time.
        /// </summary>
        public DateTime LastModified { get; set; }

        /// <summary>
        /// Gets or sets the total number of blocks in the container.
        /// </summary>
        public int TotalBlocks { get; set; }

        /// <summary>
        /// Gets or sets the number of CrownHead blocks.
        /// </summary>
        public int CrownHeadCount { get; set; }

        /// <summary>
        /// Gets or sets the number of MockHead blocks.
        /// </summary>
        public int MockHeadCount { get; set; }

        /// <summary>
        /// Gets or sets the number of WhisperHead blocks.
        /// </summary>
        public int WhisperHeadCount { get; set; }

        /// <summary>
        /// Gets or sets the total size of all blocks in bytes.
        /// </summary>
        public long TotalSize { get; set; }

        /// <summary>
        /// Gets or sets the file path of the container.
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// Gets a formatted string representation of this summary.
        /// </summary>
        /// <returns>Formatted summary string</returns>
        public override string ToString()
        {
            return $"Container {Id}\n" +
                   $"Created: {CreationTime}\n" +
                   $"Last Modified: {LastModified}\n" +
                   $"Total Blocks: {TotalBlocks}\n" +
                   $"- CrownHead: {CrownHeadCount}\n" +
                   $"- MockHead: {MockHeadCount}\n" +
                   $"- WhisperHead: {WhisperHeadCount}\n" +
                   $"Total Size: {FormatByteSize(TotalSize)}\n" +
                   (string.IsNullOrEmpty(FilePath) ? "" : $"File: {FilePath}");
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
    }
}