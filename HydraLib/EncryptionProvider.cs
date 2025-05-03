using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HydraLib.Blocks;
using HydraLib.Core;
using HydraLib.Cryptography;
using HydraLib.Security;
using HydraLib.Serialization;
using HydraLib;

namespace HydraLib
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
    }

    /// <summary>
    /// Provides the main API for the multi-layer encryption system.
    /// Orchestrates the other components to provide a unified interface for encryption operations.
    /// </summary>
    public class EncryptionProvider : IDisposable
    {
        #region Fields and Properties

        private readonly Dictionary<Guid, ContainerManager> _containers = new Dictionary<Guid, ContainerManager>();
        private bool _disposed = false;

        /// <summary>
        /// Gets the number of open containers.
        /// </summary>
        public int ContainerCount => _containers.Count;

        /// <summary>
        /// Gets whether this provider has been disposed.
        /// </summary>
        public bool IsDisposed => _disposed;

        #endregion

        #region Constructor

        /// <summary>
        /// Creates a new instance of the EncryptionProvider class.
        /// </summary>
        public EncryptionProvider()
        {
        }

        #endregion

        #region Container Management

        /// <summary>
        /// Creates a new container with the specified configuration.
        /// </summary>
        /// <param name="crownHeadCount">Number of CrownHead blocks to create</param>
        /// <param name="mockHeadCount">Number of MockHead blocks to create</param>
        /// <param name="whisperHeadCount">Number of WhisperHead blocks to create</param>
        /// <param name="useIntegrityVerification">Whether to enable integrity verification</param>
        /// <param name="compressContent">Whether to compress content before encryption</param>
        /// <returns>ID of the created container</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Guid CreateContainer(
            int crownHeadCount = 1,
            int mockHeadCount = 2,
            int whisperHeadCount = 3,
            bool useIntegrityVerification = true,
            bool compressContent = true)
        {
            ThrowIfDisposed();

            var container = ContainerManager.CreateContainer(
                crownHeadCount,
                mockHeadCount,
                whisperHeadCount,
                useIntegrityVerification,
                compressContent
            );

            _containers[container.Metadata.Id] = container;
            return container.Metadata.Id;
        }

        /// <summary>
        /// Opens an existing container from a file.
        /// </summary>
        /// <param name="filePath">Path to the container file</param>
        /// <returns>ID of the opened container</returns>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file is not a valid container</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<Guid> OpenContainerAsync(string filePath)
        {
            ThrowIfDisposed();

            var container = await ContainerManager.LoadContainerAsync(filePath);
            _containers[container.Metadata.Id] = container;
            return container.Metadata.Id;
        }

        /// <summary>
        /// Saves a container to a file.
        /// </summary>
        /// <param name="containerId">ID of the container to save</param>
        /// <param name="filePath">Path to save the container to</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="IOException">Thrown if the file cannot be written</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task SaveContainerAsync(Guid containerId, string filePath, bool overwrite = false)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            await container.SaveContainerAsync(filePath, overwrite);
        }

        /// <summary>
        /// Closes a container, removing it from the list of open containers.
        /// </summary>
        /// <param name="containerId">ID of the container to close</param>
        /// <param name="save">Whether to save the container if modified</param>
        /// <returns>True if the container was closed, false if it was not found</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<bool> CloseContainerAsync(Guid containerId, bool save = false)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                return false;

            if (save && container.IsModified && !string.IsNullOrEmpty(container.FilePath))
            {
                await container.SaveContainerAsync(container.FilePath, true);
            }

            container.Dispose();
            _containers.Remove(containerId);

            return true;
        }

        /// <summary>
        /// Gets a container by ID.
        /// </summary>
        /// <param name="containerId">ID of the container to get</param>
        /// <returns>The container manager, or null if not found</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public ContainerManager GetContainer(Guid containerId)
        {
            ThrowIfDisposed();

            return _containers.TryGetValue(containerId, out var container) ? container : null;
        }

        /// <summary>
        /// Gets all open containers.
        /// </summary>
        /// <returns>Dictionary of container IDs to container managers</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public IReadOnlyDictionary<Guid, ContainerManager> GetAllContainers()
        {
            ThrowIfDisposed();

            return new Dictionary<Guid, ContainerManager>(_containers);
        }

        /// <summary>
        /// Gets container summaries for all open containers.
        /// </summary>
        /// <returns>Dictionary of container IDs to container summaries</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Dictionary<Guid, ContainerSummary> GetContainerSummaries()
        {
            ThrowIfDisposed();

            var summaries = new Dictionary<Guid, ContainerSummary>();

            foreach (var pair in _containers)
            {
                summaries[pair.Key] = pair.Value.Summary;
            }

            return summaries;
        }

        /// <summary>
        /// Verifies the integrity of a container.
        /// </summary>
        /// <param name="containerId">ID of the container to verify</param>
        /// <returns>Integrity verification result</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public IntegrityResult VerifyContainerIntegrity(Guid containerId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return container.VerifyIntegrity();
        }

        /// <summary>
        /// Performs a deep integrity verification of a container.
        /// </summary>
        /// <param name="containerId">ID of the container to verify</param>
        /// <returns>Detailed integrity verification result</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<DetailedIntegrityResult> VerifyContainerIntegrityDeepAsync(Guid containerId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return await container.VerifyIntegrityDeepAsync();
        }

        /// <summary>
        /// Generates an integrity report for a container.
        /// </summary>
        /// <param name="containerId">ID of the container to generate the report for</param>
        /// <returns>Integrity report</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<IntegrityReport> GenerateContainerIntegrityReportAsync(Guid containerId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return await container.GenerateIntegrityReportAsync();
        }

        #endregion

        #region Block Management

        /// <summary>
        /// Creates a new block of the specified type.
        /// </summary>
        /// <param name="containerId">ID of the container to add the block to</param>
        /// <param name="type">Type of block to create</param>
        /// <returns>ID of the created block</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Guid CreateBlock(Guid containerId, BlockType type)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = BlockFactory.CreateBlock(type);
            container.AddBlock(block);

            return block.Id;
        }

        /// <summary>
        /// Gets a block from a container.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to get</param>
        /// <returns>The block, or null if not found</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Block GetBlock(Guid containerId, Guid blockId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return container.GetBlock(blockId);
        }

        /// <summary>
        /// Gets all blocks in a container.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <returns>All blocks in the container</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public IReadOnlyList<Block> GetAllBlocks(Guid containerId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return container.GetAllBlocks();
        }

        /// <summary>
        /// Gets blocks of a specific type from a container.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="type">Type of blocks to get</param>
        /// <returns>Blocks of the specified type</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public IEnumerable<Block> GetBlocksByType(Guid containerId, BlockType type)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return container.GetBlocksByType(type);
        }

        /// <summary>
        /// Removes a block from a container.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to remove</param>
        /// <returns>True if the block was removed, false if it was not found</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public bool RemoveBlock(Guid containerId, Guid blockId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            return container.RemoveBlock(blockId);
        }

        /// <summary>
        /// Sets the content of a block.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block</param>
        /// <param name="content">Content to set</param>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public void SetBlockContent(Guid containerId, Guid blockId, string content)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            block.SetContent(content);
        }

        /// <summary>
        /// Gets the content of a block as a string.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block</param>
        /// <returns>Block content as a string</returns>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public string GetBlockContent(Guid containerId, Guid blockId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            return block.GetContentString();
        }

        /// <summary>
        /// Imports a block from a file into a container.
        /// </summary>
        /// <param name="containerId">ID of the container to import into</param>
        /// <param name="filePath">Path to the block file</param>
        /// <returns>ID of the imported block</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the file does not exist</exception>
        /// <exception cref="InvalidDataException">Thrown if the file is not a valid block</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Guid ImportBlockFromFile(Guid containerId, string filePath)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            // Detect file format
            var format = BlockSerializer.DetectFileFormat(filePath);

            // Import based on format
            Block block;

            switch (format)
            {
                case BlockSerializationFormat.Binary:
                    block = BlockSerializer.DeserializeBlockFromFile(filePath);
                    break;

                case BlockSerializationFormat.Json:
                    block = BlockSerializer.DeserializeBlockFromJsonFile(filePath);
                    break;

                default:
                    throw new InvalidDataException($"Unsupported block format: {format}");
            }

            container.AddBlock(block);
            return block.Id;
        }

        /// <summary>
        /// Exports a block from a container to a file.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to export</param>
        /// <param name="filePath">Path to save the block to</param>
        /// <param name="format">Format to use for serialization</param>
        /// <param name="overwrite">Whether to overwrite an existing file</param>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if filePath is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="IOException">Thrown if the file cannot be written</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public void ExportBlockToFile(
            Guid containerId,
            Guid blockId,
            string filePath,
            BlockSerializationFormat format = BlockSerializationFormat.Binary,
            bool overwrite = false)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            // Export based on format
            switch (format)
            {
                case BlockSerializationFormat.Binary:
                    BlockSerializer.SerializeBlockToFile(block, filePath, overwrite);
                    break;

                case BlockSerializationFormat.Json:
                    BlockSerializer.SerializeBlockToJsonFile(block, filePath, overwrite);
                    break;

                default:
                    throw new ArgumentException($"Unsupported block format: {format}", nameof(format));
            }
        }

        #endregion

        #region Encryption and Decryption

        /// <summary>
        /// Encrypts a block with the specified password.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to encrypt</param>
        /// <param name="password">Password for encryption</param>
        /// <param name="compress">Whether to compress the content before encryption</param>
        /// <param name="includeEntropy">Whether to include additional entropy</param>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is already encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task EncryptBlockAsync(
            Guid containerId,
            Guid blockId,
            SecureString password,
            bool compress = true,
            bool includeEntropy = true)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            // Collect entropy if requested
            byte[] entropy = null;

            if (includeEntropy)
            {
                entropy = await container.CollectCombinedEntropyAsync();
            }

            // Encrypt the block
            container.EncryptBlock(block, password, compress, entropy);
        }

        /// <summary>
        /// Attempts to decrypt a block with the specified password.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to decrypt</param>
        /// <param name="password">Password for decryption</param>
        /// <returns>True if decryption succeeded, false if the password was incorrect</returns>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public bool DecryptBlock(Guid containerId, Guid blockId, SecureString password)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            return container.DecryptBlock(block, password);
        }

        /// <summary>
        /// Verifies if a password is correct for a block without fully decrypting it.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="blockId">ID of the block to check</param>
        /// <param name="password">Password to verify</param>
        /// <returns>True if the password appears to be correct, false otherwise</returns>
        /// <exception cref="ArgumentException">Thrown if containerId or blockId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if the block is not encrypted</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public bool VerifyBlockPassword(Guid containerId, Guid blockId, SecureString password)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            var block = container.GetBlock(blockId);

            if (block == null)
                throw new ArgumentException($"Block not found: {blockId}", nameof(blockId));

            return container.VerifyBlockPassword(block, password);
        }

        /// <summary>
        /// Finds a block that can be decrypted with the specified password.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <param name="password">Password to try</param>
        /// <returns>ID of the first block that can be decrypted, or null if none</returns>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public Guid? FindDecryptableBlock(Guid containerId, SecureString password)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            var blocks = container.GetAllBlocks();

            foreach (var block in blocks)
            {
                if (block.IsEncrypted && container.VerifyBlockPassword(block, password))
                {
                    return block.Id;
                }
            }

            return null;
        }

        /// <summary>
        /// Randomizes the order of blocks in a container.
        /// </summary>
        /// <param name="containerId">ID of the container</param>
        /// <exception cref="ArgumentException">Thrown if containerId is not found</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public void RandomizeBlockOrder(Guid containerId)
        {
            ThrowIfDisposed();

            if (!_containers.TryGetValue(containerId, out var container))
                throw new ArgumentException($"Container not found: {containerId}", nameof(containerId));

            container.RandomizeBlockOrder();
        }

        #endregion

        #region Password Management

        /// <summary>
        /// Generates a strong password.
        /// </summary>
        /// <param name="length">Length of the password to generate</param>
        /// <param name="includeSpecial">Whether to include special characters</param>
        /// <returns>A strong random password</returns>
        /// <exception cref="ArgumentException">Thrown if length is less than 12</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public string GenerateStrongPassword(int length = 16, bool includeSpecial = true)
        {
            ThrowIfDisposed();

            return SecurityUtilities.GenerateStrongPassword(length, includeSpecial);
        }

        /// <summary>
        /// Assesses the strength of a password.
        /// </summary>
        /// <param name="password">Password to assess</param>
        /// <returns>Password strength score (0-100)</returns>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public int AssessPasswordStrength(string password)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            return SecurityUtilities.CalculatePasswordStrength(password);
        }

        /// <summary>
        /// Checks if a password meets minimum strength requirements.
        /// </summary>
        /// <param name="password">Password to check</param>
        /// <param name="minScore">Minimum strength score required (0-100)</param>
        /// <returns>True if the password is sufficiently strong, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public bool IsPasswordStrong(string password, int minScore = 60)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            return SecurityUtilities.IsPasswordStrong(password, minScore);
        }

        #endregion

        #region Entropy Management

        /// <summary>
        /// Collects entropy from system sources for use in encryption operations.
        /// </summary>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public byte[] CollectSystemEntropy(int size = 32)
        {
            ThrowIfDisposed();

            return EntropyCollector.CollectSystemEntropy(size);
        }

        /// <summary>
        /// Collects entropy from user interaction for use in encryption operations.
        /// </summary>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="targetSamples">Number of user input samples to collect</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<byte[]> CollectUserEntropyAsync(
            IProgress<int> callback = null,
            int targetSamples = 32,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            try
            {
                return await EntropyCollector.CollectUserEntropyAsync(
                    callback,
                    targetSamples,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // If the operation was canceled, return at least some entropy
                return EntropyCollector.CollectSystemEntropy();
            }
            catch (Exception ex)
            {
                // Log the exception but don't expose it
                // In a real implementation, this would use a proper logging framework
                System.Diagnostics.Debug.WriteLine($"Error collecting user entropy: {ex.Message}");

                // Fall back to system entropy
                return EntropyCollector.CollectSystemEntropy();
            }
        }

        /// <summary>
        /// Collects entropy from hardware sources for use in encryption operations.
        /// </summary>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <returns>Entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public byte[] CollectHardwareEntropy(int size = 32)
        {
            ThrowIfDisposed();

            return EntropyCollector.CollectHardwareEntropy(size);
        }

        /// <summary>
        /// Collects combined entropy from multiple sources for use in encryption operations.
        /// </summary>
        /// <param name="includeUserEntropy">Whether to include user entropy</param>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="size">Size of entropy to collect in bytes</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Combined entropy bytes</returns>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<byte[]> CollectCombinedEntropyAsync(
            bool includeUserEntropy = true,
            IProgress<string> callback = null,
            int size = 32,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            return await EntropyCollector.CollectCombinedEntropyAsync(includeUserEntropy, callback, size, cancellationToken);
        }

        /// <summary>
        /// Assesses the quality of collected entropy.
        /// </summary>
        /// <param name="entropy">Entropy to assess</param>
        /// <returns>Entropy quality score (0-100)</returns>
        /// <exception cref="ArgumentNullException">Thrown if entropy is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public int AssessEntropyQuality(byte[] entropy)
        {
            ThrowIfDisposed();

            if (entropy == null)
                throw new ArgumentNullException(nameof(entropy));

            return EntropyCollector.AssessEntropyQuality(entropy);
        }

        #endregion

        #region Key Management

        /// <summary>
        /// Derives a key from a password using PBKDF2.
        /// </summary>
        /// <param name="password">Password to derive the key from</param>
        /// <param name="salt">Optional salt for key derivation (will be generated if null)</param>
        /// <param name="iterations">Number of iterations for key derivation</param>
        /// <param name="keyLength">Length of the derived key in bytes</param>
        /// <returns>Tuple containing the derived key and the salt used</returns>
        /// <exception cref="ArgumentNullException">Thrown if password is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public (byte[] Key, byte[] Salt) DeriveKey(
            SecureString password,
            byte[] salt = null,
            int iterations = 600000,
            int keyLength = 32)
        {
            ThrowIfDisposed();

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            return KeyDerivation.DeriveKey(password, salt, iterations, keyLength);
        }

        /// <summary>
        /// Enhances a key with additional entropy.
        /// </summary>
        /// <param name="baseKey">Base key to enhance</param>
        /// <param name="entropy">Additional entropy</param>
        /// <returns>Enhanced key</returns>
        /// <exception cref="ArgumentNullException">Thrown if baseKey is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public byte[] EnhanceKeyWithEntropy(byte[] baseKey, byte[] entropy)
        {
            ThrowIfDisposed();

            if (baseKey == null)
                throw new ArgumentNullException(nameof(baseKey));

            return KeyDerivation.EnhanceKeyWithEntropy(baseKey, entropy);
        }

        /// <summary>
        /// Derives a nonce from a key and additional data.
        /// </summary>
        /// <param name="key">Key to derive the nonce from</param>
        /// <param name="additionalData">Additional data to include in derivation</param>
        /// <param name="nonceSize">Size of the nonce in bytes</param>
        /// <returns>Derived nonce</returns>
        /// <exception cref="ArgumentNullException">Thrown if key is null</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public byte[] DeriveNonce(byte[] key, byte[] additionalData, int nonceSize = 12)
        {
            ThrowIfDisposed();

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            return KeyDerivation.DeriveNonce(key, additionalData, nonceSize);
        }

        #endregion

        #region File Encryption

        /// <summary>
        /// Encrypts a file using ChaCha20-Poly1305.
        /// </summary>
        /// <param name="inputFile">Path to the file to encrypt</param>
        /// <param name="outputFile">Path to save the encrypted file</param>
        /// <param name="password">Password for encryption</param>
        /// <param name="compress">Whether to compress the file before encryption</param>
        /// <param name="collectEntropy">Whether to collect additional entropy</param>
        /// <param name="overwrite">Whether to overwrite an existing output file</param>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the input file does not exist</exception>
        /// <exception cref="IOException">Thrown if the output file cannot be written</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task EncryptFileAsync(
            string inputFile,
            string outputFile,
            SecureString password,
            bool compress = true,
            bool collectEntropy = true,
            bool overwrite = false)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentNullException(nameof(inputFile));

            if (string.IsNullOrEmpty(outputFile))
                throw new ArgumentNullException(nameof(outputFile));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            if (!File.Exists(inputFile))
                throw new FileNotFoundException("Input file not found", inputFile);

            if (File.Exists(outputFile) && !overwrite)
                throw new IOException("Output file exists and overwrite is not enabled");

            try
            {
                // Read input file
                byte[] fileContent = await File.ReadAllBytesAsync(inputFile);

                // Compress if requested
                if (compress)
                {
                    fileContent = CompressionProvider.Compress(fileContent);
                }

                // Collect entropy if requested
                byte[] entropy = null;

                if (collectEntropy)
                {
                    entropy = await CollectCombinedEntropyAsync(false);
                }

                // Derive key from password
                (byte[] key, byte[] salt) = KeyDerivation.DeriveKey(password);

                if (entropy != null)
                {
                    key = KeyDerivation.EnhanceKeyWithEntropy(key, entropy);
                }

                try
                {
                    // Generate nonce
                    byte[] nonce = KeyDerivation.DeriveNonce(key, salt);

                    // Encrypt the file
                    using var crypto = new ChaCha20Poly1305(key);
                    byte[] encryptedData = crypto.Encrypt(nonce, fileContent); // Using extension method

                    // Write file header and encrypted data
                    using var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None);
                    using var writer = new BinaryWriter(outputStream);

                    // Write header signature
                    writer.Write(Encoding.UTF8.GetBytes("MLENC"));

                    // Write format version
                    writer.Write((byte)1);

                    // Write compression flag
                    writer.Write(compress);

                    // Write salt
                    writer.Write(salt.Length);
                    writer.Write(salt);

                    // Write nonce
                    writer.Write(nonce.Length);
                    writer.Write(nonce);

                    // Write encrypted data
                    writer.Write(encryptedData.Length);
                    writer.Write(encryptedData);
                }
                finally
                {
                    // Securely clear sensitive data
                    SecurityUtilities.SecureZeroMemory(key);
                    SecurityUtilities.SecureZeroMemory(fileContent);
                }
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException || ex is IOException || ex is ObjectDisposedException))
            {
                throw new IOException($"Failed to encrypt file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Decrypts a file that was encrypted with EncryptFileAsync.
        /// </summary>
        /// <param name="inputFile">Path to the encrypted file</param>
        /// <param name="outputFile">Path to save the decrypted file</param>
        /// <param name="password">Password for decryption</param>
        /// <param name="overwrite">Whether to overwrite an existing output file</param>
        /// <returns>True if decryption was successful, false if the password was incorrect</returns>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
        /// <exception cref="FileNotFoundException">Thrown if the input file does not exist</exception>
        /// <exception cref="IOException">Thrown if the output file cannot be written</exception>
        /// <exception cref="ObjectDisposedException">Thrown if this provider has been disposed</exception>
        public async Task<bool> DecryptFileAsync(
            string inputFile,
            string outputFile,
            SecureString password,
            bool overwrite = false)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentNullException(nameof(inputFile));

            if (string.IsNullOrEmpty(outputFile))
                throw new ArgumentNullException(nameof(outputFile));

            if (password == null)
                throw new ArgumentNullException(nameof(password));

            if (!File.Exists(inputFile))
                throw new FileNotFoundException("Input file not found", inputFile);

            if (File.Exists(outputFile) && !overwrite)
                throw new IOException("Output file exists and overwrite is not enabled");

            try
            {
                using var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var reader = new BinaryReader(inputStream);

                // Read and verify header signature
                byte[] signature = reader.ReadBytes(5);
                if (Encoding.UTF8.GetString(signature) != "MLENC")
                    throw new InvalidDataException("Invalid file format");

                // Read format version
                byte version = reader.ReadByte();
                if (version != 1)
                    throw new InvalidDataException($"Unsupported file format version: {version}");

                // Read compression flag
                bool isCompressed = reader.ReadBoolean();

                // Read salt
                int saltLength = reader.ReadInt32();
                byte[] salt = reader.ReadBytes(saltLength);

                // Read nonce
                int nonceLength = reader.ReadInt32();
                byte[] nonce = reader.ReadBytes(nonceLength);

                // Read encrypted data
                int encryptedLength = reader.ReadInt32();
                byte[] encryptedData = reader.ReadBytes(encryptedLength);

                // Derive key from password
                (byte[] key, _) = KeyDerivation.DeriveKey(password, salt);

                try
                {
                    // Decrypt the file
                    byte[] decryptedData;

                    try
                    {
                        using var crypto = new ChaCha20Poly1305(key);
                        decryptedData = crypto.Decrypt(nonce, encryptedData); // Using extension method
                    }
                    catch (CryptographicException)
                    {
                        // Incorrect password
                        return false;
                    }

                    // Decompress if needed
                    if (isCompressed && CompressionProvider.IsCompressed(decryptedData))
                    {
                        decryptedData = CompressionProvider.Decompress(decryptedData);
                    }

                    // Write the decrypted data
                    await File.WriteAllBytesAsync(outputFile, decryptedData);

                    // Clear decrypted data
                    SecurityUtilities.SecureZeroMemory(decryptedData);

                    return true;
                }
                finally
                {
                    // Securely clear sensitive data
                    SecurityUtilities.SecureZeroMemory(key);
                }
            }
            catch (Exception ex) when (!(ex is ArgumentNullException || ex is FileNotFoundException || ex is IOException || ex is InvalidDataException || ex is ObjectDisposedException))
            {
                throw new IOException($"Failed to decrypt file: {ex.Message}", ex);
            }
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Releases all resources used by this encryption provider.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases resources used by this encryption provider.
        /// </summary>
        /// <param name="disposing">Whether this method is being called from Dispose()</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose all containers
                    foreach (var container in _containers.Values)
                    {
                        container.Dispose();
                    }

                    // Clear collections
                    _containers.Clear();
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this encryption provider has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        /// <summary>
        /// Finalizer to ensure resources are released.
        /// </summary>
        ~EncryptionProvider()
        {
            Dispose(false);
        }

        #endregion
    }
}