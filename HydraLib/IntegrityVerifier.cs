using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using HydraLib.Core;
using HydraLib.Blocks;
using HydraLib.Container;

namespace HydraLib.Security
{
    /// <summary>
    /// Provides integrity verification functionality for the multi-layer encryption system.
    /// Implements container and block level integrity checks using HMAC-based verification.
    /// </summary>
    public class IntegrityVerifier
    {
        #region Integrity Methods

        /// <summary>
        /// Verifies the integrity of a container and its blocks.
        /// </summary>
        /// <param name="metadata">Container metadata</param>
        /// <param name="blocks">Collection of blocks in the container</param>
        /// <returns>Integrity verification result</returns>
        /// <exception cref="ArgumentNullException">Thrown if metadata or blocks are null</exception>
        public static IntegrityResult VerifyContainerIntegrity(ContainerMetadata metadata, IEnumerable<Block> blocks)
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));

            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            // Check if integrity verification is enabled
            if (!metadata.UseIntegrityVerification)
                return new IntegrityResult(IntegrityStatus.NotEnabled, "Integrity verification is not enabled for this container");

            // Verify container integrity
            try
            {
                if (string.IsNullOrEmpty(metadata.BlockIntegrityHash))
                    return new IntegrityResult(IntegrityStatus.MissingData, "Container has not been finalized with integrity information");

                bool valid = metadata.VerifyIntegrity(blocks);

                if (!valid)
                    return new IntegrityResult(IntegrityStatus.Invalid, "Container integrity verification failed");

                return new IntegrityResult(IntegrityStatus.Valid, "Container integrity verified successfully");
            }
            catch (Exception ex)
            {
                return new IntegrityResult(IntegrityStatus.Error, $"Container integrity verification error: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates an integrity signature for a collection of blocks.
        /// </summary>
        /// <param name="blocks">Blocks to sign</param>
        /// <param name="key">Key for signature generation</param>
        /// <returns>Base64-encoded integrity signature</returns>
        /// <exception cref="ArgumentNullException">Thrown if blocks or key are null</exception>
        public static string GenerateIntegritySignature(IEnumerable<Block> blocks, byte[] key)
        {
            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            using var hmac = new HMACSHA256(key);
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            // Write each block's ID, type and content hash
            foreach (var block in blocks)
            {
                writer.Write(block.Id.ToByteArray());
                writer.Write((int)block.Type);

                // Get block data for hashing
                byte[] blockData = block.IsEncrypted
                    ? block.GetEncryptedData()
                    : null;

                if (blockData != null)
                {
                    // Hash the block data
                    using var sha256 = SHA256.Create();
                    byte[] blockHash = sha256.ComputeHash(blockData);
                    writer.Write(blockHash);
                }
            }

            // Compute HMAC over all block data
            byte[] signature = hmac.ComputeHash(ms.ToArray());
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// Verifies an integrity signature for a collection of blocks.
        /// </summary>
        /// <param name="blocks">Blocks to verify</param>
        /// <param name="key">Key used for signature generation</param>
        /// <param name="expectedSignature">Expected Base64-encoded integrity signature</param>
        /// <returns>True if the signature is valid, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if any parameter is null</exception>
        public static bool VerifyIntegritySignature(IEnumerable<Block> blocks, byte[] key, string expectedSignature)
        {
            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(expectedSignature))
                throw new ArgumentNullException(nameof(expectedSignature));

            try
            {
                string actualSignature = GenerateIntegritySignature(blocks, key);
                return string.Equals(actualSignature, expectedSignature, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Block Integrity

        /// <summary>
        /// Calculates a tamper-evident hash for a block.
        /// </summary>
        /// <param name="block">Block to hash</param>
        /// <returns>Base64-encoded hash of the block</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null</exception>
        /// <exception cref="InvalidOperationException">Thrown if block is not encrypted</exception>
        public static string CalculateBlockHash(Block block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (!block.IsEncrypted)
                throw new InvalidOperationException("Block must be encrypted to calculate its hash");

            byte[] blockData = block.GetEncryptedData();

            using var sha256 = SHA256.Create();
            byte[] blockHash = sha256.ComputeHash(blockData);

            return Convert.ToBase64String(blockHash);
        }

        /// <summary>
        /// Verifies if a block has been tampered with by comparing its current hash with a previously calculated hash.
        /// </summary>
        /// <param name="block">Block to verify</param>
        /// <param name="expectedHash">Previously calculated hash</param>
        /// <returns>True if the block has not been tampered with, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if block is null or expectedHash is null or empty</exception>
        /// <exception cref="InvalidOperationException">Thrown if block is not encrypted</exception>
        public static bool VerifyBlockIntegrity(Block block, string expectedHash)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (string.IsNullOrEmpty(expectedHash))
                throw new ArgumentNullException(nameof(expectedHash));

            string currentHash = CalculateBlockHash(block);
            return string.Equals(currentHash, expectedHash, StringComparison.Ordinal);
        }

        #endregion

        #region Advanced Integrity Verification

        /// <summary>
        /// Performs a deep integrity verification of a container, checking both container-level and block-level integrity.
        /// </summary>
        /// <param name="metadata">Container metadata</param>
        /// <param name="blocks">Blocks in the container</param>
        /// <param name="blockHashes">Optional dictionary of previously calculated block hashes</param>
        /// <returns>Detailed integrity verification result</returns>
        /// <exception cref="ArgumentNullException">Thrown if metadata or blocks are null</exception>
        public static async Task<DetailedIntegrityResult> PerformDeepIntegrityVerificationAsync(
            ContainerMetadata metadata,
            IEnumerable<Block> blocks,
            IDictionary<Guid, string> blockHashes = null)
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));

            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            var result = new DetailedIntegrityResult
            {
                ContainerResult = VerifyContainerIntegrity(metadata, blocks)
            };

            // Skip block verification if container integrity verification is not enabled or failed
            if (result.ContainerResult.Status != IntegrityStatus.Valid &&
                result.ContainerResult.Status != IntegrityStatus.NotEnabled)
            {
                return result;
            }

            // Verify each block's integrity if hashes are provided
            if (blockHashes != null && blockHashes.Count > 0)
            {
                var blockResults = new Dictionary<Guid, IntegrityResult>();

                foreach (var block in blocks)
                {
                    // Skip blocks that don't have a hash in the dictionary
                    if (!blockHashes.TryGetValue(block.Id, out string expectedHash))
                        continue;

                    try
                    {
                        bool valid = VerifyBlockIntegrity(block, expectedHash);

                        if (valid)
                        {
                            blockResults[block.Id] = new IntegrityResult(
                                IntegrityStatus.Valid,
                                $"Block {block.Id} integrity verified successfully");
                        }
                        else
                        {
                            blockResults[block.Id] = new IntegrityResult(
                                IntegrityStatus.Invalid,
                                $"Block {block.Id} integrity verification failed");

                            result.AnyBlockFailed = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        blockResults[block.Id] = new IntegrityResult(
                            IntegrityStatus.Error,
                            $"Block {block.Id} integrity verification error: {ex.Message}");

                        result.AnyBlockFailed = true;
                    }

                    // Small delay to allow for UI updates and prevent freezing
                    await Task.Delay(1);
                }

                result.BlockResults = blockResults;
            }

            return result;
        }

        /// <summary>
        /// Generates an integrity report for a container and its blocks.
        /// </summary>
        /// <param name="metadata">Container metadata</param>
        /// <param name="blocks">Blocks in the container</param>
        /// <returns>Integrity report containing all verification results</returns>
        /// <exception cref="ArgumentNullException">Thrown if metadata or blocks are null</exception>
        public static async Task<IntegrityReport> GenerateIntegrityReportAsync(ContainerMetadata metadata, IEnumerable<Block> blocks)
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));

            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            var report = new IntegrityReport
            {
                ContainerId = metadata.Id,
                VerificationTime = DateTime.UtcNow,
                IntegrityEnabled = metadata.UseIntegrityVerification,
                IntegrityMethod = metadata.IntegrityMethod
            };

            // Collect block hashes for integrity verification
            var blockHashes = new Dictionary<Guid, string>();
            var blockInfos = new List<BlockIntegrityInfo>();

            foreach (var block in blocks)
            {
                if (block.IsEncrypted)
                {
                    try
                    {
                        string hash = CalculateBlockHash(block);
                        blockHashes[block.Id] = hash;

                        blockInfos.Add(new BlockIntegrityInfo
                        {
                            BlockId = block.Id,
                            BlockType = block.Type,
                            Hash = hash,
                            Size = block.GetContentSize()
                        });
                    }
                    catch (Exception)
                    {
                        // Skip blocks that can't be hashed
                    }
                }

                // Small delay to allow for UI updates and prevent freezing
                await Task.Delay(1);
            }

            report.Blocks = blockInfos;

            // Perform deep integrity verification
            var verificationResult = await PerformDeepIntegrityVerificationAsync(metadata, blocks, blockHashes);
            report.VerificationResult = verificationResult;

            // Calculate overall status
            if (verificationResult.ContainerResult.Status == IntegrityStatus.Valid && !verificationResult.AnyBlockFailed)
            {
                report.OverallStatus = IntegrityStatus.Valid;
            }
            else if (verificationResult.ContainerResult.Status == IntegrityStatus.NotEnabled)
            {
                report.OverallStatus = IntegrityStatus.NotEnabled;
            }
            else
            {
                report.OverallStatus = IntegrityStatus.Invalid;
            }

            return report;
        }

        #endregion

        #region Timer-Based Verification

        /// <summary>
        /// Detects abnormal timing during integrity verification, which might indicate tampering.
        /// </summary>
        /// <param name="metadata">Container metadata</param>
        /// <param name="blocks">Blocks in the container</param>
        /// <returns>Timing analysis result</returns>
        /// <exception cref="ArgumentNullException">Thrown if metadata or blocks are null</exception>
        public static async Task<TimingAnalysisResult> DetectAbnormalTimingAsync(ContainerMetadata metadata, IEnumerable<Block> blocks)
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));

            if (blocks == null)
                throw new ArgumentNullException(nameof(blocks));

            var result = new TimingAnalysisResult();
            var timings = new Dictionary<Guid, long>();
            var baseTiming = new Dictionary<BlockType, List<long>>();

            // Collect timing information for each block
            foreach (var block in blocks)
            {
                if (!block.IsEncrypted)
                    continue;

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                try
                {
                    CalculateBlockHash(block);
                }
                catch (Exception)
                {
                    // Ignore exceptions
                }

                stopwatch.Stop();
                long elapsed = stopwatch.ElapsedTicks;

                timings[block.Id] = elapsed;

                // Collect baseline timings by block type
                if (!baseTiming.ContainsKey(block.Type))
                    baseTiming[block.Type] = new List<long>();

                baseTiming[block.Type].Add(elapsed);

                // Small delay to prevent freezing
                await Task.Delay(1);
            }

            // Calculate average times for each block type
            var averages = new Dictionary<BlockType, double>();
            var stdDevs = new Dictionary<BlockType, double>();

            foreach (var type in baseTiming.Keys)
            {
                var times = baseTiming[type];

                if (times.Count > 0)
                {
                    // Calculate average
                    double avg = times.Average();
                    averages[type] = avg;

                    // Calculate standard deviation
                    if (times.Count > 1)
                    {
                        double sumOfSquares = times.Sum(t => Math.Pow(t - avg, 2));
                        double stdDev = Math.Sqrt(sumOfSquares / (times.Count - 1));
                        stdDevs[type] = stdDev;
                    }
                    else
                    {
                        stdDevs[type] = 0;
                    }
                }
            }

            // Detect anomalies (timing more than 3 standard deviations from the mean)
            foreach (var block in blocks)
            {
                if (!timings.ContainsKey(block.Id) || !averages.ContainsKey(block.Type) || !stdDevs.ContainsKey(block.Type))
                    continue;

                double avg = averages[block.Type];
                double stdDev = stdDevs[block.Type];
                long timing = timings[block.Id];

                // Skip if standard deviation is too small (not enough data or all values nearly identical)
                if (stdDev < 1)
                    continue;

                double zScore = Math.Abs((timing - avg) / stdDev);

                if (zScore > 3.0) // More than 3 standard deviations is suspicious
                {
                    result.AnomalousBlocks.Add(block.Id, zScore);
                }
            }

            result.AnyAnomaliesDetected = result.AnomalousBlocks.Count > 0;

            return result;
        }

        #endregion
    }

    #region Result Types

    /// <summary>
    /// Represents the status of an integrity verification operation.
    /// </summary>
    public enum IntegrityStatus
    {
        /// <summary>
        /// The integrity check was not performed.
        /// </summary>
        NotPerformed = 0,

        /// <summary>
        /// The integrity check was successful.
        /// </summary>
        Valid = 1,

        /// <summary>
        /// The integrity check failed.
        /// </summary>
        Invalid = 2,

        /// <summary>
        /// Integrity verification is not enabled.
        /// </summary>
        NotEnabled = 3,

        /// <summary>
        /// Required integrity data is missing.
        /// </summary>
        MissingData = 4,

        /// <summary>
        /// An error occurred during integrity verification.
        /// </summary>
        Error = 5
    }

    /// <summary>
    /// Represents the result of an integrity verification operation.
    /// </summary>
    public class IntegrityResult
    {
        /// <summary>
        /// Gets the status of the integrity verification.
        /// </summary>
        public IntegrityStatus Status { get; }

        /// <summary>
        /// Gets a message describing the result of the integrity verification.
        /// </summary>
        public string Message { get; }

        /// <summary>
        /// Creates a new instance of the IntegrityResult class.
        /// </summary>
        /// <param name="status">Status of the integrity verification</param>
        /// <param name="message">Message describing the result</param>
        public IntegrityResult(IntegrityStatus status, string message)
        {
            Status = status;
            Message = message;
        }

        /// <summary>
        /// Returns a string representation of this integrity result.
        /// </summary>
        /// <returns>String representation</returns>
        public override string ToString()
        {
            return $"{Status}: {Message}";
        }
    }

    /// <summary>
    /// Represents a detailed result of an integrity verification operation.
    /// </summary>
    public class DetailedIntegrityResult
    {
        /// <summary>
        /// Gets or sets the result of the container integrity verification.
        /// </summary>
        public IntegrityResult ContainerResult { get; set; }

        /// <summary>
        /// Gets or sets the results of block integrity verifications.
        /// </summary>
        public Dictionary<Guid, IntegrityResult> BlockResults { get; set; } = new Dictionary<Guid, IntegrityResult>();

        /// <summary>
        /// Gets or sets whether any block failed integrity verification.
        /// </summary>
        public bool AnyBlockFailed { get; set; }

        /// <summary>
        /// Gets a summary of the integrity verification results.
        /// </summary>
        /// <returns>Summary string</returns>
        public string GetSummary()
        {
            var sb = new StringBuilder();

            sb.AppendLine($"Container Integrity: {ContainerResult}");

            if (BlockResults != null && BlockResults.Count > 0)
            {
                sb.AppendLine($"Block Integrity: {BlockResults.Count} blocks verified");

                int validCount = BlockResults.Values.Count(r => r.Status == IntegrityStatus.Valid);
                int invalidCount = BlockResults.Values.Count(r => r.Status == IntegrityStatus.Invalid);
                int errorCount = BlockResults.Values.Count(r => r.Status == IntegrityStatus.Error);

                sb.AppendLine($"- Valid: {validCount}");
                sb.AppendLine($"- Invalid: {invalidCount}");
                sb.AppendLine($"- Errors: {errorCount}");

                if (invalidCount > 0 || errorCount > 0)
                {
                    sb.AppendLine("\nInvalid or Error Blocks:");

                    foreach (var kv in BlockResults)
                    {
                        if (kv.Value.Status == IntegrityStatus.Invalid || kv.Value.Status == IntegrityStatus.Error)
                        {
                            sb.AppendLine($"- Block {kv.Key}: {kv.Value}");
                        }
                    }
                }
            }

            return sb.ToString();
        }
    }

    /// <summary>
    /// Represents information about a block's integrity.
    /// </summary>
    public class BlockIntegrityInfo
    {
        /// <summary>
        /// Gets or sets the block ID.
        /// </summary>
        public Guid BlockId { get; set; }

        /// <summary>
        /// Gets or sets the block type.
        /// </summary>
        public BlockType BlockType { get; set; }

        /// <summary>
        /// Gets or sets the block hash.
        /// </summary>
        public string Hash { get; set; }

        /// <summary>
        /// Gets or sets the block size.
        /// </summary>
        public long Size { get; set; }
    }

    /// <summary>
    /// Represents a comprehensive integrity report for a container.
    /// </summary>
    public class IntegrityReport
    {
        /// <summary>
        /// Gets or sets the container ID.
        /// </summary>
        public Guid ContainerId { get; set; }

        /// <summary>
        /// Gets or sets the time the verification was performed.
        /// </summary>
        public DateTime VerificationTime { get; set; }

        /// <summary>
        /// Gets or sets whether integrity verification is enabled for the container.
        /// </summary>
        public bool IntegrityEnabled { get; set; }

        /// <summary>
        /// Gets or sets the integrity verification method used.
        /// </summary>
        public string IntegrityMethod { get; set; }

        /// <summary>
        /// Gets or sets the overall status of the integrity verification.
        /// </summary>
        public IntegrityStatus OverallStatus { get; set; }

        /// <summary>
        /// Gets or sets the detailed verification result.
        /// </summary>
        public DetailedIntegrityResult VerificationResult { get; set; }

        /// <summary>
        /// Gets or sets information about the blocks in the container.
        /// </summary>
        public List<BlockIntegrityInfo> Blocks { get; set; } = new List<BlockIntegrityInfo>();

        /// <summary>
        /// Gets a comprehensive report of the integrity verification.
        /// </summary>
        /// <returns>Report string</returns>
        public string GetReport()
        {
            var sb = new StringBuilder();

            sb.AppendLine($"=== Integrity Report for Container {ContainerId} ===");
            sb.AppendLine($"Verification Time: {VerificationTime}");
            sb.AppendLine($"Integrity Enabled: {IntegrityEnabled}");

            if (IntegrityEnabled)
                sb.AppendLine($"Integrity Method: {IntegrityMethod}");

            sb.AppendLine($"Overall Status: {OverallStatus}");
            sb.AppendLine();

            if (VerificationResult != null)
            {
                sb.AppendLine("Verification Results:");
                sb.AppendLine(VerificationResult.GetSummary());
            }

            sb.AppendLine($"\nBlock Information ({Blocks.Count} blocks):");

            var blocksByType = Blocks.GroupBy(b => b.BlockType);

            foreach (var group in blocksByType)
            {
                sb.AppendLine($"- {group.Key}: {group.Count()} blocks, {FormatByteSize(group.Sum(b => b.Size))}");
            }

            return sb.ToString();
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

    /// <summary>
    /// Represents the result of a timing analysis for integrity verification.
    /// </summary>
    public class TimingAnalysisResult
    {
        /// <summary>
        /// Gets or sets whether any timing anomalies were detected.
        /// </summary>
        public bool AnyAnomaliesDetected { get; set; }

        /// <summary>
        /// Gets or sets a dictionary of anomalous blocks with their Z-scores.
        /// </summary>
        public Dictionary<Guid, double> AnomalousBlocks { get; set; } = new Dictionary<Guid, double>();

        /// <summary>
        /// Gets a summary of the timing analysis results.
        /// </summary>
        /// <returns>Summary string</returns>
        public string GetSummary()
        {
            var sb = new StringBuilder();

            sb.AppendLine("Timing Analysis Results:");

            if (AnyAnomaliesDetected)
            {
                sb.AppendLine($"Anomalies Detected: {AnomalousBlocks.Count} blocks");

                foreach (var kv in AnomalousBlocks.OrderByDescending(k => k.Value))
                {
                    sb.AppendLine($"- Block {kv.Key}: Z-Score {kv.Value:F2} (Higher is more suspicious)");
                }

                sb.AppendLine("\nNote: Timing anomalies may indicate tampering, but could also be caused by system load or other factors.");
            }
            else
            {
                sb.AppendLine("No timing anomalies detected.");
            }

            return sb.ToString();
        }
    }

    #endregion
}