using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HydraLib.Core;

namespace HydraLib.Security
{
    /// <summary>
    /// Provides methods for collecting and applying entropy from various sources.
    /// Enhances cryptographic operations with additional randomness.
    /// </summary>
    public static class EntropyCollector
    {
        #region Entropy Collection Methods

        /// <summary>
        /// Collects entropy from the system environment.
        /// </summary>
        /// <param name="size">Size of the entropy buffer to generate in bytes</param>
        /// <returns>Entropy bytes</returns>
        public static byte[] CollectSystemEntropy(int size = 32)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be positive");

            // Start with cryptographically secure random data as base
            byte[] entropy = new byte[size];
            RandomNumberGenerator.Fill(entropy);

            using var hash = SHA256.Create();

            // Add various system metrics as entropy sources
            AddSystemTimeEntropy(hash);
            AddProcessEntropy(hash);
            AddMemoryEntropy(hash);
            AddSystemInfoEntropy(hash);
            AddGuidEntropy(hash);
            AddThreadEntropy(hash);

            // Mix system entropy with initial random data
            byte[] systemEntropyHash = hash.Hash;

            // XOR the system entropy hash with the initial random data
            for (int i = 0; i < entropy.Length; i++)
            {
                entropy[i] ^= systemEntropyHash[i % systemEntropyHash.Length];
            }

            return entropy;
        }

        /// <summary>
        /// Collects entropy from user interaction.
        /// Can be used to gather unpredictable entropy from user behavior.
        /// </summary>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="targetSamples">Number of user input samples to collect</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Entropy bytes derived from user interaction</returns>
        public static async Task<byte[]> CollectUserEntropyAsync(
            IProgress<int> callback = null,
            int targetSamples = 32,
            CancellationToken cancellationToken = default)
        {
            // This implementation requires GUI integration for real user input
            // Here we'll simulate it with a timer-based collection

            var samples = new List<long>();
            var random = new Random(); // For simulation only
            var stopwatch = Stopwatch.StartNew();

            try
            {
                for (int i = 0; i < targetSamples && !cancellationToken.IsCancellationRequested; i++)
                {
                    // Simulate a user action
                    int delay = random.Next(50, 500);
                    await Task.Delay(delay, cancellationToken);

                    // Record the current time
                    samples.Add(stopwatch.ElapsedTicks);

                    // Report progress
                    callback?.Report((int)((i + 1) * 100.0 / targetSamples));
                }

                return HashTimingSamples(samples);
            }
            catch (OperationCanceledException)
            {
                // If we have at least some samples, use them
                if (samples.Count > 0)
                {
                    return HashTimingSamples(samples);
                }

                // Otherwise, fall back to system entropy
                return CollectSystemEntropy();
            }
        }

        /// <summary>
        /// Collects entropy from hardware events, like timing jitter.
        /// </summary>
        /// <param name="size">Size of the entropy buffer to generate in bytes</param>
        /// <returns>Entropy bytes</returns>
        public static byte[] CollectHardwareEntropy(int size = 32)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be positive");

            using var hash = SHA256.Create();

            // Measure timing jitter in CPU operations
            CollectTimingJitter(hash, 1000);

            // Add CPU information
            AddCpuInfoEntropy(hash);

            // Get entropy from hardware TRNG if available
            AddHardwareRngEntropy(hash, size);

            // Final entropy output
            byte[] finalEntropy = new byte[size];
            byte[] hardwareEntropyHash = hash.Hash;

            // Ensure output size matches requested size
            for (int i = 0; i < size; i++)
            {
                finalEntropy[i] = hardwareEntropyHash[i % hardwareEntropyHash.Length];
            }

            return finalEntropy;
        }

        /// <summary>
        /// Collects entropy from multiple sources and combines them.
        /// Provides the highest quality entropy for critical security operations.
        /// </summary>
        /// <param name="includeUserEntropy">Whether to include user entropy (requires interaction)</param>
        /// <param name="callback">Optional callback to notify of entropy collection progress</param>
        /// <param name="size">Size of the entropy buffer to generate in bytes</param>
        /// <param name="cancellationToken">Token to cancel the collection process</param>
        /// <returns>Combined entropy bytes</returns>
        public static async Task<byte[]> CollectCombinedEntropyAsync(
            bool includeUserEntropy = true,
            IProgress<string> callback = null,
            int size = 32,
            CancellationToken cancellationToken = default)
        {
            callback?.Report("Collecting system entropy...");
            byte[] systemEntropy = CollectSystemEntropy(size);

            callback?.Report("Collecting hardware entropy...");
            byte[] hardwareEntropy = CollectHardwareEntropy(size);

            byte[] userEntropy = null;

            if (includeUserEntropy)
            {
                callback?.Report("Collecting user entropy...");

                var progress = new Progress<int>(percent =>
                {
                    callback?.Report($"Collecting user entropy... {percent}%");
                });

                try
                {
                    userEntropy = await CollectUserEntropyAsync(progress, 32, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    callback?.Report("User entropy collection canceled.");
                }
            }

            // Combine entropy sources
            callback?.Report("Combining entropy sources...");
            using var hash = SHA512.Create();

            hash.TransformBlock(systemEntropy, 0, systemEntropy.Length, null, 0);
            hash.TransformBlock(hardwareEntropy, 0, hardwareEntropy.Length, null, 0);

            if (userEntropy != null)
            {
                hash.TransformBlock(userEntropy, 0, userEntropy.Length, null, 0);
            }

            // Add some additional current values as a final source
            byte[] finalizer = Encoding.UTF8.GetBytes(DateTime.UtcNow.Ticks.ToString() + Guid.NewGuid().ToString());
            hash.TransformFinalBlock(finalizer, 0, finalizer.Length);

            // Output the combined entropy
            byte[] combinedEntropy = new byte[size];
            Buffer.BlockCopy(hash.Hash, 0, combinedEntropy, 0, Math.Min(size, hash.Hash.Length));

            callback?.Report("Entropy collection complete.");
            return combinedEntropy;
        }

        #endregion

        #region Entropy Application Methods

        /// <summary>
        /// Applies additional entropy to a key.
        /// </summary>
        /// <param name="key">Original key</param>
        /// <param name="entropy">Entropy to apply</param>
        /// <returns>Enhanced key</returns>
        public static byte[] ApplyEntropyToKey(byte[] key, byte[] entropy)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            if (entropy == null || entropy.Length == 0)
                return (byte[])key.Clone(); // Return copy of original key

            // Use HMAC to derive a new key
            using var hmac = new HMACSHA256(key);
            byte[] enhancedKey = hmac.ComputeHash(entropy);

            // Ensure enhanced key is same length as original
            if (enhancedKey.Length != key.Length)
            {
                Array.Resize(ref enhancedKey, key.Length);
            }

            return enhancedKey;
        }

        /// <summary>
        /// Applies entropy to a password before key derivation.
        /// </summary>
        /// <param name="passwordBytes">Password bytes</param>
        /// <param name="entropy">Entropy to apply</param>
        /// <returns>Password bytes with entropy applied</returns>
        public static byte[] ApplyEntropyToPassword(byte[] passwordBytes, byte[] entropy)
        {
            if (passwordBytes == null || passwordBytes.Length == 0)
                throw new ArgumentException("Password cannot be null or empty", nameof(passwordBytes));

            if (entropy == null || entropy.Length == 0)
                return (byte[])passwordBytes.Clone(); // Return copy of original password

            // Create a new salt based on the original password and entropy
            using var hmac = new HMACSHA256(passwordBytes);
            byte[] entropyHash = hmac.ComputeHash(entropy);

            // Combine password with entropy
            byte[] result = new byte[passwordBytes.Length + entropyHash.Length];
            Buffer.BlockCopy(passwordBytes, 0, result, 0, passwordBytes.Length);
            Buffer.BlockCopy(entropyHash, 0, result, passwordBytes.Length, entropyHash.Length);

            // Hash the combined value to create the enhanced password
            using var sha256 = SHA256.Create();
            byte[] enhancedPassword = sha256.ComputeHash(result);

            // Clear intermediate values
            SecurityUtilities.SecureZeroMemory(result);

            return enhancedPassword;
        }

        /// <summary>
        /// Applies entropy to a nonce to make it unique.
        /// </summary>
        /// <param name="nonce">Original nonce</param>
        /// <param name="entropy">Entropy to apply</param>
        /// <returns>Enhanced nonce</returns>
        public static byte[] ApplyEntropyToNonce(byte[] nonce, byte[] entropy)
        {
            if (nonce == null || nonce.Length == 0)
                throw new ArgumentException("Nonce cannot be null or empty", nameof(nonce));

            if (entropy == null || entropy.Length == 0)
                return (byte[])nonce.Clone(); // Return copy of original nonce

            // Create a new nonce by XORing with a hash of the entropy
            using var sha256 = SHA256.Create();
            byte[] entropyHash = sha256.ComputeHash(entropy);

            byte[] enhancedNonce = new byte[nonce.Length];

            for (int i = 0; i < nonce.Length; i++)
            {
                enhancedNonce[i] = (byte)(nonce[i] ^ entropyHash[i % entropyHash.Length]);
            }

            return enhancedNonce;
        }

        #endregion

        #region Native Method Declarations

        // These native methods are used to access system information on Windows platforms

        [StructLayout(LayoutKind.Sequential)]
        internal struct MEMORYSTATUSEX
        {
            internal uint dwLength;
            internal uint dwMemoryLoad;
            internal ulong ullTotalPhys;
            internal ulong ullAvailPhys;
            internal ulong ullTotalPageFile;
            internal ulong ullAvailPageFile;
            internal ulong ullTotalVirtual;
            internal ulong ullAvailVirtual;
            internal ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        #endregion

        #region Helper Methods

        /// <summary>
        /// Adds system time information to the entropy pool.
        /// </summary>
        private static void AddSystemTimeEntropy(HashAlgorithm hash)
        {
            // Current time
            byte[] timeBytes = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            hash.TransformBlock(timeBytes, 0, timeBytes.Length, null, 0);

            // High-precision timer
            byte[] timerBytes = BitConverter.GetBytes(Stopwatch.GetTimestamp());
            hash.TransformBlock(timerBytes, 0, timerBytes.Length, null, 0);

            // Environment ticks
            byte[] tickBytes = BitConverter.GetBytes(Environment.TickCount);
            hash.TransformBlock(tickBytes, 0, tickBytes.Length, null, 0);
        }

        /// <summary>
        /// Adds process information to the entropy pool.
        /// </summary>
        private static void AddProcessEntropy(HashAlgorithm hash)
        {
            try
            {
                var process = Process.GetCurrentProcess();

                // Process ID
                byte[] pidBytes = BitConverter.GetBytes(process.Id);
                hash.TransformBlock(pidBytes, 0, pidBytes.Length, null, 0);

                // Process start time
                byte[] startTimeBytes = BitConverter.GetBytes(process.StartTime.Ticks);
                hash.TransformBlock(startTimeBytes, 0, startTimeBytes.Length, null, 0);

                // Process working set
                byte[] workingSetBytes = BitConverter.GetBytes(process.WorkingSet64);
                hash.TransformBlock(workingSetBytes, 0, workingSetBytes.Length, null, 0);

                // Process CPU time
                byte[] cpuTimeBytes = BitConverter.GetBytes(process.TotalProcessorTime.Ticks);
                hash.TransformBlock(cpuTimeBytes, 0, cpuTimeBytes.Length, null, 0);
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Adds memory information to the entropy pool.
        /// </summary>
        private static void AddMemoryEntropy(HashAlgorithm hash)
        {
            try
            {
                // GC memory info
                byte[] gcMemBytes = BitConverter.GetBytes(GC.GetTotalMemory(false));
                hash.TransformBlock(gcMemBytes, 0, gcMemBytes.Length, null, 0);

                // System memory info (platform-dependent)
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var memoryStatus = new MEMORYSTATUSEX
                    {
                        dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>()
                    };

                    if (GlobalMemoryStatusEx(ref memoryStatus))
                    {
                        byte[] availMemBytes = BitConverter.GetBytes(memoryStatus.ullAvailPhys);
                        hash.TransformBlock(availMemBytes, 0, availMemBytes.Length, null, 0);

                        byte[] memLoadBytes = BitConverter.GetBytes(memoryStatus.dwMemoryLoad);
                        hash.TransformBlock(memLoadBytes, 0, memLoadBytes.Length, null, 0);
                    }
                }
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Adds system information to the entropy pool.
        /// </summary>
        private static void AddSystemInfoEntropy(HashAlgorithm hash)
        {
            try
            {
                // OS description
                byte[] osBytes = Encoding.UTF8.GetBytes(RuntimeInformation.OSDescription);
                hash.TransformBlock(osBytes, 0, osBytes.Length, null, 0);

                // Framework description
                byte[] frameworkBytes = Encoding.UTF8.GetBytes(RuntimeInformation.FrameworkDescription);
                hash.TransformBlock(frameworkBytes, 0, frameworkBytes.Length, null, 0);

                // Machine name (hashed to protect privacy)
                byte[] machineBytes = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName));
                hash.TransformBlock(machineBytes, 0, machineBytes.Length, null, 0);

                // Current directory (hashed to protect privacy)
                byte[] dirBytes = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.CurrentDirectory));
                hash.TransformBlock(dirBytes, 0, dirBytes.Length, null, 0);
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Adds GUID entropy to the pool.
        /// </summary>
        private static void AddGuidEntropy(HashAlgorithm hash)
        {
            // Generate multiple GUIDs for additional entropy
            for (int i = 0; i < 4; i++)
            {
                byte[] guidBytes = Guid.NewGuid().ToByteArray();
                hash.TransformBlock(guidBytes, 0, guidBytes.Length, null, 0);
            }
        }

        /// <summary>
        /// Adds thread information to the entropy pool.
        /// </summary>
        private static void AddThreadEntropy(HashAlgorithm hash)
        {
            try
            {
                // Current thread ID
                byte[] threadIdBytes = BitConverter.GetBytes(Thread.CurrentThread.ManagedThreadId);
                hash.TransformBlock(threadIdBytes, 0, threadIdBytes.Length, null, 0);

                // Current processor ID
                byte[] procIdBytes = BitConverter.GetBytes(Thread.GetCurrentProcessorId());
                hash.TransformBlock(procIdBytes, 0, procIdBytes.Length, null, 0);

                // Thread priority
                byte[] priorityBytes = BitConverter.GetBytes((int)Thread.CurrentThread.Priority);
                hash.TransformBlock(priorityBytes, 0, priorityBytes.Length, null, 0);
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Collects timing jitter from CPU operations for entropy.
        /// </summary>
        private static void CollectTimingJitter(HashAlgorithm hash, int samples)
        {
            var timings = new long[samples];
            var sw = new Stopwatch();

            for (int i = 0; i < samples; i++)
            {
                sw.Restart();
                // Perform a simple but variable-time operation
                Math.Pow(i + 1, 2);
                sw.Stop();
                timings[i] = sw.ElapsedTicks;
            }

            // Concatenate the timing values
            var buffer = new byte[samples * sizeof(long)];
            Buffer.BlockCopy(timings, 0, buffer, 0, buffer.Length);

            // Add to hash
            hash.TransformBlock(buffer, 0, buffer.Length, null, 0);
        }

        /// <summary>
        /// Adds CPU information to the entropy pool.
        /// </summary>
        private static void AddCpuInfoEntropy(HashAlgorithm hash)
        {
            try
            {
                // Processor count
                byte[] countBytes = BitConverter.GetBytes(Environment.ProcessorCount);
                hash.TransformBlock(countBytes, 0, countBytes.Length, null, 0);

                // Architecture
                byte[] archBytes = Encoding.UTF8.GetBytes(RuntimeInformation.ProcessArchitecture.ToString());
                hash.TransformBlock(archBytes, 0, archBytes.Length, null, 0);

                // Is 64-bit process
                byte[] is64BitBytes = BitConverter.GetBytes(Environment.Is64BitProcess);
                hash.TransformBlock(is64BitBytes, 0, is64BitBytes.Length, null, 0);
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Attempts to add entropy from a hardware RNG if available.
        /// </summary>
        private static void AddHardwareRngEntropy(HashAlgorithm hash, int size)
        {
            try
            {
                // Use .NET's RandomNumberGenerator which may use a hardware RNG if available
                var rngBytes = new byte[size];
                RandomNumberGenerator.Fill(rngBytes);
                hash.TransformBlock(rngBytes, 0, rngBytes.Length, null, 0);
            }
            catch
            {
                // Ignore errors - just add less entropy
            }
        }

        /// <summary>
        /// Converts timing samples to entropy.
        /// </summary>
        private static byte[] HashTimingSamples(List<long> samples)
        {
            if (samples == null || samples.Count == 0)
                return new byte[0];

            using var ms = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(ms);

            foreach (var sample in samples)
            {
                writer.Write(sample);
            }

            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(ms.ToArray());
        }

        #endregion

        #region Entropy Quality Assessment

        /// <summary>
        /// Assesses the quality of collected entropy.
        /// </summary>
        /// <param name="entropy">Entropy to assess</param>
        /// <returns>Quality score (0-100)</returns>
        public static int AssessEntropyQuality(byte[] entropy)
        {
            if (entropy == null || entropy.Length == 0)
                return 0;

            // 1. Shannon entropy calculation
            double shannonEntropy = CalculateShannonEntropy(entropy);
            int shannonScore = (int)(shannonEntropy / 8.0 * 100); // 8 bits is maximum for byte values

            // 2. Check for repeated patterns
            int repetitionScore = CheckForRepetitions(entropy);

            // 3. Assess byte distribution
            int distributionScore = AssessByteDistribution(entropy);

            // 4. Check for common entropy weaknesses
            int weaknessScore = CheckForWeaknesses(entropy);

            // Calculate overall score
            int overallScore = (shannonScore + repetitionScore + distributionScore + weaknessScore) / 4;

            return Math.Clamp(overallScore, 0, 100);
        }

        /// <summary>
        /// Calculates Shannon entropy of data.
        /// </summary>
        private static double CalculateShannonEntropy(byte[] data)
        {
            int[] counts = new int[256];

            // Count occurrences of each byte value
            foreach (byte b in data)
            {
                counts[b]++;
            }

            // Calculate entropy
            double entropy = 0;
            double dataLength = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = counts[i] / dataLength;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        /// <summary>
        /// Checks for repetitions in entropy data.
        /// </summary>
        private static int CheckForRepetitions(byte[] data)
        {
            if (data.Length < 8)
                return 50; // Not enough data to check meaningfully

            int repeats = 0;

            // Check for repeating sequences
            for (int len = 2; len <= 8; len++)
            {
                for (int i = 0; i < data.Length - len * 2; i++)
                {
                    for (int j = i + len; j < data.Length - len; j++)
                    {
                        bool matches = true;

                        for (int k = 0; k < len; k++)
                        {
                            if (data[i + k] != data[j + k])
                            {
                                matches = false;
                                break;
                            }
                        }

                        if (matches)
                        {
                            repeats++;
                        }
                    }
                }
            }

            // Score based on repetitions found
            double repetitionRate = (double)repeats / data.Length;
            int score = 100 - (int)(repetitionRate * 1000); // Penalize heavily for repetitions

            return Math.Clamp(score, 0, 100);
        }

        /// <summary>
        /// Assesses the distribution of byte values in entropy data.
        /// </summary>
        private static int AssessByteDistribution(byte[] data)
        {
            if (data.Length < 16)
                return 50; // Not enough data to check meaningfully

            int[] counts = new int[256];

            // Count occurrences of each byte value
            foreach (byte b in data)
            {
                counts[b]++;
            }

            // Check how many distinct values are used
            int distinctValues = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    distinctValues++;
                }
            }

            // Score based on the distribution
            double coverage = (double)distinctValues / 256;
            int score = (int)(coverage * 100);

            return score;
        }

        /// <summary>
        /// Checks for common entropy weaknesses.
        /// </summary>
        private static int CheckForWeaknesses(byte[] data)
        {
            if (data.Length < 8)
                return 50; // Not enough data to check meaningfully

            int score = 100;

            // Check 1: Are there long runs of the same byte?
            int maxRun = 1;
            int currentRun = 1;

            for (int i = 1; i < data.Length; i++)
            {
                if (data[i] == data[i - 1])
                {
                    currentRun++;
                    maxRun = Math.Max(maxRun, currentRun);
                }
                else
                {
                    currentRun = 1;
                }
            }

            // Penalize long runs
            if (maxRun > data.Length / 10)
            {
                score -= 20;
            }
            else if (maxRun > 4)
            {
                score -= 10;
            }

            // Check 2: Are there too many zeros?
            int zeroCount = 0;
            foreach (byte b in data)
            {
                if (b == 0)
                {
                    zeroCount++;
                }
            }

            double zeroRate = (double)zeroCount / data.Length;
            if (zeroRate > 0.1) // More than 10% zeros
            {
                score -= (int)(zeroRate * 100);
            }

            // Check 3: Are there byte patterns like 0x00, 0x01, 0x02...?
            bool hasSequence = false;
            for (int i = 1; i < data.Length - 4; i++)
            {
                if (data[i] == data[i - 1] + 1 &&
                    data[i + 1] == data[i] + 1 &&
                    data[i + 2] == data[i + 1] + 1 &&
                    data[i + 3] == data[i + 2] + 1)
                {
                    hasSequence = true;
                    break;
                }
            }

            if (hasSequence)
            {
                score -= 15;
            }

            return Math.Clamp(score, 0, 100);
        }

        #endregion
    }
}