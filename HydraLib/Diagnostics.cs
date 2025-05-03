using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;

using HydraLib.Core;
using HydraLib.Cryptography;
using HydraLib.Security;
using HydraLib;

namespace HydraLib.Diagnostics
{
    /// <summary>
    /// Provides diagnostic capabilities for the multi-layer encryption system.
    /// Includes performance monitoring, hardware detection, and security level assessment.
    /// </summary>
    public static class Diagnostics
    {
        #region System Information

        /// <summary>
        /// Gets detailed information about the current system.
        /// </summary>
        /// <returns>Dictionary of system information</returns>
        public static Dictionary<string, string> GetSystemInfo()
        {
            var info = new Dictionary<string, string>();

            // Operating system information
            info["OS"] = RuntimeInformation.OSDescription;
            info["OS Architecture"] = RuntimeInformation.OSArchitecture.ToString();
            info["Process Architecture"] = RuntimeInformation.ProcessArchitecture.ToString();
            info["Is 64-bit OS"] = Environment.Is64BitOperatingSystem.ToString();
            info["Is 64-bit Process"] = Environment.Is64BitProcess.ToString();

            // Runtime information
            info["Framework"] = RuntimeInformation.FrameworkDescription;
            info["Machine Name"] = Environment.MachineName;
            info["Process ID"] = Environment.ProcessId.ToString();
            info["Processor Count"] = Environment.ProcessorCount.ToString();

            // Memory information
            info["Total Physical Memory"] = GetPhysicalMemory();
            info["Available Physical Memory"] = GetAvailableMemory();
            info["GC Total Memory"] = FormatSize(GC.GetTotalMemory(false));

            return info;
        }

        /// <summary>
        /// Gets a string representation of system information.
        /// </summary>
        /// <returns>Formatted system information</returns>
        public static string GetSystemInfoString()
        {
            var info = GetSystemInfo();
            var sb = new StringBuilder();

            sb.AppendLine("=== System Information ===");

            foreach (var pair in info)
            {
                sb.AppendLine($"{pair.Key}: {pair.Value}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Gets the amount of physical memory in the system.
        /// </summary>
        /// <returns>Formatted memory size</returns>
        private static string GetPhysicalMemory()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Windows implementation
                    var memoryStatus = new MEMORYSTATUSEX
                    {
                        dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>()
                    };

                    if (GlobalMemoryStatusEx(ref memoryStatus))
                    {
                        return FormatSize((long)memoryStatus.ullTotalPhys);
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    // Linux implementation
                    try
                    {
                        string memInfo = System.IO.File.ReadAllText("/proc/meminfo");
                        string[] lines = memInfo.Split('\n');

                        foreach (string line in lines)
                        {
                            if (line.StartsWith("MemTotal:"))
                            {
                                string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 2 && long.TryParse(parts[1], out long kb))
                                {
                                    return FormatSize(kb * 1024);
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Ignore and fall back to default
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    // macOS implementation
                    // In a real implementation, you'd use P/Invoke to call sysctl
                    // For simplicity, we'll just return a placeholder
                }

                // Fall back to processor count as a rough estimate
                return $"~{Environment.ProcessorCount * 4} GB (estimated)";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Gets the amount of available physical memory in the system.
        /// </summary>
        /// <returns>Formatted memory size</returns>
        private static string GetAvailableMemory()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Windows implementation
                    var memoryStatus = new MEMORYSTATUSEX
                    {
                        dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>()
                    };

                    if (GlobalMemoryStatusEx(ref memoryStatus))
                    {
                        return FormatSize((long)memoryStatus.ullAvailPhys);
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    // Linux implementation
                    try
                    {
                        string memInfo = System.IO.File.ReadAllText("/proc/meminfo");
                        string[] lines = memInfo.Split('\n');

                        foreach (string line in lines)
                        {
                            if (line.StartsWith("MemAvailable:"))
                            {
                                string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 2 && long.TryParse(parts[1], out long kb))
                                {
                                    return FormatSize(kb * 1024);
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Ignore and fall back to default
                    }
                }

                // Fall back to default
                return "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Formats a byte size to a user-friendly string.
        /// </summary>
        /// <param name="bytes">Number of bytes</param>
        /// <returns>Formatted size string</returns>
        private static string FormatSize(long bytes)
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

        #region Performance Benchmarks

        /// <summary>
        /// Runs performance benchmarks for the encryption system.
        /// </summary>
        /// <param name="iterations">Number of iterations to run for each benchmark</param>
        /// <returns>Dictionary of benchmark results</returns>
        public static async Task<Dictionary<string, double>> RunBenchmarksAsync(int iterations = 10)
        {
            var results = new Dictionary<string, double>();

            // Benchmark key derivation
            results["Key Derivation (ms)"] = await BenchmarkKeyDerivationAsync(iterations);

            // Benchmark encryption
            results["Encryption (MB/s)"] = await BenchmarkEncryptionAsync(iterations);

            // Benchmark decryption
            results["Decryption (MB/s)"] = await BenchmarkDecryptionAsync(iterations);

            // Benchmark compression
            results["Compression (MB/s)"] = await BenchmarkCompressionAsync(iterations);

            // Benchmark decompression
            results["Decompression (MB/s)"] = await BenchmarkDecompressionAsync(iterations);

            // Benchmark entropy collection
            results["Entropy Collection (ms)"] = await BenchmarkEntropyCollectionAsync(iterations);

            return results;
        }

        /// <summary>
        /// Gets a string representation of benchmark results.
        /// </summary>
        /// <param name="results">Benchmark results</param>
        /// <returns>Formatted benchmark results</returns>
        public static string GetBenchmarkResultsString(Dictionary<string, double> results)
        {
            var sb = new StringBuilder();

            sb.AppendLine("=== Performance Benchmarks ===");

            foreach (var pair in results)
            {
                sb.AppendLine($"{pair.Key}: {pair.Value:0.00}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Benchmarks key derivation performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Average time in milliseconds</returns>
        private static async Task<double> BenchmarkKeyDerivationAsync(int iterations)
        {
            var password = "benchmark_password";
            var salt = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var stopwatch = new Stopwatch();
            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                stopwatch.Restart();
                KeyDerivation.DeriveKey(password, salt);
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            return totalMs / iterations;
        }

        /// <summary>
        /// Benchmarks encryption performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Performance in MB/s</returns>
        private static async Task<double> BenchmarkEncryptionAsync(int iterations)
        {
            // Generate random data for encryption
            const int dataSize = 1024 * 1024; // 1 MB
            var data = new byte[dataSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(data);

            // Generate key and nonce
            var key = new byte[32];
            var nonce = new byte[12];
            rng.GetBytes(key);
            rng.GetBytes(nonce);

            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                using var crypto = new CryptoProvider(key);

                var stopwatch = new Stopwatch();
                stopwatch.Start();
                crypto.Encrypt(data, nonce);
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            double mbPerSecond = iterations * dataSize / (1024.0 * 1024.0) / (totalMs / 1000.0);
            return mbPerSecond;
        }

        /// <summary>
        /// Benchmarks decryption performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Performance in MB/s</returns>
        private static async Task<double> BenchmarkDecryptionAsync(int iterations)
        {
            // Generate random data for encryption
            const int dataSize = 1024 * 1024; // 1 MB
            var data = new byte[dataSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(data);

            // Generate key and nonce
            var key = new byte[32];
            var nonce = new byte[12];
            rng.GetBytes(key);
            rng.GetBytes(nonce);

            // Encrypt the data once
            byte[] encryptedData;
            using (var crypto = new CryptoProvider(key))
            {
                encryptedData = crypto.Encrypt(data, nonce);
            }

            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                using var crypto = new CryptoProvider(key);

                var stopwatch = new Stopwatch();
                stopwatch.Start();
                crypto.Decrypt(encryptedData, nonce);
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            double mbPerSecond = iterations * dataSize / (1024.0 * 1024.0) / (totalMs / 1000.0);
            return mbPerSecond;
        }

        /// <summary>
        /// Benchmarks compression performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Performance in MB/s</returns>
        private static async Task<double> BenchmarkCompressionAsync(int iterations)
        {
            // Generate random data for compression
            const int dataSize = 1024 * 1024; // 1 MB
            var data = new byte[dataSize];

            // Generate somewhat compressible data (not pure random)
            using var rng = RandomNumberGenerator.Create();
            var pattern = new byte[1024];
            rng.GetBytes(pattern);

            for (int i = 0; i < dataSize; i += pattern.Length)
            {
                int copyLength = Math.Min(pattern.Length, dataSize - i);
                Buffer.BlockCopy(pattern, 0, data, i, copyLength);
            }

            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                var stopwatch = new Stopwatch();
                stopwatch.Start();
                CompressionProvider.Compress(data);
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            double mbPerSecond = iterations * dataSize / (1024.0 * 1024.0) / (totalMs / 1000.0);
            return mbPerSecond;
        }

        /// <summary>
        /// Benchmarks decompression performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Performance in MB/s</returns>
        private static async Task<double> BenchmarkDecompressionAsync(int iterations)
        {
            // Generate random data for compression
            const int dataSize = 1024 * 1024; // 1 MB
            var data = new byte[dataSize];

            // Generate somewhat compressible data (not pure random)
            using var rng = RandomNumberGenerator.Create();
            var pattern = new byte[1024];
            rng.GetBytes(pattern);

            for (int i = 0; i < dataSize; i += pattern.Length)
            {
                int copyLength = Math.Min(pattern.Length, dataSize - i);
                Buffer.BlockCopy(pattern, 0, data, i, copyLength);
            }

            // Compress the data once
            var compressedData = CompressionProvider.Compress(data);

            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                var stopwatch = new Stopwatch();
                stopwatch.Start();
                CompressionProvider.Decompress(compressedData);
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            double mbPerSecond = iterations * dataSize / (1024.0 * 1024.0) / (totalMs / 1000.0);
            return mbPerSecond;
        }

        /// <summary>
        /// Benchmarks entropy collection performance.
        /// </summary>
        /// <param name="iterations">Number of iterations</param>
        /// <returns>Average time in milliseconds</returns>
        private static async Task<double> BenchmarkEntropyCollectionAsync(int iterations)
        {
            var totalMs = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                await Task.Yield(); // Allow UI updates

                var stopwatch = new Stopwatch();
                stopwatch.Start();
                EntropyCollector.CollectSystemEntropy();
                stopwatch.Stop();

                totalMs += stopwatch.Elapsed.TotalMilliseconds;
            }

            return totalMs / iterations;
        }

        #endregion

        #region Hardware Detection

        /// <summary>
        /// Detects hardware acceleration capabilities.
        /// </summary>
        /// <returns>Dictionary of hardware capabilities</returns>
        public static Dictionary<string, bool> DetectHardwareCapabilities()
        {
            var capabilities = new Dictionary<string, bool>();

            // Check for SIMD support
            capabilities["SIMD"] = System.Numerics.Vector.IsHardwareAccelerated;

            // Check for multi-core support
            capabilities["MultiCore"] = Environment.ProcessorCount > 1;

            // Check for 64-bit architecture
            capabilities["64-bit"] = Environment.Is64BitProcess && Environment.Is64BitOperatingSystem;

            // Check for sufficient memory
            capabilities["SufficientMemory"] = HasSufficientMemory();

            // Check for AES hardware acceleration
            capabilities["AES-NI"] = HasAesHardwareAcceleration();

            // Check for fast ChaCha20 implementation
            capabilities["FastChaCha20"] = HasFastChaCha20Implementation();

            return capabilities;
        }

        /// <summary>
        /// Gets a string representation of hardware capabilities.
        /// </summary>
        /// <returns>Formatted hardware capabilities</returns>
        public static string GetHardwareCapabilitiesString()
        {
            var capabilities = DetectHardwareCapabilities();
            var sb = new StringBuilder();

            sb.AppendLine("=== Hardware Capabilities ===");

            foreach (var pair in capabilities)
            {
                sb.AppendLine($"{pair.Key}: {(pair.Value ? "Yes" : "No")}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Checks if the system has sufficient memory for intensive cryptographic operations.
        /// </summary>
        /// <returns>True if the system has sufficient memory, false otherwise</returns>
        private static bool HasSufficientMemory()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Windows implementation
                    var memoryStatus = new MEMORYSTATUSEX
                    {
                        dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>()
                    };

                    if (GlobalMemoryStatusEx(ref memoryStatus))
                    {
                        // Consider 4 GB as sufficient
                        return memoryStatus.ullTotalPhys >= 4_000_000_000;
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    // Linux implementation
                    try
                    {
                        string memInfo = System.IO.File.ReadAllText("/proc/meminfo");
                        string[] lines = memInfo.Split('\n');

                        foreach (string line in lines)
                        {
                            if (line.StartsWith("MemTotal:"))
                            {
                                string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 2 && long.TryParse(parts[1], out long kb))
                                {
                                    // Consider 4 GB as sufficient
                                    return kb >= 4_000_000;
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Ignore and fall back to default
                    }
                }

                // Default to processor count as a rough estimate
                return Environment.ProcessorCount >= 4;
            }
            catch
            {
                // Default to true if we can't determine
                return true;
            }
        }

        /// <summary>
        /// Checks if the system has AES hardware acceleration.
        /// </summary>
        /// <returns>True if AES hardware acceleration is available, false otherwise</returns>
        private static bool HasAesHardwareAcceleration()
        {
            // Perform a simple AES encryption benchmark to detect hardware acceleration
            try
            {
                using var aes = Aes.Create();
                aes.GenerateKey();
                aes.GenerateIV();

                var data = new byte[1024 * 1024]; // 1 MB
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(data);

                var stopwatch = new Stopwatch();
                stopwatch.Start();

                for (int i = 0; i < 10; i++)
                {
                    using var encryptor = aes.CreateEncryptor();
                    using var memoryStream = new System.IO.MemoryStream();
                    using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }

                stopwatch.Stop();

                // If AES hardware acceleration is available, encryption should be faster than this threshold
                return stopwatch.ElapsedMilliseconds < 500; // 500 ms for 10 MB
            }
            catch
            {
                // Default to false if we can't determine
                return false;
            }
        }

        /// <summary>
        /// Checks if the system has a fast ChaCha20 implementation.
        /// </summary>
        /// <returns>True if a fast ChaCha20 implementation is available, false otherwise</returns>
        private static bool HasFastChaCha20Implementation()
        {
            // Perform a simple ChaCha20 encryption benchmark to detect performance
            try
            {
                var key = new byte[32];
                var nonce = new byte[12];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(key);
                rng.GetBytes(nonce);

                var data = new byte[1024 * 1024]; // 1 MB
                rng.GetBytes(data);

                var stopwatch = new Stopwatch();
                stopwatch.Start();

                using var chacha = new ChaCha20Poly1305(key);
                for (int i = 0; i < 10; i++)
                {
                    chacha.Encrypt(nonce, data, null);
                    // Modify nonce for each iteration
                    nonce[0] = (byte)(nonce[0] + 1);
                }

                stopwatch.Stop();

                // If ChaCha20 is fast, encryption should be faster than this threshold
                return stopwatch.ElapsedMilliseconds < 500; // 500 ms for 10 MB
            }
            catch
            {
                // Default to false if we can't determine
                return false;
            }
        }

        #endregion

        #region Security Assessment

        /// <summary>
        /// Assesses the security level of the system.
        /// </summary>
        /// <returns>Security assessment results</returns>
        public static SecurityAssessment AssessSecurityLevel()
        {
            var assessment = new SecurityAssessment();

            // Assess hardware capabilities
            var capabilities = DetectHardwareCapabilities();
            assessment.HardwareCapabilities = capabilities;

            // Assess system environment
            assessment.IsSecureEnvironment = IsSecureEnvironment();

            // Assess encryption strength
            assessment.EncryptionStrength = AssessEncryptionStrength();

            // Assess key derivation strength
            assessment.KeyDerivationStrength = AssessKeyDerivationStrength();

            // Calculate overall score
            assessment.CalculateOverallScore();

            return assessment;
        }

        /// <summary>
        /// Gets a string representation of the security assessment.
        /// </summary>
        /// <param name="assessment">Security assessment</param>
        /// <returns>Formatted security assessment</returns>
        public static string GetSecurityAssessmentString(SecurityAssessment assessment)
        {
            var sb = new StringBuilder();

            sb.AppendLine("=== Security Assessment ===");
            sb.AppendLine($"Overall Security Score: {assessment.OverallScore} out of 100");
            sb.AppendLine($"Security Level: {assessment.SecurityLevel}");
            sb.AppendLine();

            sb.AppendLine("Hardware Capabilities:");
            foreach (var pair in assessment.HardwareCapabilities)
            {
                sb.AppendLine($"- {pair.Key}: {(pair.Value ? "Yes" : "No")}");
            }
            sb.AppendLine();

            sb.AppendLine($"Secure Environment: {(assessment.IsSecureEnvironment ? "Yes" : "No")}");
            sb.AppendLine($"Encryption Strength: {assessment.EncryptionStrength} out of 100");
            sb.AppendLine($"Key Derivation Strength: {assessment.KeyDerivationStrength} out of 100");
            sb.AppendLine();

            sb.AppendLine("Recommendations:");
            foreach (var recommendation in assessment.Recommendations)
            {
                sb.AppendLine($"- {recommendation}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Checks if the current environment is secure for cryptographic operations.
        /// </summary>
        /// <returns>True if the environment is secure, false otherwise</returns>
        private static bool IsSecureEnvironment()
        {
            bool isSecure = true;

            // Check if running in a managed environment (e.g., a debugger)
            if (Debugger.IsAttached)
            {
                isSecure = false;
            }

            // Check if running as administrator (less secure)
            if (IsRunningAsAdministrator())
            {
                isSecure = false;
            }

            // Check for virtual machine (potentially less secure)
            if (IsRunningInVirtualMachine())
            {
                isSecure = false;
            }

            return isSecure;
        }

        /// <summary>
        /// Checks if the application is running with administrator privileges.
        /// </summary>
        /// <returns>True if running as administrator, false otherwise</returns>
        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                // Default to false if we can't determine
                return false;
            }
        }

        /// <summary>
        /// Checks if the application is running in a virtual machine.
        /// </summary>
        /// <returns>True if running in a virtual machine, false otherwise</returns>
        private static bool IsRunningInVirtualMachine()
        {
            try
            {
                // Simple checks for common VM signs
                if (System.IO.Directory.Exists(@"C:\Program Files\VMware"))
                    return true;

                if (System.IO.Directory.Exists(@"C:\Program Files\Oracle\VirtualBox"))
                    return true;

                if (System.IO.Directory.Exists(@"C:\Program Files\Hyper-V"))
                    return true;

                // More advanced detection would require platform-specific code
                return false;
            }
            catch
            {
                // Default to false if we can't determine
                return false;
            }
        }

        /// <summary>
        /// Assesses the strength of the encryption implementation.
        /// </summary>
        /// <returns>Encryption strength score (0-100)</returns>
        private static int AssessEncryptionStrength()
        {
            int score = 0;

            // Base score for using ChaCha20-Poly1305
            score += 80;

            // Check for hardware acceleration
            if (HasFastChaCha20Implementation())
            {
                score += 10;
            }

            // Check for SIMD support
            if (System.Numerics.Vector.IsHardwareAccelerated)
            {
                score += 5;
            }

            // Check for 64-bit architecture
            if (Environment.Is64BitProcess)
            {
                score += 5;
            }

            return Math.Min(score, 100);
        }

        /// <summary>
        /// Assesses the strength of the key derivation implementation.
        /// </summary>
        /// <returns>Key derivation strength score (0-100)</returns>
        private static int AssessKeyDerivationStrength()
        {
            int score = 0;

            // Base score for using PBKDF2-SHA512
            score += 70;


            // Check optimal iterations
            int iterations = KeyDerivation.GetOptimalIterations();

            if (iterations >= 600000)
            {
                score += 10;
            }
            else if (iterations >= 300000)
            {
                score += 5;
            }

            return Math.Min(score, 100);
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
    }

    /// <summary>
    /// Represents the results of a security assessment.
    /// </summary>
    public class SecurityAssessment
    {
        /// <summary>
        /// Gets or sets the overall security score (0-100).
        /// </summary>
        public int OverallScore { get; private set; }

        /// <summary>
        /// Gets or sets the hardware capabilities detected on the system.
        /// </summary>
        public Dictionary<string, bool> HardwareCapabilities { get; set; } = new Dictionary<string, bool>();

        /// <summary>
        /// Gets or sets whether the environment is secure for cryptographic operations.
        /// </summary>
        public bool IsSecureEnvironment { get; set; }

        /// <summary>
        /// Gets or sets the encryption strength score (0-100).
        /// </summary>
        public int EncryptionStrength { get; set; }

        /// <summary>
        /// Gets or sets the key derivation strength score (0-100).
        /// </summary>
        public int KeyDerivationStrength { get; set; }

        /// <summary>
        /// Gets the security level based on the overall score.
        /// </summary>
        public SecurityLevel SecurityLevel
        {
            get
            {
                if (OverallScore >= 90)
                    return SecurityLevel.VeryHigh;
                else if (OverallScore >= 75)
                    return SecurityLevel.High;
                else if (OverallScore >= 60)
                    return SecurityLevel.Medium;
                else if (OverallScore >= 40)
                    return SecurityLevel.Low;
                else
                    return SecurityLevel.VeryLow;
            }
        }

        /// <summary>
        /// Gets recommendations for improving security based on the assessment.
        /// </summary>
        public List<string> Recommendations { get; private set; } = new List<string>();

        /// <summary>
        /// Calculates the overall security score based on individual assessments.
        /// </summary>
        public void CalculateOverallScore()
        {
            Recommendations.Clear();

            // Base score calculation
            int score = 0;
            int totalWeight = 0;

            // Hardware capabilities (25% weight)
            int hardwareScore = CalculateHardwareScore();
            score += hardwareScore * 25;
            totalWeight += 25;

            // Secure environment (15% weight)
            int environmentScore = IsSecureEnvironment ? 100 : 50;
            score += environmentScore * 15;
            totalWeight += 15;

            // Encryption strength (30% weight)
            score += EncryptionStrength * 30;
            totalWeight += 30;

            // Key derivation strength (30% weight)
            score += KeyDerivationStrength * 30;
            totalWeight += 30;

            // Calculate overall score
            OverallScore = score / totalWeight;

            // Generate recommendations
            GenerateRecommendations();
        }

        /// <summary>
        /// Calculates a score based on hardware capabilities.
        /// </summary>
        /// <returns>Hardware score (0-100)</returns>
        private int CalculateHardwareScore()
        {
            int score = 0;
            int count = 0;

            foreach (var capability in HardwareCapabilities)
            {
                if (capability.Value)
                {
                    score += 100;
                }

                count++;
            }

            return count > 0 ? score / count : 0;
        }

        /// <summary>
        /// Generates recommendations for improving security.
        /// </summary>
        private void GenerateRecommendations()
        {
            // Check hardware capabilities
            if (!HardwareCapabilities.GetValueOrDefault("SIMD", false))
            {
                Recommendations.Add("Consider using a system with SIMD support for better performance.");
            }

            if (!HardwareCapabilities.GetValueOrDefault("MultiCore", false))
            {
                Recommendations.Add("Consider using a multi-core system for better performance.");
            }

            if (!HardwareCapabilities.GetValueOrDefault("64-bit", false))
            {
                Recommendations.Add("Consider using a 64-bit system for better security and performance.");
            }

            if (!HardwareCapabilities.GetValueOrDefault("SufficientMemory", false))
            {
                Recommendations.Add("Increase system memory for better performance with memory-hard key derivation.");
            }

            // Check environment
            if (!IsSecureEnvironment)
            {
                Recommendations.Add("Run the application in a secure environment without debuggers or administrator privileges.");
            }

            // Check encryption strength
            if (EncryptionStrength < 90)
            {
                Recommendations.Add("Use hardware acceleration if available for better encryption performance.");
            }

            // Check key derivation strength
            if (KeyDerivationStrength < 90)
            {
                Recommendations.Add("Use Argon2id for key derivation if hardware supports it.");
                Recommendations.Add("Increase key derivation iterations for better security.");
            }
        }
    }

    /// <summary>
    /// Represents the security level of the system.
    /// </summary>
    public enum SecurityLevel
    {
        /// <summary>
        /// Very low security level.
        /// </summary>
        VeryLow,

        /// <summary>
        /// Low security level.
        /// </summary>
        Low,

        /// <summary>
        /// Medium security level.
        /// </summary>
        Medium,

        /// <summary>
        /// High security level.
        /// </summary>
        High,

        /// <summary>
        /// Very high security level.
        /// </summary>
        VeryHigh
    }

    /// <summary>
    /// Provides extension methods for the Diagnostics class.
    /// </summary>
    public static class DiagnosticsExtensions
    {
        /// <summary>
        /// Runs diagnostics and logs the results.
        /// </summary>
        /// <param name="provider">EncryptionProvider to run diagnostics on</param>
        /// <returns>The security assessment result</returns>
        public static async Task<SecurityAssessment> RunAndLogDiagnosticsAsync(this EncryptionProvider provider)
        {
            // Log system information
            string systemInfo = Diagnostics.GetSystemInfoString();
            Debug.WriteLine(systemInfo);

            // Run performance benchmarks
            var benchmarks = await Diagnostics.RunBenchmarksAsync();
            string benchmarkResults = Diagnostics.GetBenchmarkResultsString(benchmarks);
            Debug.WriteLine(benchmarkResults);

            // Detect hardware capabilities
            string hardwareCapabilities = Diagnostics.GetHardwareCapabilitiesString();
            Debug.WriteLine(hardwareCapabilities);

            // Assess security level
            var assessment = Diagnostics.AssessSecurityLevel();
            string securityAssessment = Diagnostics.GetSecurityAssessmentString(assessment);
            Debug.WriteLine(securityAssessment);

            return assessment;
        }

        /// <summary>
        /// Checks if a security level is sufficient for a specific operation.
        /// </summary>
        /// <param name="level">Security level to check</param>
        /// <param name="requiredLevel">Minimum required security level</param>
        /// <param name="reason">Reason for the check</param>
        /// <returns>True if the security level is sufficient, false otherwise</returns>
        public static bool IsSecurityLevelSufficient(this SecurityLevel level, SecurityLevel requiredLevel, out string reason)
        {
            if (level >= requiredLevel)
            {
                reason = null;
                return true;
            }

            reason = $"Operation requires {requiredLevel} security level, but current level is {level}";
            return false;
        }

        /// <summary>
        /// Gets a recommended key derivation iteration count based on the security level.
        /// </summary>
        /// <param name="level">Security level</param>
        /// <returns>Recommended iteration count</returns>
        public static int GetRecommendedKeyDerivationIterations(this SecurityLevel level)
        {
            switch (level)
            {
                case SecurityLevel.VeryHigh:
                    return 1000000;
                case SecurityLevel.High:
                    return 600000;
                case SecurityLevel.Medium:
                    return 300000;
                case SecurityLevel.Low:
                    return 150000;
                case SecurityLevel.VeryLow:
                    return 100000;
                default:
                    return 300000;
            }
        }

        /// <summary>
        /// Gets a recommended compression level based on the security level.
        /// </summary>
        /// <param name="level">Security level</param>
        /// <returns>Recommended compression level</returns>
        public static System.IO.Compression.CompressionLevel GetRecommendedCompressionLevel(this SecurityLevel level)
        {
            switch (level)
            {
                case SecurityLevel.VeryHigh:
                    return System.IO.Compression.CompressionLevel.Optimal;
                case SecurityLevel.High:
                    return System.IO.Compression.CompressionLevel.Optimal;
                case SecurityLevel.Medium:
                    return System.IO.Compression.CompressionLevel.Fastest;
                case SecurityLevel.Low:
                    return System.IO.Compression.CompressionLevel.Fastest;
                case SecurityLevel.VeryLow:
                    return System.IO.Compression.CompressionLevel.NoCompression;
                default:
                    return System.IO.Compression.CompressionLevel.Fastest;
            }
        }

        /// <summary>
        /// Gets a recommended minimum password strength based on the security level.
        /// </summary>
        /// <param name="level">Security level</param>
        /// <returns>Recommended minimum password strength</returns>
        public static int GetRecommendedMinPasswordStrength(this SecurityLevel level)
        {
            switch (level)
            {
                case SecurityLevel.VeryHigh:
                    return 90;
                case SecurityLevel.High:
                    return 80;
                case SecurityLevel.Medium:
                    return 70;
                case SecurityLevel.Low:
                    return 60;
                case SecurityLevel.VeryLow:
                    return 50;
                default:
                    return 70;
            }
        }
    }
}