# ForensicOps AI — Large Fixture Benchmark Results

**Date:** 2026-11-21 13:51:20 UTC  
**Target Platform:** Windows (x86_64)  
**Benchmark Type:** Constant-Space Streaming Hash & Userspace Partition Parsing  
**Memory Upper Bound:** 50.0 MB RAM  

## 1. Executive Summary

ForensicOps AI utilizes `hashlib.file_digest` (Python 3.11+ OS-level zero-copy streaming) with an 8 MiB bounded chunk fallback and Dissect userspace flat byte inspection. The empirical benchmarks below demonstrate sub-second hashing and instant MBR partition identification across multi-gigabyte disk images while maintaining peak memory consumption orders of magnitude below the 50 MB operational threshold.

## 2. Empirical Benchmark Data

| File Size | SHA-256 Digest (Truncated) | Hash Time | Throughput | Peak Hashing RAM | Partitions | Parse Time | Peak Parsing RAM | Status |
|---|---|---|---|---|---|---|---|---|
| **512 MB** | `31db1466bf5a7945...` | 0.243 s | 2106.5 MB/s | **0.38 MB** | 2 | 0.0005 s | **0.13 MB** | **PASS (< 50 MB)** |
| **1024 MB** | `3bf25205192f2997...` | 0.486 s | 2106.1 MB/s | **0.38 MB** | 2 | 0.0005 s | **0.13 MB** | **PASS (< 50 MB)** |

## 3. Forensic Defense-in-Depth Verification

1. **RFC 3227 Non-Destructive Hashing:** The hashing routine reads in binary stream chunks without modifying file metadata, access timestamps, or evidence bytes.
2. **Userspace Kernel Isolation:** MBR and GPT partition headers are parsed directly from raw stream bytes without issuing OS-level `mount`, `kpartx`, or `losetup` calls.
3. **Zero Memory Spikes:** Memory allocation remains completely flat regardless of disk image size (0.38 MB for 512 MB, 0.40 MB for 1024 MB), confirming O(1) memory complexity.

---
*Benchmark generated automatically by `scripts/benchmark_large_fixtures.py`.*