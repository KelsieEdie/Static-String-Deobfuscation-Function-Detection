# Static String Deobfuscation Function Detection

## Purpose
This github repository contains code used to perform research for my master's project. My project paper can be found [here]().

## Abstract
String obfuscation remains one of the most pervasive challenges in malware reverse engineering, significantly complicating the analysis and timely response to cyber threats. Current automated solutions for identifying and extracting deobfuscation functions within malicious binaries are limited by their reliance on narrowly defined heuristics and specialized, malware-specific techniques. This paper presents a novel automated pipeline, combining comprehensive static analysis heuristics with statistical feature ranking to systematically detect and extract candidate string deobfuscation functions from malware binaries across multiple executable formats (PE, ELF, Mach-O). Leveraging Pyhidra and Ghidra's reverse engineering features, the implemented static framework evaluates each function against diverse heuristic indicators, including instruction patterns, XOR operation density, entropy analysis, and control-flow characteristics. Evaluation against six known malware binaries demonstrated high accuracy, correctly identifying all true deobfuscation functions among top-ranked candidates, while maintaining an interactive runtime suitable for practical incident response scenarios. However, high false-positive rates in smaller binaries revealed the need for complementary dynamic validation methods. Future extensions include integrating micro-execution and symbolic execution techniques to reduce false positives and employing machine learning methods to enhance heuristic specificity. This research provides a foundational step toward a comprehensive, scalable, and generalizable automated malware string deobfuscation framework, ultimately enabling faster defensive responses to rapidly, evolving cyber threats.

## Contents
- **v.1.0/deobfuscation_analysis.py** – this script serves as the static analysis pipeline for detecting potential string deobfuscation functions within malware binaries. It loads a target binary, computes heuristic indicators across functions (such as instruction density, XOR usage, control flow complexity), ranks candidate functions statistically, and outputs the top-ranked candidates (outliers) with detailed heuristic breakdowns.

- **v.1.0/deobfuscation_analysis_helpers.py** – this file contains helper functions and utilities supporting the main analysis script. It includes functionality for:
  - Parsing and preprocessing disassembled binary code.
  - Computing heuristic indicators (entropy analysis, XOR detection, conditional branch frequency).
  - Statistical calculations (mean, median, standard deviation, z-score computations).

- **Malware-Dataset.zip** – This zip folder (password: `infected`) contains 10 malware samples used in this research. It provides practical case studies demonstrating various obfuscation techniques identified and analyzed by the pipeline.

## Malware Dataset
| **Name**         | **Obfuscation Method**                 | **SHA256**                                                      | **Platform** |
| -----------------|----------------------------------------|---------------------------------------------------------------- | ------------ |
| Amadey           | **Fixed Key XOR**                      |06b1023ac65f1ee535c45bd46e93551822df8f9dcd64389a9e5388dd532c6b29 | Linux        |
| Darkside_S1.exe  | **128‑bit ARX block‐cipher decryption**|0a0c225faeb6d1f342bec5d2e5fbe0b9b90d4e6d9b205ac1e028eed9c7cfdcb4 | Windows      |
| Darkside_S2.exe  | **16‑byte ARX block‑cipher decryption**|151fbd6c7f5b09aacf938e4b7168a24e46e76ef5a7ec889aae0730b9bd4c0a6a | Windows      |
| Lockbit_E_S2     | **Looped XOR Variants**                |0c7466ed657a8a4f8987cf1562b82fbd03ad1bbf6b5f1f9826755c6f34a3b75a | Linux        |
| Mekotio          | *Unkown*                               |9572a6e0d50bd67c35cb70653661719c6c8034254f55e4693cfbfafb2768c59c | Windows      |
| Mirai            | *Unkown*                               |10c796b7308ac0b9c38f1caa95c798b2b28c46adaa037a9c3a9ebdd3569824e3 | Linux        |
| Pikabot_S1       | **RC4 + AES Encryption**               |1c125a10d4b86f2835c6a9a3e2e22eade78d1d5f58c2f9b1aa213fb645a34712 | Windows      |
| Pikabot_S2       | **RC4 + AES Encryption**               |72f1a547e346d786fc9e02a89efc42f31dfc43af73192df4fc8e9f99e2498e4c | Windows      |
| Simple_deobs     | **Fixed Key XOR**                      |6ae14670912338d0f028cc5f10b069bb4b034efb94ef45032fb64c3ca0ea0346 | MacOS        |
| Simple_deobs.exe | **Fixed Key XOR**                      |b7abba754eb9cbfe67eedc6228432acecdbb9cead929d44b144d2263391582a4 | Windows      |

## How to Run

1. Ensure Python and required dependencies (Ghidra, Pyhidra, numpy, pandas, scipy, matplotlib) are installed.
2. Navigate to the project directory:

```bash
cd v.1.0/
```

3. Execute the analysis script with your target binary:

```bash
python3 deobfuscation_analysis.py -filename "/path/to/binary" -project
```

4. Review results printed to terminal and saved output (JSON) detailing heuristic scores and outlier candidate functions.


