# OsageLOM

Malware detection using ByteFormer transformer on PE executable opcodes.

## Overview

OsageLOM is a malware classification system that uses a transformer-based neural network (ByteFormer) to analyze PE (Portable Executable) files and classify them either malware or benign. The model is trained on raw byte sequences of  executable sections of said PE files.

## Architecture

- **ByteFormer**: A transformer encoder that processes raw bytes from PE executable sections
- Input: Raw bytes from `.text`, `.code` and other executable sections
- Output: Binary classification (malware/benign)


