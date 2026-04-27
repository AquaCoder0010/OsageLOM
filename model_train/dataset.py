"""
Dataset classes for ByteFormer
Handles loading raw byte files (text files with binary byte strings).
"""

import os
import torch
from torch.utils.data import Dataset, DataLoader
from pathlib import Path
from typing import Optional, Tuple, List


class BytesTransform:
    """
    Transform that loads raw byte data from text files.
    
    The dataset contains text files where each line contains space-separated
    byte values (0-255), e.g., "23 156 89 255 0 34"
    """
    
    def __init__(
        self,
        max_length: Optional[int] = None,
        pad_value: int = -1
    ):
        """
        Args:
            max_length: Maximum sequence length (truncate if longer, pad if shorter)
            pad_value: Value used for padding shorter sequences
        """
        self.max_length = max_length
        self.pad_value = pad_value
    
    def __call__(self, filepath: Path) -> torch.Tensor:
        """
        Load byte data from a text file.
        
        Args:
            filepath: Path to the text file containing byte values
        
        Returns:
            Tensor of shape [seq_len] containing byte values as long
        """
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Parse space-separated byte values
        byte_values = list(content)
        byte_tensor = torch.tensor(byte_values, dtype=torch.long)
        
        # Handle max_length
        if self.max_length is not None:
            seq_len = byte_tensor.shape[0]
            
            if seq_len > self.max_length:
                # Truncate
                byte_tensor = byte_tensor[:self.max_length]
            elif seq_len < self.max_length:
                # Pad
                padding = torch.full((self.max_length - seq_len,), self.pad_value, dtype=torch.long)
                byte_tensor = torch.cat([byte_tensor, padding])
        
        return byte_tensor


class ByteFormerDataset(Dataset):
    """
    Dataset that loads raw byte sequences from text files.
    
    Expected directory structure:
        root/
            class_0/
                file1.txt
                file2.txt
            class_1/
                file3.txt
    """
    
    def __init__(
        self,
        root: str,
        transform: Optional[BytesTransform] = None,
        max_length: Optional[int] = None,
        extensions: Tuple[str, ...] = (".rtc",)
    ):
        """
        Args:
            root: Root directory containing class subdirectories
            transform: Optional transform to apply to byte sequences
            max_length: Maximum sequence length
            extensions: Valid file extensions
        """
        self.root = Path(root)
        self.transform = transform or BytesTransform(max_length=max_length)
        
        # Build list of (file_path, class_idx) tuples
        self.samples: List[Tuple[Path, int]] = []
        self.class_to_idx = {}
        
        for class_name in sorted(os.listdir(root)):
            class_dir = self.root / class_name
            if not class_dir.is_dir():
                continue
            
            class_idx = len(self.class_to_idx)
            self.class_to_idx[class_name] = class_idx
            
            for file_path in class_dir.iterdir():
                if file_path.suffix.lower() in extensions:
                    self.samples.append((file_path, class_idx))
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int]:
        filepath, label = self.samples[idx]
        
        # Load and transform byte sequence
        bytes_tensor = self.transform(filepath)
        
        return bytes_tensor, label
    
    def get_class_counts(self) -> dict:
        """Get count of samples per class."""
        counts = {}
        for _, label in self.samples:
            counts[label] = counts.get(label, 0) + 1
        return counts


class CollateFn:
    """Collate function to handle variable-length byte sequences."""
    
    def __init__(self, pad_value: int = -1):
        """
        Args:
            pad_value: Value used for padding shorter sequences
        """
        self.pad_value = pad_value
    
    def __call__(self, batch: List[Tuple[torch.Tensor, int]]) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Collate batch of (bytes, label) tuples.
        
        Returns:
            padded_bytes: [batch_size, max_seq_len]
            labels: [batch_size]
        """
        bytes_list, labels = zip(*batch)
        
        # Get max sequence length in batch
        max_seq_len = max(b.shape[0] for b in bytes_list)
        
        # Pad sequences
        padded = torch.full((len(bytes_list), max_seq_len), self.pad_value, dtype=torch.long)
        
        for i, bytes_tensor in enumerate(bytes_list):
            seq_len = bytes_tensor.shape[0]
            padded[i, :seq_len] = bytes_tensor
        
        labels = torch.tensor(labels, dtype=torch.long)
        
        return padded, labels


def create_dataloader(
    dataset: Dataset,
    batch_size: int = 32,
    shuffle: bool = True,
    num_workers: int = 4,
    **kwargs
) -> DataLoader:
    """
    Create a DataLoader with custom collate function.
    
    Args:
        dataset: Dataset to load from
        batch_size: Number of samples per batch
        shuffle: Whether to shuffle data
        num_workers: Number of worker processes
        **kwargs: Additional arguments for CollateFn
    
    Returns:
        DataLoader instance
    """
    collate_fn = CollateFn(**kwargs)
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        collate_fn=collate_fn
    )
