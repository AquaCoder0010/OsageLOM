"""
Training script for ByteFormer model.
"""

import os
import argparse
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from torch.cuda.amp import autocast, GradScaler
from pathlib import Path
from tqdm import tqdm

from model import create_byteformer
from dataset import ByteFormerDataset, BytesTransform, create_dataloader


def train_one_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: torch.device,
    scaler: GradScaler,
    epoch: int
) -> float:
    """
    Train for one epoch.
    
    Args:
        model: ByteFormer model
        dataloader: Training data loader
        criterion: Loss function
        optimizer: Optimizer
        device: Computation device
        scaler: Gradient scaler for mixed precision
        epoch: Current epoch number
    
    Returns:
        Average training loss
    """
    model.train()
    total_loss = 0.0
    
    pbar = tqdm(dataloader, desc=f"Epoch {epoch}")
    for batch_idx, (inputs, targets) in enumerate(pbar):
        inputs = inputs.to(device)
        targets = targets.to(device)
        
        optimizer.zero_grad()
        
        # Mixed precision training
        with autocast():
            outputs = model(inputs)
            loss = criterion(outputs, targets)
        
        scaler.scale(loss).backward()
        scaler.step(optimizer)
        scaler.update()
        
        total_loss += loss.item()
        pbar.set_postfix({"loss": loss.item()})
    
    return total_loss / len(dataloader)


def evaluate(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: nn.Module,
    device: torch.device
) -> dict:
    """
    Evaluate model on validation set.
    
    Args:
        model: ByteFormer model
        dataloader: Validation data loader
        criterion: Loss function
        device: Computation device
    
    Returns:
        Dictionary with evaluation metrics
    """
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    
    with torch.no_grad():
        for inputs, targets in dataloader:
            inputs = inputs.to(device)
            targets = targets.to(device)
            
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()
    
    return {
        "loss": total_loss / len(dataloader),
        "accuracy": 100.0 * correct / total
    }


def save_checkpoint(
    model: nn.Module,
    optimizer: optim.Optimizer,
    epoch: int,
    metrics: dict,
    save_path: str
):
    """Save model checkpoint."""
    checkpoint = {
        "epoch": epoch,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "metrics": metrics
    }
    torch.save(checkpoint, save_path)
    print(f"Checkpoint saved to {save_path}")


def test(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
    num_classes: int
) -> dict:
    """
    Evaluate model on test set with detailed metrics.
    
    Args:
        model: ByteFormer model
        dataloader: Test data loader
        criterion: Loss function
        device: Computation device
        num_classes: Number of classes
    
    Returns:
        Dictionary with evaluation metrics including per-class accuracy
    """
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    
    # Per-class tracking
    class_correct = [0] * num_classes
    class_total = [0] * num_classes
    
    # Top-k tracking
    top3_correct = 0
    top5_correct = 0
    
    all_preds = []
    all_targets = []
    all_probs = []
    
    with torch.no_grad():
        for inputs, targets in dataloader:
            inputs = inputs.to(device)
            targets = targets.to(device)
            
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            
            total_loss += loss.item()
            
            # Get probabilities for top-k
            probs = torch.softmax(outputs, dim=1)
            
            # Top-1 accuracy
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()
            
            # Per-class accuracy
            for i in range(targets.size(0)):
                label = targets[i].item()
                class_total[label] += 1
                if predicted[i] == targets[i]:
                    class_correct[label] += 1
            
            all_preds.extend(predicted.cpu().numpy())
            all_targets.extend(targets.cpu().numpy())
            all_probs.append(probs.cpu())
    
    # Calculate metrics
    accuracy = 100.0 * correct / total
    avg_loss = total_loss / len(dataloader)
    
    # Per-class accuracy
    class_accuracy = {}
    for i in range(num_classes):
        if class_total[i] > 0:
            class_accuracy[i] = 100.0 * class_correct[i] / class_total[i]
    
    print("\n" + "=" * 50)
    print("TEST RESULTS")
    print("=" * 50)
    print(f"Total samples:     {total}")
    print(f"Average loss:     {avg_loss:.4f}")
    print(f"Top-1 Accuracy:   {accuracy:.2f}%")
    print("-" * 50)
    print("Per-class Accuracy:")
    for i, acc in class_accuracy.items():
        print(f"  Class {i}: {acc:.2f}% ({class_correct[i]}/{class_total[i]})")
    print("=" * 50 + "\n")
    
    return {
        "loss": avg_loss,
        "accuracy": accuracy,
        "class_accuracy": class_accuracy,
        "class_correct": class_correct,
        "class_total": class_total
    }


def main(args):
    """Main training function."""
    # Set device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    model = create_byteformer(
        mode=args.mode,
        num_classes=2,
        vocab_size=args.vocab_size,
        embed_dim=args.embed_dim,
        n_layers=args.n_layers,
        n_heads=args.n_heads,
        ffn_dim=args.ffn_dim,
        conv_kernel_size=args.conv_kernel_size,
        max_num_tokens=args.max_seq_len,
        window_size=args.window_size
    ).to(device)
    

    if args.test_dir:
        # Load checkpoint
        if args.checkpoint:
            print(f"Loading checkpoint from {args.checkpoint}")
            checkpoint = torch.load(args.checkpoint, map_location=device)
            model.load_state_dict(checkpoint["model_state_dict"])
        
        # Create test dataset
        test_transform = BytesTransform(max_length=args.max_seq_len)
        
        test_dataset = ByteFormerDataset(
            root=args.test_dir,
            transform=test_transform
        )
        
        test_loader = create_dataloader(
            test_dataset,
            batch_size=args.batch_size,
            shuffle=False,
            num_workers=args.num_workers
        )
        
        print(f"Test samples: {len(test_dataset)}")
        
        criterion = nn.CrossEntropyLoss()
        test_metrics = test(model, test_loader, criterion, device, len(test_dataset.class_to_idx))
        return
    

    # Create transforms
    train_transform = BytesTransform(max_length=args.max_seq_len)
    
    # Create datasets
    train_dataset = ByteFormerDataset(
        root=args.train_dir,
        transform=train_transform
    )
    
    val_dataset = ByteFormerDataset(
        root=args.val_dir,
        transform=train_transform
    )

    print(f"Train samples: {len(train_dataset)}, Val samples: {len(val_dataset)}")
    
    # Create dataloaders
    train_loader = create_dataloader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=args.num_workers
    )
    
    val_loader = create_dataloader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=args.num_workers
    )
    
    # Create model
    model = create_byteformer(
        mode=args.mode,
        num_classes=len(train_dataset.class_to_idx),
        vocab_size=args.vocab_size,
        embed_dim=args.embed_dim,
        n_layers=args.n_layers,
        n_heads=args.n_heads,
        ffn_dim=args.ffn_dim,
        conv_kernel_size=args.conv_kernel_size,
        max_num_tokens=args.max_seq_len,
        window_size=args.window_size
    ).to(device)
    
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
        
    # Loss and optimizer
    criterion = nn.CrossEntropyLoss(label_smoothing=args.label_smoothing)
    optimizer = optim.AdamW(
        model.parameters(),
        lr=args.learning_rate,
        weight_decay=args.weight_decay
    )
    
    # Learning rate scheduler
    scheduler = optim.lr_scheduler.CosineAnnealingLR(
        optimizer,
        T_max=args.epochs
    )    
    # Mixed precision scaler
    scaler = GradScaler()
    # Training loop
    best_acc = 0.0
    os.makedirs(args.save_dir, exist_ok=True)
    
    for epoch in range(1, args.epochs + 1):
        train_loss = train_one_epoch(
            model, train_loader, criterion, optimizer, device, scaler, epoch
        )
        val_metrics = evaluate(model, val_loader, criterion, device)
        
        scheduler.step()
        
        print(f"Epoch {epoch}/{args.epochs}:")
        print(f"  Train Loss: {train_loss:.4f}")
        print(f"  Val Loss: {val_metrics['loss']:.4f}, Val Acc: {val_metrics['accuracy']:.2f}%")
        
        # Save best model
        if val_metrics["accuracy"] > best_acc:
            best_acc = val_metrics["accuracy"]
            save_checkpoint(
                model, optimizer, epoch, val_metrics,
                os.path.join(args.save_dir, "best_model.pth")
            )
        
        # Save periodic checkpoint
        if epoch % args.save_freq == 0:
            save_checkpoint(
                model, optimizer, epoch, val_metrics,
                os.path.join(args.save_dir, f"checkpoint_epoch_{epoch}.pth")
            )
    
    print(f"Training complete! Best accuracy: {best_acc:.2f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train ByteFormer model")
    
    # Data arguments
    parser.add_argument("--train-dir", type=str, required=False, help="Training data directory")
    parser.add_argument("--val-dir", type=str, required=False, help="Validation data directory")
    parser.add_argument("--max-seq-len", type=int, default=100000, help="Maximum sequence length")
    
    # Model arguments
    parser.add_argument("--mode", type=str, default="tiny", choices=["tiny", "small", "base"])
    parser.add_argument("--vocab-size", type=int, default=257)
    parser.add_argument("--embed-dim", type=int, default=192)
    parser.add_argument("--n-layers", type=int, default=12)
    parser.add_argument("--n-heads", type=int, default=3)
    parser.add_argument("--ffn-dim", type=int, default=768)
    parser.add_argument("--conv-kernel-size", type=int, default=16)
    parser.add_argument("--window-size", type=int, default=128)
    
    # Training arguments
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=0.05)
    parser.add_argument("--label-smoothing", type=float, default=0.1)
    parser.add_argument("--num-workers", type=int, default=4)
    
    # Save arguments
    parser.add_argument("--save-dir", type=str, default="checkpoints")
    parser.add_argument("--save-freq", type=int, default=10)
    
    # Test arguments
    parser.add_argument("--test-dir", type=str, default=None, help="Test data directory (for testing mode)")
    parser.add_argument("--checkpoint", type=str, default=None, help="Path to model checkpoint for testing")
    
    args = parser.parse_args()
    main(args)
