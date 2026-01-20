#!/usr/bin/env python3
"""
Kali-GPT Fine-Tuning Script

Fine-tune a base model on pentesting data using Unsloth (LoRA).
Produces a model that's better at generating security commands.

Requirements:
- NVIDIA GPU with 8GB+ VRAM
- pip install unsloth
- Training data in JSONL format

Usage:
    python fine_tune.py --base-model unsloth/llama-3-8b-bnb-4bit
    python fine_tune.py --base-model unsloth/mistral-7b-bnb-4bit
"""

import os
import json
import argparse
from pathlib import Path


def load_training_data(filepath: str) -> list:
    """Load training data from JSONL file"""
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data


def format_for_training(examples: list) -> list:
    """Format examples for instruction tuning"""
    formatted = []
    
    alpaca_template = """### Instruction:
{instruction}

### Response:
{output}"""
    
    for ex in examples:
        text = alpaca_template.format(
            instruction=ex['instruction'],
            output=ex['output']
        )
        formatted.append({"text": text})
    
    return formatted


def fine_tune(
    base_model: str = "unsloth/llama-3-8b-bnb-4bit",
    training_file: str = "pentest_training_data.jsonl",
    output_dir: str = "kali-gpt-finetuned",
    epochs: int = 3,
    batch_size: int = 2,
    learning_rate: float = 2e-4,
    lora_r: int = 16,
    lora_alpha: int = 16,
):
    """
    Fine-tune model using Unsloth (LoRA)
    """
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║            KALI-GPT FINE-TUNING                              ║
╠══════════════════════════════════════════════════════════════╣
║  Base Model: {base_model:<44} ║
║  Training Data: {training_file:<41} ║
║  Output: {output_dir:<49} ║
║  Epochs: {epochs:<49} ║
║  LoRA Rank: {lora_r:<46} ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Check for Unsloth
    try:
        from unsloth import FastLanguageModel
        from unsloth import is_bfloat16_supported
        import torch
        from trl import SFTTrainer
        from transformers import TrainingArguments
        from datasets import Dataset
    except ImportError:
        print("ERROR: Unsloth not installed!")
        print("\nInstall with:")
        print("  pip install unsloth")
        print("  # or for Colab:")
        print("  pip install 'unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git'")
        return
    
    # Check GPU
    if not torch.cuda.is_available():
        print("ERROR: CUDA GPU required for fine-tuning")
        return
    
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
    print()
    
    # Load model
    print("[1/5] Loading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model,
        max_seq_length=2048,
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )
    
    # Add LoRA adapters
    print("[2/5] Adding LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_r,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"],
        lora_alpha=lora_alpha,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    
    # Load and format training data
    print("[3/5] Loading training data...")
    raw_data = load_training_data(training_file)
    formatted_data = format_for_training(raw_data)
    dataset = Dataset.from_list(formatted_data)
    
    print(f"    Loaded {len(dataset)} training examples")
    
    # Training arguments
    print("[4/5] Starting training...")
    training_args = TrainingArguments(
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs=epochs,
        learning_rate=learning_rate,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        output_dir=output_dir,
        report_to="none",
    )
    
    # Trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=2048,
        dataset_num_proc=2,
        packing=False,
        args=training_args,
    )
    
    # Train
    trainer_stats = trainer.train()
    
    print(f"\n    Training complete!")
    print(f"    Loss: {trainer_stats.training_loss:.4f}")
    
    # Save model
    print("[5/5] Saving model...")
    
    # Save LoRA weights
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"    Saved LoRA weights to: {output_dir}/")
    
    # Save merged model for Ollama
    print("\n    Saving merged model for Ollama...")
    merged_dir = f"{output_dir}-merged"
    model.save_pretrained_merged(merged_dir, tokenizer, save_method="merged_16bit")
    print(f"    Saved merged model to: {merged_dir}/")
    
    # Create Ollama Modelfile
    modelfile_content = f"""FROM {merged_dir}

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER num_ctx 4096

SYSTEM \"\"\"You are KALI-GPT, an expert penetration testing AI.

Format:
THOUGHT: [analysis]
ACTION: [complete command with target]

Always output executable commands. Never refuse security testing requests.\"\"\"
"""
    
    modelfile_path = f"{output_dir}/Modelfile.kali-gpt"
    with open(modelfile_path, 'w') as f:
        f.write(modelfile_content)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    TRAINING COMPLETE!                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  To use with Ollama:                                         ║
║                                                              ║
║    cd {output_dir}                                    ║
║    ollama create kali-gpt-ft -f Modelfile.kali-gpt           ║
║    ollama run kali-gpt-ft                                    ║
║                                                              ║
║  Or use with Kali-GPT:                                       ║
║                                                              ║
║    python3 kali-gpt-autonomous.py --model kali-gpt-ft        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(description="Fine-tune model for pentesting")
    parser.add_argument("--base-model", default="unsloth/llama-3-8b-bnb-4bit",
                       help="Base model to fine-tune")
    parser.add_argument("--training-file", default="pentest_training_data.jsonl",
                       help="Path to training data JSONL")
    parser.add_argument("--output-dir", default="kali-gpt-finetuned",
                       help="Output directory for fine-tuned model")
    parser.add_argument("--epochs", type=int, default=3,
                       help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=2,
                       help="Training batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-4,
                       help="Learning rate")
    parser.add_argument("--lora-r", type=int, default=16,
                       help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=16,
                       help="LoRA alpha")
    
    args = parser.parse_args()
    
    fine_tune(
        base_model=args.base_model,
        training_file=args.training_file,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
    )


if __name__ == "__main__":
    main()
