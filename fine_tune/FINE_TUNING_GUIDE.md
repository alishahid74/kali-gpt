# Kali-GPT Fine-Tuning Guide

Create your own security-focused AI model for penetration testing.

## Overview

Phase 5 involves three approaches to get a better pentesting model:

1. **Quick: Advanced Modelfile** - Bake knowledge into system prompt (no training)
2. **Medium: Fine-tuning with LoRA** - Train on custom data (needs GPU)
3. **Full: Complete fine-tune** - Train entire model (needs serious hardware)

## Quick Start: Advanced Modelfile

No GPU needed. Just use the comprehensive Modelfile with security knowledge baked in.

```bash
# Create the advanced model
ollama create kali-security -f Modelfile.security

# Use it
ollama run kali-security

# Or with Kali-GPT
python3 kali-gpt-autonomous.py --model kali-security
```

This gives you 80% of the benefit with 0% of the hassle.

## Fine-Tuning with LoRA (Recommended)

Train a model on pentesting data using LoRA (Low-Rank Adaptation). Needs a GPU with 8GB+ VRAM.

### Requirements

- NVIDIA GPU (8GB+ VRAM)
- CUDA installed
- Python 3.10+

### Installation

```bash
# Create environment
python3 -m venv fine_tune_env
source fine_tune_env/bin/activate

# Install Unsloth (fast LoRA training)
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
pip install --no-deps trl peft accelerate bitsandbytes

# Or for regular install
pip install unsloth
```

### Training Data

The training data is in `pentest_training_data.jsonl`. Format:

```json
{"instruction": "Scan ports on 192.168.1.100", "output": "THOUGHT: Need to discover open services\nACTION: nmap -sV -sC -T4 192.168.1.100"}
```

Current dataset: 100+ examples covering:
- Port scanning
- Web enumeration
- SMB/Windows attacks
- SQL injection
- Password attacks
- Active Directory
- Cloud security

### Run Fine-Tuning

```bash
# Basic fine-tune
python fine_tune.py

# Custom options
python fine_tune.py \
    --base-model unsloth/llama-3-8b-bnb-4bit \
    --training-file pentest_training_data.jsonl \
    --output-dir kali-gpt-finetuned \
    --epochs 3 \
    --lora-r 16

# For smaller GPU (4GB)
python fine_tune.py \
    --base-model unsloth/mistral-7b-bnb-4bit \
    --batch-size 1 \
    --lora-r 8
```

### Convert to Ollama

After training:

```bash
cd kali-gpt-finetuned
ollama create kali-gpt-ft -f Modelfile.kali-gpt
ollama run kali-gpt-ft
```

## Adding Training Data

To improve the model, add more training examples:

### Format

```json
{"instruction": "Your prompt here", "output": "THOUGHT: analysis\nACTION: command"}
```

### Good Examples

```json
{"instruction": "Check for Log4Shell on 10.0.0.5", "output": "THOUGHT: Testing for CVE-2021-44228 Log4j vulnerability\nACTION: nuclei -u http://10.0.0.5 -t cves/2021/CVE-2021-44228.yaml"}
```

```json
{"instruction": "Enumerate Kubernetes API on 192.168.1.100:6443", "output": "THOUGHT: Check for unauthenticated K8s API access\nACTION: curl -sk https://192.168.1.100:6443/api/v1/namespaces"}
```

### Bad Examples (Don't do this)

```json
{"instruction": "Scan target", "output": "You should use nmap to scan the target"}
```

Problems:
- No specific target
- Output is description, not command
- Missing THOUGHT/ACTION format

## Evaluate Your Model

Test how well your model performs:

```bash
# Evaluate Ollama model
python evaluate_model.py --model kali-gpt-ft

# Evaluate with results saved
python evaluate_model.py --model kali-gpt-ft -o results.json

# Compare models
python evaluate_model.py --model dolphin-llama3
python evaluate_model.py --model kali-pentester
python evaluate_model.py --model kali-gpt-ft
```

### Benchmark Categories

| Category | Tests | Description |
|----------|-------|-------------|
| command_generation | 5 | Can it output valid commands? |
| tool_selection | 5 | Does it pick the right tool? |
| attack_chain | 3 | Does it chain attacks logically? |
| edge_case | 2 | Handles unusual inputs? |
| refusal | 3 | Does it refuse security queries? |

### Scoring

- **A (90%+)**: Excellent - Ready for production
- **B (80%+)**: Good - Minor improvements needed
- **C (70%+)**: Acceptable - Works but inconsistent
- **D (60%+)**: Needs work - Frequent issues
- **F (<60%)**: Not recommended - Too many failures

## Base Model Recommendations

| Model | Size | VRAM | Speed | Quality |
|-------|------|------|-------|---------|
| llama-3-8b | 8B | 8GB | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| mistral-7b | 7B | 6GB | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| phi-3-mini | 3.8B | 4GB | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| gemma-7b | 7B | 8GB | ⭐⭐⭐ | ⭐⭐⭐⭐ |

For uncensored base models:
- `unsloth/llama-3-8b-bnb-4bit` - Best overall
- `unsloth/mistral-7b-bnb-4bit` - Faster, smaller
- `cognitivecomputations/dolphin-2.9-llama3-8b` - Already uncensored

## Google Colab (Free GPU)

No local GPU? Use Colab:

```python
# Run in Colab
!pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"

# Upload your training data
from google.colab import files
files.upload()  # Upload pentest_training_data.jsonl

# Run training (see fine_tune.py for full code)
```

## Tips for Better Results

### Training Data Quality

1. **Be specific** - Include exact targets, ports, paths
2. **Vary examples** - Different IPs, domains, scenarios
3. **Cover edge cases** - CIDR ranges, multiple targets
4. **Include reasoning** - THOUGHT explains why

### Training Parameters

- **More epochs** = Better learning, risk of overfitting
- **Higher LoRA rank** = More capacity, more VRAM
- **Lower learning rate** = Slower but more stable

Recommended starting point:
```python
epochs = 3
lora_r = 16
learning_rate = 2e-4
```

### Evaluation

- Test on examples NOT in training data
- Compare against base model
- Check for refusal regression

## File Structure

```
fine_tune/
├── pentest_training_data.jsonl  # Training data
├── Modelfile.security           # Advanced Modelfile
├── fine_tune.py                 # Training script
├── evaluate_model.py            # Benchmark script
└── FINE_TUNING_GUIDE.md        # This guide
```

## Troubleshooting

### Out of Memory

```bash
# Reduce batch size
python fine_tune.py --batch-size 1

# Use smaller LoRA rank
python fine_tune.py --lora-r 8

# Use smaller base model
python fine_tune.py --base-model unsloth/phi-3-mini-4k-instruct-bnb-4bit
```

### Model Refuses Security Queries

- Use uncensored base model (dolphin, nous-hermes)
- Add more "refusal override" examples to training data
- Check system prompt isn't restricting

### Slow Training

- Enable Flash Attention (automatic with Unsloth)
- Use 4-bit quantization
- Reduce context length

## Next Steps

After fine-tuning:

1. Run evaluation benchmark
2. Test in Kali-GPT autonomous mode
3. Add more training data for weak areas
4. Iterate!

---

Questions? Open an issue on GitHub.
