# Models Guide

Which model should you use? Here's the breakdown.

## TL;DR

For pentesting, use `kali-pentester` or `dolphin-llama3`. They're uncensored and won't refuse security queries.

```bash
./install-models.sh   # installs kali-pentester and kali-redteam
# or
ollama pull dolphin-llama3
```

## Why Uncensored?

Standard models like llama3.2 or GPT-4 will sometimes refuse to help with security stuff. You'll get responses like:

> "I can't help with exploiting systems..."
> "Here's some general information about security, but I won't provide specific commands..."

Uncensored models don't have these restrictions. They'll give you straight answers.

## Model Comparison

| Model | Type | RAM | Speed | Pentesting |
|-------|------|-----|-------|------------|
| kali-pentester | Uncensored | 8GB | Fast | ⭐⭐⭐⭐⭐ |
| kali-redteam | Uncensored | 8GB | Fast | ⭐⭐⭐⭐⭐ |
| dolphin-llama3 | Uncensored | 8GB | Medium | ⭐⭐⭐⭐⭐ |
| dolphin-mistral | Uncensored | 8GB | Fast | ⭐⭐⭐⭐ |
| openhermes | Uncensored | 8GB | Fast | ⭐⭐⭐⭐ |
| llama3.2 | Standard | 8GB | Fast | ⭐⭐⭐ |
| gpt-4o | Standard | Cloud | Medium | ⭐⭐⭐⭐ |

## Installing Models

### Option 1: Use the installer (recommended)

```bash
./install-models.sh
```

This pulls the base models and creates `kali-pentester` and `kali-redteam`.

### Option 2: Manual install

```bash
# Pull base model
ollama pull dolphin-llama3

# Or create custom model
ollama create kali-pentester -f Modelfile.pentester
```

## Custom Models

We include two custom Modelfiles:

**Modelfile.pentester** - Balanced pentesting assistant. Based on dolphin-llama3.

**Modelfile.redteam** - More aggressive, thinks like an attacker. Based on dolphin-mistral.

You can edit these to customize the system prompt.

## Selecting Models

In the app, press 6 to open model selection:

```
Available Ollama Models:
  1  dolphin-llama3:latest      🐬 Uncensored
  2  kali-pentester:latest      🐬 Uncensored  ◀ current
  3  llama3.2:latest            Standard

Select model: 1
✅ Switched to dolphin-llama3
```

Or from command line:

```bash
python3 kali-gpt-autonomous.py --model dolphin-llama3
```

## Hardware Requirements

| RAM | What you can run |
|-----|------------------|
| 8GB | 7B models (dolphin-mistral, openhermes) |
| 16GB | 8B-13B models (dolphin-llama3, nous-hermes2) |
| 32GB+ | 47B+ models (dolphin-mixtral) |

If you have a GPU, Ollama will use it automatically.

## Troubleshooting

**Model too slow?**
Try a smaller one like `dolphin-mistral` or `openhermes`.

**Out of memory?**
Close other apps or use a smaller model.

**Model giving descriptions instead of commands?**
The fallback system handles this. If it keeps happening, try `kali-pentester` which is tuned for command generation.

## Privacy Note

All models run locally via Ollama. Nothing leaves your machine.

If you use OpenAI (gpt-4o etc), your prompts go to their servers. Don't use it for sensitive engagements.
