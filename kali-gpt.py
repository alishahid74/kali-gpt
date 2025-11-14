#!/usr/bin/env python3
import os
import pyperclip
import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Console for output
console = Console()
log_file = os.path.expanduser("~/.kali_gpt_logs.txt")

def log_interaction(user_input, ai_response):
    with open(log_file, "a") as f:
        f.write(f"\n\n[{datetime.datetime.now()}] USER: {user_input}\nGPT: {ai_response}\n")

def display_menu():
    table = Table(title="Kali GPT - Pentest Assistant", show_lines=True)
    table.add_column("Option", justify="center")
    table.add_column("Action")
    table.add_row("1", "Ask a custom question")
    table.add_row("2", "Common payload generation")
    table.add_row("3", "Explain a tool")
    table.add_row("4", "Show last response again")
    table.add_row("5", "Exit")
    console.print(table)

def ask_gpt(prompt_text):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful Kali Linux cybersecurity assistant. Be concise and practical."},
            {"role": "user", "content": prompt_text}
        ],
        temperature=0.5,
        max_tokens=800
    )
    return response.choices[0].message.content

def main():
    console.print(Panel.fit("[bold green]Welcome to Kali GPT Terminal Assistant[/bold green]"))
    last_response = None
    while True:
        display_menu()
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5"])
        if choice == "1":
            user_input = Prompt.ask("[bold yellow]Enter your question[/bold yellow]")
            response = ask_gpt(user_input)
            console.print(Panel.fit(response, title="Kali GPT Response", subtitle="Copied to clipboard"))
            pyperclip.copy(response)
            log_interaction(user_input, response)
            last_response = response
        elif choice == "2":
            payload_type = Prompt.ask("What payload? (e.g., reverse shell, msfvenom, bash)")
            response = ask_gpt(f"Generate a {payload_type} payload for Kali Linux")
            console.print(Panel.fit(response, title="Payload", subtitle="Copied to clipboard"))
            pyperclip.copy(response)
            log_interaction(payload_type, response)
            last_response = response
        elif choice == "3":
            tool_name = Prompt.ask("Which tool? (e.g., Nmap, BurpSuite, Hydra)")
            response = ask_gpt(f"Explain how to use {tool_name} with examples")
            console.print(Panel.fit(response, title="Tool Explanation", subtitle="Copied to clipboard"))
            pyperclip.copy(response)
            log_interaction(tool_name, response)
            last_response = response
        elif choice == "4":
            if last_response:
                console.print(Panel.fit(last_response, title="Last Response", subtitle="Re-copied to clipboard"))
                pyperclip.copy(last_response)
            else:
                console.print("[red]No previous response to show[/red]")
        elif choice == "5":
            console.print("[bold cyan]Exiting Kali GPT. Stay safe![/bold cyan]")
            break

if __name__ == "__main__":
    main()
