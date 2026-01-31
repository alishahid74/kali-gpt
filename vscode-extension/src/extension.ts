/**
 * Kali-GPT VS Code Extension v4.0
 * AI-Powered Penetration Testing - 220+ Tools
 */

import * as vscode from 'vscode';

const TOOLS = {
    'Recon': ['nmap', 'masscan', 'rustscan', 'enum4linux'],
    'Web': ['gobuster', 'ffuf', 'nuclei', 'nikto', 'sqlmap'],
    'Password': ['hydra', 'john', 'hashcat'],
    'Cloud': ['prowler', 'trivy', 'kube-hunter'],
    'Binary': ['gdb', 'radare2', 'checksec'],
    'CTF': ['volatility', 'steghide', 'binwalk']
};

let output: vscode.OutputChannel;

export function activate(ctx: vscode.ExtensionContext) {
    output = vscode.window.createOutputChannel('Kali-GPT');
    
    ctx.subscriptions.push(
        vscode.commands.registerCommand('kali-gpt.scan', scan),
        vscode.commands.registerCommand('kali-gpt.ask', ask),
        vscode.commands.registerCommand('kali-gpt.nmap', () => run('nmap')),
        vscode.commands.registerCommand('kali-gpt.gobuster', () => run('gobuster')),
        vscode.commands.registerCommand('kali-gpt.nuclei', () => run('nuclei')),
        vscode.commands.registerCommand('kali-gpt.tools', tools)
    );
    
    vscode.window.registerTreeDataProvider('kali-gpt-tools', new ToolsTree());
    vscode.window.showInformationMessage('Kali-GPT v4.0 Ready');
}

async function scan() {
    const target = await vscode.window.showInputBox({ prompt: 'Target IP/URL' });
    if (!target) return;
    
    const type = await vscode.window.showQuickPick([
        'Quick Scan (nmap)', 'Web Scan', 'Full Scan'
    ]);
    
    const term = vscode.window.createTerminal('Kali-GPT');
    term.show();
    
    if (type?.includes('Quick')) {
        term.sendText(`nmap -sV -sC ${target}`);
    } else if (type?.includes('Web')) {
        term.sendText(`gobuster dir -u ${target} -w /usr/share/wordlists/dirb/common.txt`);
    } else {
        term.sendText(`nmap -A -T4 ${target}`);
    }
}

async function run(tool: string) {
    const target = await vscode.window.showInputBox({ prompt: 'Target' });
    if (!target) return;
    
    const term = vscode.window.createTerminal('Kali-GPT');
    term.show();
    
    const cmds: {[k:string]: string} = {
        'nmap': `nmap -sV -sC ${target}`,
        'gobuster': `gobuster dir -u ${target} -w /usr/share/wordlists/dirb/common.txt`,
        'nuclei': `nuclei -u ${target}`,
        'nikto': `nikto -h ${target}`,
        'sqlmap': `sqlmap -u "${target}" --batch`
    };
    
    term.sendText(cmds[tool] || `${tool} ${target}`);
}

async function ask() {
    const q = await vscode.window.showInputBox({ prompt: 'Ask Kali-GPT AI' });
    if (!q) return;
    
    output.show();
    output.appendLine(`\n🤖 Query: ${q}\n`);
    output.appendLine('For AI assistance, run: python3 kali-gpt-autonomous.py');
    output.appendLine('Then select Option 4 (Ask AI)\n');
}

async function tools() {
    const cat = await vscode.window.showQuickPick(Object.keys(TOOLS));
    if (!cat) return;
    
    const tool = await vscode.window.showQuickPick(TOOLS[cat as keyof typeof TOOLS]);
    if (tool) await run(tool);
}

class ToolsTree implements vscode.TreeDataProvider<vscode.TreeItem> {
    getTreeItem(e: vscode.TreeItem) { return e; }
    
    getChildren(e?: vscode.TreeItem): vscode.TreeItem[] {
        if (!e) {
            return Object.keys(TOOLS).map(c => {
                const item = new vscode.TreeItem(c, vscode.TreeItemCollapsibleState.Collapsed);
                item.iconPath = new vscode.ThemeIcon('folder');
                return item;
            });
        }
        return (TOOLS[e.label as keyof typeof TOOLS] || []).map(t => {
            const item = new vscode.TreeItem(t);
            item.iconPath = new vscode.ThemeIcon('wrench');
            item.command = { command: 'kali-gpt.scan', title: 'Run' };
            return item;
        });
    }
}

export function deactivate() { output?.dispose(); }
