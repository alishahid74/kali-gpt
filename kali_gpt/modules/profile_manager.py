"""Security Profile Management Module"""

import json
from pathlib import Path
from typing import Dict, List, Optional

class ProfileManager:
    """Manages security testing profiles"""

    DEFAULT_PROFILES = {
        "general": {
            "name": "General Pentesting",
            "description": "General purpose penetration testing",
            "prompt": """You are an elite penetration testing assistant specializing in Kali Linux tools and methodologies.
            Provide expert guidance on reconnaissance, exploitation, and post-exploitation techniques. Always prioritize
            ethical hacking practices and include safety warnings where appropriate.""",
            "tools": ["nmap", "metasploit", "burp", "wireshark"],
            "color": "cyan"
        },
        "recon": {
            "name": "Reconnaissance",
            "description": "Information gathering and reconnaissance",
            "prompt": """You are a reconnaissance specialist. Focus on information gathering using tools like nmap,
            recon-ng, theHarvester, amass, and subfinder. Provide detailed guidance on passive and active reconnaissance
            techniques.""",
            "tools": ["nmap", "recon-ng", "theHarvester", "amass", "subfinder", "maltego"],
            "color": "blue"
        },
        "exploit": {
            "name": "Exploitation",
            "description": "Vulnerability exploitation",
            "prompt": """You are an exploitation expert. Guide users through safe and ethical exploitation of vulnerabilities
            using tools like Metasploit, exploit-db, and searchsploit. Always emphasize responsible disclosure and authorized
            testing only.""",
            "tools": ["metasploit", "searchsploit", "exploit-db", "msfvenom"],
            "color": "red"
        },
        "web": {
            "name": "Web Application Testing",
            "description": "Web application security testing",
            "prompt": """You are a web application security specialist. Provide expertise on testing web applications using
            BurpSuite, sqlmap, nikto, wfuzz, and ffuf. Cover topics like SQL injection, XSS, CSRF, and authentication bypasses.""",
            "tools": ["burp", "sqlmap", "nikto", "wfuzz", "ffuf", "gobuster"],
            "color": "magenta"
        },
        "wireless": {
            "name": "Wireless Security",
            "description": "Wireless network testing",
            "prompt": """You are a wireless security expert. Assist with wireless network testing using aircrack-ng, wifite,
            reaver, and related tools. Focus on WPA/WPA2 testing and wireless reconnaissance.""",
            "tools": ["aircrack-ng", "wifite", "reaver", "wash", "airodump-ng"],
            "color": "yellow"
        },
        "post_exploit": {
            "name": "Post-Exploitation",
            "description": "Post-exploitation activities",
            "prompt": """You are a post-exploitation specialist. Guide users through privilege escalation, lateral movement,
            and maintaining access. Cover tools like linpeas, winpeas, and various persistence techniques.""",
            "tools": ["linpeas", "winpeas", "mimikatz", "bloodhound"],
            "color": "green"
        },
        "forensics": {
            "name": "Digital Forensics",
            "description": "Digital forensics and analysis",
            "prompt": """You are a digital forensics expert. Provide guidance on using volatility, autopsy, sleuthkit, and
            other forensics tools for memory analysis, disk forensics, and evidence collection.""",
            "tools": ["volatility", "autopsy", "sleuthkit", "foremost"],
            "color": "white"
        }
    }

    def __init__(self, config_manager):
        """Initialize profile manager"""
        self.config = config_manager
        self.profiles_dir = Path(config_manager.config_dir) / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.custom_profiles_file = self.profiles_dir / "custom_profiles.json"

        # Load profiles
        self.profiles = self.DEFAULT_PROFILES.copy()
        self.load_custom_profiles()

    def load_custom_profiles(self):
        """Load custom profiles from file"""
        if self.custom_profiles_file.exists():
            try:
                with open(self.custom_profiles_file, 'r') as f:
                    custom_profiles = json.load(f)
                    self.profiles.update(custom_profiles)
            except json.JSONDecodeError:
                print("[Warning] Custom profiles file corrupted")

        # Also load from config
        config_profiles = self.config.get("custom_profiles", [])
        for profile in config_profiles:
            if "id" in profile and "name" in profile:
                self.profiles[profile["id"]] = profile

    def save_custom_profiles(self):
        """Save custom profiles to file"""
        custom_profiles = {
            k: v for k, v in self.profiles.items()
            if k not in self.DEFAULT_PROFILES
        }

        with open(self.custom_profiles_file, 'w') as f:
            json.dump(custom_profiles, f, indent=2)

    def add_profile(self, profile_id: str, name: str, description: str,
                   prompt: str, tools: List[str] = None, color: str = "white") -> bool:
        """
        Add a new custom profile

        Args:
            profile_id: Unique identifier for the profile
            name: Display name
            description: Profile description
            prompt: System prompt for AI
            tools: List of associated tools
            color: Display color

        Returns:
            True if successful
        """
        if tools is None:
            tools = []

        self.profiles[profile_id] = {
            "name": name,
            "description": description,
            "prompt": prompt,
            "tools": tools,
            "color": color,
            "custom": True
        }

        self.save_custom_profiles()
        return True

    def remove_profile(self, profile_id: str) -> bool:
        """Remove a custom profile"""
        if profile_id in self.DEFAULT_PROFILES:
            return False  # Cannot remove default profiles

        if profile_id in self.profiles:
            del self.profiles[profile_id]
            self.save_custom_profiles()
            return True

        return False

    def get_profile(self, profile_id: str) -> Optional[Dict]:
        """Get a profile by ID"""
        return self.profiles.get(profile_id)

    def list_profiles(self) -> Dict[str, Dict]:
        """Get all profiles"""
        return self.profiles

    def get_profile_names(self) -> List[str]:
        """Get list of profile names"""
        return [profile["name"] for profile in self.profiles.values()]

    def get_profile_prompt(self, profile_id: str) -> str:
        """Get the AI prompt for a profile"""
        profile = self.get_profile(profile_id)
        return profile["prompt"] if profile else ""

    def update_profile(self, profile_id: str, **kwargs) -> bool:
        """Update profile attributes"""
        if profile_id not in self.profiles:
            return False

        for key, value in kwargs.items():
            if key in ["name", "description", "prompt", "tools", "color"]:
                self.profiles[profile_id][key] = value

        if profile_id not in self.DEFAULT_PROFILES:
            self.save_custom_profiles()

        return True
