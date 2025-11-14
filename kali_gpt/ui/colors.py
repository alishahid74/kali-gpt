"""Color Scheme Module"""

class ColorScheme:
    """Define color schemes for the application"""

    # Profile colors
    PROFILE_COLORS = {
        "general": "cyan",
        "recon": "blue",
        "exploit": "red",
        "web": "magenta",
        "wireless": "yellow",
        "post_exploit": "green",
        "forensics": "white"
    }

    # Severity colors
    SEVERITY_COLORS = {
        "CRITICAL": "bright_red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "NONE": "dim"
    }

    # Status colors
    STATUS_COLORS = {
        "pending": "yellow",
        "in_progress": "blue",
        "completed": "green",
        "failed": "red"
    }

    # UI element colors
    UI_COLORS = {
        "header": "cyan",
        "menu": "white",
        "prompt": "cyan",
        "error": "red",
        "success": "green",
        "warning": "yellow",
        "info": "blue"
    }

    @staticmethod
    def get_profile_color(profile: str) -> str:
        """Get color for a profile"""
        return ColorScheme.PROFILE_COLORS.get(profile, "white")

    @staticmethod
    def get_severity_color(severity: str) -> str:
        """Get color for a severity level"""
        return ColorScheme.SEVERITY_COLORS.get(severity.upper(), "white")

    @staticmethod
    def get_status_color(status: str) -> str:
        """Get color for a status"""
        return ColorScheme.STATUS_COLORS.get(status, "white")
