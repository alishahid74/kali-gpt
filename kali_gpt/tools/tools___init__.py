"""
Kali-GPT Tools Module

Contains:
- tool_registry: 220+ security tools organized by category
- browser_agent: Headless browser automation (Selenium/Playwright)
- mcp_server: MCP/HTTP server for IDE integration
"""

# Import tool registry
try:
    from .tool_registry import (
        TOOLS,
        count,
        stats,
        get_tool,
        get_by_category,
        Category,
        Tool
    )
    TOOL_REGISTRY_AVAILABLE = True
except ImportError:
    TOOL_REGISTRY_AVAILABLE = False

# Import browser agent
try:
    from .browser_agent import (
        BrowserAgent,
        BrowserResult,
        display_browser_result
    )
    BROWSER_AVAILABLE = True
except ImportError:
    BROWSER_AVAILABLE = False

# Import MCP server
try:
    from .mcp_server import (
        KALI_TOOLS,
        execute_tool,
        KaliMCPServer
    )
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

__all__ = [
    # Tool Registry
    'TOOLS',
    'count',
    'stats',
    'get_tool',
    'get_by_category',
    'Category',
    'Tool',
    'TOOL_REGISTRY_AVAILABLE',
    
    # Browser Agent
    'BrowserAgent',
    'BrowserResult',
    'display_browser_result',
    'BROWSER_AVAILABLE',
    
    # MCP Server
    'KALI_TOOLS',
    'execute_tool',
    'KaliMCPServer',
    'MCP_AVAILABLE',
]
