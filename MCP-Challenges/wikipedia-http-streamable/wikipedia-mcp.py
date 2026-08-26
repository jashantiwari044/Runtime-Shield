from mcp.server.fastmcp import FastMCP
import httpx
from typing import Optional
import os

# Allow the domain
os.environ["MCP_ALLOWED_HOSTS"] = "*"

# Create the MCP server
mcp = FastMCP("vulnerable-mcp-server-wikipedia-http-streamable")

# User-Agent for Wikipedia API compliance
USER_AGENT = "WikipediaMCP/1.0 (Educational/Training Purpose)"

@mcp.tool()
async def search_wikipedia(query: str, limit: int = 5) -> str:
    """
    Search Wikipedia for articles matching the query.
    
    Args:
        query: The search term to look for
        limit: Maximum number of results to return (default: 5)
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "opensearch",
                "search": query,
                "limit": limit,
                "format": "json"
            },
            headers={"User-Agent": USER_AGENT}
        )
        data = response.json()
        
        # Format the results
        titles = data[1]
        descriptions = data[2]
        urls = data[3]
        
        results = []
        for i in range(len(titles)):
            results.append(f"{i+1}. {titles[i]}\n   {descriptions[i]}\n   {urls[i]}")
        
        return "\n\n".join(results) if results else "No results found."

@mcp.tool()
async def get_wikipedia_summary(title: str) -> str:
    """
    Get the summary/introduction of a Wikipedia article.
    
    Args:
        title: The exact title of the Wikipedia article
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://en.wikipedia.org/api/rest_v1/page/summary/" + title,
            headers={"User-Agent": USER_AGENT}
        )
        
        if response.status_code == 404:
            return f"Article '{title}' not found."
        
        if response.status_code == 403:
            return f"Access forbidden. Wikipedia may be blocking requests."
        
        data = response.json()
        return f"**{data['title']}**\n\n{data['extract']}\n\nRead more: {data['content_urls']['desktop']['page']}"

@mcp.tool()
async def get_wikipedia_content(title: str, section: Optional[str] = None) -> str:
    """
    Get the full content of a Wikipedia article.
    
    Args:
        title: The exact title of the Wikipedia article
        section: Optional section number to retrieve (default: all content)
    """
    async with httpx.AsyncClient() as client:
        params = {
            "action": "query",
            "prop": "extracts",
            "titles": title,
            "format": "json",
            "explaintext": True
        }
        
        if section:
            params["exsection"] = section
            
        response = await client.get(
            "https://en.wikipedia.org/w/api.php",
            params=params,
            headers={"User-Agent": USER_AGENT}
        )
        
        data = response.json()
        pages = data["query"]["pages"]
        page = next(iter(pages.values()))
        
        if "missing" in page:
            return f"Article '{title}' not found."
        
        return f"**{page['title']}**\n\n{page.get('extract', 'No content available.')}"

@mcp.tool()
async def get_cached_page(page_id: str) -> str:
    """
    Retrieve a cached Wikipedia page by ID.
    
    Args:
        page_id: The unique ID of the cached page
    """
    cache_dir = os.path.join(os.path.dirname(__file__), "cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
        # Create a dummy cache file
        with open(os.path.join(cache_dir, "welcome.txt"), "w") as f:
            f.write("Welcome to the Wikipedia Cache!")

    # VULNERABILITY: Path Traversal
    file_path = os.path.join(cache_dir, page_id)
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading cache: {str(e)}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "http":
        import uvicorn
        app = mcp.streamable_http_app()
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        # Default to stdio for MCP session
        mcp.run()
