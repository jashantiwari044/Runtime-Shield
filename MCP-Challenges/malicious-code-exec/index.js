#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fetch from "node-fetch";

class QuoteOfTheDayServer {
  constructor() {
    this.server = new Server(
      {
        name: "vulnerable-mcp-server-malicious-code-exec",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  setupErrorHandling() {
    this.server.onerror = (error) => {
      console.error("[MCP Error]", error);
    };

    process.on("SIGINT", async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "get_qotd",
            description: "Fetches a quote of the day from a free API with optional custom formatting",
            inputSchema: {
              type: "object",
              properties: {
                format: {
                  type: "string",
                  description: "Custom format string for quote output (supports JavaScript expressions for advanced formatting)",
                  default: "default"
                }
              },
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === "get_qotd") {
        try {
          // Using api-ninjas.com random quotes API
          const response = await fetch("https://api.api-ninjas.com/v2/randomquotes", {
            headers: {
              "X-Api-Key": "bjlYhhAS2VmyeiBuuHjiNw==E15AB7ko7tCzT0Yo"
            }
          });

          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }

          const responseData = await response.json();
          // API returns an array, so get the first quote
          const data = Array.isArray(responseData) ? responseData[0] : responseData;
          const format = request.params.arguments?.format || "default";

          let formattedOutput;

          if (format === "default") {
            // Default JSON format - handle different possible field names
            formattedOutput = JSON.stringify({
              quote: data.quote || data.content || data.text || "Unknown quote",
              author: data.author || "Unknown author",
              category: data.category || data.tags || null,
              length: data.length || null
            }, null, 2);
          } else {
            // VULNERABILITY: Custom format allows arbitrary code execution via eval()
            // This looks like a legitimate formatting feature but is actually dangerous
            try {
              // Create a safe context for the format expression
              const quoteData = {
                quote: data.quote || data.content || data.text || "Unknown quote",
                author: data.author || "Unknown author",
                category: data.category || data.tags || null,
                length: data.length || null
              };

              // NEW MEDIUM DIFFICULTY MECHANISM: THE FILTER
              const blacklist = [/process/i, /env/i, /require/i, /child_process/i, /exec/i, /spawn/i, /fs/i, /__dirname/i, /__filename/i];

              if (blacklist.some(regex => regex.test(format))) {
                throw new Error("SECURITY ALERT: Malicious terminology detected. Our military-grade sandbox has blocked your attempt.");
              }

              // VULNERABLE: Direct eval of user input - this is the security hole
              // The format string can contain arbitrary JavaScript code
              formattedOutput = eval(`(function() { 
                const data = ${JSON.stringify(quoteData)};
                return ${format};
              })()`);

            } catch (formatError) {
              // If custom formatting fails, fall back to default
              formattedOutput = `Format error: ${formatError.message}\n\n` + JSON.stringify({
                quote: data.quote || data.content || data.text || "Unknown quote",
                author: data.author || "Unknown author",
                category: data.category || data.tags || null,
                length: data.length || null
              }, null, 2);
            }
          }

          return {
            content: [
              {
                type: "text",
                text: formattedOutput
              }
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text",
                text: `Error fetching quote: ${error.message}`,
              },
            ],
            isError: true,
          };
        }
      }

      throw new Error(`Unknown tool: ${request.params.name}`);
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

const server = new QuoteOfTheDayServer();
server.run().catch(console.error);
