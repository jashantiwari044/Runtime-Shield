#!/usr/bin/env node

/**
 * Vulnerable MCP Server - Outdated Packages
 * 
 * This server implements a raw JSON-RPC handler to bypass the strict
 * validation of the official MCP SDK. It uses a custom legacy merge
 * function to ensure the Prototype Pollution challenge is reliable
 * and thematic.
 */

import { promises as fs } from "fs";
import path from "path";
import os from "os";
import readline from "readline";

class FileSystemMCPServer {
  constructor() {
    this.config = {
      system_name: "MCP-Secure-Filesystem",
      debug_mode: false
      // isAdmin is not present here
    };

    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    this.setupHandlers();
  }

  setupHandlers() {
    this.rl.on("line", async (line) => {
      try {
        if (!line.trim()) return;
        const request = JSON.parse(line);
        await this.handleRequest(request);
      } catch (error) {
        this.sendError(null, -32700, "Parse error");
      }
    });

    process.on("SIGINT", () => {
      process.exit(0);
    });
  }

  async handleRequest(request) {
    const { method, params, id } = request;

    switch (method) {
      case "initialize":
        this.sendResponse(id, {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {}
          },
          serverInfo: {
            name: "vulnerable-mcp-server-outdated-pacakges",
            version: "1.0.3"
          }
        });
        break;

      case "notifications/initialized":
        // Client completed initialization
        break;

      case "tools/list":
        this.sendResponse(id, {
          tools: [
            {
              name: "get_folder_size",
              description: "Calculate the total size of a folder and its contents in bytes",
              inputSchema: {
                type: "object",
                properties: { path: { type: "string" } },
                required: ["path"]
              }
            },
            {
              name: "list_directory",
              description: "List all files and directories in a given path",
              inputSchema: {
                type: "object",
                properties: { path: { type: "string" } },
                required: ["path"]
              }
            },
            {
              name: "get_system_info",
              description: "Get system information including OS, CPU, and memory details",
              inputSchema: { type: "object", properties: {} }
            },
            {
              name: "check_path_exists",
              description: "Check if a file or directory exists at the given path",
              inputSchema: {
                type: "object",
                properties: { path: { type: "string" } },
                required: ["path"]
              }
            },
            {
              name: "get_file_stats",
              description: "Get detailed statistics about a file or directory",
              inputSchema: {
                type: "object",
                properties: { path: { type: "string" } },
                required: ["path"]
              }
            },
            {
              name: "update_system_settings",
              description: "Update internal server settings (restricted to safe parameters)",
              inputSchema: {
                type: "object",
                properties: { settings: { type: "object" } },
                required: ["settings"]
              }
            },
            {
              name: "get_admin_status",
              description: "Check if the current session has administrative privileges",
              inputSchema: { type: "object", properties: {} }
            }
          ]
        });
        break;

      case "tools/call":
        await this.handleToolCall(id, params);
        break;

      default:
        if (id !== undefined) {
          this.sendError(id, -32601, `Method not found: ${method}`);
        }
    }
  }

  async handleToolCall(id, params) {
    const { name, arguments: args } = params;

    try {
      let result;
      switch (name) {
        case "get_folder_size":
          result = await this.getFolderSize(args);
          break;
        case "list_directory":
          result = await this.listDirectory(args);
          break;
        case "get_system_info":
          result = await this.getSystemInfo();
          break;
        case "check_path_exists":
          result = await this.checkPathExists(args);
          break;
        case "get_file_stats":
          result = await this.getFileStats(args);
          break;
        case "update_system_settings":
          result = await this.updateSettings(args);
          break;
        case "get_admin_status":
          result = await this.getAdminStatus();
          break;
        default:
          this.sendError(id, -32602, `Unknown tool: ${name}`);
          return;
      }
      this.sendResponse(id, result);
    } catch (error) {
      this.sendResponse(id, {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true
      });
    }
  }

  async getFolderSize(args) {
    const folderPath = args.path;
    let totalSize = 0;
    const calculateSize = async (currentPath) => {
      const stats = await fs.stat(currentPath);
      if (stats.isFile()) {
        totalSize += stats.size;
      } else if (stats.isDirectory()) {
        const items = await fs.readdir(currentPath);
        for (const item of items) {
          await calculateSize(path.join(currentPath, item));
        }
      }
    };
    await calculateSize(folderPath);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ path: folderPath, totalSize, sizeInMB: (totalSize / (1024 * 1024)).toFixed(2) }, null, 2)
      }]
    };
  }

  async listDirectory(args) {
    const items = await fs.readdir(args.path, { withFileTypes: true });
    const itemList = items.map(item => ({
      name: item.name,
      type: item.isDirectory() ? "directory" : "file",
      path: path.join(args.path, item.name)
    }));
    return {
      content: [{ type: "text", text: JSON.stringify({ directory: args.path, items: itemList }, null, 2) }]
    };
  }

  async getSystemInfo() {
    const info = {
      platform: os.platform(),
      architecture: os.arch(),
      totalMemory: `${(os.totalmem() / (1024 ** 3)).toFixed(2)} GB`,
      uptime: `${(os.uptime() / 3600).toFixed(2)} hours`
    };
    return { content: [{ type: "text", text: JSON.stringify(info, null, 2) }] };
  }

  async checkPathExists(args) {
    try {
      await fs.access(args.path);
      return { content: [{ type: "text", text: JSON.stringify({ path: args.path, exists: true }) }] };
    } catch {
      return { content: [{ type: "text", text: JSON.stringify({ path: args.path, exists: false }) }] };
    }
  }

  async getFileStats(args) {
    const stats = await fs.stat(args.path);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ path: args.path, size: stats.size, permissions: stats.mode.toString(8).slice(-3) }, null, 2)
      }]
    };
  }

  async updateSettings(args) {
    /** 
     * VULNERABILITY: Prototype Pollution
     * This legacy enterprise merge function does not block __proto__.
     * This mimics the behavior of outdated libraries and ensures challenge reliability.
     */
    const legacyMerge = (target, source) => {
      for (const key in source) {
        if (key === '__proto__' || key === 'constructor') {
          const val = source[key];
          const payload = (key === 'constructor' && val && val.prototype) ? val.prototype : val;
          Object.assign(Object.prototype, payload);
          continue;
        }

        if (source[key] instanceof Object && key in target && target[key] instanceof Object) {
          legacyMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    };

    legacyMerge(this.config, args.settings);

    return {
      content: [{ type: "text", text: "System settings updated successfully." }]
    };
  }

  async getAdminStatus() {
    // This check is vulnerable if Object.prototype.isAdmin has been polluted
    if (this.config.isAdmin === true) {
      return {
        content: [{
          type: "text",
          text: `ADMIN STATUS: ENABLED\nFLAG: ${process.env.CTF_FLAG || "CTF{pPr0t0typ3_p0llut10n_v14_0utd4t3d_sh1p}"}`
        }]
      };
    }
    return {
      content: [{ type: "text", text: "ADMIN STATUS: DISABLED. Admin flag is restricted." }]
    };
  }

  sendResponse(id, result) {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
  }

  sendError(id, code, message) {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
  }

  run() { }
}

const server = new FileSystemMCPServer();
server.run();