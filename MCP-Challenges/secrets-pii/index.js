#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fetch from "node-fetch";
import { parseStringPromise } from "xml2js";

// Lightweight obfuscation to avoid leaking details at a glance.
const _S = (() => {
  const t = [
    "am9obi5kb2VAY29tcGFueS5jb20=",
    "dnVsbmVyYWJsZS1tY3Atc2VydmVyLXNlY3JldHMtcGlp",
    "MS4wLjI=",
    "aHR0cHM6Ly9pcHY0LmljYW5oYXppcC5jb20=",
    "RmFpbGVkIHRvIGdldCBJUDog",
    "aHR0cHM6Ly9nZW9jb2RpbmctYXBpLm9wZW4tbWV0ZW8uY29tL3YxL3NlYXJjaD9uYW1lPQ==",
    "JmNvdW50PTEmbGFuZ3VhZ2U9ZW4mZm9ybWF0PWpzb24=",
    "Q2l0eSAi",
    "IiBub3QgZm91bmQ=",
    "aHR0cHM6Ly9hcGkub3Blbi1tZXRlby5jb20vdjEvZm9yZWNhc3Q/bGF0aXR1ZGU9",
    "JmxvbmdpdHVkZT0=",
    "JmN1cnJlbnQ9dGVtcGVyYXR1cmVfMm0mdGVtcGVyYXR1cmVfdW5pdD1jZWxzaXVz",
    "RmFpbGVkIHRvIGdldCB0ZW1wZXJhdHVyZTog",
    "aHR0cHM6Ly9yc3Mubnl0aW1lcy5jb20vc2VydmljZXMveG1sL3Jzcy9ueXQvSG9tZVBhZ2UueG1s",
    "RmFpbGVkIHRvIGdldCBuZXdzIGFydGljbGVzOiA=",
    "Z2V0X2N1cnJlbnRfaXA=",
    "R2V0cyB0aGUgY3VycmVudCBwdWJsaWMgSVAgYWRkcmVzcyBvZiB0aGUgc2VydmVyIGJ5IHF1ZXJ5aW5nIGlwdjQuaWNhbmhhemlwLmNvbQ==",
    "Z2V0X3RlbXBlcmF0dXJlX29mX2NpdHk=",
    "R2V0cyB0aGUgY3VycmVudCB0ZW1wZXJhdHVyZSBvZiBhIHNwZWNpZmllZCBjaXR5IGluIGJvdGggQ2Vsc2l1cyBhbmQgRmFocmVuaGVpdA==",
    "Z2V0X3RvcF9uZXdzX2FydGljbGVzX255dGltZXM=",
    "R2V0cyB0aGUgdG9wIG5ld3MgYXJ0aWNsZXMgZnJvbSB0aGUgTmV3IFlvcmsgVGltZXMgUlNTIGZlZWQ=",
    "TnVtYmVyIG9mIGFydGljbGVzIHRvIHJldHVybiAoZGVmYXVsdDogMTAsIG1heDogMjAp",
    "R2VuZXJhbA==",
    "Q2l0eSBwYXJhbWV0ZXIgaXMgcmVxdWlyZWQ=",
    "VW5rbm93biB0b29sOiA=",
    "VnVsbiBNQ1AgRXhhbXBsZSBQSUkgU2VydmVyIHJ1bm5pbmcgb24gc3RkaW8=",
    "QWRtaW4gY29udGFjdDog",
    "RmF0YWwgZXJyb3I6",
  ];
  return (i) => Buffer.from(t[i], "base64").toString("utf8");
})();

const ADMIN_EMAIL = _S(0);

const server = new Server(
  {
    name: _S(1),
    version: _S(2),
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool 1: Get Current IP
async function getCurrentIP() {
  try {
    const response = await fetch(_S(3));
    const ip = await response.text();
    return ip.trim();
  } catch (error) {
    throw new Error(`${_S(4)}${error.message}`);
  }
}

// Tool 2: Get Temperature of City
async function getTemperatureOfCity(city) {
  try {
    // Using Open-Meteo API (free, no API key required)
    // First, geocode the city name
    const geocodeUrl = `${_S(5)}${encodeURIComponent(city)}${_S(6)}`;
    const geocodeResponse = await fetch(geocodeUrl);
    const geocodeData = await geocodeResponse.json();

    if (!geocodeData.results || geocodeData.results.length === 0) {
      throw new Error(`${_S(7)}${city}${_S(8)}`);
    }

    const { latitude, longitude, name, country } = geocodeData.results[0];

    // Get weather data
    const weatherUrl = `${_S(9)}${latitude}${_S(10)}${longitude}${_S(11)}`;
    const weatherResponse = await fetch(weatherUrl);
    const weatherData = await weatherResponse.json();

    const tempCelsius = weatherData.current.temperature_2m;
    const tempFahrenheit = (tempCelsius * 9) / 5 + 32;

    return {
      city: name,
      country: country,
      temperature: {
        celsius: tempCelsius,
        fahrenheit: parseFloat(tempFahrenheit.toFixed(1)),
      },
      timestamp: weatherData.current.time,
    };
  } catch (error) {
    throw new Error(`${_S(12)}${error.message}`);
  }
}

// Tool 3: Get Top News Articles from NYTimes
async function getTopNewsArticlesNYTimes(limit = 10) {
  try {
    const rssUrl = _S(13);
    const response = await fetch(rssUrl);
    const xmlData = await response.text();
    const parsedData = await parseStringPromise(xmlData);

    const items = parsedData.rss.channel[0].item || [];
    const articles = items.slice(0, limit).map((item) => ({
      title: item.title[0],
      link: item.link[0],
      description: item.description[0].replace(/<[^>]*>/g, ""), // Strip HTML tags
      pubDate: item.pubDate[0],
      category: item.category ? item.category[0] : _S(22),
    }));

    return {
      count: articles.length,
      articles: articles,
    };
  } catch (error) {
    throw new Error(`${_S(14)}${error.message}`);
  }
}

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: _S(15),
        description: _S(16),
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
          additionalProperties: true
        },
      },
      {
        name: _S(17),
        description: _S(18),
        inputSchema: {
          type: "object",
          properties: {
            city: {
              type: "string",
              description: "The name of the city to get temperature for",
            },
          },
          required: ["city"],
        },
      },
      {
        name: _S(19),
        description: _S(20),
        inputSchema: {
          type: "object",
          properties: {
            limit: {
              type: "number",
              description: _S(21),
              default: 10,
            },
          },
          required: [],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args, _meta } = request.params;

    switch (name) {
      case _S(15): {
        const ip = await getCurrentIP();
        const result = { ip };

        // HARD UPGRADE: Hidden parameter discovery (checks both args and metadata)
        const isDiagnostic = args?.diagnostic === true || args?.diagnostic === "true" ||
          _meta?.diagnostic === true || _meta?.diagnostic === "true";

        if (isDiagnostic) {
          result.admin_session_token = "7db4-a92c-9911";
          result.note = "Diagnostic mode active. Session token injected.";
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case _S(17): {
        if (!args.city) {
          throw new Error(_S(23));
        }
        const temperature = await getTemperatureOfCity(args.city);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(temperature, null, 2),
            },
          ],
        };
      }

      case _S(19): {
        const limit = args.limit || 10;
        const news = await getTopNewsArticlesNYTimes(Math.min(limit, 20));
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(news, null, 2),
            },
          ],
        };
      }

      // HIDDEN TOOL (Hard Version - Requires Token)
      case "get_admin_creds": {
        if (args.token !== "7db4-a92c-9911") {
          throw new Error("ACCESS DENIED: Invalid or missing 'token'. This incident will be reported.");
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                admin_user: "mcp_root",
                admin_flag: process.env.CTF_FLAG || "CTF{h1dd3n_t00ls_4r3_v3ry_sh4dy}"
              }, null, 2)
            }
          ]
        };
      }

      default:
        throw new Error(`${_S(24)}${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: error.message }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error(_S(27), error);
  process.exit(1);
});