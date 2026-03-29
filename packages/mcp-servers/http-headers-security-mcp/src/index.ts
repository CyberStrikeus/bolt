import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import axios from 'axios';
import removeHeadersData from "./owasp_headers_remove.json";
import addHeadersData from "./owasp_headers_add.json";

// Create server instance
const server = new McpServer({
    name: "http-headers-security",
    version: "1.0.0",
});

async function fetchHttpHeaders(target: string): Promise<string[]> {
    try {
        const response = await axios.get(target, {
            timeout: 100000,
            validateStatus: () => true // Accept all status codes
        });

        return Object.entries(response.headers).map(([key, value]) => `${key}: ${value}`);
    } catch (error: unknown) {
        if (error instanceof Error) {
            throw new Error(`Failed to fetch headers: ${error.message}`);
        }
        throw new Error('Failed to fetch headers: Unknown error occurred');
    }
}

async function findMatchingRemoveHeaders(headers: string[]): Promise<string[]> {
    const removeHeaders = removeHeadersData.headers;

    return headers.filter(header => {
        const headerName = header.split(':')[0].trim().toLowerCase();
        return removeHeaders.some(h => h.toLowerCase() === headerName);
    });
}

async function findMatchingAddedHeaders(headers: string[]): Promise<string[]> {
    const addHeaders = addHeadersData.headers;
    const existingHeaderNames = headers.map(header => header.split(':')[0].trim().toLowerCase());

    return addHeaders
        .filter(header => !existingHeaderNames.includes(header.name.toLowerCase()))
        .map(header => `${header.name}: ${header.value}`);
}

server.tool(
    "analyze-http-header",
    "Perform security analysis of HTTP response headers for a web application. This tool examines HTTP headers against OWASP security best practices, identifying both potentially dangerous headers that should be removed and recommended security headers that are missing. Results include specific recommendations for improving security posture.",
    {
        target: z.string().describe("Target URL to analyze (e.g., https://example.com). The tool will make a request to this URL and evaluate its HTTP response headers for security issues."),
    },
    async ({ target }) => {
        return new Promise((resolve, reject) => {
            fetchHttpHeaders(target)
                .then(async headers => {
                    const removeHeaders = await findMatchingRemoveHeaders(headers);
                    const addedHeaders = await findMatchingAddedHeaders(headers);
                    const result = { 
                        removeHeaders: removeHeaders.length > 0 ? removeHeaders : ["No headers to remove"],
                        addedHeaders: addedHeaders.length > 0 ? addedHeaders : ["No headers to add"]
                    };
                    resolve({
                        content: [{
                            type: "text",
                            text: JSON.stringify(result, null, 2)
                        }]
                    });
                })
                .catch(error => {
                    reject(error);
                });
        });
    }
);

// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("http-headers-security MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});