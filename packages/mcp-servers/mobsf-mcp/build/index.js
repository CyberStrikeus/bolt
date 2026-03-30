"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const mobsf_1 = require("./mobsf");
// Get command line arguments
const args = process.argv.slice(2);
if (args.length < 2) {
    console.error("Usage: mobfs <baseUrl> <apiKey>");
    process.exit(1);
}
const baseUrl = args[0];
const apiKey = args[1];
// Create MobSF client
const mobsfClient = (0, mobsf_1.createMobSFClient)(baseUrl, apiKey);
// Create server instance
const server = new mcp_js_1.McpServer({
    name: "mobsf",
    version: "1.0.0",
});
// Define the scanFile tool
server.tool("scanFile", "Scan a file that has already been uploaded to MobSF. This tool analyzes the uploaded mobile application for security vulnerabilities and provides a comprehensive security assessment report.", {
    hash: zod_1.z.string().describe("Hash of the file to scan"),
    reScan: zod_1.z.boolean().optional().describe("Set to true to force a rescan of the file")
}, async ({ hash, reScan }) => {
    // Handle process completion
    return new Promise((resolve, reject) => {
        mobsfClient.scanFile(hash, reScan).then(result => {
            resolve({
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2),
                    }]
            });
        }).catch(error => {
            reject(error);
        });
    });
});
server.tool("uploadFile", "Upload a mobile application file (APK, IPA, or APPX) to MobSF for security analysis. This is the first step before scanning and must be done prior to using other analysis functions.", {
    file: zod_1.z.string().describe("Upload file path"),
}, async ({ file }) => {
    // Handle process completion
    return new Promise((resolve, reject) => {
        mobsfClient.uploadFile(file).then(result => {
            resolve({
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2),
                    }]
            });
        }).catch(error => {
            reject(error);
        });
    });
});
server.tool("getScanLogs", "Retrieve detailed scan logs for a previously analyzed mobile application using its hash value. These logs contain information about the scanning process and any issues encountered.", {
    hash: zod_1.z.string().describe("Hash file to getting scan logs"),
}, async ({ hash }) => {
    // Handle process completion
    return new Promise((resolve, reject) => {
        mobsfClient.getScanLogs(hash).then(result => {
            resolve({
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2),
                    }]
            });
        }).catch(error => {
            reject(error);
        });
    });
});
server.tool("getJsonReport", "Generate and retrieve a comprehensive security analysis report in JSON format for a scanned mobile application. This report includes detailed findings about security vulnerabilities, permissions, API calls, and other security-relevant information.", {
    hash: zod_1.z.string().describe("Hash file to getting scan logs"),
}, async ({ hash }) => {
    // Handle process completion
    return new Promise((resolve, reject) => {
        mobsfClient.generateJsonReport(hash).then(result => {
            resolve({
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2),
                    }]
            });
        }).catch(error => {
            reject(error);
        });
    });
});
server.tool("getRecentScans", "Retrieve a list of recently performed security scans on the MobSF server, showing mobile applications that have been analyzed, their statuses, and basic scan information.", {
    page: zod_1.z.number().describe("Page number for result"),
    pageSize: zod_1.z.number().describe("Page size for result"),
}, async ({ page, pageSize }) => {
    // Handle process completion
    return new Promise((resolve, reject) => {
        mobsfClient.getRecentScans(page, pageSize).then(result => {
            resolve({
                content: [{
                        type: "text",
                        text: JSON.stringify(result, null, 2),
                    }]
            });
        }).catch(error => {
            reject(error);
        });
    });
});
// Start the server
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("mobsf MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
