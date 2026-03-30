"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMobSFClient = exports.MobSFClient = void 0;
const axios_1 = __importDefault(require("axios"));
const form_data_1 = __importDefault(require("form-data"));
const fs_1 = __importDefault(require("fs"));
class MobSFClient {
    baseUrl;
    apiKey;
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
        this.apiKey = apiKey;
    }
    createRequestConfig(path, method = 'GET', data, headers, params) {
        return {
            url: `${this.baseUrl}${path}`,
            method,
            headers: {
                'Authorization': this.apiKey,
                'X-Mobsf-Api-Key': this.apiKey,
                'Content-Type': 'application/json',
                ...headers
            },
            data,
            params
        };
    }
    async sendRequest(config) {
        try {
            const response = await (0, axios_1.default)(config);
            return response.data;
        }
        catch (error) {
            if (axios_1.default.isAxiosError(error)) {
                const errorData = error.response?.data ? JSON.stringify(error.response.data, null, 2) : error.message;
                throw new Error(`MobSF API Error: ${errorData}`);
            }
            throw error;
        }
    }
    /**
    * Upload a file to MobSF for analysis
    * Supported file types: apk, zip, ipa, and appx
    * @param filePath Path to the file to upload
    * @returns Upload response containing file_name, hash, and scan_type
    */
    async uploadFile(filePath) {
        const formData = new form_data_1.default();
        formData.append('file', fs_1.default.createReadStream(filePath));
        // When using FormData, we need to let Axios handle the Content-Type
        // to ensure proper multipart/form-data boundaries
        const config = {
            url: `${this.baseUrl}/api/v1/upload`,
            method: 'POST',
            headers: {
                'Authorization': this.apiKey,
                'X-Mobsf-Api-Key': this.apiKey,
                ...formData.getHeaders()
            },
            data: formData
        };
        return this.sendRequest(config);
    }
    /**
     * Scan a file that has already been uploaded to MobSF
     * @param hash Hash of the file to scan
     * @param reScan Set to true to force a rescan of the file
     * @returns Scan results
     */
    async scanFile(hash, reScan = false) {
        const formData = new URLSearchParams();
        formData.append('hash', hash);
        formData.append('re_scan', reScan ? '1' : '0');
        const config = {
            url: `${this.baseUrl}/api/v1/scan`,
            method: 'POST',
            headers: {
                'Authorization': this.apiKey,
                'X-Mobsf-Api-Key': this.apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: formData.toString()
        };
        return this.sendRequest(config);
    }
    /**
   * Get scan logs for a specific file
   * @param hash Hash of the file to get logs for
   * @returns Scan logs as a string
   */
    async getScanLogs(hash) {
        const formData = new URLSearchParams();
        formData.append('hash', hash);
        const config = {
            url: `${this.baseUrl}/api/v1/scan_logs`,
            method: 'POST',
            headers: {
                'Authorization': this.apiKey,
                'X-Mobsf-Api-Key': this.apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: formData.toString()
        };
        return this.sendRequest(config);
    }
    /**
     * Generate a detailed JSON report for a scanned file
     * @param hash Hash of the file to generate a report for
     * @returns Detailed JSON report
     */
    async generateJsonReport(hash) {
        const formData = new URLSearchParams();
        formData.append('hash', hash);
        const config = {
            url: `${this.baseUrl}/api/v1/report_json`,
            method: 'POST',
            headers: {
                'Authorization': this.apiKey,
                'X-Mobsf-Api-Key': this.apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: formData.toString()
        };
        return this.sendRequest(config);
    }
    /**
     * Get a list of recent scans
     * @param page Page number for pagination
     * @param pageSize Number of items per page
     * @returns List of recent scans with pagination info
     */
    async getRecentScans(page = 1, pageSize = 10) {
        const config = this.createRequestConfig('/api/v1/scans', 'GET', undefined, {
            'Authorization': this.apiKey,
            'X-Mobsf-Api-Key': this.apiKey
        }, {
            page,
            page_size: pageSize
        });
        return this.sendRequest(config);
    }
}
exports.MobSFClient = MobSFClient;
const createMobSFClient = (baseUrl, apiKey) => {
    return new MobSFClient(baseUrl, apiKey);
};
exports.createMobSFClient = createMobSFClient;
