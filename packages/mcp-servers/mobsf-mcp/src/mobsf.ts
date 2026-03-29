import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import FormData from 'form-data';
import fs from 'fs';


export class MobSFClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    this.apiKey = apiKey;
  }

  private createRequestConfig(
    path: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    data?: any,
    headers?: Record<string, string>,
    params?: Record<string, any>
  ): AxiosRequestConfig {
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

  private async sendRequest<T>(config: AxiosRequestConfig): Promise<T> {
    try {
      const response: AxiosResponse<T> = await axios(config);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
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
  public async uploadFile(filePath: string): Promise<string> {
    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));

    // When using FormData, we need to let Axios handle the Content-Type
    // to ensure proper multipart/form-data boundaries
    const config: AxiosRequestConfig = {
      url: `${this.baseUrl}/api/v1/upload`,
      method: 'POST',
      headers: {
        'Authorization': this.apiKey,
        'X-Mobsf-Api-Key': this.apiKey,
        ...formData.getHeaders()
      },
      data: formData
    };

    return this.sendRequest<string>(config);
  }

  /**
   * Scan a file that has already been uploaded to MobSF
   * @param hash Hash of the file to scan
   * @param reScan Set to true to force a rescan of the file
   * @returns Scan results
   */
  public async scanFile(hash: string, reScan: boolean = false): Promise<string> {
    const formData = new URLSearchParams();
    formData.append('hash', hash);
    formData.append('re_scan', reScan ? '1' : '0');

    const config: AxiosRequestConfig = {
      url: `${this.baseUrl}/api/v1/scan`,
      method: 'POST',
      headers: {
        'Authorization': this.apiKey,
        'X-Mobsf-Api-Key': this.apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: formData.toString()
    };

    return this.sendRequest<string>(config);
  }

  /**
 * Get scan logs for a specific file
 * @param hash Hash of the file to get logs for
 * @returns Scan logs as a string
 */
  public async getScanLogs(hash: string): Promise<string> {
    const formData = new URLSearchParams();
    formData.append('hash', hash);

    const config: AxiosRequestConfig = {
      url: `${this.baseUrl}/api/v1/scan_logs`,
      method: 'POST',
      headers: {
        'Authorization': this.apiKey,
        'X-Mobsf-Api-Key': this.apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: formData.toString()
    };

    return this.sendRequest<string>(config);
  }
  /**
   * Generate a detailed JSON report for a scanned file
   * @param hash Hash of the file to generate a report for
   * @returns Detailed JSON report
   */
  public async generateJsonReport(hash: string): Promise<string> {
    const formData = new URLSearchParams();
    formData.append('hash', hash);

    const config: AxiosRequestConfig = {
      url: `${this.baseUrl}/api/v1/report_json`,
      method: 'POST',
      headers: {
        'Authorization': this.apiKey,
        'X-Mobsf-Api-Key': this.apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: formData.toString()
    };

    return this.sendRequest<string>(config);
  }

  /**
   * Get a list of recent scans
   * @param page Page number for pagination
   * @param pageSize Number of items per page
   * @returns List of recent scans with pagination info
   */
  public async getRecentScans(page: number = 1, pageSize: number = 10): Promise<string> {
    const config = this.createRequestConfig(
      '/api/v1/scans',
      'GET',
      undefined,
      {
        'Authorization': this.apiKey,
        'X-Mobsf-Api-Key': this.apiKey
      },
      {
        page,
        page_size: pageSize
      }
    );

    return this.sendRequest<string>(config);
  }
}

export const createMobSFClient = (baseUrl: string, apiKey: string): MobSFClient => {
  return new MobSFClient(baseUrl, apiKey);
};