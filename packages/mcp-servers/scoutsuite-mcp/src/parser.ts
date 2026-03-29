const fs = require('fs');
const vm = require('vm');

interface Findings {
    [key: string]: any;
}

interface ServiceData {
    filters?: object;
    findings?: Findings;
    [key: string]: any;
}

interface ScoutSuiteResults {
    services: {
        [serviceName: string]: ServiceData;
    };
}

type FullReportResult = Record<string, Findings>;
type SummaryReportResult = Record<string, string[]>;

function getFindingsFromScoutSuite(
    filePath: string,
    full_report: true
): FullReportResult;
function getFindingsFromScoutSuite(
    filePath: string,
    full_report: false
): SummaryReportResult;
function getFindingsFromScoutSuite(
    filePath: string,
    full_report: boolean
): FullReportResult | SummaryReportResult {
    const fileContent = fs.readFileSync(filePath, 'utf-8');

    const context: Record<string, any> = {};
    vm.createContext(context);
    vm.runInContext(fileContent, context);

    const results: ScoutSuiteResults = context.scoutsuite_results;
    const services = results.services;

    const servicesWithFindings: FullReportResult | SummaryReportResult = {};

    for (const [serviceName, serviceData] of Object.entries(services)) {
        if (
            serviceData.findings &&
            Object.keys(serviceData.findings).length > 0
        ) {
            servicesWithFindings[serviceName] = full_report
                ? serviceData.findings
                : Object.keys(serviceData.findings);
        }
    }

    return servicesWithFindings;
}

function extractReportJsPath(output: string): string | null {
    const regex = /Saving data to (scoutsuite-report\/scoutsuite-results\/scoutsuite_results_[\w\-]+\.js)/;
    const match = output.match(regex);
    return match ? match[1] : null;
}


module.exports = { getFindingsFromScoutSuite,extractReportJsPath };