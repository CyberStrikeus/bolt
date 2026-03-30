"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const vm = require('vm');
function getFindingsFromScoutSuite(filePath, full_report) {
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    const context = {};
    vm.createContext(context);
    vm.runInContext(fileContent, context);
    const results = context.scoutsuite_results;
    const services = results.services;
    const servicesWithFindings = {};
    for (const [serviceName, serviceData] of Object.entries(services)) {
        if (serviceData.findings &&
            Object.keys(serviceData.findings).length > 0) {
            servicesWithFindings[serviceName] = full_report
                ? serviceData.findings
                : Object.keys(serviceData.findings);
        }
    }
    return servicesWithFindings;
}
function extractReportJsPath(output) {
    const regex = /Saving data to (scoutsuite-report\/scoutsuite-results\/scoutsuite_results_[\w\-]+\.js)/;
    const match = output.match(regex);
    return match ? match[1] : null;
}
module.exports = { getFindingsFromScoutSuite, extractReportJsPath };
