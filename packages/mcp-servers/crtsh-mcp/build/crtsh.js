"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GetCrtSh = GetCrtSh;
async function GetCrtSh(target) {
    const subdomains = await sendReqCrtSh(target);
    var results = ClearResult(subdomains, target);
    return results;
}
async function sendReqCrtSh(query) {
    try {
        const response = await fetch(`https://crt.sh/?q=${query}&output=json`);
        if (!response.ok) {
            return [];
        }
        const crtshResponse = await response.json();
        const domains = [];
        for (const crtshResp of crtshResponse) {
            // NameValue'yi parse et ve domains array'ine ekle
            const nameValues = parseNameValue(crtshResp.name_value);
            domains.push(...nameValues);
        }
        return domains;
    }
    catch (error) {
        console.error("Error fetching from crt.sh:", error);
        return [];
    }
}
function parseNameValue(nameValue) {
    // \n karakterine göre böl
    const values = nameValue.split("\n");
    // Boş değerleri filtrele
    const result = values.filter(v => v !== "");
    return result;
}
function ClearResult(result, name) {
    const escapedName = name.replace(/\./g, "\\.");
    const re = new RegExp(`[^.]+\\.${escapedName}\\b`);
    const unique = {};
    const uniqueList = [];
    for (const val of result) {
        if (!unique[val]) {
            if (re.test(val)) {
                unique[val] = true;
                uniqueList.push(val);
            }
        }
    }
    return uniqueList;
}
