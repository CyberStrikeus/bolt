interface CrtShResponse {
    issuer_ca_id: number;
    issuer_name: string;
    common_name: string;
    name_value: string;
    id: number;
    entry_timestamp: string;
    not_before: string;
    not_after: string;
    serial_number: string;
    result_count: number;
}


export async function GetCrtSh(target: string): Promise<string[]> {
    const subdomains = await sendReqCrtSh(target);
    var results  = ClearResult(subdomains,target)
    return results;
}

async function sendReqCrtSh(query: string): Promise<string[]> {
    try {
        const response = await fetch(`https://crt.sh/?q=${query}&output=json`);

        if (!response.ok) {
            return [];
        }

        const crtshResponse: CrtShResponse[] = await response.json();
        const domains: string[] = [];

        for (const crtshResp of crtshResponse) {
            // NameValue'yi parse et ve domains array'ine ekle
            const nameValues = parseNameValue(crtshResp.name_value);
            domains.push(...nameValues);
        }

        return domains;
    } catch (error) {
        console.error("Error fetching from crt.sh:", error);
        return [];
    }
}

function parseNameValue(nameValue: string): string[] {
    // \n karakterine göre böl
    const values = nameValue.split("\n");

    // Boş değerleri filtrele
    const result = values.filter(v => v !== "");

    return result;
}

function ClearResult(result: string[], name: string): string[] {
   
    const escapedName = name.replace(/\./g, "\\.");

    
    const re = new RegExp(`[^.]+\\.${escapedName}\\b`);

    const unique: { [key: string]: boolean } = {};
    const uniqueList: string[] = [];

    
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