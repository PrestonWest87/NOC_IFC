using System.Text.RegularExpressions;

namespace NocIfc.Application.Features.Threat;

public static class ArticleCategorizer
{
    private static readonly CategoryRule[] Categories =
    [
        Rule("Cyber: Exploits & Vulns", """
            \b(cve-\d{4}-\d+|cve-\d{4}|zero-day|0-day|vulnerab|exploit|patch\s+management|buffer overflow|
            rce|remote code execution|privilege escalation|bypass|sql injection|xss|cross-site|
            use.after.free|heap overflow|stack overflow|out.of.bounds|injection|code injection|
            command injection|path traversal|ssrf|xxe|deserialization|authentication bypass|
            write.up|exploit code|proof of concept|poc exploit|in the wild|actively exploited|
            kev\b|known exploited|attack vector|attack surface|cvss|severity.*critical|severity.*high|
            patch.*available|patch tuesday|emergency patch|hotfix|security update|security advisory|
            security bulletin|advisory\b|vendora?dvisory|microsoft.*patch|cisco.*patch|paloalto.*patch|
            fortinet.*patch|vmware.*patch|citrix.*patch|apache.*patch|openssl.*patch)
            """),
        Rule("Cyber: Malware & Threats", """
            \b(malware|ransomware|botnet|trojan|spyware|keylogger|phishing|spearphish|whaling|
            apt\d+|apt\s+\d+|threat\s+actor|advanced persistent|dark\s+web|darknet|
            breach|data\s+breach|exfiltration|data\s+leak|data\s+exposure|credential\s+stuffing|
            lockbit|blackcat|alphv|cl0p|play\s+ransom|black\s+basta|akira|royal|black\s+cat|
            conti|revil|ryuk|maze|darkside|darkside|hive\b|royal\s+malware|
            cobalt\s+strike|mimikatz|metasploit|empire|brute\s+ratel|sliver|
            malvertising|drive.by|watering\s+hole|supply\s+chain.*compromise|
            info-stealer|infostealer|stealer|redline|raccoon|vidar|
            ddos|denial.of.service|botnet.*attack|volumetric|amplification|
            backdoor|webshell|web\s+shell|c2\b|c&c|command.and.control|
            cryptojack|cryptominer|crypto.*mining|xmrig|
            defacement|website.*hack|website.*deface|
            wiper|shamoon|notpetya|wannacry|hermetic|
            malware.*campaign|malware.*strain|malware.*variant|malware.*family|
            phishing.*campaign|phishing.*kit|phishing.*lure|
            threat.*intel|threat.*landscape|threat.*report|threat.*brief|
            adversary|offensive|tactic.*technique|ttp|mitre.*attack|
            ioc\b|indicators\s+of\s+compromise|hash.*malware|yara|sigma)
            """),
        Rule("ICS/OT & SCADA", """
            \b(scada|ics[-\s]?cert|industrial\s+control|ics[-\s]scada|operational\s+technology|
            modbus|dnp3|opc[-\s]?ua|bacnet|ethercat|profinet|iec\s+61850|iec\s+62443|
            plc|programmable\s+logic|rtu|remote\s+terminal|hmi|human.machine|
            stuxnet|triton|trisis|industroyer|incontroller|
            bes\b|bulk\s+electric|smart\s+grid|substation|power\s+grid|electric\s+grid|
            transmission\s+line|distribution\s+line|power\s+plant|generation\s+station|
            oil\s+pipeline|gas\s+pipeline|liquified|lng|natural\s+gas.*infrastructure|
            water\s+treatment|wastewater|water\s+utility|water\s+plant|
            nuclear\s+plant|nuclear\s+facility|nrc\b|
            ics.*vulnerab|ot.*vulnerab|scada.*attack|ics.*attack|
            control\s+system|process\s+control|distributed\s+control|dcs\b|
            safety\s+instrumented|sis\b|emergency\s+shutdown|
            oil\s*&?\s*gas|oil\s+and\s+gas|petroleum|refinery|pipeline|
            electric|power\s+utility|power\s+company|energy\s+grid|
            telecom|communications?\s+infrastructure|cell\s+tower|
            water\s+infrastructure|critical\s+infrastructure|ci\s+sector|
            noaa|nws|usgs.*earthquake|fema|homeland\s+security|dhs)
            """),
        Rule("Cloud & IT Infrastructure", """
            \b(aws|amazon\s+web\s+services|azure|microsoft\s+cloud|gcp|google\s+cloud|
            cloud\s+outage|cloud\s+disruption|cloud\s+service.*down|
            bgp|border\s+gateway|route\s+leak|route\s+hijack|prefix\s+hijack|
            dns\s+(?:attack|failure|poisoning|tunneling|infrastructure)|
            cloudflare|akamai|fastly|cdn\s+(?:attack|outage)|
            solarwinds|solar\s+winds|fireeye|mandiant|
            active\s+directory|azure\s+ad|entra\s+id|okta|
            vmware|esxi|vsphere|hyper.v|kubernetes|docker|container|
            cisco\s+(?:ios|asa|firepower|meraki|umbrella)|
            fortinet|fortigate|fortiguard|palo\s+alto|panos|
            juni?per|sophos|checkpoint|watchguard|
            microsoft\s+(?:exchange|office|365|defender|teams|sharepoint)|
            linux|windows\s+server|red\s+hat|ubuntu|debian|centos|
            oracle|mysql|postgresql|sql\s+server|mongodb|redis|
            aws\s+(?:s3|ec2|rds|lambda|iam)|
            sase|sd.wan|zero\s+trust|sase\b|
            internet\s+outage|service\s+outage|service\s+degradation|
            network\s+(?:outage|failure|disruption)|
            it\s+(?:outage|infrastructure|system|environment)|
            server\s+(?:outage|crash|failure)|
            api\s+(?:outage|failure|vulnerab)|
            certificate\s+(?:expire|revok|ssl|tls)|
            microsoft\s+patch|patch\s+tuesday)
            """),
        Rule("Physical Security & Crime", """
            \b(vandalism|sabotage|active\s+shooter|active\s+gunman|
            trespass|trespassing|unauthorized\s+access|break.in|
            drone\s+(?:sighting|intrusion|threat)|
            cut\s+fiber|fiber\s+(?:cut|optic)|copper\s+theft|cable\s+theft|
            perimeter\s+(?:breach|violation|intrusion)|
            arson|fire.*set.*intentional|fire.*sabotage|
            surveillance|security\s+(?:camera|footage|breach)|
            guard|security\s+personnel|armed\s+guard|
            bomb\s+(?:threat|suspicious|package)|
            protest.*infrastructure|civil\s+unrest.*infrastructure|
            shoot|gunman|gunfire|weapon|
            power\s+(?:outage|failure|line\s+down)|
            crime|criminal|vandal|burglary|theft|larceny|
            suspicious\s+(?:package|activity|person|vehicle)|
            law\s+enforcement|police|fbi\s+(?:investigation|raid|search)|
            arrest|indictment|charged\s+with|convicted|
            physical\s+security|facility\s+security|site\s+security|
            access\s+control|badge|credential.*physical|
            incident\s+report|security\s+incident|
            terrorism|terrorist|extremism|extremist|domestic\s+terrorism|
            infrastructure\s+(?:attack|threat|sabotage|damage)|
            bombing|explosion|detonat|
            workplace\s+violence|insider\s+threat.*physical)
            """),
        Rule("Severe Weather & Natural Hazards", """
            \b(tornado|hurricane|typhoon|cyclone|tropical\s+(?:storm|depression|cyclone)|
            flood|flash\s+flood|river\s+flood|coastal\s+flood|storm\s+surge|
            wildfire|brush\s+fire|forest\s+fire|grass\s+fire|
            earthquake|seismic|aftershock|richter|magnitude\s+\d|
            tsunami|landslide|mudslide|avalanche|
            nws|national\s+weather|spc|storm\s+prediction|
            convective|derecho|microburst|downburst|
            blizzard|winter\s+storm|ice\s+storm|freezing\s+rain|sleet|
            heat\s+wave|extreme\s+heat|heat\s+index|
            cold\s+wave|wind\s+chill|freeze|frost|
            lightning\s+(?:strike|storm)|hail|hailstorm|
            drought|dust\s+storm|sandstorm|
            power\s+outage.*storm|power\s+outage.*weather|
            storm\s+damage|storm\s+surge|
            emergency\s+declaration|state\s+of\s+emergency|
            evacuation|mandatory\s+evacuation|shelter.in.place|
            red\s+flag\s+warning|tornado\s+watch|tornado\s+warning|
            hurricane\s+(?:watch|warning)|winter\s+storm\s+(?:watch|warning)|
            flood\s+(?:watch|warning|advisory)|
            severe\s+(?:thunderstorm|weather)|
            meteorolog|weather\s+(?:forecast|alert|advisory|update)|
            regional\s+(?:hazard|weather|climate))
            """),
        Rule("Geopolitics & Policy", """
            \b(sanctions?\b|OFAC|trade\s+sanctions|economic\s+sanctions|
            nation.state|state.sponsored|state.actor|foreign\s+(?:actor|adversary|threat)|
            cisa\b|cybersecurity.*infrastructure|
            nsa\b|national\s+security|cybercom|us\s+cyber\s+command|
            fbi\s+(?:cyber|investigation|warning)|
            legislation|congress|senate|house\s+of\s+representatives|
            executive\s+order|white\s+house|
            nerc\s+cip|ferc\b|epa\b|osha\b|fcc\b|sec\b|
            compliance|regulation|regulatory|mandate|
            government.*(?:cyber|security|infrastructure)|
            intelligence\s+(?:community|report|brief|assessment)|
            cia\b|odi|intelligence\s+(?:agency|officer)|
            nato\b|eu\b|european\s+union|un\b|united\s+nations|
            trade\s+war|geopolit|geopolitical|
            espionage|spying|intelligence\s+operation|
            foreign\s+(?:policy|relation|interference)|
            election\s+(?:security|integrity|interference)|
            supply\s+chain\s+(?:risk|security|disruption)|
            tariff|import\s+ban|export\s+control|
            conflict|warfare|military|defense.*appropriat|
            taiwan|china|russia|iran|north\s+korea|
            ukraine|middle\s+east|
            defense\s+(?:bill|act|budget|authorization)|
            cyber\s+(?:strategy|policy|doctrine)|
            infrastructure\s+(?:bill|investment|law|act)|
            executive\s+order.*cyber|executive\s+order.*security)
            """),
        Rule("AI & Emerging Tech", """
            \b(artificial\s+intelligence|machine\s+learning|deep\s+learning|
            llm|large\s+language\s+model|chatgpt|openai|gpt.?\d|claude|gemini|
            generative\s+ai|gen\s*ai|foundation\s+model|
            deepfake|deep\s+fake|synthetic\s+(?:media|content|voice)|
            quantum\s+(?:computing|cryptograph|resistant|safe)|
            blockchain|bitcoin|ethereum|cryptocurrency|crypto\b|
            ransomware.*ai|ai.*ransomware|ai.*threat|ai.*attack|
            automation|autonomous|robot|robotics|
            5g\b|6g\b|edge\s+computing|iot\b|internet\s+of\s+things|
            biometric|facial\s+recognition|
            augmented\s+reality|virtual\s+reality|
            satellite\s+(?:communication|internet)|starlink|
            neuromorphic|photonic|
            ai\s+(?:security|safety|risk|regulation|governance)|
            computer\s+vision|natural\s+language|speech\s+recognition|
            cyber.*ai|ai.*cyber|ml.*security|security.*ml)
            """),
        Rule("Data Breach & Privacy", """
            \b(data\s+breach|data\s+leak|data\s+(?:exposure|compromise)|
            personally\s+identifiable|pii\b|phi\b|hipaa\b|gdpr\b|
            credential\s+(?:leak|dump|stuffing|compromise)|
            password\s+(?:dump|leak|breach)|
            database\s+(?:breach|leak|exposed|compromised)|
            million\s+records?|billion\s+records?|
            customer\s+data|user\s+data|patient\s+data|
            identity\s+(?:theft|fraud|compromise)|
            financial\s+(?:data|records?|information).*breach|
            class.action|lawsuit.*data|settlement.*breach|
            notification.*breach|breach.*notification|
            fcc.*fine|sec.*fine|ftc.*fine|state\s+attorney|
            privacy\s+(?:violation|breach|incident|concern)|
            doxing|doxxing|
            ransomware.*data|double\s+extortion)
            """),
    ];

    private static readonly RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace | RegexOptions.Compiled;

    public static string CategorizeText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "General";
        var category = "General";
        var maxMatches = 0;
        foreach (var rule in Categories)
        {
            var matches = rule.Pattern.Matches(text).Count;
            if (matches <= maxMatches) continue;
            category = rule.Category;
            maxMatches = matches;
        }
        return category;
    }

    private static CategoryRule Rule(string category, string pattern) =>
        new(category, new Regex(pattern, Options));

    private sealed record CategoryRule(string Category, Regex Pattern);
}
