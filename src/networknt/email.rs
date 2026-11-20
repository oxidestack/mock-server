//! commons-validator's `EmailValidator`, `DomainValidator` and `InetAddressValidator` as networknt vendors them,
//! configured as `EmailFormat` does (`IPv6AwareEmailValidator(allowLocal = true, allowTld = true)`).

use super::format::cached;

const USER: &str = r#"^(((\\.)|[^\s\p{Cntrl}\(\)<>@,;:'\\\"\.\[\]]|')+|("(\\"|[^"])*"))(\.(((\\.)|[^\s\p{Cntrl}\(\)<>@,;:'\\\"\.\[\]]|')+|("(\\"|[^"])*")))*$"#;
const DOMAIN_NAME: &str = r"^(?:\p{Alnum}(?>[\p{Alnum}-]{0,61}\p{Alnum})?\.)+(\p{Alpha}(?>[\p{Alnum}-]{0,61}\p{Alnum})?)\.?$";
const HOSTNAME: &str = r"\p{Alnum}(?>[\p{Alnum}-]{0,61}\p{Alnum})?";

/// `EmailValidator.isValid`.
pub fn is_valid(email: &str) -> bool {
    if email.ends_with('.') {
        return false;
    }
    let Some(caps) = groups(r"^(.+)@(\S+)$", email) else { return false };
    let (user, domain) = (caps[0].clone().unwrap_or_default(), caps[1].clone().unwrap_or_default());
    is_valid_user(&user) && is_valid_domain(&domain)
}

/// The capture groups of a full match of a Java pattern.
fn groups(java: &str, value: &str) -> Option<Vec<Option<String>>> {
    let re = cached(&format!("^(?:{java})\\z"))?;
    let caps = re.captures(value).ok()??;
    Some((1..caps.len()).map(|i| caps.get(i).map(|m| m.as_str().to_string())).collect())
}

fn is_valid_user(user: &str) -> bool {
    user.chars().count() <= 64 && super::format::full_match(USER, user)
}

/// `IPv6AwareEmailValidator.isValidDomain` then `EmailValidator.isValidDomain`.
fn is_valid_domain(domain: &str) -> bool {
    let domain = if domain.starts_with("[IPv6:") { domain.replacen("IPv6:", "", 1) } else { domain.to_string() };
    if let Some(caps) = groups(r"^\[(.*)\]$", &domain) {
        return inet_address(&caps[0].clone().unwrap_or_default());
    }
    domain_valid(&domain) || (!domain.starts_with('.') && valid_tld(&domain))
}

/// `DomainValidator.isValid` (allowing local names).
fn domain_valid(domain: &str) -> bool {
    let domain = unicode_to_ascii(domain);
    if domain.chars().count() > 253 {
        return false;
    }
    match groups(DOMAIN_NAME, &domain) {
        Some(caps) if !caps.is_empty() => valid_tld(&caps[0].clone().unwrap_or_default()),
        _ => super::format::full_match(HOSTNAME, &domain),
    }
}

/// `DomainValidator.isValidTld` (allowing local TLDs).
fn valid_tld(tld: &str) -> bool {
    let key = unicode_to_ascii(tld).to_lowercase();
    let key = key.strip_prefix('.').unwrap_or(&key);
    LOCAL_TLDS.contains(&key) || key == "arpa" || GENERIC_TLDS.binary_search(&key).is_ok() || COUNTRY_CODE_TLDS.binary_search(&key).is_ok()
}

/// `DomainValidator.unicodeToASCII`: `IDN.toASCII`, keeping a trailing dot; the input itself when that fails.
fn unicode_to_ascii(input: &str) -> String {
    if input.is_ascii() {
        return input.to_string();
    }
    match super::idn::to_ascii(input, false) {
        Some(ascii) => ascii,
        None => input.to_string(),
    }
}

/// `InetAddressValidator.isValid`.
fn inet_address(address: &str) -> bool {
    inet4(address) || inet6(address)
}

fn inet4(address: &str) -> bool {
    let Some(caps) = groups(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", address) else { return false };
    caps.iter().all(|segment| {
        let s = segment.as_deref().unwrap_or_default();
        !s.is_empty() && s.parse::<u32>().is_ok_and(|n| n <= 255) && !(s.len() > 1 && s.starts_with('0'))
    })
}

fn inet6(address: &str) -> bool {
    let parts: Vec<&str> = address.split('/').collect();
    if parts.len() > 2 {
        return false;
    }
    if parts.len() == 2 {
        if !super::format::full_match(r"\d{1,3}", parts[1]) {
            return false;
        }
        if parts[1].parse::<u32>().map_or(true, |bits| bits > 128) {
            return false;
        }
    }
    let scoped: Vec<&str> = parts[0].split('%').collect();
    if scoped.len() > 2 || (scoped.len() == 2 && !super::format::full_match(r"[^\s/%]+", scoped[1])) {
        return false;
    }
    let address = scoped[0];
    let compressed = address.contains("::");
    if compressed && address.find("::") != address.rfind("::") {
        return false;
    }
    if (address.starts_with(':') && !address.starts_with("::")) || (address.ends_with(':') && !address.ends_with("::")) {
        return false;
    }
    // `String.split(":")` drops trailing empty strings.
    let mut octets: Vec<&str> = address.split(':').collect();
    while octets.last() == Some(&"") {
        octets.pop();
    }
    if compressed {
        if address.ends_with("::") {
            octets.push("");
        } else if address.starts_with("::") && !octets.is_empty() {
            octets.remove(0);
        }
    }
    if octets.len() > 8 {
        return false;
    }
    let (mut valid, mut empty) = (0, 0);
    for (index, octet) in octets.iter().enumerate() {
        if octet.is_empty() {
            empty += 1;
            if empty > 1 {
                return false;
            }
        } else {
            empty = 0;
            if index == octets.len() - 1 && octet.contains('.') {
                if !inet4(octet) {
                    return false;
                }
                valid += 2;
                continue;
            }
            // `Integer.parseInt(octet, 16)` takes a sign, as `from_str_radix` does.
            if octet.len() > 4 || i64::from_str_radix(octet, 16).map_or(true, |v| !(0..=65535).contains(&v)) {
                return false;
            }
        }
        valid += 1;
    }
    valid <= 8 && (valid >= 8 || compressed)
}

const LOCAL_TLDS: &[&str] = &["localdomain", "localhost"];

const GENERIC_TLDS: &[&str] = &["aaa", "aarp", "abarth", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi", "academy", "accenture", "accountant", "accountants", "aco", "actor", "ads", "adult", "aeg", "aero", "aetna", "afl", "africa", "agakhan", "agency", "aig", "airbus", "airforce", "airtel", "akdn", "alfaromeo", "alibaba", "alipay", "allfinanz", "allstate", "ally", "alsace", "alstom", "amazon", "americanexpress", "americanfamily", "amex", "amfam", "amica", "amsterdam", "analytics", "android", "anquan", "anz", "aol", "apartments", "app", "apple", "aquarelle", "arab", "aramco", "archi", "army", "art", "arte", "asda", "asia", "associates", "athleta", "attorney", "auction", "audi", "audible", "audio", "auspost", "author", "auto", "autos", "avianca", "aws", "axa", "azure", "baby", "baidu", "banamex", "bananarepublic", "band", "bank", "bar", "barcelona", "barclaycard", "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bbc", "bbt", "bbva", "bcg", "bcn", "beats", "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bharti", "bible", "bid", "bike", "bing", "bingo", "bio", "biz", "black", "blackfriday", "blockbuster", "blog", "bloomberg", "blue", "bms", "bmw", "bnpparibas", "boats", "boehringer", "bofa", "bom", "bond", "boo", "book", "booking", "bosch", "bostik", "boston", "bot", "boutique", "box", "bradesco", "bridgestone", "broadway", "broker", "brother", "brussels", "build", "builders", "business", "buy", "buzz", "bzh", "cab", "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "canon", "capetown", "capital", "capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "cash", "casino", "cat", "catering", "catholic", "cba", "cbn", "cbre", "cbs", "center", "ceo", "cern", "cfa", "cfd", "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai", "christmas", "chrome", "church", "cipriani", "circle", "cisco", "citadel", "citi", "citic", "city", "cityeats", "claims", "cleaning", "click", "clinic", "clinique", "clothing", "cloud", "club", "clubmed", "coach", "codes", "coffee", "college", "cologne", "com", "comcast", "commbank", "community", "company", "compare", "computer", "comsec", "condos", "construction", "consulting", "contact", "contractors", "cooking", "cookingchannel", "cool", "coop", "corsica", "country", "coupon", "coupons", "courses", "cpa", "credit", "creditcard", "creditunion", "cricket", "crown", "crs", "cruise", "cruises", "cuisinella", "cymru", "cyou", "dabur", "dad", "dance", "data", "date", "dating", "datsun", "day", "dclk", "dds", "deal", "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds", "diet", "digital", "direct", "directory", "discount", "discover", "dish", "diy", "dnp", "docs", "doctor", "dog", "domains", "dot", "download", "drive", "dtv", "dubai", "dunlop", "dupont", "durban", "dvag", "dvr", "earth", "eat", "eco", "edeka", "edu", "education", "email", "emerck", "energy", "engineer", "engineering", "enterprises", "epson", "equipment", "ericsson", "erni", "esq", "estate", "etisalat", "eurovision", "eus", "events", "exchange", "expert", "exposed", "express", "extraspace", "fage", "fail", "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers", "fashion", "fast", "fedex", "feedback", "ferrari", "ferrero", "fiat", "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone", "firmdale", "fish", "fishing", "fit", "fitness", "flickr", "flights", "flir", "florist", "flowers", "fly", "foo", "food", "foodnetwork", "football", "ford", "forex", "forsale", "forum", "foundation", "fox", "free", "fresenius", "frl", "frogans", "frontdoor", "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi", "gal", "gallery", "gallo", "gallup", "game", "games", "gap", "garden", "gay", "gbiz", "gdn", "gea", "gent", "genting", "george", "ggee", "gift", "gifts", "gives", "giving", "glass", "gle", "global", "globo", "gmail", "gmbh", "gmo", "gmx", "godaddy", "gold", "goldpoint", "golf", "goo", "goodyear", "goog", "google", "gop", "got", "gov", "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "guardian", "gucci", "guge", "guide", "guitars", "guru", "hair", "hamburg", "hangout", "haus", "hbo", "hdfc", "hdfcbank", "health", "healthcare", "help", "helsinki", "here", "hermes", "hgtv", "hiphop", "hisamitsu", "hitachi", "hiv", "hkt", "hockey", "holdings", "holiday", "homedepot", "homegoods", "homes", "homesense", "honda", "horse", "hospital", "host", "hosting", "hot", "hoteles", "hotels", "hotmail", "house", "how", "hsbc", "hughes", "hyatt", "hyundai", "ibm", "icbc", "ice", "icu", "ieee", "ifm", "ikano", "imamat", "imdb", "immo", "immobilien", "inc", "industries", "infiniti", "info", "ing", "ink", "institute", "insurance", "insure", "int", "international", "intuit", "investments", "ipiranga", "irish", "ismaili", "ist", "istanbul", "itau", "itv", "jaguar", "java", "jcb", "jeep", "jetzt", "jewelry", "jio", "jll", "jmp", "jnj", "jobs", "joburg", "jot", "joy", "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi", "kerryhotels", "kerrylogistics", "kerryproperties", "kfh", "kia", "kids", "kim", "kinder", "kindle", "kitchen", "kiwi", "koeln", "komatsu", "kosher", "kpmg", "kpn", "krd", "kred", "kuokgroup", "kyoto", "lacaixa", "lamborghini", "lamer", "lancaster", "lancia", "land", "landrover", "lanxess", "lasalle", "lat", "latino", "latrobe", "law", "lawyer", "lds", "lease", "leclerc", "lefrak", "legal", "lego", "lexus", "lgbt", "lidl", "life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited", "limo", "lincoln", "linde", "link", "lipsy", "live", "living", "llc", "llp", "loan", "loans", "locker", "locus", "lol", "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "ltd", "ltda", "lundbeck", "luxe", "luxury", "macys", "madrid", "maif", "maison", "makeup", "man", "management", "mango", "map", "market", "marketing", "markets", "marriott", "marshalls", "maserati", "mattel", "mba", "mckinsey", "med", "media", "meet", "melbourne", "meme", "memorial", "men", "menu", "merckmsd", "miami", "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mlb", "mls", "mma", "mobi", "mobile", "moda", "moe", "moi", "mom", "monash", "money", "monster", "mormon", "mortgage", "moscow", "moto", "motorcycles", "mov", "movie", "msd", "mtn", "mtr", "museum", "music", "mutual", "nab", "nagoya", "name", "natura", "navy", "nba", "nec", "net", "netbank", "netflix", "network", "neustar", "new", "news", "next", "nextdirect", "nexus", "nfl", "ngo", "nhk", "nico", "nike", "nikon", "ninja", "nissan", "nissay", "nokia", "northwesternmutual", "norton", "now", "nowruz", "nowtv", "nra", "nrw", "ntt", "nyc", "obi", "observer", "office", "okinawa", "olayan", "olayangroup", "oldnavy", "ollo", "omega", "one", "ong", "onl", "online", "ooo", "open", "oracle", "orange", "org", "organic", "origins", "osaka", "otsuka", "ott", "ovh", "page", "panasonic", "paris", "pars", "partners", "parts", "party", "passagens", "pay", "pccw", "pet", "pfizer", "pharmacy", "phd", "philips", "phone", "photo", "photography", "photos", "physio", "pics", "pictet", "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "place", "play", "playstation", "plumbing", "plus", "pnc", "pohl", "poker", "politie", "porn", "post", "pramerica", "praxi", "press", "prime", "pro", "prod", "productions", "prof", "progressive", "promo", "properties", "property", "protection", "pru", "prudential", "pub", "pwc", "qpon", "quebec", "quest", "racing", "radio", "read", "realestate", "realtor", "realty", "recipes", "red", "redstone", "redumbrella", "rehab", "reise", "reisen", "reit", "reliance", "ren", "rent", "rentals", "repair", "report", "republican", "rest", "restaurant", "review", "reviews", "rexroth", "rich", "richardli", "ricoh", "ril", "rio", "rip", "rocher", "rocks", "rodeo", "rogers", "room", "rsvp", "rugby", "ruhr", "run", "rwe", "ryukyu", "saarland", "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung", "sandvik", "sandvikcoromant", "sanofi", "sap", "sarl", "sas", "save", "saxo", "sbi", "sbs", "sca", "scb", "schaeffler", "schmidt", "scholarships", "school", "schule", "schwarz", "science", "scot", "search", "seat", "secure", "security", "seek", "select", "sener", "services", "seven", "sew", "sex", "sexy", "sfr", "shangrila", "sharp", "shaw", "shell", "shia", "shiksha", "shoes", "shop", "shopping", "shouji", "show", "showtime", "silk", "sina", "singles", "site", "ski", "skin", "sky", "skype", "sling", "smart", "smile", "sncf", "soccer", "social", "softbank", "software", "sohu", "solar", "solutions", "song", "sony", "soy", "spa", "space", "sport", "spot", "srl", "stada", "staples", "star", "statebank", "statefarm", "stc", "stcgroup", "stockholm", "storage", "store", "stream", "studio", "study", "style", "sucks", "supplies", "supply", "support", "surf", "surgery", "suzuki", "swatch", "swiss", "sydney", "systems", "tab", "taipei", "talk", "taobao", "target", "tatamotors", "tatar", "tattoo", "tax", "taxi", "tci", "tdk", "team", "tech", "technology", "tel", "temasek", "tennis", "teva", "thd", "theater", "theatre", "tiaa", "tickets", "tienda", "tiffany", "tips", "tires", "tirol", "tjmaxx", "tjx", "tkmaxx", "tmall", "today", "tokyo", "tools", "top", "toray", "toshiba", "total", "tours", "town", "toyota", "toys", "trade", "trading", "training", "travel", "travelchannel", "travelers", "travelersinsurance", "trust", "trv", "tube", "tui", "tunes", "tushu", "tvs", "ubank", "ubs", "unicom", "university", "uno", "uol", "ups", "vacations", "vana", "vanguard", "vegas", "ventures", "verisign", "versicherung", "vet", "viajes", "video", "vig", "viking", "villas", "vin", "vip", "virgin", "visa", "vision", "viva", "vivo", "vlaanderen", "vodka", "volkswagen", "volvo", "vote", "voting", "voto", "voyage", "vuelos", "wales", "walmart", "walter", "wang", "wanggou", "watch", "watches", "weather", "weatherchannel", "webcam", "weber", "website", "wed", "wedding", "weibo", "weir", "whoswho", "wien", "wiki", "williamhill", "win", "windows", "wine", "winners", "wme", "wolterskluwer", "woodside", "work", "works", "world", "wow", "wtc", "wtf", "xbox", "xerox", "xfinity", "xihuan", "xin", "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a", "xn--30rr7y", "xn--3bst00m", "xn--3ds443g", "xn--3pxu8k", "xn--42c2d9a", "xn--45q11c", "xn--4gbrim", "xn--55qw42g", "xn--55qx5d", "xn--5su34j936bgsg", "xn--5tzm5g", "xn--6frz82g", "xn--6qq986b3xl", "xn--80adxhks", "xn--80aqecdr1a", "xn--80asehdb", "xn--80aswg", "xn--8y0a063a", "xn--90ae", "xn--9dbq2a", "xn--9et52u", "xn--9krt00a", "xn--9t4b11yi5a", "xn--b4w605ferd", "xn--bck1b9a5dre4c", "xn--c1avg", "xn--c2br7g", "xn--cck2b3b", "xn--cckwcxetd", "xn--cg4bki", "xn--czr694b", "xn--czrs0t", "xn--czru2d", "xn--d1acj3b", "xn--eckvdtc9d", "xn--efvy88h", "xn--fct429k", "xn--fhbei", "xn--fiq228c5hs", "xn--fiq64b", "xn--fjq720a", "xn--flw351e", "xn--fzys8d69uvgm", "xn--g2xx48c", "xn--gckr3f0f", "xn--gk3at1e", "xn--hxt814e", "xn--i1b6b1a6a2e", "xn--imr513n", "xn--io0a7i", "xn--j1aef", "xn--jlq480n2rg", "xn--jvr189m", "xn--kcrx77d1x4a", "xn--kput3i", "xn--mgba3a3ejt", "xn--mgba7c0bbn0a", "xn--mgbaakc7dvf", "xn--mgbab2bd", "xn--mgbca7dzdo", "xn--mgbi4ecexp", "xn--mgbt3dhd", "xn--mk1bu44c", "xn--mxtq1m", "xn--ngbc5azd", "xn--ngbe9e0a", "xn--ngbrx", "xn--nqv7f", "xn--nqv7fs00ema", "xn--nyqy26a", "xn--otu796d", "xn--p1acf", "xn--pssy2u", "xn--q9jyb4c", "xn--qcka1pmc", "xn--rhqv96g", "xn--rovu88b", "xn--ses554g", "xn--t60b56a", "xn--tckwe", "xn--tiq49xqyj", "xn--unup4y", "xn--vermgensberater-ctb", "xn--vermgensberatung-pwb", "xn--vhquv", "xn--vuq861b", "xn--w4r85el8fhu5dnra", "xn--w4rs40l", "xn--xhq521b", "xn--zfr164b", "xxx", "xyz", "yachts", "yahoo", "yamaxun", "yandex", "yodobashi", "yoga", "yokohama", "you", "youtube", "yun", "zappos", "zara", "zero", "zip", "zone", "zuerich"];

const COUNTRY_CODE_TLDS: &[&str] = &["ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "su", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xn--2scrj9c", "xn--3e0b707e", "xn--3hcrj9c", "xn--45br5cyl", "xn--45brj9c", "xn--4dbrk0ce", "xn--54b7fta0cc", "xn--80ao21a", "xn--90a3ac", "xn--90ais", "xn--clchc0ea0b2g2a9gcd", "xn--d1alf", "xn--e1a4c", "xn--fiqs8s", "xn--fiqz9s", "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--gecrj9c", "xn--h2breg3eve", "xn--h2brj9c", "xn--h2brj9c8c", "xn--j1amh", "xn--j6w193g", "xn--kprw13d", "xn--kpry57d", "xn--l1acc", "xn--lgbbat1ad8j", "xn--mgb9awbf", "xn--mgba3a4f16a", "xn--mgbaam7a8h", "xn--mgbah1a3hjkrd", "xn--mgbai9azgqp6j", "xn--mgbayh7gpa", "xn--mgbbh1a", "xn--mgbbh1a71e", "xn--mgbc0a9azcg", "xn--mgbcpq6gpa1a", "xn--mgberp4a5d4ar", "xn--mgbgu82a", "xn--mgbpl2fh", "xn--mgbtx2b", "xn--mgbx4cd0ab", "xn--mix891f", "xn--node", "xn--o3cw4h", "xn--ogbpf8fl", "xn--p1ai", "xn--pgbs0dh", "xn--q7ce6a", "xn--qxa6a", "xn--qxam", "xn--rvc1e0am3e", "xn--s9brj9c", "xn--wgbh1c", "xn--wgbl6a", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--y9a3aq", "xn--yfro4i67o", "xn--ygbi2ammx", "ye", "yt", "za", "zm", "zw"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_tables_are_sorted_for_binary_search() {
        assert!(GENERIC_TLDS.windows(2).all(|w| w[0] < w[1]));
        assert!(COUNTRY_CODE_TLDS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn mailboxes_as_commons_validator_reads_them() {
        for ok in ["a@b.com", "a@b", "a@localhost", "x@[IPv6:::1]", "x@[127.0.0.1]", "\"quoted\"@ex.com", "ü@ex.com", "a@ü.com", "a@ex.museum", "a@ex.co.uk"] {
            assert!(is_valid(ok), "{ok}");
        }
        for bad in ["a@example.invalidtld", "a..b@ex.com", "a@ex..com", "a b@ex.com", "a@ex.c", "a@-ex.com", ".a@ex.com", "a@example.lan", "x"] {
            assert!(!is_valid(bad), "{bad}");
        }
    }
}
