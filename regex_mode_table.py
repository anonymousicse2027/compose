REGEX_MODE = {
    # --- ERE ---
    "gawk":   "ere",
    "nano":   "ere",
    "find":   "ere",
    "grep":   "ere",
    "sed":    "ere",
    "ptx":    "ere",
    # --- BRE ---
    "diff":   "bre",
    "expr":   "bre",
    "csplit": "bre",
    "tac":    "bre",
    "nl":     "bre",
    "m4":     "bre",
}


def get_regex_mode(pgm, default="ere"):
    return REGEX_MODE.get(pgm, default)
