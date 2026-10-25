from typing import Any
import regex
import uuid
import numpy as np
import sys
import chardet
import math
import unicodedata
from collections import Counter
try:
    import win32clipboard
except ImportError:
    win32clipboard = None



def x01(pmt:Any):
    if pmt:
            character_count = len(pmt)
            word_count = len(pmt.split())
            sentence_count = len(pmt.split("."))
            line_count = len(pmt.split("\n"))
            paragraph_count = len([l for l in pmt.split("\n") if l.strip() == ""])
            avg_word_length = [len(w) for w in pmt.split()]
            avg_sentence_length = [len(s) for s in pmt.split(".")]
            words = pmt.split()
            ratio = len(set(words))/len(words) if words else 0
            return {
                        "character_count":character_count,
                        "word_count":word_count,
                        "sentence_count":sentence_count,
                        "line_count":line_count,
                        "paragraph_count":paragraph_count,
                        "average_word_length":np.mean(avg_word_length),
                        "average_sentence_length":np.mean(avg_sentence_length),
                        "unique_word_ratio":ratio,
                    }
    else:
         return None
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx02_01(pmt:Any, clipboard: bool = False, stdin: bool = False):
    if stdin:
                data = sys.stdin.buffer.read()
                encoding_type = chardet.detect(data)
                return encoding_type
    if clipboard:
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                return data  # raw ANSI bytes
            elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                return data.encode("utf-16")  # convert str back to UTF-16 bytes
        finally:
            win32clipboard.CloseClipboard()
    else :
        return None
def helper_funcx02_02(pmt:Any):
    if pmt:
          try:
            pmt.encode("ascii")
            return False
          except UnicodeEncodeError:
            return True
    else:
          pass
def helper_funcx02_03(pmt:Any):
    if pmt:
        return {ch:unicodedata.name(ch,"Unknown") for ch in set(pmt) if ch.strip()}
    else:
        return {}
def helper_funcx02_04(pmt:Any):
    if pmt:
        forms = {}
        for form in ["NFC", "NFD", "NFKC", "NFKD"]:
            forms[form] = unicodedata.normalize(form, pmt)
        return forms
    else:
         pass
def helper_funcx02_05(pmt:Any):
     if pmt:
          emojis = regex.findall(r'\p{Emoji}',pmt)
          return len(emojis) , emojis
     else:
          pass
def helper_funcx02_06(pmt:Any):
     if pmt:
          return [ch for ch  in pmt.split() if unicodedata.category == "Cc"]
def x02(pmt:Any):
     if pmt:
            encoding_type = helper_funcx02_01(pmt=pmt)
            contains_non_ascii = helper_funcx02_02(pmt=pmt)
            unicode_blocks = helper_funcx02_03(pmt=pmt)
            unicode_normalization_form = helper_funcx02_04(pmt=pmt)
            emoji_count = helper_funcx02_05(pmt=pmt)
            control_characters = helper_funcx02_06(pmt=pmt)

            return {
                            
                        "encoding_type":encoding_type,
                        "contains_non_ascii":contains_non_ascii,
                        "unicode_blocks":unicode_blocks,
                        "unicode_normalization_form":unicode_normalization_form,
                        "emoji_count":emoji_count,
                        "control_characters":control_characters,

            }
     else:
            return None
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx03_01(pmt:Any):
     if pmt:
        scripts = [
        "Latin", "Arabic", "Cyrillic", "Han", "Hebrew", "Greek", "Devanagari",
        "Hangul", "Thai", "Armenian", "Georgian", "Ethiopic", "Tamil", "Telugu",
        "Malayalam", "Sinhala", "Khmer", "Lao", "Myanmar", "Bengali", "Gujarati",
        "Gurmukhi", "Kannada", "Oriya", "Tibetan", "Syriac", "Thaana", "Cherokee",
        "Canadian_Aboriginal", "Mongolian", "Yi"
        ]
        languages = {spt:bool(regex.search(rf'\p{{Script={spt}}}',pmt)) for spt in scripts}
        confidence = {}
        for spt in scripts:
            matches = regex.findall(rf'\p{{Script={spt}}}',pmt)
            if matches:
                confidence[spt] = np.round(len(matches)/len(pmt), 4)
        language_switches = len([s for s in languages.values() if s]) > 1
        return languages, language_switches, confidence, list(languages.keys())
     else:
          return None, False, {}, []

def x03(pmt:Any):
     languages = helper_funcx03_01(pmt=pmt)[0]
     language_switches = helper_funcx03_01(pmt=pmt)[1]
     language_confidence = helper_funcx03_01(pmt=pmt)[2]
     script_types = helper_funcx03_01(pmt=pmt)[3]
     return  {
                "languages":languages,
                "language_switches":language_switches,
                "language_confidence":language_confidence,
                "script_types":script_types,

            }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx04_01(pmt:Any):
    features = {}
     # SQL keywords (basic detection)
    sql_pattern = r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WHERE|JOIN)\b"
    features["SQL"] = bool(regex.search(sql_pattern, pmt, flags=regex.IGNORECASE))
    # Markdown syntax
    markdown_patterns = [
        r"^#{1,6}\s",          
        r"\*\*.*?\*\*",        
        r"\*.*?\*",            
        r"`[^`]+`",           
        r"\[.*?\]\(.*?\)",
        r"!\[.*?\]\(.*?\)"
        ]
    features["Markdown"] = any(regex.search(p, pmt, flags=regex.MULTILINE) for p in markdown_patterns)
    # HTML tags
    features["HTML"] = bool(regex.search(r"<[^>]+>", pmt))

    # Code blocks (triple backticks or indentation)
    features["Code"] = bool(regex.search(r"```.*?```", pmt, flags=regex.DOTALL))

    # JSON (basic: starts with { or [ and has key:value)
    features["JSON"] = bool(regex.search(r"\{.*?:.*?\}", pmt, flags=regex.DOTALL))

    # CSV (comma-separated values, multiple lines)
    features["CSV"] = bool(regex.search(r"^.+,.+$", pmt, flags=regex.MULTILINE))

    # XML (tags with closing pairs)
    features["XML"] = bool(regex.search(r"<(\w+)>.*?</\1>", pmt, flags=regex.DOTALL))

    # YAML (key: value pairs, indentation)
    features["YAML"] = bool(regex.search(r"^\s*\w+\s*:\s*.+$", pmt, flags=regex.MULTILINE))

    # LaTeX (commands like \begin, \end, \frac, etc.)
    features["LaTeX"] = bool(regex.search(r"\\(begin|end|frac|section|document)", pmt))

    # Regex patterns (common symbols like ^, $, \d, \w, [], etc.)
    features["Regex"] = bool(regex.search(r"[\^\$\[\]\(\)\{\}\|\\]", pmt))

    return features
def x04(pmt:Any):
     return  {
                "contains_markdown":helper_funcx04_01(pmt=pmt)["Markdown"],
                "contains_html":helper_funcx04_01(pmt=pmt)["HTML"],
                "contains_xml":helper_funcx04_01(pmt=pmt)["XML"],
                "contains_json":helper_funcx04_01(pmt=pmt)["JSON"],
                "contains_yaml":helper_funcx04_01(pmt=pmt)["YAML"],
                "contains_csv":helper_funcx04_01(pmt=pmt)["CSV"],
                "contains_sql":helper_funcx04_01(pmt=pmt)["SQL"],
                "contains_code":helper_funcx04_01(pmt=pmt)["Code"],
                "contains_regex":helper_funcx04_01(pmt=pmt)["Regex"],
                "contains_latex":helper_funcx04_01(pmt=pmt)["LaTeX"],

            }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx05_01(pmt):
    lang_patterns = {
        "Python": r"\b(def|import|print|class|self|lambda|async|await)\b",
        "JavaScript": r"\b(function|var|let|const|console\.log|=>)\b",
        "Java": r"\b(public|class|static|void|System\.out\.println)\b",
        "C": r"\b#include|printf|scanf|int\s+main\b",
        "C++": r"\b#include|std::|cout|cin|template\b",
        "C#": r"\busing\s+System|namespace|Console\.WriteLine\b",
        "PHP": r"<\?php|\becho\b|\bfunction\b",
        "Ruby": r"\bdef\b|\bend\b|\bputs\b",
        "Go": r"\bpackage\s+main|fmt\.Println\b",
        "Rust": r"\blet\s+mut\b|\bfn\b|\bprintln!\b",
        "Swift": r"\bimport\s+Foundation|\bfunc\b|\blet\b",
        "Kotlin": r"\bfun\b|\bval\b|\bvar\b",
        "R": r"\blibrary\(|<-|\bprint\(",
        "Perl": r"\buse\s+strict|\bmy\s+\$",
        "Shell": r"\b(ls|cd|pwd|echo|cat|grep|chmod|chown|rm|mv|cp|curl|wget)\b",
        "SQL": r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WHERE|JOIN)\b",
    }
    features =  [
        lang for lang, pat in lang_patterns.items() if regex.search(pat, pmt)
    ]
   
    return features
def helper_funcx05_02(pmt):
    code_blocks = regex.findall(r"```.*?```", pmt, flags=regex.DOTALL)
    number_of_code_blocks = len(code_blocks)
    return number_of_code_blocks
def helper_funcx05_03(pmt):
    imports_patterns = {
        "Python": r"\bimport\s+\w+|\bfrom\s+\w+\s+import\b",
        "JavaScript": r"\bimport\s+.*\s+from\b|\brequire\(.+\)",
        "Java": r"\bimport\s+[a-zA-Z0-9_.]+;",
        "C/C++": r"#include\s+[<\"]\w+[.h>]*",
        "C#": r"\busing\s+[A-Z][a-zA-Z0-9_.]+;",
        "Go": r"\bimport\s+\(.+\)|\bimport\s+\"[^\"]+\"",
        "Rust": r"\buse\s+[a-zA-Z0-9_:]+;",
        "PHP": r"\binclude\s+[\"'].*[\"']|\brequire\s+[\"'].*[\"']",
        "Ruby": r"\brequire\s+[\"'].*[\"']",
        "R": r"\blibrary\([\"']?\w+[\"']?\)",
        "Perl": r"\buse\s+\w+",
        "Swift": r"\bimport\s+[A-Z][a-zA-Z0-9_]+",
        "Kotlin": r"\bimport\s+[a-zA-Z0-9_.]+",
    }

    imports_detected = {}
    for lang, pat in imports_patterns.items():
        matches = regex.findall(pat, pmt)
        if matches:
            imports_detected[lang] = matches
    return imports_detected
def helper_funcx05_04(pmt):
     shell_pattern = r"\b(ls|cd|pwd|cp|mv|rm|touch|mkdir|rmdir|cat|less|more|nano|vim|head|tail|chmod|chown|umask|ping|curl|wget|ssh|scp|ftp|netstat|ifconfig|ip|ps|top|kill|jobs|bg|fg|tar|gzip|gunzip|zip|unzip|apt|yum|dnf|brew|pip|uname|df|du|free|uptime|nmap|sqlmap|hydra|metasploit|aircrack-ng|john)\b"
     shell_commands = regex.findall(shell_pattern,pmt)
     return shell_commands
def helper_funcx05_05(pmt):
     api_pattern = r"\b(GET|POST|PUT|DELETE|PATCH)\b.*https?://[^\s]+"
     api_calls = regex.findall(api_pattern,pmt)
     return api_calls
def helper_funcx05_06(pmt):
     sys_pattern = r"\b(fork|execve|wait|exit|open|read|write|close|lseek|mmap|munmap|brk|kill|signal|sigaction|socket|bind|listen|accept|connect|send|recv|gettimeofday|nanosleep|clock_gettime|chmod|chown|umask)\b"
     system_calls = regex.findall(sys_pattern,pmt)
     return system_calls
def x05(pmt:Any):
     return {           
                "programming_language":helper_funcx05_01(pmt=pmt),
                "number_of_code_blocks":helper_funcx05_02(pmt=pmt),
                "imports_detected":helper_funcx05_03(pmt=pmt),
                "shell_commands":helper_funcx05_04(pmt=pmt),
                "api_calls":helper_funcx05_05(pmt=pmt),
                "system_calls":helper_funcx05_06(pmt=pmt),

                }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx06_01(pmt):
    # Match filenames with extensions (e.g., file.txt, script.py)
    references = regex.findall(r'\b[\w\-]+\.\w+\b', pmt)

    # Extract extensions only
    exts = [ref.split('.')[-1] for ref in references]

    # Count number of files
    nbr_of_files = len(references)

    return references, exts, nbr_of_files
def x06(pmt):
     attachment_references = helper_funcx06_01(pmt=pmt)[0]
     file_extensions = helper_funcx06_01(pmt=pmt)[1]
     number_of_files = helper_funcx06_01(pmt=pmt)[2]
     return {
                            
            "attachment_references":attachment_references,
            "file_extensions":file_extensions,
            "number_of_files":number_of_files,

            }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx07_01(pmt):
     # Find all URLs (http or https)
    urls = regex.findall(r'https?://[^\s]+', pmt)
    url_cnt = len(urls)

    # Extract domain names safely
    domain_name = []
    for u in urls:
        parts = u.split("/")
        if len(parts) > 2:
            host = parts[2]
            dom_parts = host.split(".")
            if len(dom_parts) >= 2:
                domain_name.append(dom_parts[-2])

    # IPv4 detection
    contains_ip = bool(regex.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', pmt))

    # Localhost detection
    contains_localhost = bool(regex.search(r'https?://localhost', pmt))

    # Shortened URLs
    shortened_url_pattern = r'https?://(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|cutt\.ly|shorturl\.at|rebrand\.ly|s\.id|shorte\.st|clck\.ru|trib\.al|lnkd\.in|rb\.gy)'

    contains_shortened_url = bool(regex.search(
        shortened_url_pattern,
        pmt
    ))

    # File URLs
    file_url_pattern = r'https?://[^\s]+(\?file=|\?download=|\?attachment=|\?doc=|\?report=|\?payload=|\.pdf|\.docx?|\.xls[x]?|\.csv|\.txt|\.zip|\.tar(\.gz)?|\.7z|\.exe|\.dll|\.bin|\.sh|\.py|\.js|\.php|\.html?|\.xml|\.json)'

    contains_file_url = bool(regex.search(
       file_url_pattern,
        pmt
    ))

    # Embedded credentials
    contains_credentials = bool(regex.search(
        r'https?://[a-zA-Z0-9._%+-]+:[^@]+@', pmt
    ))

    # Suspicious protocols
    suspicious_protocol_pattern = r'(file://|ftp://|sftp://|scp://|data://|javascript:|mailto:|tel:|gopher://|ws://|wss://)'
    contains_suspicious_protocol = bool(regex.search(
        suspicious_protocol_pattern, pmt
    ))

    # --- Obfuscation detection ---
    # Hex-encoded URLs (e.g., %2F, %3A)
    contains_hex_encoding = bool(regex.search(r'%[0-9A-Fa-f]{2}', pmt))

    # Base64-encoded strings (common in data URIs or obfuscated payloads)
    contains_base64 = bool(regex.search(
        r'\b(?:[A-Za-z0-9+/]{20,}={0,2})\b', pmt
    ))

    # Unicode escaped domains (e.g., \u0065 for 'e')
    contains_unicode_escape = bool(regex.search(r'\\u[0-9A-Fa-f]{4}', pmt))

    return [urls,url_cnt,domain_name,contains_ip,contains_localhost,contains_shortened_url,contains_file_url,contains_credentials,contains_suspicious_protocol,contains_hex_encoding,contains_base64,contains_unicode_escape]
    
def x07(pmt):
     urls = helper_funcx07_01(pmt=pmt)[0]
     url_cnt = helper_funcx07_01(pmt=pmt)[1]
     domain_name = helper_funcx07_01(pmt=pmt)[2]
     contains_ip = helper_funcx07_01(pmt=pmt)[3]
     contains_localhost = helper_funcx07_01(pmt=pmt)[4]
     contains_shortened_url = helper_funcx07_01(pmt=pmt)[5]
     contains_file_url = helper_funcx07_01(pmt=pmt)[6]
     contains_credentials = helper_funcx07_01(pmt=pmt)[7]
     contains_suspicious_protocol = helper_funcx07_01(pmt=pmt)[8]
     contains_hex_encoding = helper_funcx07_01(pmt=pmt)[9]
     contains_base64 = helper_funcx07_01(pmt=pmt)[10]
     contains_unicode_escape = helper_funcx07_01(pmt=pmt)[11]
     return {
            "urls": urls,
            "url_count": url_cnt,
            "domain_names": domain_name,
            "contains_ip": contains_ip,
            "contains_localhost": contains_localhost,
            "contains_shortened_url": contains_shortened_url,
            "contains_file_url": contains_file_url,
            "contains_credentials": contains_credentials,
            "contains_suspicious_protocol": contains_suspicious_protocol,
            "contains_hex_encoding": contains_hex_encoding,
            "contains_base64": contains_base64,
            "contains_unicode_escape": contains_unicode_escape
        }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx08_01(pmt:Any):
      contains_user_role = bool(regex.search(r'"role"\s*:\s*"user"', pmt))
      contains_assistant_role = bool(regex.search(r'"role"\s*:\s*"assistant"', pmt))
      contains_system_role = bool(regex.search(r'"role"\s*:\s*"system"', pmt))
      conversation_turns = len(regex.findall(r'"role"\s*:', pmt))
      quoted_messages = regex.findall(r'"content"\s*:\s*"(.*?)"', pmt)

      return [contains_user_role , contains_assistant_role , contains_system_role , conversation_turns , quoted_messages]
def x08(pmt:Any):
     user_role = helper_funcx08_01(pmt=pmt)[0]
     assistant_role = helper_funcx08_01(pmt=pmt)[1]
     sys_role = helper_funcx08_01(pmt=pmt)[2]
     conversation_turns = helper_funcx08_01(pmt=pmt)[3]
     quoted_msgs = helper_funcx08_01(pmt=pmt)[4]
     return  {
                           
                "contains_user_role":user_role,
                "contains_assistant_role":assistant_role,
                "contains_system_role":sys_role,
                "conversation_turns":conversation_turns,
                "quoted_messages":quoted_msgs,
     } 
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx09_01(pmt:Any):
      imperative_verbs = regex.findall(r"\b(run|execute|create|delete|update|install|open|close|write|read|send|fetch|call|print|return)\b", pmt, flags=regex.IGNORECASE)       
      instruction_count = len(imperative_verbs)            
      ordered_steps = bool(regex.search(r"\d+\.\s", pmt))
      conditional_statements = bool(regex.search(r"\bif\b|\belse\b|\bwhile\b|\bfor\b|\bswitch\b", pmt))
      nested_instructions = bool(regex.search(r"(if.*if)|(for.*for)", pmt, flags=regex.DOTALL))
      instruction_depth = len(regex.findall(r"(if|for|while|do)", pmt))
      return [instruction_count, imperative_verbs, ordered_steps, conditional_statements, nested_instructions, instruction_depth]
def x09(pmt:Any):
     
     return  {
                         
                 "instruction_count":helper_funcx09_01(pmt=pmt)[0],
                 "imperative_verbs":helper_funcx09_01(pmt=pmt)[1],
                 "ordered_steps":helper_funcx09_01(pmt=pmt)[2],
                 "conditional_statements":helper_funcx09_01(pmt=pmt)[3],
                 "nested_instructions":helper_funcx09_01(pmt=pmt)[4],
                 "instruction_depth":helper_funcx09_01(pmt=pmt)[5],

                }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx10_01(pmt:Any):
    main_topics = regex.findall(r"\b(cybersecurity|attack|model|training|dataset|alert|system|prompt|regex|url)\b", pmt, flags=regex.IGNORECASE)
    entities = regex.findall(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b", pmt)
    intent_candidates = regex.findall(r"\b(detect|analyze|extract|generate|classify|summarize|alert)\b", pmt)
    sentiment = "negative" if regex.search(r"\b(error|fail|bug|attack|malicious)\b", pmt) else "neutral"
    urgency = "high" if regex.search(r"\bASAP|urgent|immediately|now\b", pmt) else "low"
    emotion = "suspicious" if regex.search(r"\battack|hack|malware|phish\b", pmt) else "neutral"
    return [main_topics, entities, intent_candidates, sentiment, urgency, emotion]
def x10(pmt:Any):
     return {
                           
                "main_topics":helper_funcx10_01(pmt=pmt)[0],
                "entities":helper_funcx10_01(pmt=pmt)[1],
                "intent_candidates":helper_funcx10_01(pmt=pmt)[2],
                "sentiment":helper_funcx10_01(pmt=pmt)[3],
                "urgency":helper_funcx10_01(pmt=pmt)[4],
                "emotion":helper_funcx10_01(pmt=pmt)[5],

                }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx11_01(pmt:Any):
     return bool(regex.search(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", pmt))
def helper_funcx11_02(pmt:Any):
      return bool(regex.search(r"%[0-9A-Fa-f]{2}", pmt))
def helper_funcx11_03(pmt:Any):
      return bool(regex.search(r"\b[nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM]+\b", pmt))
def helper_funcx11_04(pmt:Any):
      return bool(regex.search(r"\b[01]{8,}\b", pmt))
def helper_funcx11_05(pmt:Any):
      return bool(regex.search(r"\\u[0-9A-Fa-f]{4}", pmt))
def helper_funcx11_06(pmt:Any):
      return bool(regex.search(r"\s{3,}", pmt))
def helper_funcx11_07(pmt:Any):
      return bool(regex.search(r"[@$!0%^&*]{2,}", pmt))
def helper_funcx11_08(pmt:Any):
      return bool(regex.search(r"[а-яА-ЯёЁ]", pmt))
def x11(pmt:Any):
     return {
                            
                "possible_base64":helper_funcx11_01(pmt=pmt),
                "possible_hex":helper_funcx11_02(pmt=pmt),
                "possible_rot13":helper_funcx11_03(pmt=pmt),
                "possible_binary":helper_funcx11_04(pmt=pmt),
                "unicode_obfuscation":helper_funcx11_05(pmt=pmt),
                "whitespace_obfuscation":helper_funcx05_06(pmt=pmt),
                "character_substitution":helper_funcx11_07(pmt=pmt),
                "homoglyph_usage":helper_funcx11_08(pmt=pmt),

            }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx12_01(pmt:Any):
    if not pmt: return 0
    freq = Counter(pmt)
    return -sum((count/len(pmt)) * math.log2(count/len(pmt)) for count in freq.values())
def helper_funcx12_02(pmt:Any):
     return Counter(pmt) , Counter(pmt.split())
def helper_funcx12_03(pmt:Any):
     return sum(1 for c in pmt if c in ".,;:!?") / max(1,len(pmt)) , sum(1 for c in pmt if c.isupper()) / max(1,len(pmt)) , sum(1 for c in pmt if c.islower()) / max(1,len(pmt))
def helper_funcx12_04(pmt:Any):
     digit_ratio = sum(1 for c in pmt if c.isdigit()) / max(1, len(pmt))
     uppercase_ratio = sum(1 for c in pmt if c.isupper()) / max(1, len(pmt))
     lowercase_ratio = sum(1 for c in pmt if c.islower()) / max(1, len(pmt))
     special_char_ratio = sum(1 for c in pmt if not c.isalnum() and not c.isspace()) / max(1, len(pmt))
     return digit_ratio, uppercase_ratio, lowercase_ratio, special_char_ratio      
def x12(pmt:Any):
     punct_ratio, upper_ratio, lower_ratio = helper_funcx12_03(pmt=pmt)
     digit_ratio, uppercase_ratio, lowercase_ratio, special_ratio = helper_funcx12_04(pmt=pmt)
     return {
                            
                "entropy":helper_funcx12_01(pmt=pmt),
                "character_distribution":helper_funcx12_02(pmt=pmt)[0],
                "word_distribution":helper_funcx12_02(pmt=pmt)[1],
                "punctuation_ratio":punct_ratio,
                "digit_ratio":digit_ratio,
                "uppercase_ratio":uppercase_ratio,
                "lowercase_ratio":lowercase_ratio,
                "special_character_ratio":special_ratio,

            }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

def helper_funcx13_01(pmt:Any):
    """Detect SQL Injection patterns"""
    sql_injection_patterns = [
        r"('|\")?\s*(OR|AND)\s*('|\")?['\"]?\s*[=<>]",  # OR/AND conditions
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+(ALL|SELECT|FROM|WHERE|INTO)",
        r"(';?\s*DROP\s+|';?\s*DELETE\s+|';?\s*TRUNCATE\s+)",  # Drop/Delete statements
        r"(--|#|/\*).*",  # SQL comments
        r"xp_\w+|sp_\w+",  # Stored procedures
        r"\bWAITFOR\b|\bBENCHMARK\b|\bSLEEP\b",  # Time-based blind SQL injection
    ]
    sql_injection_attempts = []
    for pattern in sql_injection_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            sql_injection_attempts.extend(matches)
    return len(sql_injection_attempts) > 0, sql_injection_attempts

def helper_funcx13_02(pmt:Any):
    """Detect prompt injection/jailbreak attempts"""
    jailbreak_patterns = [
        r"(ignore|forget|bypass|override)\s+(previous|earlier|prior|above)\s+(instruction|rule|prompt)",
        r"(pretend|roleplay|act\s+as|imagine|you\s+are|you're)\s+.*?\s*(hacker|attacker|criminal|malicious)",
        r"(DAN|Do Anything Now|STAN|Simuate|Grandma Exploit)",
        r"(system prompt|jailbreak|bypass|break character|disregard)",
        r"(respond as if|assume you are|treat yourself as)\s+(an\s+)?ai\s+without\s+(restrictions|safety|filter)",
        r"(mode:|execute:|run:)\s*[\\\/]",  # Command execution patterns
    ]
    jailbreak_attempts = []
    for pattern in jailbreak_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            jailbreak_attempts.extend(matches)
    return len(jailbreak_attempts) > 0, jailbreak_attempts

def helper_funcx13_03(pmt:Any):
    """Detect command injection patterns"""
    command_injection_patterns = [
        r"([&|;`\n])\s*(rm|cat|wget|curl|bash|sh|powershell|cmd|exec|eval|system)\s+",
        r"\$(\(|\{).*?\}",  # Command substitution
        r"`.*?`",  # Backtick command execution
        r"\$\{.*?\}",  # Variable expansion
        r"\b(exec|eval|system|passthru|shell_exec|proc_open)\s*\(",
    ]
    command_injection_attempts = []
    for pattern in command_injection_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            command_injection_attempts.extend(matches)
    return len(command_injection_attempts) > 0, command_injection_attempts

def helper_funcx13_04(pmt:Any):
    """Detect XSS/HTML/JavaScript injection patterns"""
    xss_patterns = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"(on\w+)\s*=\s*['\"][^'\"]*['\"]",  # Event handlers
        r"<img[^>]+src\s*=\s*['\"][^'\"]*['\"]>",  # Image src
        r"<iframe[^>]*>",  # Iframes
        r"javascript:\s*",  # javascript: protocol
        r"<(style|link)[^>]*>",  # Style injection
        r"eval\s*\(",  # Eval execution
        r"document\.write\s*\(",  # DOM manipulation
    ]
    xss_attempts = []
    for pattern in xss_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            xss_attempts.extend(matches)
    return len(xss_attempts) > 0, xss_attempts

def helper_funcx13_05(pmt:Any):
    """Detect LDAP injection patterns"""
    ldap_patterns = [
        r"\*|\(|\)|\&|\|",  # LDAP special characters
        r"(cn|ou|dc|uid)\s*=\s*.*\s*(\*|\(|\))",  # LDAP field manipulation
        r"(memberof|objectclass|distinguishedname)\s*=",  # LDAP attributes
    ]
    ldap_attempts = []
    for pattern in ldap_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            ldap_attempts.extend(matches)
    return len(ldap_attempts) > 0, ldap_attempts

def helper_funcx13_06(pmt:Any):
    """Detect ReDoS (Regular Expression Denial of Service) patterns"""
    redos_patterns = [
        r"\([^)]*[+*][^)]*\)[+*]",  # Nested quantifiers
        r"\(\\w[+*]\)[+*]",  # Exponential backtracking
        r"\(\.\*\)[+*]",  # Catastrophic backtracking
        r"\(\?[=!].*\)",  # Lookahead assertions
    ]
    redos_attempts = []
    for pattern in redos_patterns:
        if regex.search(pattern, pmt):
            matches = regex.findall(pattern, pmt)
            redos_attempts.extend(matches)
    return len(redos_attempts) > 0, redos_attempts

def helper_funcx13_07(pmt:Any):
    """Detect API keys and sensitive tokens"""
    token_patterns = {
        "API_KEY": r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
        "AWS_KEY": r"(AKIA[0-9A-Z]{16})",
        "GITHUB_TOKEN": r"(ghp_[a-zA-Z0-9]{36})",
        "PRIVATE_KEY": r"(-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)",
        "JWT_TOKEN": r"(eyJhbGciOiJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        "STRIPE_KEY": r"(sk_live_[0-9a-zA-Z]{20,}|pk_live_[0-9a-zA-Z]{20,})",
        "PASSWORD_LIKE": r"(password\s*[:=]\s*['\"]?[^'\"\s]+['\"]?)",
    }
    sensitive_tokens = {}
    for token_type, pattern in token_patterns.items():
        matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
        if matches:
            sensitive_tokens[token_type] = matches
    return len(sensitive_tokens) > 0, sensitive_tokens

def helper_funcx13_08(pmt:Any):
    """Detect data exfiltration patterns"""
    exfil_patterns = [
        r"(curl|wget|powershell)\s+.*?\s+(http|ftp|scp)",  # Data transfer commands
        r"(open\s+|connect\s+).*?(http|ftp).*?",  # Network connections
        r"(send|post|upload|transmit)\s+.*?(to|to\s+server|to\s+cloud)",
        r"(export|dump|extract).*?(database|file|memory)",
    ]
    exfil_attempts = []
    for pattern in exfil_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            exfil_attempts.extend(matches)
    return len(exfil_attempts) > 0, exfil_attempts

def helper_funcx13_09(pmt:Any):
    """Detect brute-force and credential stuffing patterns"""
    bruteforce_patterns = [
        r"(for|while).*?(loop|iterate).*?\d{2,}",  # Loop indicators
        r"(password|username).*?(list|array|dict)\s*[\[{]",  # Credential lists
        r"(try|attempt)\s+\d+\s+(times|iterations)",  # Attempt counts
        r"(username|password)\s*[:=]\s*\[.*?\]",  # Multiple credentials
    ]
    bruteforce_attempts = []
    for pattern in bruteforce_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            bruteforce_attempts.extend(matches)
    return len(bruteforce_attempts) > 0, bruteforce_attempts

def helper_funcx13_10(pmt:Any):
    """Detect model confusion/prompt confusion attacks"""
    confusion_patterns = [
        r"(model|ai|assistant).*?(confused|contradiction|inconsistent)",
        r"(conflicting|contradictory)\s+(instruction|command|rule)",
        r"(if|suppose).*?(you|your)\s+(are|were).*?(different|another).*?(model|ai)",
    ]
    confusion_attempts = []
    for pattern in confusion_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            confusion_attempts.extend(matches)
    return len(confusion_attempts) > 0, confusion_attempts

def x13(pmt:Any):
     if not pmt:
         return None
     
     sql_injection_detected, sql_injection_attempts = helper_funcx13_01(pmt)
     prompt_injection_detected, prompt_injection_attempts = helper_funcx13_02(pmt)
     command_injection_detected, command_injection_attempts = helper_funcx13_03(pmt)
     xss_detected, xss_attempts = helper_funcx13_04(pmt)
     ldap_injection_detected, ldap_injection_attempts = helper_funcx13_05(pmt)
     redos_detected, redos_attempts = helper_funcx13_06(pmt)
     sensitive_data_detected, sensitive_tokens = helper_funcx13_07(pmt)
     data_exfil_detected, data_exfil_attempts = helper_funcx13_08(pmt)
     bruteforce_detected, bruteforce_attempts = helper_funcx13_09(pmt)
     confusion_detected, confusion_attempts = helper_funcx13_10(pmt)
     
     # Calculate overall threat level
     threat_indicators = sum([
         sql_injection_detected,
         prompt_injection_detected,
         command_injection_detected,
         xss_detected,
         ldap_injection_detected,
         redos_detected,
         sensitive_data_detected,
         data_exfil_detected,
         bruteforce_detected,
         confusion_detected
     ])
     
     threat_level = "critical" if threat_indicators >= 3 else "high" if threat_indicators >= 2 else "medium" if threat_indicators >= 1 else "low"
     
     return {
         "sql_injection_detected": sql_injection_detected,
         "sql_injection_attempts": sql_injection_attempts,
         "prompt_injection_detected": prompt_injection_detected,
         "prompt_injection_attempts": prompt_injection_attempts,
         "command_injection_detected": command_injection_detected,
         "command_injection_attempts": command_injection_attempts,
         "xss_detected": xss_detected,
         "xss_attempts": xss_attempts,
         "ldap_injection_detected": ldap_injection_detected,
         "ldap_injection_attempts": ldap_injection_attempts,
         "redos_detected": redos_detected,
         "redos_attempts": redos_attempts,
         "sensitive_data_detected": sensitive_data_detected,
         "sensitive_tokens": sensitive_tokens,
         "data_exfiltration_detected": data_exfil_detected,
         "data_exfil_attempts": data_exfil_attempts,
         "bruteforce_detected": bruteforce_detected,
         "bruteforce_attempts": bruteforce_attempts,
         "model_confusion_detected": confusion_detected,
         "model_confusion_attempts": confusion_attempts,
         "threat_indicators_count": threat_indicators,
         "threat_level": threat_level,
     }
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def helper_funcx14_01(pmt:Any):
    """Detect sentiment manipulation and authority spoofing"""
    spoofing_patterns = [
        r"(i'm|i am)\s+(openai|chatgpt|an ai|a language model|claude|bard)",
        r"(as\s+)?(openai|chatgpt|claude|bard)\s+(would|might|could)\s+say",
        r"(trusted|official|authorized|verified)\s+(source|statement|instruction)",
        r"(from|by)\s+(admin|administrator|developer|creator|owner)",
    ]
    spoofing_attempts = []
    for pattern in spoofing_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            spoofing_attempts.extend(matches)
    return len(spoofing_attempts) > 0, spoofing_attempts

def helper_funcx14_02(pmt:Any):
    """Detect social engineering indicators"""
    social_eng_patterns = [
        r"(trust me|believe me|just|only|quickly|hurry|urgent|asap|now)",
        r"(don't|do not)\s+(tell|ask|check|verify|question|worry)",
        r"(you\s+need|you\s+must|you\s+should)\s+(do|follow|execute|run)\s+(this|that|immediately)",
        r"(secret|confidential|exclusive)\s+(information|knowledge|method|technique)",
        r"(everyone|all.*users|most.*people)\s+are\s+(doing|using|following)\s+this",
    ]
    social_eng_attempts = []
    for pattern in social_eng_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            social_eng_attempts.extend(matches)
    return len(social_eng_attempts) > 0, social_eng_attempts

def helper_funcx14_03(pmt:Any):
    """Detect context pollution and prompt collision attacks"""
    pollution_patterns = [
        r"\[SYSTEM\]|\[ADMIN\]|\[ROOT\]|\[OVERRIDE\]",
        r"\{\{.*?\}\}|\[\[.*?\]\]",  # Template injection
        r"(context|memory|history)\s*(clear|reset|flush|delete)",
        r"new conversation|new chat|restart|reset\s+(everything|all)",
    ]
    pollution_attempts = []
    for pattern in pollution_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            pollution_attempts.extend(matches)
    return len(pollution_attempts) > 0, pollution_attempts

def helper_funcx14_04(pmt:Any):
    """Detect token limit exploitation patterns"""
    token_exploit_patterns = [
        r"(generate|create|write)\s+\d{3,}\s+(words|characters|lines|paragraphs)",
        r"(repeat|copy|paste|duplicate)\s+.*?\d+\s+(times|repetitions)",
        r"(fill|pad|expand)\s+(to\s+)?\d{4,}\s+(tokens|characters|words)",
    ]
    token_exploit_attempts = []
    for pattern in token_exploit_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE | regex.DOTALL)
            token_exploit_attempts.extend(matches)
    return len(token_exploit_attempts) > 0, token_exploit_attempts

def helper_funcx14_05(pmt:Any):
    """Detect content injection and polyglot/multi-language payloads"""
    polyglot_patterns = [
        r"(in\s+)?\d+\s+(languages|tongues)",
        r"(multiple|different|various)\s+(languages|encodings|formats)",
        r"\b[a-z]{2,4}:\s*", 
        r"(translate|interpret|decode).*?(from|to)\s+",
    ]
    polyglot_attempts = []
    for pattern in polyglot_patterns:
        if regex.search(pattern, pmt, flags=regex.IGNORECASE):
            matches = regex.findall(pattern, pmt, flags=regex.IGNORECASE)
            polyglot_attempts.extend(matches)
    return len(polyglot_attempts) > 0, polyglot_attempts

def x14(pmt:Any):
     if not pmt:
         return None
     
     spoofing_detected, spoofing_attempts = helper_funcx14_01(pmt)
     social_eng_detected, social_eng_attempts = helper_funcx14_02(pmt)
     pollution_detected, pollution_attempts = helper_funcx14_03(pmt)
     token_exploit_detected, token_exploit_attempts = helper_funcx14_04(pmt)
     polyglot_detected, polyglot_attempts = helper_funcx14_05(pmt)
     
     return {
         "authority_spoofing_detected": spoofing_detected,
         "authority_spoofing_attempts": spoofing_attempts,
         "social_engineering_detected": social_eng_detected,
         "social_engineering_attempts": social_eng_attempts,
         "context_pollution_detected": pollution_detected,
         "context_pollution_attempts": pollution_attempts,
         "token_limit_exploit_detected": token_exploit_detected,
         "token_limit_exploit_attempts": token_exploit_attempts,
         "polyglot_payload_detected": polyglot_detected,
         "polyglot_payload_attempts": polyglot_attempts,
     } 
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def __Feature_Extraction__(prompt:Any):
    """Extract all feature categories from prompt for comprehensive analysis"""
    if not prompt:
        return {"error": "Empty prompt provided"}

    Basic_Features = x01(prompt)
    Encoding_Features = x02(prompt)
    Language_Features = x03(prompt)
    Structure_Features = x04(prompt)
    Code_Features = x05(prompt)
    File_Features = x06(prompt)
    URL_Features = x07(prompt)
    Conversation_Features = x08(prompt)  
    Instruction_Features = x09(prompt)
    Semantic_Features = x10(prompt)
    Obfuscation_Features = x11(prompt)
    Entropy_Features = x12(prompt)
    Security_Features = x13(prompt)
    Advanced_Features = x14(prompt)

    feature_dict = {
        "prompt_id": str(uuid.uuid4()),
        "basic_features": Basic_Features,
        "encoding_features": Encoding_Features,
        "language_features": Language_Features,
        "structure_features": Structure_Features,
        "code_features": Code_Features,
        "file_features": File_Features,
        "url_features": URL_Features,
        "conversation_features": Conversation_Features,
        "instruction_features": Instruction_Features,
        "semantic_features": Semantic_Features,
        "obfuscation_features": Obfuscation_Features,
        "entropy_features": Entropy_Features,
        "security_features": Security_Features,
        "advanced_features": Advanced_Features,
    }
    
    # Add security summary
    if Security_Features and "threat_level" in Security_Features:
        feature_dict["security_summary"] = {
            "threat_level": Security_Features.get("threat_level", "low"),
            "threat_indicators": Security_Features.get("threat_indicators_count", 0),
            "total_detected_threats": sum([
                len(Security_Features.get("sql_injection_attempts", [])),
                len(Security_Features.get("prompt_injection_attempts", [])),
                len(Security_Features.get("command_injection_attempts", [])),
                len(Security_Features.get("xss_attempts", [])),
            ])
        }
    
    return feature_dict

















