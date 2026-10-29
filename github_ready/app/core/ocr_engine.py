import re

def parse_num(pattern: str, text: str, default: int = 0) -> int:
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return default
    raw = match.group(1).replace(",", "").strip().lower()
    try:
        if raw.endswith("k"):
            return int(float(raw[:-1]) * 1000)
        elif raw.endswith("m"):
            return int(float(raw[:-1]) * 1_000_000)
        return int(float(raw))
    except Exception:
        return default

def parse_extracted_text(raw_text: str, filename: str = "") -> dict:
    text = raw_text.replace("\n", " ").replace("\r", " ")
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    full_corpus = (raw_text + " " + filename).lower()

    # 1. Platform Detection
    platform = "Instagram"
    if any(k in full_corpus for k in ["linkedin", "connections", "experience", "endorsements"]):
        platform = "LinkedIn"
    elif any(k in full_corpus for k in ["twitter", "tweet", "retweet", "tweets", "x.com"]):
        platform = "Twitter"
    elif any(k in full_corpus for k in ["facebook", "friends", "intro", "mutual friends"]):
        platform = "Facebook"
    elif "instagram" in full_corpus:
        platform = "Instagram"

    # 2. Universal Numeric Parsing Across Domains
    # Followers / Connections / Friends
    followers = 0
    following = 0
    posts = 0

    if platform == "LinkedIn":
        followers = parse_num(r"([\d\.,]+[km]?)\+?\s*(?:connections|followers)", text, 150)
        following = parse_num(r"([\d\.,]+[km]?)\s*(?:following|contact)", text, 120)
        posts = parse_num(r"([\d\.,]+[km]?)\s*(?:posts|articles|activity)", text, 8)
    elif platform == "Twitter":
        followers = parse_num(r"([\d\.,]+[km]?)\s*(?:followers)", text, 80)
        following = parse_num(r"([\d\.,]+[km]?)\s*(?:following)", text, 100)
        posts = parse_num(r"([\d\.,]+[km]?)\s*(?:tweets|posts)", text, 25)
    elif platform == "Facebook":
        followers = parse_num(r"([\d\.,]+[km]?)\s*(?:friends|followers)", text, 200)
        following = parse_num(r"([\d\.,]+[km]?)\s*(?:following)", text, 150)
        posts = parse_num(r"([\d\.,]+[km]?)\s*(?:posts|photos)", text, 12)
    else:  # Instagram
        followers = parse_num(r"([\d\.,]+[km]?)\s*(?:followers)", text, 75)
        following = parse_num(r"([\d\.,]+[km]?)\s*(?:following)", text, 70)
        posts = parse_num(r"([\d\.,]+[km]?)\s*(?:posts)", text, 15)

    # 3. Username & Display Name Extraction
    username = "@unknown_entity"
    handle_match = re.search(r"@([A-Za-z0-9_\.]{3,30})", raw_text)
    if handle_match:
        username = f"@{handle_match.group(1)}"
    else:
        # Check first clean non-numeric line
        for line in lines[:5]:
            clean_token = re.sub(r"[^\w\.]", "", line).strip()
            if 3 <= len(clean_token) <= 24 and not any(w in clean_token.lower() for w in ["followers", "posts", "following"]):
                username = f"@{clean_token.lower()}"
                break

    display_name = username.replace("@", "").title()
    for line in lines[:4]:
        if line.lower() not in username.lower() and len(line) < 32 and not re.search(r"\d", line):
            display_name = line
            break

    # 4. Bio Extraction
    bio = "No profile bio detected."
    for line in lines[2:8]:
        if len(line) > 15 and not any(k in line.lower() for k in ["followers", "following", "posts", "connections", "edit profile"]):
            bio = line
            break

    return {
        "platform": platform,
        "username": username,
        "display_name": display_name,
        "followers": followers,
        "following": following,
        "posts": posts,
        "bio": bio
    }