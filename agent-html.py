import re
import uuid
import time
import json
import base64
import random
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from openai import OpenAI


API_KEY = ""
BASE_URL = ""
MODEL = "gpt-5.5"

OUTPUT_DIR = Path("/root/htmls")

TARGET_SUCCESS = 36

MAX_WORKERS = 2

CURRENT_YEAR = datetime.now().year

MIN_DELAY_AFTER_TASK = 8
MAX_DELAY_AFTER_TASK = 22

RETRY_PER_PAGE = 6
BLOCK_SLEEP = 180
NORMAL_SLEEP = 35

# 100KB HTML 建议 20000+
MAX_TOKENS = 24000
TEMPERATURE = 0.86
TOP_P = 0.92

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg, flush=True)


def make_client():
    return OpenAI(
        api_key=API_KEY,
        base_url=BASE_URL,
        timeout=900,
        default_headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
            "Accept": "application/json",
            "X-Title": "HTML Batch Generator",
            "HTTP-Referer": "https://localhost"
        }
    )


LANGUAGE_PROFILES = [
    {
        "label": "English",
        "instruction": "Write entirely in natural English.",
        "html_lang": "en",
        "dir": "ltr"
    },
    {
        "label": "British English",
        "instruction": "Write entirely in natural British English with subtle local phrasing.",
        "html_lang": "en-GB",
        "dir": "ltr"
    },
    {
        "label": "American English",
        "instruction": "Write entirely in natural American English.",
        "html_lang": "en-US",
        "dir": "ltr"
    },
    {
        "label": "French",
        "instruction": "Write entirely in natural French.",
        "html_lang": "fr",
        "dir": "ltr"
    },
    {
        "label": "Canadian French",
        "instruction": "Write entirely in natural Canadian French.",
        "html_lang": "fr-CA",
        "dir": "ltr"
    },
    {
        "label": "German",
        "instruction": "Write entirely in natural German.",
        "html_lang": "de",
        "dir": "ltr"
    },
    {
        "label": "Austrian German",
        "instruction": "Write entirely in natural Austrian German.",
        "html_lang": "de-AT",
        "dir": "ltr"
    },
    {
        "label": "Spanish",
        "instruction": "Write entirely in natural Spanish.",
        "html_lang": "es",
        "dir": "ltr"
    },
    {
        "label": "Mexican Spanish",
        "instruction": "Write entirely in natural Mexican Spanish.",
        "html_lang": "es-MX",
        "dir": "ltr"
    },
    {
        "label": "Argentinian Spanish",
        "instruction": "Write entirely in natural Argentinian Spanish.",
        "html_lang": "es-AR",
        "dir": "ltr"
    },
    {
        "label": "Italian",
        "instruction": "Write entirely in natural Italian.",
        "html_lang": "it",
        "dir": "ltr"
    },
    {
        "label": "Portuguese",
        "instruction": "Write entirely in natural Portuguese.",
        "html_lang": "pt",
        "dir": "ltr"
    },
    {
        "label": "Brazilian Portuguese",
        "instruction": "Write entirely in natural Brazilian Portuguese.",
        "html_lang": "pt-BR",
        "dir": "ltr"
    },
    {
        "label": "Dutch",
        "instruction": "Write entirely in natural Dutch.",
        "html_lang": "nl",
        "dir": "ltr"
    },
    {
        "label": "Swedish",
        "instruction": "Write entirely in natural Swedish.",
        "html_lang": "sv",
        "dir": "ltr"
    },
    {
        "label": "Norwegian",
        "instruction": "Write entirely in natural Norwegian Bokmal.",
        "html_lang": "no",
        "dir": "ltr"
    },
    {
        "label": "Danish",
        "instruction": "Write entirely in natural Danish.",
        "html_lang": "da",
        "dir": "ltr"
    },
    {
        "label": "Finnish",
        "instruction": "Write entirely in natural Finnish.",
        "html_lang": "fi",
        "dir": "ltr"
    },
    {
        "label": "Polish",
        "instruction": "Write entirely in natural Polish.",
        "html_lang": "pl",
        "dir": "ltr"
    },
    {
        "label": "Czech",
        "instruction": "Write entirely in natural Czech.",
        "html_lang": "cs",
        "dir": "ltr"
    },
    {
        "label": "Hungarian",
        "instruction": "Write entirely in natural Hungarian.",
        "html_lang": "hu",
        "dir": "ltr"
    },
    {
        "label": "Romanian",
        "instruction": "Write entirely in natural Romanian.",
        "html_lang": "ro",
        "dir": "ltr"
    },
    {
        "label": "Greek",
        "instruction": "Write entirely in natural Greek.",
        "html_lang": "el",
        "dir": "ltr"
    },
    {
        "label": "Turkish",
        "instruction": "Write entirely in natural Turkish.",
        "html_lang": "tr",
        "dir": "ltr"
    },
    {
        "label": "Vietnamese",
        "instruction": "Write entirely in natural Vietnamese.",
        "html_lang": "vi",
        "dir": "ltr"
    },
    {
        "label": "Thai",
        "instruction": "Write entirely in natural Thai.",
        "html_lang": "th",
        "dir": "ltr"
    },
    {
        "label": "Indonesian",
        "instruction": "Write entirely in natural Indonesian.",
        "html_lang": "id",
        "dir": "ltr"
    },
    {
        "label": "Malay",
        "instruction": "Write entirely in natural Malay.",
        "html_lang": "ms",
        "dir": "ltr"
    },
    {
        "label": "Filipino",
        "instruction": "Write entirely in natural Filipino.",
        "html_lang": "fil",
        "dir": "ltr"
    },
    {
        "label": "Swahili",
        "instruction": "Write entirely in natural Swahili.",
        "html_lang": "sw",
        "dir": "ltr"
    },
    {
        "label": "Afrikaans",
        "instruction": "Write entirely in natural Afrikaans.",
        "html_lang": "af",
        "dir": "ltr"
    },
    {
        "label": "Russian",
        "instruction": "Write entirely in natural Russian.",
        "html_lang": "ru",
        "dir": "ltr"
    },
    {
        "label": "Ukrainian",
        "instruction": "Write entirely in natural Ukrainian.",
        "html_lang": "uk",
        "dir": "ltr"
    },
    {
        "label": "Bulgarian",
        "instruction": "Write entirely in natural Bulgarian.",
        "html_lang": "bg",
        "dir": "ltr"
    },
    {
        "label": "Hindi",
        "instruction": "Write entirely in natural Hindi.",
        "html_lang": "hi",
        "dir": "ltr"
    },
    {
        "label": "Bengali",
        "instruction": "Write entirely in natural Bengali.",
        "html_lang": "bn",
        "dir": "ltr"
    },
    {
        "label": "Tamil",
        "instruction": "Write entirely in natural Tamil.",
        "html_lang": "ta",
        "dir": "ltr"
    },
    {
        "label": "Japanese",
        "instruction": "Write entirely in natural Japanese.",
        "html_lang": "ja",
        "dir": "ltr"
    },
    {
        "label": "Korean",
        "instruction": "Write entirely in natural Korean.",
        "html_lang": "ko",
        "dir": "ltr"
    },
    {
        "label": "Simplified Chinese",
        "instruction": "Write entirely in natural Simplified Chinese.",
        "html_lang": "zh-CN",
        "dir": "ltr"
    },
    {
        "label": "Traditional Chinese",
        "instruction": "Write entirely in natural Traditional Chinese.",
        "html_lang": "zh-Hant",
        "dir": "ltr"
    },
    {
        "label": "Arabic",
        "instruction": "Write entirely in natural Modern Standard Arabic. Use right-to-left layout where appropriate.",
        "html_lang": "ar",
        "dir": "rtl"
    },
    {
        "label": "Persian",
        "instruction": "Write entirely in natural Persian. Use right-to-left layout where appropriate.",
        "html_lang": "fa",
        "dir": "rtl"
    },
    {
        "label": "Hebrew",
        "instruction": "Write entirely in natural Hebrew. Use right-to-left layout where appropriate.",
        "html_lang": "he",
        "dir": "rtl"
    },

    # bilingual
    {
        "label": "English + French bilingual",
        "instruction": "Write a bilingual article in English and French. Each major section should include both languages in an elegant editorial rhythm.",
        "html_lang": "en",
        "dir": "ltr"
    },
    {
        "label": "Spanish + English bilingual",
        "instruction": "Write a bilingual article in Spanish and English. Alternate paragraphs or use paired summaries.",
        "html_lang": "es",
        "dir": "ltr"
    },
    {
        "label": "Japanese + English bilingual",
        "instruction": "Write a bilingual article in Japanese and English. Use Japanese for the main narrative and English for notes, captions, and summaries.",
        "html_lang": "ja",
        "dir": "ltr"
    },
    {
        "label": "Korean + English bilingual",
        "instruction": "Write a bilingual article in Korean and English. Use Korean for the main narrative and English for marginal notes.",
        "html_lang": "ko",
        "dir": "ltr"
    },
    {
        "label": "Chinese + English bilingual",
        "instruction": "Write a bilingual article in Simplified Chinese and English. Use Chinese for the main narrative and English for captions, metadata, and side notes.",
        "html_lang": "zh-CN",
        "dir": "ltr"
    },
    {
        "label": "Arabic + English bilingual",
        "instruction": "Write a bilingual article in Arabic and English. Use Arabic as the primary narrative and English for summaries and labels. Support RTL thoughtfully.",
        "html_lang": "ar",
        "dir": "rtl"
    },

    # multilingual
    {
        "label": "Multilingual European edition",
        "instruction": "Write a multilingual editorial page using English, French, Spanish, German, and Italian. Use one primary language with multilingual side notes, quotes, and summaries.",
        "html_lang": "en",
        "dir": "ltr"
    },
    {
        "label": "Multilingual Asian edition",
        "instruction": "Write a multilingual editorial page using English, Japanese, Korean, Chinese, and Thai. Keep language blocks clearly labelled and visually intentional.",
        "html_lang": "en",
        "dir": "ltr"
    },
    {
        "label": "Global multilingual edition",
        "instruction": "Write a multilingual magazine page using English, Spanish, Arabic, Japanese, French, and Chinese. Include labelled language sections, local observations, and parallel summaries.",
        "html_lang": "en",
        "dir": "ltr"
    }
]


TOPICS = [
    "a quiet morning routine in a dense city",
    "a long walk through a coastal town after the busy season",
    "the emotional design of small apartments",
    "slow travel and memory",
    "remote work from a mountain village",
    "late-night neighborhood cafes",
    "personal notebooks and useful archives",
    "urban gardens on ordinary streets",
    "second-hand bookstores and memory",
    "low-carbon weekend travel",
    "small design studios and client trust",
    "the comfort of train stations",
    "rain glass and city lights",
    "simple smart home habits",
    "why some personal blogs feel alive",
    "analog hobbies in digital homes",
    "building useful things slowly",
    "the social life of public libraries",
    "neighborhood markets and local taste",
    "sleep screens and evening rituals",
    "quiet productivity without hustle",
    "small music scenes in ordinary cities",
    "boutique hotels and spatial details",
    "handmade objects and patience",
    "creative co-working spaces",
    "public parks as emotional infrastructure",
    "digital minimalism in daily life",
    "old tools in modern studios",
    "reading cooking and walking on weekends",
    "good interfaces as good manners",
    "moving to a smaller home",
    "breakfast culture around the world",
    "local bakeries as neighborhood anchors",
    "repair culture",
    "creative burnout and recovery",
    "temporary rooms that feel like home",
    "color shadow and silence in design",
    "handwritten notes",
    "working near windows",
    "small rituals for remote work",
    "small museums",
    "islands outside high season",
    "ordinary objects as personal landmarks",
    "small independent magazines",
    "the design of quiet hotel lobbies",
    "neighborhood walking routes",
    "weekend food markets",
    "living with fewer digital tools",
    "how people make rented rooms personal",
    "morning light and work habits",
    "local coffee counters and daily conversations",
    "a personal guide to slower evenings",
    "the culture of repairing old bicycles",
    "how balcony gardens change apartment life",
    "the quiet value of public benches",
    "why neighborhood newsletters still work",
    "studio rituals among independent designers",
    "how weekend trains shape small memories",
    "the texture of old maps and city walks",
    "minimal tools for a calmer digital life",
    "what small restaurants teach about hospitality",
    "a practical notebook system for busy weeks",
    "multilingual neighborhoods and everyday translation",
    "night buses and the private geography of cities",
    "how tiny kitchens shape domestic routines",
    "local radio, small weather reports, and memory",
    "train window landscapes and notebook fragments",
    "ordinary courtyards as social architecture",
    "small islands, ferry schedules, and slow mornings",
    "paper receipts as a record of travel",
    "how neighborhood laundries become public rooms",
    "the quiet choreography of shared work tables"
]


STYLES = [
    "minimal editorial page with generous white space",
    "dark city journal with glowing accents",
    "warm lifestyle blog with cream tones and soft cards",
    "retro newspaper inspired page",
    "glass style layered interface",
    "black and gold long form essay",
    "Nordic clean blog",
    "brutalist creative page with strong borders",
    "nature inspired page with green tones",
    "modern editorial page with structured sections",
    "Mediterranean travel diary",
    "dark notebook style journal",
    "avant garde portfolio article",
    "architecture magazine layout",
    "vintage postcard blog",
    "colorful Memphis inspired article",
    "academic essay page",
    "modern news feature page",
    "immersive longread with table of contents",
    "soft clay style blog",
    "high contrast zine layout",
    "quiet gallery style article",
    "premium newsletter page",
    "urban field notes layout",
    "cinematic monochrome article",
    "warm coffeehouse newsletter",
    "clean product design journal",
    "soft pastel personal blog",
    "dense magazine feature page",
    "luxury black ivory editorial",
    "muted botanical magazine",
    "Swiss grid inspired feature page",
    "ocean blue travel journal",
    "desert toned personal essay",
    "gallery like photography article",
    "modern SaaS editorial hybrid",
    "handmade notebook interface",
    "soft neumorphic reading page",
    "dramatic split screen magazine",
    "high contrast editorial poster",
    "calm archive style longread",
    "warm analog travel diary",
    "premium independent media page",
    "experimental creative studio journal",
    "neo brutalist multilingual cultural magazine",
    "luxury editorial site with cinematic gradients",
    "interactive atlas inspired longform article",
    "museum wall label inspired digital essay",
    "Japanese stationery inspired reading interface",
    "Nordic archive with warm tactile details",
    "Swiss poster grid with animated cards",
    "urban night market magazine feature",
    "monochrome photography journal with accent color",
    "soft futuristic reading dashboard",
    "paper collage inspired independent zine",
    "high-end travel magazine with layered maps",
    "calm productivity notebook with animated margins",
    "editorial portfolio with oversized typography",
    "art book inspired essay page",
    "retro terminal mixed with literary magazine",
    "botanical field guide with modern cards",
    "cinematic split-screen travel longread",
    "premium newsletter mixed with data dashboard",
    "local culture magazine with illustrated sections",
    "architectural review layout with measurements",
    "warm analog diary with ticket and receipt motifs",
    "global city guide with multilingual labels",
    "slow journalism feature with dense side notes"
]


LAYOUTS = [
    "single column article",
    "left table of contents and right article",
    "large hero followed by article cards",
    "magazine introduction and normal article body",
    "timeline article",
    "classic blog with author sidebar",
    "centered reading column",
    "split hero and article",
    "asymmetric editorial grid",
    "article with side notes",
    "notebook sections",
    "dashboard inspired blog",
    "travel journal layout",
    "minimal zine layout",
    "card based article layout",
    "wide hero with narrow reading column",
    "two column feature article",
    "editorial index followed by longread",
    "hero poster layout with compact article",
    "floating cards around a reading rail",
    "stacked chapter cards",
    "newspaper grid with modern interaction",
    "visual diary layout",
    "premium newsletter layout",
    "side rail navigation layout",
    "large quote led article",
    "interactive reading board",
    "chapter based magazine feature",
    "longform article with sticky multilingual table of contents",
    "editorial map layout with article chapters",
    "split screen hero with scrolling chapter rail",
    "magazine cover followed by dense reading sections",
    "archive wall with feature essay",
    "interactive notebook with expandable side notes",
    "wide cinematic hero with floating metadata panels",
    "asymmetric cards around a central reading column",
    "atlas inspired grid with routes and observations",
    "bilingual parallel column article",
    "RTL magazine layout with mirrored side rail",
    "field guide layout with specimens and notes",
    "premium dossier layout with index cards",
    "reading room layout with chapter shelves",
    "visual essay with large inline SVG scenes"
]


INTERACTIONS = [
    "reading progress bar",
    "back to top button",
    "theme switch",
    "smooth scrolling",
    "font size controls",
    "favorite button",
    "scroll reveal",
    "mobile menu",
    "active section marker",
    "copy article link",
    "collapsible notes",
    "section highlight",
    "keyboard friendly menu",
    "expandable glossary",
    "reading mode toggle",
    "section copy buttons",
    "local reading preference storage",
    "animated table of contents",
    "contrast toggle",
    "estimated reading position indicator"
]


FAVICON_SHAPES = [
    "circle",
    "diamond",
    "hexagon",
    "orbit",
    "wave",
    "monogram",
    "split",
    "stack",
    "spark",
    "ring",
    "leaf",
    "grid",
    "bolt",
    "moon"
]


def count_html():
    return len(list(OUTPUT_DIR.glob("index_*.html")))


def random_date():
    days = random.randint(1, 730)
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


def make_file_path(num):
    raw = f"{num}-{uuid.uuid4()}-{time.time()}-{random.random()}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return OUTPUT_DIR / f"index_{num}_{h}.html"


def clean_html(text):
    if not text:
        return ""

    text = text.strip()
    text = re.sub(r"^```html\s*", "", text, flags=re.I)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    low = text.lower()
    a = low.find("<!doctype html")
    b = low.find("<html")

    if a >= 0:
        text = text[a:]
    elif b >= 0:
        text = text[b:]

    return text.strip()


def validate_html(html):
    low = html.lower()

    checks = [
        ("<!doctype html", "missing doctype"),
        ("<html", "missing html tag"),
        ("<head", "missing head tag"),
        ("<body", "missing body tag"),
        ("</html>", "missing closing html tag")
    ]

    for needle, err in checks:
        if needle not in low:
            return False, err

    # 100KB 目标，实际生成时 80KB 以上算合格，避免失败率太高
    size = len(html.encode("utf-8"))
    if size < 80 * 1024:
        return False, f"html too short for large target: {round(size / 1024, 1)}KB"

    bad_words = [
        "Lorem ipsum",
        "lorem ipsum",
        "placeholder",
        "ChatGPT",
        "OpenAI",
        "language model",
        "as an ai",
        "As an AI",
        "AI-generated",
        "generated by AI"
    ]

    for w in bad_words:
        if w in html:
            return False, f"bad phrase: {w}"

    if "data:image/svg+xml;base64," not in html:
        return False, "missing embedded base64 favicon"

    if 'rel="icon"' not in low and "rel='icon'" not in low:
        return False, "missing favicon rel"

    external_patterns = [
        r'<script[^>]+src=["\']https?://',
        r'<link[^>]+href=["\']https?://',
        r'<img[^>]+src=["\']https?://',
        r'@import\s+url\(["\']?https?://',
        r'<iframe[^>]+src=["\']https?://'
    ]

    for pat in external_patterns:
        if re.search(pat, html, flags=re.I):
            return False, "contains external asset"

    return True, "ok"


def make_profile(num):
    hue1 = random.randint(0, 360)
    hue2 = (hue1 + random.randint(45, 170)) % 360
    hue3 = (hue2 + random.randint(45, 170)) % 360

    raw = f"{num}-{uuid.uuid4()}-{time.time()}-{random.random()}"
    signature = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    favicon_seed = hashlib.sha256((raw + "-favicon").encode("utf-8")).hexdigest()

    lang = random.choice(LANGUAGE_PROFILES)

    target_kb = random.randint(92, 120)

    return {
        "num": num,
        "language": lang["label"],
        "language_instruction": lang["instruction"],
        "html_lang": lang["html_lang"],
        "dir": lang["dir"],
        "topic": random.choice(TOPICS),
        "style": random.choice(STYLES),
        "layout": random.choice(LAYOUTS),
        "date": random_date(),
        "year": CURRENT_YEAR,
        "hue1": hue1,
        "hue2": hue2,
        "hue3": hue3,
        "radius": random.choice(["0px", "4px", "8px", "12px", "18px", "24px", "32px", "40px"]),
        "width": random.choice(["960px", "1040px", "1120px", "1200px", "1280px", "1360px", "1440px"]),
        "interactions": random.sample(INTERACTIONS, random.randint(7, 10)),
        "signature": signature,
        "favicon_seed": favicon_seed,
        "favicon_shape": random.choice(FAVICON_SHAPES),
        "density": random.choice(["airy", "compact", "editorial", "immersive", "magazine-like", "quiet", "bold", "dense", "layered"]),
        "mood": random.choice(["calm", "cinematic", "warm", "precise", "reflective", "urban", "organic", "luxury", "nocturnal", "tactile"]),
        "structure": random.choice([
            "essay with side notes",
            "magazine feature",
            "personal field journal",
            "visual longread",
            "compact newsletter",
            "premium article page",
            "archive inspired article",
            "travel diary feature",
            "annotated cultural guide",
            "slow media dossier",
            "local magazine special issue",
            "interactive reading notebook",
            "multilingual cultural dossier",
            "field guide with editorial annotations"
        ]),
        "target_kb": target_kb,
        "target_chars": target_kb * 1024,
        "section_count": random.randint(11, 16),
        "related_count": random.randint(8, 12),
        "note_count": random.randint(8, 13),
        "svg_count": random.randint(5, 8),
        "data_panels": random.randint(3, 5)
    }


def hsl(h, s=85, l=55):
    return f"hsl({h} {s}% {l}%)"


def make_svg_favicon(profile):
    seed = profile["favicon_seed"]
    shape = profile["favicon_shape"]

    h1 = profile["hue1"]
    h2 = profile["hue2"]
    h3 = profile["hue3"]

    c1 = hsl(h1, 88, 56)
    c2 = hsl(h2, 86, 52)
    c3 = hsl(h3, 82, 64)

    nums = [int(seed[i:i + 2], 16) for i in range(0, 24, 2)]
    mark = re.sub(r"[^a-zA-Z0-9]", "", profile["signature"]).upper()[:2] or "NX"

    x1 = 12 + nums[0] % 40
    y1 = 12 + nums[1] % 40
    r1 = 8 + nums[2] % 18
    r2 = 4 + nums[3] % 10
    rot = nums[4] % 70 - 35
    rx = 12 + nums[5] % 14

    gid = "g" + profile["signature"]
    sid = "s" + profile["signature"]
    rid = "r" + profile["signature"]

    defs = f'''
    <defs>
      <linearGradient id="{gid}" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="{c1}"/>
        <stop offset="52%" stop-color="{c2}"/>
        <stop offset="100%" stop-color="{c3}"/>
      </linearGradient>
      <radialGradient id="{rid}" cx="32%" cy="24%" r="74%">
        <stop offset="0%" stop-color="#ffffff" stop-opacity=".95"/>
        <stop offset="45%" stop-color="#ffffff" stop-opacity=".22"/>
        <stop offset="100%" stop-color="#ffffff" stop-opacity="0"/>
      </radialGradient>
      <filter id="{sid}" x="-25%" y="-25%" width="150%" height="150%">
        <feDropShadow dx="0" dy="4" stdDeviation="5" flood-color="#000000" flood-opacity=".34"/>
      </filter>
    </defs>
    '''

    if shape == "circle":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#0b1020"/>
        <circle cx="32" cy="32" r="24" fill="url(#{gid})" filter="url(#{sid})"/>
        <circle cx="{x1}" cy="{y1}" r="{r2}" fill="url(#{rid})"/>
        <path d="M17 39 C25 23, 38 47, 49 21" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" opacity=".9"/>
        '''
    elif shape == "diamond":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#090b12"/>
        <path d="M32 6 L58 32 L32 58 L6 32 Z" fill="url(#{gid})" filter="url(#{sid})"/>
        <path d="M21 32 L30 41 L45 22" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" opacity=".92"/>
        '''
    elif shape == "hexagon":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#10131f"/>
        <path d="M32 6 L55 19 L55 45 L32 58 L9 45 L9 19 Z" fill="url(#{gid})"/>
        <circle cx="32" cy="32" r="{r1}" fill="none" stroke="#fff" stroke-width="4" opacity=".84"/>
        <circle cx="32" cy="32" r="{r2}" fill="#fff"/>
        '''
    elif shape == "orbit":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#070914"/>
        <circle cx="32" cy="32" r="22" fill="url(#{gid})"/>
        <ellipse cx="32" cy="32" rx="27" ry="10" fill="none" stroke="#fff" stroke-width="3" opacity=".75" transform="rotate({rot} 32 32)"/>
        <ellipse cx="32" cy="32" rx="25" ry="9" fill="none" stroke="#fff" stroke-width="2" opacity=".42" transform="rotate({-rot} 32 32)"/>
        <circle cx="{x1}" cy="{y1}" r="5" fill="#fff"/>
        '''
    elif shape == "wave":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="url(#{gid})"/>
        <path d="M7 40 C17 25, 25 52, 35 35 S50 20, 58 32" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round"/>
        <path d="M9 25 C18 14, 27 34, 38 22 S51 12, 57 20" fill="none" stroke="#fff" stroke-opacity=".5" stroke-width="3" stroke-linecap="round"/>
        '''
    elif shape == "monogram":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="url(#{gid})"/>
        <circle cx="50" cy="14" r="10" fill="#fff" opacity=".24"/>
        <circle cx="14" cy="52" r="13" fill="#000" opacity=".16"/>
        <text x="32" y="40" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="22" font-weight="900" fill="#fff" letter-spacing="-1">{mark}</text>
        '''
    elif shape == "split":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#0a0d16"/>
        <path d="M8 8 H56 V32 H8 Z" fill="{c1}"/>
        <path d="M8 32 H56 V56 H8 Z" fill="{c2}"/>
        <path d="M8 8 H32 V56 H8 Z" fill="{c3}" opacity=".75"/>
        <circle cx="32" cy="32" r="15" fill="#fff" opacity=".9"/>
        <circle cx="32" cy="32" r="7" fill="#0a0d16"/>
        '''
    elif shape == "stack":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#10131f"/>
        <rect x="13" y="15" width="36" height="36" rx="10" fill="{c1}" transform="rotate({rot} 32 32)"/>
        <rect x="17" y="12" width="34" height="34" rx="10" fill="{c2}" opacity=".82" transform="rotate({-rot} 32 32)"/>
        <rect x="20" y="19" width="24" height="24" rx="8" fill="#fff" opacity=".9"/>
        '''
    elif shape == "spark":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="url(#{gid})"/>
        <path d="M32 8 L38 26 L56 32 L38 38 L32 56 L26 38 L8 32 L26 26 Z" fill="#fff" opacity=".92"/>
        <circle cx="32" cy="32" r="{r2}" fill="{c2}"/>
        '''
    elif shape == "leaf":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#0c1510"/>
        <path d="M14 47 C15 21, 37 8, 53 12 C53 35, 40 53, 17 51 Z" fill="url(#{gid})"/>
        <path d="M19 47 C28 35, 39 25, 50 15" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" opacity=".8"/>
        '''
    elif shape == "grid":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#0b0d14"/>
        <rect x="12" y="12" width="17" height="17" rx="5" fill="{c1}"/>
        <rect x="35" y="12" width="17" height="17" rx="5" fill="{c2}"/>
        <rect x="12" y="35" width="17" height="17" rx="5" fill="{c3}"/>
        <rect x="35" y="35" width="17" height="17" rx="5" fill="#fff" opacity=".9"/>
        '''
    elif shape == "bolt":
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="url(#{gid})"/>
        <path d="M36 6 L16 35 H31 L27 58 L49 27 H34 Z" fill="#fff" opacity=".92"/>
        '''
    else:
        body = f'''
        <rect width="64" height="64" rx="{rx}" fill="#080b14"/>
        <path d="M43 9 C34 13 28 23 28 34 C28 45 34 52 44 55 C28 58 12 46 12 31 C12 17 25 7 43 9 Z" fill="url(#{gid})"/>
        <circle cx="{x1}" cy="{y1}" r="{r2}" fill="#fff" opacity=".86"/>
        '''

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
{defs}
{body}
</svg>'''

    return re.sub(r"\s+", " ", svg).strip()


def favicon_data_uri(profile):
    svg = make_svg_favicon(profile)
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def inject_favicon(html, profile):
    href = favicon_data_uri(profile)

    html = re.sub(
        r'<link\s+[^>]*rel=["\'](?:shortcut\s+icon|icon|apple-touch-icon|mask-icon)["\'][^>]*>\s*',
        '',
        html,
        flags=re.I
    )

    html = re.sub(
        r'<meta\s+[^>]*name=["\']theme-color["\'][^>]*>\s*',
        '',
        html,
        flags=re.I
    )

    block = f'''
    <link rel="icon" href="{href}" type="image/svg+xml" sizes="any">
    <link rel="shortcut icon" href="{href}" type="image/svg+xml">
    <meta name="theme-color" content="{hsl(profile['hue1'], 88, 56)}">
    '''

    if re.search(r"</head>", html, flags=re.I):
        html = re.sub(r"</head>", block + "\n</head>", html, count=1, flags=re.I)
    else:
        html = block + "\n" + html

    return html


def repair_existing_index_favicons():
    fixed = 0

    for html_path in OUTPUT_DIR.glob("index_*.html"):
        try:
            html = html_path.read_text(encoding="utf-8", errors="ignore")

            if "data:image/svg+xml;base64," in html and ('rel="icon"' in html.lower() or "rel='icon'" in html.lower()):
                continue

            seed = hashlib.sha256((html_path.stem + str(time.time())).encode("utf-8")).hexdigest()

            profile = {
                "hue1": int(seed[0:2], 16) % 360,
                "hue2": int(seed[2:4], 16) % 360,
                "hue3": int(seed[4:6], 16) % 360,
                "signature": seed[:12],
                "favicon_seed": seed,
                "favicon_shape": random.choice(FAVICON_SHAPES)
            }

            html = inject_favicon(html, profile)
            html_path.write_text(html, encoding="utf-8")
            fixed += 1

        except Exception as e:
            log(f"[REPAIR-FAIL] file={html_path} error={e}")

    if fixed:
        log(f"[REPAIR] embedded favicon fixed for existing index pages: {fixed}")


def build_prompt(p):
    rtl_block = ""
    if p["dir"] == "rtl":
        rtl_block = """
- This language uses right-to-left reading. Use dir="rtl" on the html element or major content containers where appropriate.
- Make navigation, cards, side notes, buttons, and table of contents work gracefully in RTL.
"""

    return f"""
Create one complete standalone HTML document.

ABSOLUTE OUTPUT RULES:
- Return only the complete HTML source.
- Start with <!doctype html>.
- Use <html lang="{p["html_lang"]}" dir="{p["dir"]}">.
- Include complete <head> and <body>.
- Put all CSS inside this same HTML file.
- Put all JavaScript inside this same HTML file.
- Do not load external images, fonts, scripts, stylesheets, iframes, analytics, APIs, icons, or remote assets.
- Do not use http:// or https:// asset URLs anywhere.
- Do not mention prompts, systems, tools, models, automation, AI, or generation.
- Do not use lorem ipsum.
- Do not use placeholder content.
- Do not output markdown fences.
- Finish the complete document with </html>.

LANGUAGE:
- Language profile: {p["language"]}
- Writing instruction: {p["language_instruction"]}
- All visible interface text and article text should follow this language profile.
- If bilingual or multilingual, make the language mix intentional, labelled, readable, and editorial.
{rtl_block}

TARGET SIZE:
- Final HTML source should be approximately {p["target_kb"]}KB.
- Aim for at least {p["target_chars"]} UTF-8 bytes.
- Do not pad with meaningless repetition.
- Reach the size naturally with rich article writing, detailed CSS, several components, many cards, inline SVG illustrations, long captions, side notes, related posts, and defensive JavaScript.

PAGE IDENTITY:
- Topic: {p["topic"]}
- Publication date: {p["date"]}
- Footer year: {p["year"]}
- Unique signature: {p["signature"]}

VISUAL DIRECTION:
- Visual style: {p["style"]}
- Layout: {p["layout"]}
- Structure: {p["structure"]}
- Mood: {p["mood"]}
- Density: {p["density"]}
- Color hints: {p["hue1"]}, {p["hue2"]}, {p["hue3"]}
- Border radius: {p["radius"]}
- Max width: {p["width"]}

DESIGN REQUIREMENTS:
- Make it look like a polished independent magazine, premium journal, cultural dossier, or high-end personal publication.
- Avoid ordinary templates.
- Use a distinctive visual system: layered backgrounds, gradients, patterns, cards, editorial lines, shadows, borders, soft glow, typographic rhythm, metadata chips, decorative dividers, floating labels, and strong section hierarchy.
- Use CSS custom properties extensively.
- Include responsive layouts for desktop, tablet, and mobile.
- Include thoughtful hover states, focus states, transitions, and reduced-motion support.
- Include at least {p["svg_count"]} original inline SVG decorative illustrations, maps, diagrams, patterns, or editorial scenes.
- Include at least {p["data_panels"]} compact data panels, index panels, weather cards, route cards, archive cards, or small dashboard widgets.
- The page should be visually impressive and clearly different from a basic blog.

REQUIRED CONTENT:
- Navigation.
- Large hero area.
- Title and subtitle.
- Author block.
- Publication date.
- Reading time.
- Tags.
- Editorial summary.
- Table of contents.
- At least {p["section_count"]} substantial article sections.
- At least two pull quotes.
- At least one useful checklist, field guide, method list, or practical routine.
- At least {p["note_count"]} note cards, side cards, marginalia blocks, observation cards, or expandable details.
- One timeline, route, process, archive, or seasonal rhythm section.
- One compact data/index panel.
- One conclusion.
- At least {p["related_count"]} related posts.
- Footer with year {p["year"]}.

WRITING STYLE:
- Make it feel like a real independent blog article or magazine longread.
- Use concrete details: streets, rooms, tools, food, weather, light, windows, bags, benches, notebooks, transit, receipts, plants, radios, cafes, stations, rain, markets, and small routines.
- Avoid generic motivational language.
- Avoid repetitive sentence patterns.
- Make the article rich, specific, believable, and calm.
- Use paragraph variety, captions, annotations, lists, micro-stories, and precise sensory details.

INTERACTIONS:
Include these features: {", ".join(p["interactions"])}.

Mandatory interactions:
- Reading progress bar.
- Back to top button.
- Smooth scrolling.
- Active table of contents marker.
- Copy article link button.
- Theme switcher.
- Font size controls.
- Collapsible notes or expandable cards.
- Mobile menu.
- Scroll reveal.
- JavaScript must be defensive and not throw errors if an element is missing.

ACCESSIBILITY:
- Use semantic HTML.
- Use accessible labels.
- Use keyboard-friendly controls.
- Use visible focus states.
- Respect prefers-reduced-motion.

FINAL REMINDER:
- Single HTML file only.
- No external resources.
- No remote URLs.
- No unfinished document.
- Output only the complete HTML.
""".strip()


def call_model(prompt):
    client = make_client()
    chunks = []
    finish_reason = None

    stream = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=TEMPERATURE,
        top_p=TOP_P,
        max_tokens=MAX_TOKENS,
        stream=True
    )

    for event in stream:
        try:
            if not event.choices:
                continue

            choice = event.choices[0]

            if getattr(choice, "finish_reason", None):
                finish_reason = choice.finish_reason

            delta = choice.delta
            piece = getattr(delta, "content", None)

            if piece:
                chunks.append(piece)

        except Exception:
            continue

    text = "".join(chunks)

    if finish_reason == "length":
        raise RuntimeError("model output truncated by max_tokens")

    return text


def generate_one(num):
    for attempt in range(1, RETRY_PER_PAGE + 1):
        profile = make_profile(num)

        try:
            log(
                f"[CALL] index={num} attempt={attempt} "
                f"lang={profile['language']} style={profile['style']} icon={profile['favicon_shape']} "
                f"target={profile['target_kb']}KB"
            )

            raw = call_model(build_prompt(profile))
            html = clean_html(raw)

            html = html.replace("{{CURRENT_YEAR}}", str(CURRENT_YEAR))
            html = re.sub(r"©\s*20\d{2}", f"© {CURRENT_YEAR}", html)

            html = inject_favicon(html, profile)

            ok, reason = validate_html(html)
            if not ok:
                raise RuntimeError(reason)

            html_path = make_file_path(num)
            html_path.write_text(html, encoding="utf-8")

            size_kb = round(len(html.encode("utf-8")) / 1024, 1)

            meta_path = html_path.with_suffix(".json")
            meta_path.write_text(
                json.dumps(profile, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

            return {
                "ok": True,
                "num": num,
                "file": str(html_path),
                "language": profile["language"],
                "style": profile["style"],
                "icon": profile["favicon_shape"],
                "size_kb": size_kb,
                "error": None
            }

        except Exception as e:
            msg = str(e)
            low = msg.lower()

            wait_seconds = NORMAL_SLEEP

            if "blocked" in low:
                wait_seconds = BLOCK_SLEEP
            elif "524" in low:
                wait_seconds = BLOCK_SLEEP
            elif "timeout" in low:
                wait_seconds = BLOCK_SLEEP
            elif "rate" in low or "limit" in low:
                wait_seconds = BLOCK_SLEEP
            elif "cloudflare" in low:
                wait_seconds = BLOCK_SLEEP
            elif "truncated" in low:
                wait_seconds = NORMAL_SLEEP

            log(f"[RETRY] index={num} attempt={attempt}/{RETRY_PER_PAGE} error={msg} sleep={wait_seconds}s")
            time.sleep(wait_seconds)

    return {
        "ok": False,
        "num": num,
        "file": None,
        "language": None,
        "style": None,
        "icon": None,
        "size_kb": None,
        "error": "failed after retries"
    }


def main():
    repair_existing_index_favicons()

    log("=" * 78)
    log("Concurrent streaming single-HTML generator with embedded SVG favicons started")
    log(f"Base URL: {BASE_URL}")
    log(f"Model: {MODEL}")
    log(f"Target success: {TARGET_SUCCESS}")
    log(f"Output dir: {OUTPUT_DIR}")
    log(f"Existing index HTML: {count_html()}")
    log(f"Workers: {MAX_WORKERS}")
    log(f"Max tokens: {MAX_TOKENS}")
    log("=" * 78)

    next_num = count_html() + 1
    active = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while count_html() < TARGET_SUCCESS or active:
            while count_html() + len(active) < TARGET_SUCCESS and len(active) < MAX_WORKERS:
                future = executor.submit(generate_one, next_num)
                active.add(future)
                log(f"[SUBMIT] index={next_num} active={len(active)} success={count_html()}/{TARGET_SUCCESS}")
                next_num += 1
                time.sleep(random.randint(1, 4))

            if not active:
                break

            done, active = wait(active, return_when=FIRST_COMPLETED)

            for future in done:
                try:
                    result = future.result()
                except Exception as e:
                    log(f"[FUTURE-FAIL] error={e}")
                    continue

                if result["ok"]:
                    log(
                        f"[OK] index={result['num']} lang={result['language']} "
                        f"icon={result['icon']} size={result['size_kb']}KB file={result['file']}"
                    )
                else:
                    log(f"[FAIL] index={result['num']} error={result['error']}")

                delay = random.randint(MIN_DELAY_AFTER_TASK, MAX_DELAY_AFTER_TASK)
                log(f"[PAUSE] {delay}s before filling next slot")
                time.sleep(delay)

            log(f"[PROGRESS] success={count_html()}/{TARGET_SUCCESS} active={len(active)}")

    log("=" * 78)
    log(f"DONE total={count_html()}")
    log("=" * 78)


if __name__ == "__main__":
    main()
