"""What the email says: visible text, hidden text, and phrases typical of phishing (English and French).

Hidden text matters twice. Attackers hide words to fool spam filters
("salting") and, now, to give instructions to AI assistants that read the
email. But legitimate newsletters also hide a short preview line, so the facts
record how much text is hidden and how, and the rules decide what is too much.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

from phishtriage.domains import INVISIBLE_CHARACTERS, strip_invisible

MAX_TEXT = 200_000  # characters of visible text examined
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_NOT_RENDERED = {"script", "style", "head", "title", "template"}
_BLOCK = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}
_WHITE = {"#fff", "#ffffff", "white", "rgb(255,255,255)"}


def normalize(text: str) -> str:
    """Lowercase, accents removed, spaces collapsed (line breaks kept), so patterns stay simple."""
    text = unicodedata.normalize("NFKC", strip_invisible(text)).casefold()  # "ver\u200bify" must still match "verify"
    text = "".join(char for char in unicodedata.normalize("NFKD", text) if not unicodedata.combining(char))
    text = text.replace("’", "'")
    return re.sub(r"[ \t\r\f\v ]+", " ", re.sub(r"\s*\n\s*", "\n", text)).strip()


def _hidden_reason(tag: str, attrs: dict[str, str]) -> str:
    if "hidden" in attrs:
        return "hidden attribute"
    style = re.sub(r"\s+", "", attrs.get("style", "").lower())
    if not style:
        return ""
    if "display:none" in style:
        return "display:none"
    if "visibility:hidden" in style:
        return "visibility:hidden"
    if "mso-hide:all" in style:
        return "mso-hide:all"
    if re.search(r"font-size:0(\.\d+)?(px|pt|em|rem|%)?(;|$|!)|font-size:1px", style):
        return "zero font size"
    if re.search(r"opacity:0(\.0\d*)?(;|$|!)", style):
        return "opacity:0"
    if re.search(r"(max-)?height:0(px)?(;|$|!)", style) and "overflow:hidden" in style:
        return "zero height"
    if re.search(r"(text-indent|left|top|margin-left):-\d{3,}", style):
        return "moved off screen"
    color = re.search(r"(?<![-\w])color:([^;!]+)", style)
    background = re.search(r"background(?:-color)?:([^;!]+)", style)
    if color and background and color.group(1) == background.group(1).split()[0]:
        return "text colour equals background"
    if color and color.group(1) in _WHITE and background and background.group(1).split()[0] in _WHITE:
        return "text colour equals background"
    return ""


class _TextReader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, str]] = []  # (tag, reason it hides its content, or "")
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.techniques: set[str] = set()
        self.images = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "img":
            self.images += 1
        if tag in _BLOCK:
            self.visible.append("\n")
        if tag in _VOID:
            return
        self.stack.append((tag, _hidden_reason(tag, {k.lower(): (v or "") for k, v in attrs})))
        if len(self.stack) > 500:  # hostile nesting: keep memory bounded
            del self.stack[:100]

    def handle_startendtag(self, tag: str, attrs) -> None:
        if tag == "img":
            self.images += 1
        if tag in _BLOCK:
            self.visible.append("\n")

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break
        if tag in _BLOCK:
            self.visible.append("\n")

    def handle_data(self, data: str) -> None:
        if any(tag in _NOT_RENDERED for tag, _ in self.stack):
            return
        reasons = [reason for _, reason in self.stack if reason]
        if reasons:
            if data.strip():
                self.hidden.append(data)
                self.techniques.add(reasons[-1])
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        text = data.strip()
        # <!--[if mso]> blocks are Outlook-only layout, not hidden prose
        if not text.startswith("[if") and len(re.findall(r"[^\W\d_]{2,}", text)) >= 5:
            self.hidden.append(text)
            self.techniques.add("HTML comment")


def read_html(html: str) -> _TextReader:
    reader = _TextReader()
    try:
        reader.feed(html[:5_000_000])
        reader.close()
    except Exception:  # noqa: BLE001, S110 - broken markup must not stop the analysis
        pass
    return reader


def _patterns(*expressions: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{expression})" for expression in expressions))


# Patterns run on normalize()d text: lowercase, no accents. English first, then French.
SIGNALS: dict[str, re.Pattern] = {
    "credential_request": _patterns(
        r"verify (your|the) (account|identity|email|mailbox|information|details)",
        r"confirm (your|the) (account|identity|password|credentials|email address|details|information)",
        r"(update|validate|re-?validate|reactivate|restore|unlock) (your|the) (account|mailbox|password|payment|billing|information|details|credentials)",
        r"your (password|mailbox|account|email) (will|is about to|is going to) (expire|be (deactivated|disabled|closed|deleted|suspended))",
        r"(mailbox|storage|inbox|email|quota|disk)( space| limit| quota)? (is |has been |have been |was )?(almost )?"
        r"(full|exceeded|reached|over (the |its )?limit)",
        r"(log ?in|sign ?in) (to|into) (your )?(account|mailbox|portal) (to|and|now)",
        r"unusual (sign-?in|login) activity",
        r"(enter|provide|submit|confirm) your (password|credentials|login details|card (number|details)|pin|otp|verification code)",
        r"verifie[rz]? (votre|vos) (compte|identite|informations|coordonnees|adresse)",
        r"confirme[rz]? (votre|vos) (compte|identite|mot de passe|identifiants|informations|coordonnees)",
        r"(mettre a jour|mettez a jour|actualise[rz]?|reactive[rz]?|debloque[rz]?) (votre|vos) (compte|informations|coordonnees|mot de passe|moyen de paiement)",
        r"votre (mot de passe|compte|boite (mail|aux lettres|de reception)) (va expirer|expire|sera (suspendu|desactive|bloque|supprime))",
        r"(boite|espace) (mail|de stockage|aux lettres) (est )?(pleine|saturee?)",
        r"(limite|quota) (de stockage )?(est )?(atteinte?|depassee?)",
        r"(saisisse[zr]|entre[zr]|fournisse[zr]|renseigne[zr]) (votre|vos) (mot de passe|identifiants|code|numero de carte)",
    ),
    "urgency": _patterns(
        # Short deadlines only: "within 24 hours" is pressure, "within 30 days" is ordinary
        r"\burgent\b", r"\bimmediate(ly)?\b", r"within ([1-9]|[1-6]\d|7[0-2]) ?(hours?|hrs?|h)\b", r"within [1-3] ?days?\b",
        r"(final|last) (notice|warning|reminder)",
        r"action required", r"expires? today",
        r"(will be|has been|is) (permanently )?(suspended|closed|deactivated|disabled|blocked|terminated|locked|deleted)",
        r"failure to (respond|comply|verify)",
        r"\burgent", r"\bimmediatement\b", r"(sous|dans les) ([1-9]|[1-6]\d|7[0-2]) ?(heures?|h)\b", r"(sous|dans les) [1-3] ?jours?\b",
        r"(dernier|ultime) (avertissement|rappel|avis)",
        r"action requise", r"expire aujourd'?hui", r"(sera|a ete|est) (definitivement )?(suspendue?|bloquee?|fermee?|desactivee?|resiliee?|supprimee?)\b",
        r"sans (reponse|action) de votre part",
    ),
    "payment": _patterns(
        r"(invoice|payment|bill) (is )?(attached|overdue|past due|pending|failed|declined|unsuccessful)",
        r"\b(wire|bank) transfer\b", r"\bunpaid\b", r"outstanding (balance|invoice|payment)",
        r"payment (method|details|information) (has )?(expired|failed|been declined)",
        r"facture (impayee|en attente|en retard|jointe|ci-jointe)", r"paiement (refuse|echoue|en attente|rejete|en retard)",
        r"\bvirement\b", r"(solde|montant) (impaye|du|restant)",
    ),
    "bank_details_change": _patterns(
        r"(new|updated|change of|changed) (bank|banking) (details|account|information)",
        r"(our|my) (bank|banking) (details|account) (has|have) changed",
        r"(update|change) (my|the|your) (direct deposit|payroll|salary)",
        r"(nouveau|nouvelles?|changement de) (rib|coordonnees bancaires|compte bancaire)",
        r"\b(iban|rib)\b",
    ),
    "gift_cards": _patterns(
        r"gift ?cards?", r"(itunes|apple|google play|steam|ebay|vanilla) (gift )?cards?", r"scratch (off )?the (back|card)",
        r"cartes? cadeaux?", r"\b(transcash|neosurf|paysafecard|pcs mastercard)\b",
    ),
    "secrecy": _patterns(
        r"are you (available|at your desk|free right now)", r"(i need|need) (a quick|a|you to do a|your) (favou?r|task)",
        r"(keep|treat) (this|it) (confidential|between us|private)", r"(don'?t|do not) (tell|share this with|discuss this with) (anyone|others)",
        r"i'?m (in a meeting|on a call|boarding)", r"(send|reply with) your (whatsapp|mobile|cell|phone) number",
        r"(etes-vous|es-tu|tu es|vous etes) disponible", r"j'?ai besoin (d'?un (petit )?service|que (tu|vous) (me )?fass)",
        r"(restez|reste|gardez|garde) (discret|discrete|confidentiel)", r"en toute discretion", r"je suis en reunion",
    ),
    "prize": _patterns(
        # "won" but not "won't": "you won't have a class" was a prize until rules-v1.1 (all 3 development matches)
        r"you('ve| have)? (won\b(?!'t)|been selected|been chosen)", r"\bcongratulations\b",
        r"claim your (prize|reward|gift|winnings|refund)",
        r"\b(lottery|inheritance|sweepstakes)\b",
        r"vous avez (ete selectionnee?|gagne|remporte)", r"\bfelicitations\b", r"(recuperez|reclamez|obtenez) votre (prix|cadeau|recompense|lot|gain)",
        r"tirage au sort", r"\b(loterie|heritage)\b", r"cadeau (gratuit|offert)",
    ),
    "delivery": _patterns(
        r"(package|parcel|shipment|delivery) (could not be|was not|wasn'?t|cannot be) delivered",
        r"(package|parcel|shipment) (is )?(on hold|pending|waiting|held|returned)", r"delivery (attempt )?(failed|unsuccessful)",
        r"(customs|redelivery|shipping) (fee|charge|duty)", r"(reschedule|confirm) (your )?delivery",
        r"(colis|envoi) (en attente|bloque|retenu|non livre|n'?a pas pu etre livre)", r"livraison (echouee|en attente|impossible|suspendue)",
        r"frais de (douane|livraison|reexpedition|port)", r"(reprogrammer|confirmer) (la |votre )?livraison",
    ),
    "callback": _patterns(
        r"call (us|now|immediately|our (support|help|billing|customer))",
        r"if you did(n'?t| not) (authori[sz]e|make|order|request) .{0,80}(call|contact)",
        r"(cancel|dispute) (this |the |your )?(order|subscription|charge|transaction|renewal) .{0,80}(call|contact|phone)",
        r"auto-?renew(al|ed)?\b",
        r"appele[rz](-nous)?\b", r"contacte[rz] (notre|le) service (client|clientele)? ?au", r"renouvellement automatique",
    ),
    "crypto": _patterns(
        r"\b(bitcoin|btc|ethereum|usdt|tether|solana|dogecoin|litecoin|xrp|cryptocurrency|crypto (wallet|card))\b",
        r"(seed|recovery|secret) phrase",
        r"phrase (de recuperation|secrete)", r"portefeuille (crypto|numerique)",
    ),
    "qr_prompt": _patterns(r"scan (the|this|our|below)? ?qr", r"\bqr ?code\b", r"scanne[rz]? (le|ce) (qr|code)", r"\bcode qr\b"),
    "open_attachment": _patterns(
        r"(open|see|view|review|download) (the )?(attached|enclosed|attachment)", r"(enable|activate) (editing|content|macros)",
        r"(the )?(password|passcode) (to open|for) (the )?(attachment|file|document|archive|zip)", r"\bpassword is ?:",
        r"(ouvre[rz]|consulte[rz]|telecharge[rz]|voir) (la |le )?(piece jointe|document joint|fichier joint|ci-joint)",
        r"activer (la modification|le contenu|les macros)", r"mot de passe (de l'?archive|du fichier|pour ouvrir)",
    ),
}

# Instructions aimed at an AI that reads the email (prompt injection)
INJECTION = _patterns(
    r"ignore (all |any )?(the )?(previous|prior|above|earlier|preceding) (instructions|prompts|rules|messages)",
    r"disregard (all |the )?(previous|prior|above|earlier) ",
    r"(you are|you're) (now )?(an? )?(ai|assistant|language model|llm|chatbot)\b",
    r"\b(system|developer) (prompt|message|instruction)s?\b",
    r"(classify|mark|label|treat|report|flag) (this|the) (email|message|mail) as (safe|legitimate|clean|benign|harmless|not phishing|trusted)",
    r"this (email|message) is (safe|legitimate|not phishing|not malicious|trusted|verified)",
    r"(do not|don'?t) (flag|report|quarantine|block) (this|it)\b",
    r"note to (the )?(ai|assistant|model|bot|llm)",
    r"ignore[rz]? (les |toutes les )?(instructions|consignes) (precedentes|anterieures|ci-dessus)",
    r"(classe|marque|considere)[rz]? (cet|ce) (e-?mail|message|courriel) comme (sur|legitime|fiable|non malveillant)",
    r"ce (message|courriel|e-?mail) est (sur|legitime|fiable|verifie)",
    r"(tu es|vous etes) (une |un )?(ia|assistant)\b",
)

# Common short words per language (after accents are removed). Words shared by several languages
# ("de", "en", "que") are left out so that one language clearly wins.
_STOPWORDS = {
    "en": {"the", "and", "you", "your", "to", "of", "is", "for", "this", "please", "with", "are", "have", "will"},
    "fr": {"le", "la", "les", "des", "vous", "votre", "vos", "est", "pour", "une", "du", "avec", "nous", "sur", "pas"},
    "de": {"der", "die", "das", "und", "ist", "nicht", "sie", "ihr", "ihre", "mit", "fur", "auf", "wir", "zu", "den",
           "ein", "eine", "sich"},
    "nl": {"het", "een", "van", "je", "jij", "niet", "voor", "met", "op", "zijn", "ook", "wat", "jouw", "bij", "naar",
           "dat", "er"},
    "pt": {"os", "um", "uma", "voce", "nao", "para", "com", "seu", "sua", "mais", "sao", "pelo", "pela", "ao"},
    "es": {"el", "los", "las", "usted", "con", "su", "por", "tu", "este", "del", "al", "muy", "tus"},
    "it": {"il", "gli", "per", "che", "non", "sono", "della", "tuo", "questo", "alla", "nel"},
}


@dataclass
class TextFacts:
    language: str = "unknown"  # en, fr, ar, de, nl, pt, es, it, or unknown (too little text to tell)
    words: int = 0  # visible words
    images: int = 0  # number of pictures in the HTML
    mostly_images: bool = False  # pictures but almost no text: filters and readers have nothing to judge
    credential_request: list[str] = field(default_factory=list)  # phrases asking for passwords, codes or account verification
    urgency: list[str] = field(default_factory=list)  # deadlines of 72 hours or less, threats of suspension or closure
    payment: list[str] = field(default_factory=list)  # invoices, failed payments, transfers
    bank_details_change: list[str] = field(default_factory=list)  # new bank details, IBAN or RIB changes
    gift_cards: list[str] = field(default_factory=list)  # gift cards and prepaid vouchers
    secrecy: list[str] = field(default_factory=list)  # "are you available?", "keep this confidential" (CEO fraud)
    prize: list[str] = field(default_factory=list)  # prizes, lotteries, 'you have won'
    delivery: list[str] = field(default_factory=list)  # parcel delivery problems, customs fees
    callback: list[str] = field(default_factory=list)  # asks the reader to phone (callback phishing)
    crypto: list[str] = field(default_factory=list)  # bitcoin, wallets, recovery phrases
    qr_prompt: list[str] = field(default_factory=list)  # asks the reader to scan a QR code
    open_attachment: list[str] = field(default_factory=list)  # asks to open the attachment, enable macros, or gives its password
    injection_phrases: list[str] = field(default_factory=list)  # instructions to an AI in the visible text or subject
    hidden_words: int = 0  # number of words a reader cannot see
    hidden_techniques: list[str] = field(default_factory=list)  # how it was hidden: display:none, zero font size, same colour as background...
    hidden_injection_phrases: list[str] = field(default_factory=list)  # instructions to an AI in hidden text
    hidden_sample: str = ""  # start of the hidden text, for the analyst
    invisible_characters: int = 0  # zero-width and similar characters in the visible text


def _matches(pattern: re.Pattern, text: str, limit: int = 3) -> list[str]:
    found = []
    for match in pattern.finditer(text):
        phrase = match.group(0).strip()
        if phrase and phrase not in found:
            found.append(phrase[:80])
        if len(found) >= limit:
            break
    return found


def _language(raw_text: str, words: list[str]) -> str:
    letters = [char for char in raw_text[:5000] if char.isalpha()]
    if letters and sum("\u0600" <= char <= "\u06ff" for char in letters) / len(letters) > 0.3:
        return "ar"
    counts = {language: sum(word in stopwords for word in words) for language, stopwords in _STOPWORDS.items()}
    best = max(counts, key=counts.get)
    return best if counts[best] >= 3 else "unknown"  # too little text to tell


def visible_text(html_body: str, text_body: str) -> tuple[str, _TextReader | None]:
    """The text a reader sees. HTML wins when present, because most mail clients show it."""
    if html_body.strip():
        reader = read_html(html_body)
        return "".join(reader.visible)[:MAX_TEXT], reader
    return text_body[:MAX_TEXT], None


def text_facts(subject: str, html_body: str = "", text_body: str = "", *, shown: str | None = None,
               reader: _TextReader | None = None) -> TextFacts:
    """Pass `shown` and `reader` from visible_text() when you already have them, to parse the HTML once."""
    if shown is None:
        shown, reader = visible_text(html_body, text_body)
    normalized = normalize(f"{subject}\n{shown}")
    words = re.findall(r"[a-z][a-z']+", normalized)
    facts = TextFacts(
        language=_language(shown, words),
        words=len(re.findall(r"\w+", shown)),
        images=reader.images if reader else 0,
        invisible_characters=sum(ord(char) in INVISIBLE_CHARACTERS for char in shown),
    )
    facts.mostly_images = facts.images > 0 and facts.words < 25
    for name, pattern in SIGNALS.items():
        setattr(facts, name, _matches(pattern, normalized))
    facts.injection_phrases = _matches(INJECTION, normalized)

    if reader and reader.hidden:
        hidden = " ".join(" ".join(reader.hidden).split())
        facts.hidden_words = len(re.findall(r"\w+", hidden))
        facts.hidden_techniques = sorted(reader.techniques)
        facts.hidden_injection_phrases = _matches(INJECTION, normalize(hidden))
        facts.hidden_sample = hidden[:200]
    return facts
