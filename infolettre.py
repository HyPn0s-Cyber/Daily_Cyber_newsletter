import os
import feedparser
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import date, datetime, timezone
import requests
from bs4 import BeautifulSoup

# ---- Résumé automatique avec SUMY ----
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

import nltk
nltk.download('punkt', quiet=True)
nltk.download('punkt_tab', quiet=True)

def summarize_text(text, sentences_count=2):
    """Résumé en quelques phrases avec Sumy (LSA)."""
    parser = PlaintextParser.from_string(text, Tokenizer("english"))
    summarizer = LsaSummarizer()
    summary = summarizer(parser.document, sentences_count)
    return " ".join(str(sentence) for sentence in summary)

def fetch_article_content(url):
    """Récupère le contenu principal d’un article (texte brut)."""
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        paragraphs = [p.get_text() for p in soup.find_all("p")]
        return " ".join(paragraphs[:20])  # limite à 20 paragraphes
    except Exception:
        return ""

def get_cves_today():
    """Récupère les CVE publiées aujourd’hui via l’API NVD avec un résumé et lien cliquable."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={today}T00:00:00.000&pubEndDate={today}T23:59:59.000"
    )
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            cves.append((cve_id, desc, link))

        return cves
    except Exception as e:
        print(f"Erreur récupération CVE : {e}")
        return []

# ---- Liste des flux RSS ----
rss_feeds = [
    "https://www.cert.ssi.gouv.fr/feed/",   # CERT-FR
    "https://us-cert.cisa.gov/ncas/alerts.xml",  # USA
    "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en", # Canada
    "https://krebsonsecurity.com/feed/",
    "https://threatpost.com/feed/",
    "https://feeds.feedburner.com/securityweek",
    "https://www.zdnet.com/topic/security/rss.xml",
    "https://feeds.feedburner.com/TheHackersNews"
]

# ---- Collecte des articles ----
articles = []
today = datetime.now(timezone.utc).date()

for url in rss_feeds:
    feed = feedparser.parse(url)
    for entry in feed.entries[:5]:  # max 5 articles par site
        # Vérifier la date
        if hasattr(entry, "published_parsed"):
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).date()
            if published != today:
                continue  # ignorer si pas publié aujourd’hui

        title = entry.title
        link = entry.link
        description = getattr(entry, "summary", "")

        # Récupérer texte complet et résumer
        content = fetch_article_content(link)
        if content:
            summary = summarize_text(content, 2)
        else:
            summary = description[:200]  # fallback

        articles.append((title, link, summary))

# ---- Récupérer les CVE du jour ----
cves = get_cves_today()

# ---- Création du mail HTML ----
html_items = ""
for title, link, summary in articles:
    html_items += f"""
    <li>
        <a href="{link}"><b>{title}</b></a><br>
        <p>{summary}</p>
    </li>
    """

html_cves = ""
for cve in cves:
    if len(cve) == 3:
        cve_id, desc, link = cve
        html_cves += f"""
        <li>
            <b><a href="{link}">{cve_id}</a></b>: {desc}
        </li>
        """
    else:  # fallback si jamais pas de lien
        cve_id, desc = cve
        html_cves += f"""
        <li>
            <b>{cve_id}</b>: {desc}
        </li>
        """

html_content = f"""
<html>
  <body>
    <h2>Résumé cybersécurité du {date.today()}</h2>
    <h3>📰 Articles du jour</h3>
    <ul>
      {html_items if html_items else "<li>Aucun article publié aujourd'hui.</li>"}
    </ul>
    <h3>⚠️ CVE du jour</h3>
    <ul>
      {html_cves if html_cves else "<li>Aucune nouvelle CVE aujourd'hui.</li>"}
    </ul>
    <hr>
    <p><i>Infolettre générée automatiquement. Crédits Ги́пн0с 2025</i></p>
  </body>
</html>
"""

# ---- Envoi du mail (Sécurisé avec variables d'environnement) ----
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

if not EMAIL_USER or not EMAIL_PASSWORD:
    print("❌ Erreur : Les variables EMAIL_USER ou EMAIL_PASSWORD ne sont pas configurées dans les secrets GitHub.")
    exit(1)

msg = MIMEMultipart("alternative")
msg["Subject"] = f"Résumé cybersécurité du {date.today()}"
msg["From"] = EMAIL_USER
msg["To"] = EMAIL_USER  # Envoi automatique à votre propre adresse
msg.attach(MIMEText(html_content, "html"))

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
    print("✅ Mail envoyé avec succès !")
except Exception as e:
    print(f"❌ Erreur lors de l'envoi du mail : {e}")