"""Static wordlists + probe parameters (no logic, no requests).

Moved out of core/scanner.py so scan logic stays readable. Importers
keep working: scanner re-exports every name defined here.
"""

from __future__ import annotations

# Probe params when a page has no links. Overlaps redirect/traversal/IDOR
# key names on purpose, so the newer checks find targets automatically.
# First 16 are the historic core set (order kept for stable tests).
FUZZ_PARAMS = ["id", "q", "query", "s", "search", "keyword", "name", "term",
               "file", "page", "lang", "redirect", "next", "preview",
               "template", "theme",
               # P3 hidden/uncommon discovery: URL, API, sort/filter, user
               # content and open-redirect families (read-only GET probes).
               "url", "uri", "callback", "return", "dest", "continue",
               "ref", "target", "redirect_uri", "return_url", "callback_url",
               "forward", "goto", "to", "next_url", "sort", "order",
               "filter", "category", "limit", "offset", "uid", "user_id",
               "account", "profile", "comment", "message", "body", "text",
               "title", "content", "desc", "data", "value", "input",
               "email", "format", "view", "action", "type", "webhook",
               "feed", "src", "link", "domain", "host"]

# Endpoints that may accept uploads
UPLOAD_PATHS = [
    "/upload", "/uploads", "/upload.php", "/file-upload",
    "/admin/upload", "/admin/uploads", "/wp-admin/media-new.php",
    "/uploads.php", "/uploader", "/filemanager",
]

# Built-in quick wordlists (category -> paths). Picked by tech fingerprint.
WL_GENERAL = [
    "admin", "administrator", "login", "panel", "dashboard", "manager",
    "portal", "backend", "secure", "private", "internal", "staff",
    "signup", "register", "account", "profile", "settings", "user", "users",
    "member", "session", "token", "auth", "oauth", "sso", "logout",
    "password", "reset", "forgot", "verify", "captcha",
    "search", "help", "contact", "about", "status", "health", "metrics",
    "debug", "console", "support", "ticket", "docs", "blog", "forum",
    "shop", "cart", "checkout", "payment", "order",
    "static", "assets", "images", "css", "js", "fonts", "download",
    "uploads", "upload", "files", "media",
    "backup", "bak", "old", "test", "dev", "config",
    "sitemap.xml", ".well-known/security.txt",
    "api", "graphql", "console", "server-status",
]
WL_WORDPRESS = [
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "xmlrpc.php", "wp-config.php.bak", "readme.html", "license.txt",
    "wp-content/debug.log", "wp-admin/admin-ajax.php", "wp-cron.php",
    "wp-content/uploads", "wp-includes/js/jquery/jquery.js",
    # High-impact plugin install surface (version via vuln-components)
    "wp-content/plugins/hunk-companion/readme.txt",
]
WL_PHP = [
    "phpinfo.php", "info.php", "phpmyadmin", "adminer.php", "pma",
    ".git/HEAD", ".git/config", "composer.json", "composer.lock",
    "config.php.bak", "config.php.old", "index.php.bak", "index.php.old",
    ".env", ".htaccess", ".htpasswd",
]
WL_NODE = [
    "package.json", "package-lock.json", "yarn.lock", ".env", ".env.local",
    "server.js", "app.js", "index.js", ".npmrc", ".nvmrc",
    "webpack.config.js", ".babelrc", "next.config.js",
    # CI/CD exposure (token leaks ride these surfaces)
    ".github/workflows/ci.yml", ".github/workflows/main.yml",
    ".github/workflows/",
]
WL_JAVA = [
    "WEB-INF/web.xml", "WEB-INF/classes/", "actuator", "actuator/health",
    "actuator/env", "actuator/info", "manager/html", "manager/status",
    ".env", "application.properties", "crowd.properties", "config.json",
]
WL_PYTHON = [
    ".env", "settings.py.bak", "settings.py.old", "config.py.bak",
    "requirements.txt", "app.py.bak", "manage.py", "admin/",
    "static/admin/", "media/",
]
WL_API = [
    "api/v1", "api/v2", "api/docs", "api-docs", "swagger", "swagger.json",
    "openapi.json", "graphiql", "playground", "rest", "v1", "v2",
    "api/users", "api/login", "api/health",
]
WL_BACKUP_SECRET = [
    "backup.zip", "www.zip", "site.zip", "old.zip", "test.zip", "bak.zip",
    "backup.tar.gz", "www.tar.gz", "db.sql", "dump.sql", "backup.sql",
    "database.sql", "web.config", ".env.bak", ".env.old", "config.bak",
]
WL_TECHMAP = {
    "wordpress": WL_WORDPRESS + WL_PHP,
    "php": WL_PHP,
    "node": WL_NODE,
    "nextjs": WL_NODE,
    "java": WL_JAVA,
    "python": WL_PYTHON,
}
# kept for compatibility (unused now, --wordlist files take precedence)
DIR_WORDLIST = WL_GENERAL

RECURSE_FILE_SUFFIX = [".bak", ".old", "~", ".swp", ".save"]
RECURSE_DIR_EXTRA = ["backup.zip", ".git/HEAD", "index.php.bak", "web.config"]
# Backup mutations of a found directory itself: /admin -> /admin.bak, ...
RECURSE_DIR_MUTATIONS = [".bak", ".old", ".zip", "~"]
# Same name, different handler: /admin -> /admin.php, /admin.aspx, ...
RECURSE_DIR_FILE_EXT = [".php", ".aspx", ".jsp", ".html"]


def wordlist_for_techs(techs: list[str] | None) -> list[str]:
    """Tech'e ozel + GENERAL + API + yedekler. Yuksek sinyal basa. Tekrarsiz."""
    paths: list[str] = []
    for t in techs or []:
        paths += WL_TECHMAP.get(t, [])
    paths += WL_GENERAL + WL_API + WL_BACKUP_SECRET
    return list(dict.fromkeys(paths))
