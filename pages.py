"""
INFILTRATION PAYLOAD DATABASE
-----------------------------
Tactical collection of admin access vectors for penetration testing operations.
"""

# Common admin panel vectors (high-priority targets)
common_admin_vectors = [
    # Standard admin paths
    'admin', 'administrator', 'adm', 'administration', 'adminpanel',
    'cp', 'control', 'controlpanel', 'console', 'cpanel',
    'login', 'wp-login.php', 'administrator/index.php',
    'admin-console', 'admin.php', 'admin.aspx', 'admin.jsp',
    'admin.html', 'admin/login', 'admin/login.jsp', 'admin/index.jsp',
    'moderator', 'webadmin', 'websiteadmin', 'backend',
    'manager', 'mgr', 'useradmin', 'superuser',
    'sysadmin', 'supervisor', 'authorize',
    
    # Case variations
    'ADMIN', 'Admin', 'Admin-Page', 'ADMIN-LOGIN',
    'superuser-page', 'Admin-Login', 'Administrator-Login',
    'administrator/login.php', 'admin/admin-login.php',
]

# CMS and framework-specific vectors
cms_vectors = [
    # WordPress
    'wp-admin', 'wp-admin/login.php', 'wp-admin/admin.php',
    'wp-login', 'wp-login.php', 'wordpress/wp-admin',
    'wordpress/wp-login.php', 'wp/wp-admin', 'wp/wp-login.php',
    'wp-content/plugins', 'wp-content/themes', 'wp-config.php',
    
    # Joomla
    'administrator', 'administrator/index.php', 'joomla/administrator',
    'joomla/administrator/index.php', 'administrator/manifests', 
    'administrator/components', 'administrator/modules',
    
    # Drupal
    'admin', 'user/login', 'user', 'user/1', 'admin/content',
    'admin/structure', 'admin/appearance', 'admin/people',
    'admin/modules', 'admin/configuration', 'admin/reports',
    'admin/help', 'node/add', 'user/register',
    
    # Magento
    'admin', 'magento/admin', 'index.php/admin',
    'index.php/magento/admin', 'admin_BVZY1', 'magento/admin_BVZY1',
    'index.php/admin_BVZY1', 'admin/dashboard',
    
    # Laravel
    'admin', 'admin/login', 'admin/dashboard', 'login',
    'backend/login', 'backend', 'admin/settings',
    
    # Django
    'admin', 'admin/login', 'django/admin',
    'administrator/admin', 'admin/auth', 'admin/login/?next=/admin/',
]

# Server and application vectors
server_app_vectors = [
    # Server admin
    'phpmyadmin', 'phpMyAdmin', 'myadmin', 'mysqladmin', 'mysql',
    'sql', 'webdb', 'adminer', 'sqlmanager', 'dbadmin',
    'pma', 'PMA', 'phpmyadmin/index.php', 'mysql/admin',
    
    # Web app manager
    'plesk', 'webmin', 'webmin/filemanager', 'maint', 'cgi-bin',
    'directadmin', 'staradmin', 'ServerAdministrator',
    
    # Monitoring tools
    'monitor', 'monitoring', 'logs', 'awstats', 'webalizer',
    'stats', 'statistics', 'webmail', 'roundcube',
]

# Sensitive information vectors
sensitive_vectors = [
    # Configuration files
    'config', 'config.php', 'configuration', 'settings',
    'setup', 'install', 'install.php', 'installer',
    'conf', 'config.inc.php', 'settings.php',
    'php.ini', '.env', 'config.json', 'web.config',
    
    # Information leakage
    'info.php', 'phpinfo.php', 'test.php', 'readme',
    'README.md', 'changelog', 'robots.txt', 'sitemap.xml',
    'license.txt', 'error_log', 'error.log',
    'log', 'backup', 'bak', 'old', 'temp',
    
    # API endpoints
    'api', 'api/v1', 'api/v2', 'rest', 'graphql',
    'swagger', 'api-docs', 'api/docs',
]

# Modern cloud app vectors
cloud_vectors = [
    # Cloud platforms
    'portal', 'dashboard', 'cloud', 'manage', 'management',
    'account', 'user', 'profile', 'console',
    
    # SaaS products
    'auth', 'authorize', 'authenticate', 'signin',
    'sso', 'saml', 'oauth', 'login/oauth',
    'auth/admin', 'auth/login',
]

# Legacy system vectors (often overlooked)
legacy_vectors = [
    # Old systems
    'administrator', 'admin1', 'admin2', 'admin3',
    'root', 'system', 'sys', 'panel', 'sshadmin',
    'smbadmin', 'control', 'staff', 'dev', 'support',
    'newadmin', 'administratoraccounts', 'access',
]

# Protected app areas
protected_areas = [
    'secure', 'private', 'restricted', 'auth', 'member', 
    'members', 'dashboard', 'user/profile', 'profile', 
    'account', 'accounts', 'secret', 'control', 'member/login',
    'customer', 'customers', 'client', 'clients', 'users',
]

# Combine all vectors into main payload list
# Order by priority for tactical penetration
pages = (
    common_admin_vectors +
    cms_vectors +
    server_app_vectors +
    sensitive_vectors +
    cloud_vectors +
    legacy_vectors +
    protected_areas +
    [
        # Additional old paths from original list
        'adm', 'amanda', 'apache', 'bin', 'ftp', 'guest', 'http', 'httpd',
        'lp', 'mail', 'nobody', 'operator', 'acces', 'activitats', 'actualitat',
        'administracio', 'afegir', 'agafar', 'agenda', 'ajuda', 'ajudes',
        'antic', 'arrel', 'article', 'articles', 'arxiu', 'arxius', 'aule',
        'aules', 'avaluacio', 'borsa', 'botiga', 'bulleti', 'bustia', 'calaix',
        'campanyes', 'capsalera', 'carpeta', 'cat', 'catala', 'cataleg',
        'catalegs', 'categories', 'celler', 'cerca', 'cercador', 'claus',
        'client', 'clients', 'colleccio', 'comunicacio', 'comunitat', 'confirmacio',
        'contingut', 'continguts', 'copia', 'correu', 'crida', 'dades', 'demamar',
        'demanas', 'descarrega', 'descarregues', 'desenvolupament', 'directori',
        'disseny', 'document', 'documentacio', 'documents', 'eines', 'empreses',
        'enllacos', 'entitats', 'entorns', 'esborrar', 'escola', 'estudiant',
        'externes', 'finestra', 'fitxer', 'fitxers', 'fonts', 'formulari',
        'formularis', 'forum', 'forums', 'gestio', 'glossari', 'historic',
        'imatge', 'imatges', 'informacio', 'inici', 'institucio', 'jocs',
        'lletres', 'lleure', 'llibres', 'llista', 'localitzador', 'locals',
        'maquinari', 'meu', 'mitjans', 'modul', 'moduls', 'mostra', 'mostres',
        'mot', 'navegacio', 'noticies', 'nou', 'novetats', 'nul', 'obrir',
        'operacio', 'organitzacions', 'pagines', 'pas', 'personals', 'pestanya',
        'pestanyes', 'peu', 'porta', 'primer', 'principal', 'privat', 'programari',
        'projecte', 'projectes', 'prova', 'proves', 'public', 'publicacions',
        'pujar', 'recerca', 'recre', 'recull', 'reculls', 'registre', 'registres',
        'salo', 'seccio', 'secretaria', 'segon', 'seguretat', 'serveis', 'sistemes',
        'sumari', 'sumaris', 'tasques', 'taula', 'tauler', 'tecnic', 'temes',
        'tercer', 'titulars', 'tot', 'totes', 'tots', 'transit', 'transmissio',
        'treballador', 'treballadors', 'tren', 'trenacc', 'usuari', 'usuaris',
        'vell', 'veure', 'xarxa', 'xarxas', 'root1', 'webmaster', 'wp',
        'wp-app', 'wp-atom', 'wpau-backup', 'wp-blog-header', 'wpcallback',
        'wp-comments', 'wp-commentsrss2', 'wp-config', 'wpcontent', 'wp-content',
        'wp-cron', 'wp-dbmanager', 'wp-feed', 'wp-icludes', 'wp-images',
        'wp-includes', 'wp-links-opml', 'wp-load', 'wp-mail', 'wp-pass',
        'wp-rdf', 'wp-register', 'wp-rss', 'wp-rss2', 'wps', 'wp-settings',
        'wp-signup', 'wp-syntax', 'wp-trackback', 'wrap', 'writing', 'ws',
        'ws_ftp', 'WS_FTP', 'WS_FTP.LOG', 'ws-client', 'wsdl', 'wss', 'wstat',
        'wstats', 'wt', 'wtai', 'wusage', 'wwhelp', 'www', 'www1', 'www2',
        'www3', 'wwwboard', 'wwwjoin', 'wwwlog', 'wwwroot', 'www-sql',
        'wwwstat', 'wwwstats', 'wwwthreads', 'wwwuser', 'wysiwyg', 'wysiwygpro',
        'x', 'X', 'xajax', 'xajax_js', 'xalan', 'xbox', 'xcache', 'xcart',
        'xd_receiver', 'xdb', 'xerces', 'xfer', 'xhtml', 'xlogin', 'xls',
        'xmas', 'xml', 'XML', 'xmlfiles', 'xmlimporter', 'xmlrpc', 'xml-rpc',
        'xmlrpc.php', 'xmlrpc_server', 'xmlrpc_server.php', 'servicer', 'servlet',
        'servlets', 'session', 'sessions', 'set', 'setting', 'settings', 'setup',
        'share', 'shared', 'shell', 'shit', 'shop', 'shopper', 'show', 'showcode',
        'shtml', 'sign', 'signature', 'signin', 'simple', 'single', 'site',
        'sitemap', 'sites', 'small', 'snoop', 'soap', 'soapdocs', 'software',
        'solaris', 'solutions', 'somebody', 'source', 'sources', 'spain',
        'spanish', 'sql', 'sqladmin', 'src', 'srchad', 'srv', 'ssi', 'ssl',
        'staff', 'start', 'startpage', 'stat', 'statistic', 'statistics',
        'stats', 'status', 'stop', 'store', 'story', 'string', 'student',
        'stuff', 'style', 'stylesheet', 'stylesheets', 'submit', 'submitter',
        'sun', 'super', 'support', 'supported', 'survey', 'svc', 'svn', 'svr',
        'sw', 'sys', 'sysadmin', 'system', 'table', 'tag', 'tape', 'tar',
        'target', 'tech', 'temp', 'template', 'templates', 'temporal', 'temps',
        'terminal', 'test', 'testing', 'tests', 'text', 'texts', 'ticket',
        'tmp', 'today', 'tool', 'toolbar', 'tools', 'top', 'topics', 'tour',
        'tpv', 'trace', 'traffic', 'transactions', 'transfer', 'transport',
        'trap', 'trash', 'tree', 'trees', 'tutorial', 'uddi', 'uninstall',
        'unix', 'up', 'update', 'updates', 'upload', 'uploader', 'uploads',
        'usage', 'user', 'users', 'usr', 'ustats', 'util', 'utilities',
        'utility', 'utils', 'validation', 'validatior', 'vap', 'var', 'vb',
        'vbs', 'vbscript', 'vbscripts', 'vfs', 'view', 'viewer', 'views',
        'virtual', 'visitor', 'vpn', 'w', 'w3', 'w3c', 'warez', 'wdav', 'web',
        'webaccess', 'webadmin', 'webapp', 'webboard', 'webcart', 'webdata',
        'webdav', 'webdist', 'webhits', 'weblog', 'weblogic', 'weblogs',
        'webmail', 'webmaster', 'websearch', 'website', 'webstat', 'webstats',
        'webvpn', 'welcome', 'wellcome', 'whatever', 'whatnot', 'whois', 'will',
        'win', 'windows', 'word', 'wordpress', 'work', 'workplace', 'workshop'
    ]
)

# Remove any duplicates while preserving order
pages = list(dict.fromkeys(pages))

# Add modern web framework admin endpoints
advanced_vectors = [
    # New frameworks and modern paths
    'graphql/console', 'api/swagger', 'graphiql', 'playground',
    'actuator', 'actuator/health', 'actuator/info',
    'metrics', 'prometheus', 'trace', 'env',
    'v1/api-docs', 'swagger-ui.html', 'health',
    
    # Modern SPA admin paths
    'app/admin', 'dashboard', 'console/login',
    'admin-ui', 'admin/#/login', 'admin/#/dashboard',
    'panel/#/', 'manage', 'manage/dashboard',
    
    # Kubernetes/Docker related paths
    'kube', 'kubernetes', 'k8s', 'docker', 'swarm',
    'portainer', 'rancher', 'traefik', 'dashboard',
    
    # New security paths
    '.git/config', '.git/HEAD', '.env',
    '.gitlab-ci.yml', '.circleci/config.yml',
    '.github/workflows', 'deploy.yaml',
    'wp-config.php.bak', 'config.php.bak',
    '.htpasswd', '.htaccess',
]

# Extended the list with advanced vectors
pages.extend(advanced_vectors)

# Ensure no duplicates in final payload list
pages = list(dict.fromkeys(pages))

# Stats for operator awareness
"""
PAYLOAD INTELLIGENCE
--------------------
Total infiltration vectors: {0}
Primary admin targets: {1}
CMS specific vectors: {2}
Server application vectors: {3}
Sensitive information vectors: {4}
Cloud platform vectors: {5}
Legacy system vectors: {6}
Protected area vectors: {7}
Advanced recon vectors: {8}
""".format(
    len(pages),
    len(common_admin_vectors),
    len(cms_vectors),
    len(server_app_vectors),
    len(sensitive_vectors),
    len(cloud_vectors),
    len(legacy_vectors),
    len(protected_areas),
    len(advanced_vectors)
)