/*
 * ngx_http_shield_patterns.h
 *
 * Compiled-in signature tables for ngx_http_shield_module.
 *
 * Scope: exploitation of vulnerabilities that were patched years ago. Every
 * signature is something no legitimate client ever sends in a URI, query
 * string, scanned header, or request body. The goal is a near-zero
 * false-positive "legacy exploit floor" for large hosters who cannot
 * guarantee every customer application is patched -- NOT a general-purpose WAF.
 *
 * Rules for adding a signature:
 *   - Store it LOWERCASE. The engine lowercases every input buffer before
 *     scanning, so uppercase bytes here can never match.
 *   - Never a bare single keyword ("select", "or", "cat"). Use a multi-token
 *     combination that only appears in an attack ("union select", "; wget ").
 *     t/28-fp-negative.t exists to catch violations of this rule.
 *   - Percent-encoding is already decoded twice by the engine, so write the
 *     decoded form ("../"), not "%2e%2e%2f". The exceptions are signatures
 *     that only make sense in their encoded form (overlong UTF-8, %00, %0d%0a);
 *     those are matched against the RAW input as well as the decoded one.
 *
 * Adding a whole category = add an enum value, add a table, add one row to
 * ngx_http_shield_categories[]. No engine change required.
 */

#ifndef NGX_HTTP_SHIELD_PATTERNS_H_INCLUDED_
#define NGX_HTTP_SHIELD_PATTERNS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

/* A single signature: a lowercase literal and its length (computed at compile
 * time from the string literal, so the two can never drift). */
typedef struct {
    const char  *s;
    size_t       len;
} ngx_http_shield_sig_t;

#define NGX_HTTP_SHIELD_SIG(str)  { (str), sizeof(str) - 1 }

/* Which normalized buffer a signature set applies to. A category may want to
 * match its patterns against the raw (still-encoded) input too -- e.g. %00 and
 * %0d%0a and overlong-UTF-8 sequences are meaningful precisely because they are
 * encoded. NGX_HTTP_SHIELD_MATCH_RAW says "also scan the raw input". */
#define NGX_HTTP_SHIELD_MATCH_DECODED  0x1
#define NGX_HTTP_SHIELD_MATCH_RAW      0x2

/* Category identifiers. The order here defines the bit position used by the
 * shield_skip bitmask, so only ever append. */
typedef enum {
    NGX_HTTP_SHIELD_CAT_SQLI = 0,
    NGX_HTTP_SHIELD_CAT_XSS,
    NGX_HTTP_SHIELD_CAT_TRAVERSAL,
    NGX_HTTP_SHIELD_CAT_OVERLONG,
    NGX_HTTP_SHIELD_CAT_CMDI,
    NGX_HTTP_SHIELD_CAT_LFI_RFI,
    NGX_HTTP_SHIELD_CAT_CRLF,
    NGX_HTTP_SHIELD_CAT_NULLBYTE,
    NGX_HTTP_SHIELD_CAT_TEMPLATE,
    NGX_HTTP_SHIELD_CAT_DESERIAL,
    NGX_HTTP_SHIELD_CAT_SHELLSHOCK,
    NGX_HTTP_SHIELD_CAT_PHP_RCE,
    NGX_HTTP_SHIELD_CAT_JAVA_RCE,
    NGX_HTTP_SHIELD_CAT_JAVA_EVAL,
    NGX_HTTP_SHIELD_CAT_RAILS_YAML,
    NGX_HTTP_SHIELD_CAT_DRUPAL,
    NGX_HTTP_SHIELD_CAT_VBULLETIN,
    NGX_HTTP_SHIELD_CAT_XMLRPC,
    NGX_HTTP_SHIELD_CAT_SSI,
    NGX_HTTP_SHIELD_CAT_IMAGETRAGICK,
    NGX_HTTP_SHIELD_CAT_HTTPOXY,
    NGX_HTTP_SHIELD_CAT_RANGE_DOS,
    NGX_HTTP_SHIELD_CAT_SENSITIVE_FILE,
    NGX_HTTP_SHIELD_CAT_WEBSHELL,
    NGX_HTTP_SHIELD_CAT_SSRF_META,
    NGX_HTTP_SHIELD_CAT_N            /* count -- keep last */
} ngx_http_shield_cat_e;

/* ---- 1. SQL injection -------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_sqli[] = {
    NGX_HTTP_SHIELD_SIG("union select"),
    NGX_HTTP_SHIELD_SIG("union all select"),
    NGX_HTTP_SHIELD_SIG("' or 1=1"),
    NGX_HTTP_SHIELD_SIG("\" or 1=1"),
    NGX_HTTP_SHIELD_SIG("or '1'='1"),
    NGX_HTTP_SHIELD_SIG("or 1=1--"),
    NGX_HTTP_SHIELD_SIG("or 1=1#"),
    NGX_HTTP_SHIELD_SIG(") or ('1'='1"),
    NGX_HTTP_SHIELD_SIG("sleep("),
    NGX_HTTP_SHIELD_SIG("benchmark("),
    NGX_HTTP_SHIELD_SIG("waitfor delay"),
    NGX_HTTP_SHIELD_SIG("information_schema"),
    NGX_HTTP_SHIELD_SIG("group_concat("),
    NGX_HTTP_SHIELD_SIG("load_file("),
    NGX_HTTP_SHIELD_SIG("into outfile"),
    NGX_HTTP_SHIELD_SIG("into dumpfile"),
    NGX_HTTP_SHIELD_SIG("extractvalue("),
    NGX_HTTP_SHIELD_SIG("updatexml("),
};

/* ---- 2. XSS ------------------------------------------------------------ */
static const ngx_http_shield_sig_t  ngx_http_shield_xss[] = {
    NGX_HTTP_SHIELD_SIG("<script"),
    NGX_HTTP_SHIELD_SIG("</script"),
    NGX_HTTP_SHIELD_SIG("javascript:"),
    NGX_HTTP_SHIELD_SIG("vbscript:"),
    NGX_HTTP_SHIELD_SIG("onerror="),
    NGX_HTTP_SHIELD_SIG("onload="),
    NGX_HTTP_SHIELD_SIG("onmouseover="),
    NGX_HTTP_SHIELD_SIG("onfocus="),
    NGX_HTTP_SHIELD_SIG("document.cookie"),
    NGX_HTTP_SHIELD_SIG("<svg/onload"),
    NGX_HTTP_SHIELD_SIG("<iframe"),
    NGX_HTTP_SHIELD_SIG("<img src=x"),
};

/* ---- 3. Path traversal ------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_traversal[] = {
    NGX_HTTP_SHIELD_SIG("../"),
    NGX_HTTP_SHIELD_SIG("..\\"),
    NGX_HTTP_SHIELD_SIG("..;/"),          /* Tomcat / Citrix path bypass    */
    NGX_HTTP_SHIELD_SIG(".%2e/"),         /* Apache CVE-2021-41773          */
    NGX_HTTP_SHIELD_SIG("/etc/passwd"),
    NGX_HTTP_SHIELD_SIG("/etc/shadow"),
    NGX_HTTP_SHIELD_SIG("/proc/self/environ"),
    NGX_HTTP_SHIELD_SIG("win.ini"),
    NGX_HTTP_SHIELD_SIG("boot.ini"),
    NGX_HTTP_SHIELD_SIG("\\windows\\system32"),
};

/* ---- 4. Overlong-UTF-8 traversal (matched against RAW input) ----------- */
static const ngx_http_shield_sig_t  ngx_http_shield_overlong[] = {
    NGX_HTTP_SHIELD_SIG("%c0%af"),        /* overlong '/'                   */
    NGX_HTTP_SHIELD_SIG("%c1%9c"),        /* overlong '\'                   */
    NGX_HTTP_SHIELD_SIG("%c0%2f"),
    NGX_HTTP_SHIELD_SIG("%c0%ae"),        /* overlong '.'                   */
    NGX_HTTP_SHIELD_SIG("%e0%80%af"),
};

/* ---- 5. Command injection ---------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_cmdi[] = {
    NGX_HTTP_SHIELD_SIG(";wget "),
    NGX_HTTP_SHIELD_SIG(";curl "),
    NGX_HTTP_SHIELD_SIG("|wget "),
    NGX_HTTP_SHIELD_SIG("|curl "),
    NGX_HTTP_SHIELD_SIG("&&cat "),
    NGX_HTTP_SHIELD_SIG(";cat "),
    NGX_HTTP_SHIELD_SIG("$(curl"),
    NGX_HTTP_SHIELD_SIG("$(wget"),
    NGX_HTTP_SHIELD_SIG("`wget"),
    NGX_HTTP_SHIELD_SIG("`curl"),
    NGX_HTTP_SHIELD_SIG("/bin/sh"),
    NGX_HTTP_SHIELD_SIG("/bin/bash"),
    NGX_HTTP_SHIELD_SIG("chmod 777"),
    NGX_HTTP_SHIELD_SIG("cmd.exe?/c"),
    NGX_HTTP_SHIELD_SIG("/winnt/system32"),   /* Code Red / Nimda era       */
};

/* ---- 6. File inclusion (LFI/RFI) --------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_lfi_rfi[] = {
    NGX_HTTP_SHIELD_SIG("php://input"),
    NGX_HTTP_SHIELD_SIG("php://filter"),
    NGX_HTTP_SHIELD_SIG("data://text"),
    NGX_HTTP_SHIELD_SIG("expect://"),
    NGX_HTTP_SHIELD_SIG("zip://"),
    NGX_HTTP_SHIELD_SIG("phar://"),
    NGX_HTTP_SHIELD_SIG("glob://"),
    /* Deliberately NOT "=http://" / "=https://": legitimate redirect and
     * callback params (?return=https://..., ?next=https://...) carry those
     * constantly, so they are far too broad for a near-zero-FP ruleset.
     * Classic RFP via a fetched wrapper is caught above; remote-URL SSRF that
     * targets infrastructure is caught by the cloud-metadata category. */
};

/* ---- 7. CRLF / HTTP response splitting (matched against RAW input) ------ */
static const ngx_http_shield_sig_t  ngx_http_shield_crlf[] = {
    NGX_HTTP_SHIELD_SIG("%0d%0a"),
    NGX_HTTP_SHIELD_SIG("%0a%0d"),
    NGX_HTTP_SHIELD_SIG("\r\nset-cookie"),
    NGX_HTTP_SHIELD_SIG("\r\nlocation:"),
    NGX_HTTP_SHIELD_SIG("%0d%0aset-cookie"),
};

/* ---- 8. Null byte / encoding abuse (matched against RAW input) --------- */
static const ngx_http_shield_sig_t  ngx_http_shield_nullbyte[] = {
    NGX_HTTP_SHIELD_SIG("%00"),
    NGX_HTTP_SHIELD_SIG("%2500"),         /* double-encoded NUL             */
    NGX_HTTP_SHIELD_SIG("%252e%252e"),    /* double-encoded ..              */
    NGX_HTTP_SHIELD_SIG("%252f"),         /* double-encoded /               */
};

/* ---- 9. JNDI / template injection -------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_template[] = {
    NGX_HTTP_SHIELD_SIG("${jndi:"),       /* Log4Shell CVE-2021-44228       */
    NGX_HTTP_SHIELD_SIG("${env:"),
    NGX_HTTP_SHIELD_SIG("${lower:"),
    NGX_HTTP_SHIELD_SIG("${upper:"),
    NGX_HTTP_SHIELD_SIG("${sys:"),
    NGX_HTTP_SHIELD_SIG("${${"),          /* nested obfuscation             */
    NGX_HTTP_SHIELD_SIG("#{7*7}"),
};

/* ---- 10. Deserialization / XXE ----------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_deserial[] = {
    NGX_HTTP_SHIELD_SIG("ro0ab"),         /* base64 of Java stream header    */
    NGX_HTTP_SHIELD_SIG("aced0005"),      /* hex of Java stream header       */
    NGX_HTTP_SHIELD_SIG("o:21:\"jdatabasedrivermysqli\""), /* Joomla 2015-8562 */
    NGX_HTTP_SHIELD_SIG("<!entity"),
    /* Deliberately NOT "<!doctype": legitimate HTML/XML bodies carry it.
     * XXE is caught by the entity declaration + an external system reference. */
    NGX_HTTP_SHIELD_SIG("system \"file:"),
    NGX_HTTP_SHIELD_SIG("system 'file:"),
    NGX_HTTP_SHIELD_SIG("system \"http:"),
};

/* ---- 11. Shellshock ---------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_shellshock[] = {
    NGX_HTTP_SHIELD_SIG("() {"),          /* CVE-2014-6271 function prologue */
};

/* ---- 12. Ancient PHP RCE chains ---------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_php_rce[] = {
    NGX_HTTP_SHIELD_SIG("-d allow_url_include"),        /* CVE-2012-1823    */
    NGX_HTTP_SHIELD_SIG("-d auto_prepend_file"),
    NGX_HTTP_SHIELD_SIG("eval-stdin.php"),              /* CVE-2017-9841    */
    NGX_HTTP_SHIELD_SIG("invokefunction&function=call_user_func_array"), /* ThinkPHP */
    NGX_HTTP_SHIELD_SIG("s=/index/\\think"),
};

/* ---- 13. Struts / Spring RCE ------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_java_rce[] = {
    NGX_HTTP_SHIELD_SIG("%{(#"),          /* Struts OGNL CVE-2017-5638      */
    NGX_HTTP_SHIELD_SIG("${(#"),
    NGX_HTTP_SHIELD_SIG("(#_memberaccess"),
    NGX_HTTP_SHIELD_SIG("class.module.classloader"),    /* Spring4Shell     */
    NGX_HTTP_SHIELD_SIG("class['module']"),
};

/* ---- 14. Java runtime eval --------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_java_eval[] = {
    NGX_HTTP_SHIELD_SIG("java.lang.runtime"),
    NGX_HTTP_SHIELD_SIG("getruntime().exec"),
    NGX_HTTP_SHIELD_SIG("java.lang.processbuilder"),
    NGX_HTTP_SHIELD_SIG("t(java.lang.runtime)"),        /* ES Groovy 2015-1427 */
};

/* ---- 15. Rails YAML deserialization ------------------------------------ */
static const ngx_http_shield_sig_t  ngx_http_shield_rails_yaml[] = {
    NGX_HTTP_SHIELD_SIG("!ruby/object:"),   /* CVE-2013-0156                */
    NGX_HTTP_SHIELD_SIG("!ruby/hash:"),
    NGX_HTTP_SHIELD_SIG("!ruby/struct:"),
};

/* ---- 16. Drupalgeddon2 ------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_drupal[] = {
    NGX_HTTP_SHIELD_SIG("[#post_render]"),  /* CVE-2018-7600                */
    NGX_HTTP_SHIELD_SIG("[#markup]"),
    NGX_HTTP_SHIELD_SIG("[#lazy_builder]"),
    NGX_HTTP_SHIELD_SIG("#post_render]="),
};

/* ---- 17. vBulletin RCE ------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_vbulletin[] = {
    NGX_HTTP_SHIELD_SIG("widgetconfig[code]"),  /* CVE-2019-16759           */
    NGX_HTTP_SHIELD_SIG("widgetconfig['code']"),
};

/* ---- 18. WordPress xmlrpc multicall abuse (body) ----------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_xmlrpc[] = {
    NGX_HTTP_SHIELD_SIG("system.multicall"),
    NGX_HTTP_SHIELD_SIG("wp.getusersblogs"),
};

/* ---- 19. SSI injection ------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_ssi[] = {
    NGX_HTTP_SHIELD_SIG("<!--#exec"),
    NGX_HTTP_SHIELD_SIG("<!--#include virtual"),
    NGX_HTTP_SHIELD_SIG("<!--#include file"),
};

/* ---- 20. ImageTragick (body) ------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_imagetragick[] = {
    NGX_HTTP_SHIELD_SIG("push graphic-context"),    /* CVE-2016-3714        */
    NGX_HTTP_SHIELD_SIG("fill 'url(https"),
    NGX_HTTP_SHIELD_SIG("fill 'url(|"),
};

/* Categories 21 (httpoxy) and 22 (Apache-Killer Range) are structural
 * checks implemented directly in the engine, not signature tables. */

/* ---- 23. Sensitive-file probes ----------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_sensitive_file[] = {
    NGX_HTTP_SHIELD_SIG("/.env"),
    NGX_HTTP_SHIELD_SIG("/.git/"),
    NGX_HTTP_SHIELD_SIG("/.svn/"),
    NGX_HTTP_SHIELD_SIG("/.hg/"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.bak"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.save"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.swp"),
    NGX_HTTP_SHIELD_SIG("wp-config.php~"),
    NGX_HTTP_SHIELD_SIG("/.aws/credentials"),
    NGX_HTTP_SHIELD_SIG("/.ssh/id_rsa"),
    NGX_HTTP_SHIELD_SIG("/.ds_store"),
    NGX_HTTP_SHIELD_SIG("/.htpasswd"),
};

/* ---- 24. Webshell probes ----------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_webshell[] = {
    NGX_HTTP_SHIELD_SIG("c99.php"),
    NGX_HTTP_SHIELD_SIG("r57.php"),
    NGX_HTTP_SHIELD_SIG("wso.php"),
    NGX_HTTP_SHIELD_SIG("b374k"),
    NGX_HTTP_SHIELD_SIG("alfa.php"),
    NGX_HTTP_SHIELD_SIG("/shell.php?cmd="),
    NGX_HTTP_SHIELD_SIG("/cmd.php?cmd="),
    NGX_HTTP_SHIELD_SIG("filesman"),
};

/* ---- 25. Cloud metadata SSRF ------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_ssrf_meta[] = {
    NGX_HTTP_SHIELD_SIG("169.254.169.254"),
    NGX_HTTP_SHIELD_SIG("metadata.google.internal"),
    NGX_HTTP_SHIELD_SIG("/latest/meta-data/"),
    NGX_HTTP_SHIELD_SIG("/metadata/v1/"),
    NGX_HTTP_SHIELD_SIG("/computemetadata/v1/"),
};

/* One row per signature-table category. Structural categories (httpoxy,
 * range-dos) are not listed here -- they have no table. */
typedef struct {
    ngx_http_shield_cat_e         cat;
    const char                   *name;   /* shield_skip token + log label   */
    const ngx_http_shield_sig_t  *sigs;
    ngx_uint_t                    nsigs;
    ngx_uint_t                    match;  /* DECODED and/or RAW              */
} ngx_http_shield_catdef_t;

#define NGX_HTTP_SHIELD_TABLE(c, nm, arr, m)                                  \
    { (c), (nm), (arr), sizeof(arr) / sizeof((arr)[0]), (m) }

static const ngx_http_shield_catdef_t  ngx_http_shield_categories[] = {
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SQLI, "sqli",
        ngx_http_shield_sqli, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_XSS, "xss",
        ngx_http_shield_xss, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_TRAVERSAL, "traversal",
        ngx_http_shield_traversal, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_OVERLONG, "overlong",
        ngx_http_shield_overlong, NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_CMDI, "cmdi",
        ngx_http_shield_cmdi, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_LFI_RFI, "lfi",
        ngx_http_shield_lfi_rfi, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_CRLF, "crlf",
        ngx_http_shield_crlf,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_NULLBYTE, "nullbyte",
        ngx_http_shield_nullbyte, NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_TEMPLATE, "template",
        ngx_http_shield_template, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_DESERIAL, "deserial",
        ngx_http_shield_deserial, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SHELLSHOCK, "shellshock",
        ngx_http_shield_shellshock, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_PHP_RCE, "php_rce",
        ngx_http_shield_php_rce, NGX_HTTP_SHIELD_MATCH_DECODED),
    /* java_rce also matches RAW: Struts OGNL (%{(#...) travels literally in
     * the Content-Type header, and percent-decoding corrupts the literal
     * "%{" before the decoded scan can see it. */
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_JAVA_RCE, "java_rce",
        ngx_http_shield_java_rce,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_JAVA_EVAL, "java_eval",
        ngx_http_shield_java_eval, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_RAILS_YAML, "rails_yaml",
        ngx_http_shield_rails_yaml, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_DRUPAL, "drupal",
        ngx_http_shield_drupal, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_VBULLETIN, "vbulletin",
        ngx_http_shield_vbulletin, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_XMLRPC, "xmlrpc",
        ngx_http_shield_xmlrpc, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SSI, "ssi",
        ngx_http_shield_ssi, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_IMAGETRAGICK, "imagetragick",
        ngx_http_shield_imagetragick, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SENSITIVE_FILE, "sensitive_file",
        ngx_http_shield_sensitive_file, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_WEBSHELL, "webshell",
        ngx_http_shield_webshell, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SSRF_META, "ssrf_meta",
        ngx_http_shield_ssrf_meta, NGX_HTTP_SHIELD_MATCH_DECODED),
};

#define NGX_HTTP_SHIELD_NCATEGORIES                                           \
    (sizeof(ngx_http_shield_categories) /                                     \
     sizeof(ngx_http_shield_categories[0]))

/* Structural categories carry names too, for shield_skip + logging. */
#define NGX_HTTP_SHIELD_NAME_HTTPOXY    "httpoxy"
#define NGX_HTTP_SHIELD_NAME_RANGE_DOS  "range_dos"

#endif /* NGX_HTTP_SHIELD_PATTERNS_H_INCLUDED_ */
