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
 *     t/05-fp-negative.t exists to catch violations of this rule.
 *     If the attack token is ALSO legitimate traffic on its own (a real
 *     product path, a word that occurs in prose), it does not belong here at
 *     all -- make it an AND-rule term instead, so it only fires alongside the
 *     gadget that makes it an attack. See ngx_http_shield_rules[] below.
 *   - Percent-encoding is already decoded by the engine, so write the
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
    NGX_HTTP_SHIELD_CAT_NOSQL,
    NGX_HTTP_SHIELD_CAT_SSTI,
    NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH,
    NGX_HTTP_SHIELD_CAT_CTRL_CHAR,
    NGX_HTTP_SHIELD_CAT_N            /* count -- keep last */
} ngx_http_shield_cat_e;

/* ---- 1. SQL injection -------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_sqli[] = {
    NGX_HTTP_SHIELD_SIG("union select"),
    NGX_HTTP_SHIELD_SIG("union all select"),
    NGX_HTTP_SHIELD_SIG("union distinct select"),
    NGX_HTTP_SHIELD_SIG("' or 1=1"),
    NGX_HTTP_SHIELD_SIG("\" or 1=1"),
    NGX_HTTP_SHIELD_SIG("or '1'='1"),
    NGX_HTTP_SHIELD_SIG("or \"1\"=\"1"),
    NGX_HTTP_SHIELD_SIG("or 1=1--"),
    NGX_HTTP_SHIELD_SIG("or 1=1#"),
    NGX_HTTP_SHIELD_SIG("or 1=1/*"),
    NGX_HTTP_SHIELD_SIG(") or ('1'='1"),
    NGX_HTTP_SHIELD_SIG("' or ''='"),
    NGX_HTTP_SHIELD_SIG("' and '1'='1"),
    NGX_HTTP_SHIELD_SIG("' and sleep("),
    NGX_HTTP_SHIELD_SIG("' or sleep("),
    NGX_HTTP_SHIELD_SIG("\" and sleep("),
    NGX_HTTP_SHIELD_SIG("\" or sleep("),
    NGX_HTTP_SHIELD_SIG(") and sleep("),
    NGX_HTTP_SHIELD_SIG(") or sleep("),
    NGX_HTTP_SHIELD_SIG(";sleep("),
    NGX_HTTP_SHIELD_SIG("select sleep("),
    NGX_HTTP_SHIELD_SIG(" or sleep("),
    NGX_HTTP_SHIELD_SIG(" and sleep("),
    NGX_HTTP_SHIELD_SIG("admin'--"),
    NGX_HTTP_SHIELD_SIG("'='') or"),
    /* No bare "sleep(" — it is ordinary text in SQL documentation, tutorials
     * and search queries, so it blocks legitimate traffic. Time-based SQLi is
     * covered by the quote-context form above and by the vendor-specific
     * functions below, which have no benign meaning in a request. */
    NGX_HTTP_SHIELD_SIG("pg_sleep("),
    NGX_HTTP_SHIELD_SIG("benchmark("),
    NGX_HTTP_SHIELD_SIG("waitfor delay"),
    NGX_HTTP_SHIELD_SIG("dbms_pipe.receive_message"),
    NGX_HTTP_SHIELD_SIG("information_schema"),
    NGX_HTTP_SHIELD_SIG("group_concat("),
    NGX_HTTP_SHIELD_SIG("load_file("),
    NGX_HTTP_SHIELD_SIG("into outfile"),
    NGX_HTTP_SHIELD_SIG("into dumpfile"),
    NGX_HTTP_SHIELD_SIG("extractvalue("),
    NGX_HTTP_SHIELD_SIG("updatexml("),
    NGX_HTTP_SHIELD_SIG("procedure analyse("),
    NGX_HTTP_SHIELD_SIG("; drop table"),
    NGX_HTTP_SHIELD_SIG("; drop database"),
    NGX_HTTP_SHIELD_SIG("xp_cmdshell"),
    NGX_HTTP_SHIELD_SIG("utl_inaddr"),
    NGX_HTTP_SHIELD_SIG("utl_http.request"),
    NGX_HTTP_SHIELD_SIG("json_arrayagg("),
    NGX_HTTP_SHIELD_SIG("/**/union/**/"),
    NGX_HTTP_SHIELD_SIG("/*!50000"),          /* MySQL versioned-comment bypass */
    NGX_HTTP_SHIELD_SIG("0x53514c"),
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
    NGX_HTTP_SHIELD_SIG("ontoggle="),
    NGX_HTTP_SHIELD_SIG("onanimationstart="),
    NGX_HTTP_SHIELD_SIG("onpointerover="),
    NGX_HTTP_SHIELD_SIG("document.cookie"),
    NGX_HTTP_SHIELD_SIG("document.location"),
    NGX_HTTP_SHIELD_SIG("window.location"),
    NGX_HTTP_SHIELD_SIG("<svg/onload"),
    NGX_HTTP_SHIELD_SIG("<svg onload"),
    NGX_HTTP_SHIELD_SIG("<iframe"),
    NGX_HTTP_SHIELD_SIG("<img src=x"),
    NGX_HTTP_SHIELD_SIG("<body onload"),
    NGX_HTTP_SHIELD_SIG("<details open onto"),
    NGX_HTTP_SHIELD_SIG("<object data="),
    NGX_HTTP_SHIELD_SIG("<embed src="),
    NGX_HTTP_SHIELD_SIG("<base href="),
    NGX_HTTP_SHIELD_SIG("formaction="),
    NGX_HTTP_SHIELD_SIG("srcdoc="),
    NGX_HTTP_SHIELD_SIG("expression("),          /* legacy IE CSS expression */
    NGX_HTTP_SHIELD_SIG("fromcharcode("),
    NGX_HTTP_SHIELD_SIG("eval(atob("),
    NGX_HTTP_SHIELD_SIG("alert(document."),
    NGX_HTTP_SHIELD_SIG("<script>alert"),
    NGX_HTTP_SHIELD_SIG("javascript&colon;"),
};

/* ---- 3. Path traversal ------------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_traversal[] = {
    NGX_HTTP_SHIELD_SIG("../"),
    NGX_HTTP_SHIELD_SIG("..\\"),
    NGX_HTTP_SHIELD_SIG("....//"),        /* filter-bypass collapse         */
    NGX_HTTP_SHIELD_SIG("....\\\\"),
    NGX_HTTP_SHIELD_SIG("..;/"),          /* Tomcat / Citrix path bypass    */
    NGX_HTTP_SHIELD_SIG(".%2e/"),         /* Apache CVE-2021-41773          */
    NGX_HTTP_SHIELD_SIG("%2e%2e/"),
    NGX_HTTP_SHIELD_SIG("..%2f"),
    NGX_HTTP_SHIELD_SIG("..%5c"),
    NGX_HTTP_SHIELD_SIG(".%%32%65"),      /* Apache CVE-2021-42013          */
    NGX_HTTP_SHIELD_SIG("/etc/passwd"),
    NGX_HTTP_SHIELD_SIG("/etc/shadow"),
    NGX_HTTP_SHIELD_SIG("/etc/hosts"),
    NGX_HTTP_SHIELD_SIG("/etc/group"),
    NGX_HTTP_SHIELD_SIG("/proc/self/environ"),
    NGX_HTTP_SHIELD_SIG("/proc/self/cmdline"),
    NGX_HTTP_SHIELD_SIG("/proc/self/fd/"),
    NGX_HTTP_SHIELD_SIG("win.ini"),
    NGX_HTTP_SHIELD_SIG("boot.ini"),
    NGX_HTTP_SHIELD_SIG("\\windows\\system32"),
    NGX_HTTP_SHIELD_SIG("/windows/win.ini"),
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
    NGX_HTTP_SHIELD_SIG(";id;"),
    NGX_HTTP_SHIELD_SIG(";id "),
    NGX_HTTP_SHIELD_SIG(";uname"),
    NGX_HTTP_SHIELD_SIG("$(id)"),
    NGX_HTTP_SHIELD_SIG("$(curl"),
    NGX_HTTP_SHIELD_SIG("$(wget"),
    NGX_HTTP_SHIELD_SIG("`wget"),
    NGX_HTTP_SHIELD_SIG("`curl"),
    NGX_HTTP_SHIELD_SIG("`id`"),
    NGX_HTTP_SHIELD_SIG("/bin/sh"),
    NGX_HTTP_SHIELD_SIG("/bin/bash"),
    NGX_HTTP_SHIELD_SIG("bash -i"),
    NGX_HTTP_SHIELD_SIG("/dev/tcp/"),
    NGX_HTTP_SHIELD_SIG("${ifs}"),
    NGX_HTTP_SHIELD_SIG("$ifs$"),
    NGX_HTTP_SHIELD_SIG(";nc "),
    NGX_HTTP_SHIELD_SIG("nc -e"),
    NGX_HTTP_SHIELD_SIG("ncat -e"),
    NGX_HTTP_SHIELD_SIG(";python -c"),
    NGX_HTTP_SHIELD_SIG(";perl -e"),
    NGX_HTTP_SHIELD_SIG("chmod 777"),
    NGX_HTTP_SHIELD_SIG("chmod +x"),
    NGX_HTTP_SHIELD_SIG("cmd.exe?/c"),
    NGX_HTTP_SHIELD_SIG("/c powershell"),
    NGX_HTTP_SHIELD_SIG("powershell -e"),
    NGX_HTTP_SHIELD_SIG("powershell -enc"),
    NGX_HTTP_SHIELD_SIG("certutil -urlcache"),
    NGX_HTTP_SHIELD_SIG("certutil.exe -urlcache"),
    NGX_HTTP_SHIELD_SIG("/winnt/system32"),   /* Code Red / Nimda era       */
};

/* ---- 6. File inclusion (LFI/RFI) --------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_lfi_rfi[] = {
    NGX_HTTP_SHIELD_SIG("php://input"),
    NGX_HTTP_SHIELD_SIG("php://filter"),
    NGX_HTTP_SHIELD_SIG("php://fd"),
    NGX_HTTP_SHIELD_SIG("data://text"),
    NGX_HTTP_SHIELD_SIG("expect://"),
    NGX_HTTP_SHIELD_SIG("zip://"),
    NGX_HTTP_SHIELD_SIG("phar://"),
    NGX_HTTP_SHIELD_SIG("glob://"),
    NGX_HTTP_SHIELD_SIG("rar://"),
    NGX_HTTP_SHIELD_SIG("ogg://"),
    NGX_HTTP_SHIELD_SIG("compress.zlib://"),
    NGX_HTTP_SHIELD_SIG("compress.bzip2://"),
    NGX_HTTP_SHIELD_SIG("gopher://"),        /* SSRF/RFI smuggling wrapper   */
    NGX_HTTP_SHIELD_SIG("dict://"),
    NGX_HTTP_SHIELD_SIG("file:///etc/"),
    NGX_HTTP_SHIELD_SIG("pearcmd.php"),      /* LFI-to-RCE via PEAR          */
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
    NGX_HTTP_SHIELD_SIG("\r\ncontent-length"),
    NGX_HTTP_SHIELD_SIG("%0d%0aset-cookie"),
    NGX_HTTP_SHIELD_SIG("%0d%0alocation:"),
    NGX_HTTP_SHIELD_SIG("%0d%0acontent-length"),
    NGX_HTTP_SHIELD_SIG("%0aset-cookie"),
    NGX_HTTP_SHIELD_SIG("%e5%98%8a%e5%98%8d"), /* overlong-UTF-8 CR LF        */
    NGX_HTTP_SHIELD_SIG("%u000d%u000a"),       /* IIS %u-encoded CRLF         */
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
    NGX_HTTP_SHIELD_SIG("jndi:ldap:"),
    NGX_HTTP_SHIELD_SIG("jndi:rmi:"),
    NGX_HTTP_SHIELD_SIG("jndi:dns:"),
    NGX_HTTP_SHIELD_SIG("jndi:iiop:"),
    NGX_HTTP_SHIELD_SIG("jndi:ldaps:"),
    NGX_HTTP_SHIELD_SIG("jndi:nis:"),
    NGX_HTTP_SHIELD_SIG("${env:"),
    NGX_HTTP_SHIELD_SIG("${lower:"),
    NGX_HTTP_SHIELD_SIG("${upper:"),
    NGX_HTTP_SHIELD_SIG("${sys:"),
    NGX_HTTP_SHIELD_SIG("${date:"),
    NGX_HTTP_SHIELD_SIG("${ctx:"),
    NGX_HTTP_SHIELD_SIG("${main:"),
    NGX_HTTP_SHIELD_SIG("${::-"),         /* Log4Shell defanging bypass     */
    NGX_HTTP_SHIELD_SIG("${${"),          /* nested obfuscation             */
    NGX_HTTP_SHIELD_SIG("${${lower:"),
    NGX_HTTP_SHIELD_SIG("#{7*7}"),
};

/* ---- 10. Deserialization / XXE ----------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_deserial[] = {
    NGX_HTTP_SHIELD_SIG("ro0ab"),         /* base64 of Java stream header    */
    NGX_HTTP_SHIELD_SIG("aced0005"),      /* hex of Java stream header       */
    NGX_HTTP_SHIELD_SIG("o:21:\"jdatabasedrivermysqli\""), /* Joomla 2015-8562 */
    /* Well-known Java deserialization gadget classes -- no legitimate request
     * carries these by name. */
    NGX_HTTP_SHIELD_SIG("jdbcrowsetimpl"),
    NGX_HTTP_SHIELD_SIG("templatesimpl"),
    NGX_HTTP_SHIELD_SIG("com.sun.org.apache.xalan"),
    NGX_HTTP_SHIELD_SIG("badattributevalueexpexception"),
    NGX_HTTP_SHIELD_SIG("org.apache.commons.collections.functors"),
    NGX_HTTP_SHIELD_SIG("org.apache.commons.collections4.functors"),
    NGX_HTTP_SHIELD_SIG("com.mchange.v2.c3p0"),
    NGX_HTTP_SHIELD_SIG("<java.lang.processbuilder"), /* XStream CVE-2017-9805 */
    NGX_HTTP_SHIELD_SIG("<work:workcontext"),         /* WebLogic 2017-10271  */
    NGX_HTTP_SHIELD_SIG("wls-wsat/coordinatorporttype"),
    /* Fastjson / Jackson autotype to a native class. */
    NGX_HTTP_SHIELD_SIG("\"@type\":\"com.sun."),
    NGX_HTTP_SHIELD_SIG("\"@type\":\"java.lang"),
    NGX_HTTP_SHIELD_SIG("\"@type\":\"org.apache"),
    NGX_HTTP_SHIELD_SIG("\"@type\":\"ch.qos.logback"),
    NGX_HTTP_SHIELD_SIG("\"@type\":\"com.alibaba"),
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
    NGX_HTTP_SHIELD_SIG("-d auto_append_file"),
    NGX_HTTP_SHIELD_SIG("-d allow_url_fopen"),
    NGX_HTTP_SHIELD_SIG("-dsafe_mode"),
    NGX_HTTP_SHIELD_SIG("eval-stdin.php"),              /* CVE-2017-9841    */
    NGX_HTTP_SHIELD_SIG("invokefunction&function=call_user_func_array"), /* ThinkPHP */
    NGX_HTTP_SHIELD_SIG("s=/index/\\think"),
    NGX_HTTP_SHIELD_SIG("think\\app/invokefunction"),
    NGX_HTTP_SHIELD_SIG("?a=fetch&content=<?php"),
    NGX_HTTP_SHIELD_SIG("<?php system("),
    NGX_HTTP_SHIELD_SIG("<?php eval("),
    NGX_HTTP_SHIELD_SIG("<?php passthru("),
    NGX_HTTP_SHIELD_SIG("php_value auto_prepend"),
    NGX_HTTP_SHIELD_SIG("/phppath/php"),
    NGX_HTTP_SHIELD_SIG("allow_url_include=1"),
};

/* ---- 13. Struts / Spring RCE ------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_java_rce[] = {
    NGX_HTTP_SHIELD_SIG("%{(#"),          /* Struts OGNL CVE-2017-5638      */
    NGX_HTTP_SHIELD_SIG("${(#"),
    NGX_HTTP_SHIELD_SIG("(#_memberaccess"),
    NGX_HTTP_SHIELD_SIG("#_memberaccess["),
    NGX_HTTP_SHIELD_SIG("ognl.ognlcontext"),
    NGX_HTTP_SHIELD_SIG("(#context["),
    NGX_HTTP_SHIELD_SIG("@ognl.ognlruntime@"),
    NGX_HTTP_SHIELD_SIG("struts.devmode"),
    NGX_HTTP_SHIELD_SIG("redirect:${"),
    NGX_HTTP_SHIELD_SIG("action:${"),
    NGX_HTTP_SHIELD_SIG("class.module.classloader"),    /* Spring4Shell     */
    NGX_HTTP_SHIELD_SIG("class['module']"),
    NGX_HTTP_SHIELD_SIG("class.classloader"),
    /* Confluence OGNL (CVE-2022-26134): fully-qualified Runtime/OGNL gadget
     * refs that no legitimate request carries by name. */
    NGX_HTTP_SHIELD_SIG("@java.lang.runtime@getruntime().exec("),
    NGX_HTTP_SHIELD_SIG("@ognl.ognlcontext@default_member_access"),
    NGX_HTTP_SHIELD_SIG("@org.apache.commons.io.ioutils@"),
    NGX_HTTP_SHIELD_SIG("com.opensymphony.webwork.servletactioncontext"),
    NGX_HTTP_SHIELD_SIG("(#cmd="),                       /* OGNL process exec */
    NGX_HTTP_SHIELD_SIG("new java.lang.processbuilder("),
};

/* ---- 14. Java runtime eval --------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_java_eval[] = {
    NGX_HTTP_SHIELD_SIG("java.lang.runtime"),
    NGX_HTTP_SHIELD_SIG("getruntime().exec"),
    NGX_HTTP_SHIELD_SIG("runtime.getruntime"),
    NGX_HTTP_SHIELD_SIG("java.lang.processbuilder"),
    NGX_HTTP_SHIELD_SIG("new processbuilder"),
    NGX_HTTP_SHIELD_SIG("t(java.lang.runtime)"),        /* ES Groovy 2015-1427 */
    NGX_HTTP_SHIELD_SIG("javax.script.scriptengine"),
    NGX_HTTP_SHIELD_SIG("freemarker.template.utility.execute"),
    NGX_HTTP_SHIELD_SIG("<#assign"),                    /* Freemarker SSTI     */
    NGX_HTTP_SHIELD_SIG("com.opensymphony.xwork2"),
    NGX_HTTP_SHIELD_SIG("javax.naming.initialcontext"),
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
    /* No "wp.getusersblogs": it is a documented, legitimate WordPress XML-RPC
     * method that ordinary clients call. It signals abuse only in VOLUME, and
     * volume is not expressible as a term set -- an AND-rule pairing it with
     * the <methodCall> envelope would match the legitimate call too, since
     * every XML-RPC request carries that envelope. It stays out per the
     * near-zero-false-positive contract. The brute-force amplifier itself
     * (system.multicall) is still blocked as a standalone signature. */
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
    NGX_HTTP_SHIELD_SIG("/.bzr/"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.bak"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.save"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.swp"),
    NGX_HTTP_SHIELD_SIG("wp-config.php.orig"),
    NGX_HTTP_SHIELD_SIG("wp-config.php~"),
    NGX_HTTP_SHIELD_SIG("/.aws/credentials"),
    NGX_HTTP_SHIELD_SIG("/.ssh/id_rsa"),
    NGX_HTTP_SHIELD_SIG("/.ssh/id_dsa"),
    NGX_HTTP_SHIELD_SIG("/.ssh/authorized_keys"),
    NGX_HTTP_SHIELD_SIG("/.ds_store"),
    NGX_HTTP_SHIELD_SIG("/.htpasswd"),
    NGX_HTTP_SHIELD_SIG("/.bash_history"),
    NGX_HTTP_SHIELD_SIG("/.mysql_history"),
    NGX_HTTP_SHIELD_SIG("/.npmrc"),
    NGX_HTTP_SHIELD_SIG("/.dockercfg"),
    NGX_HTTP_SHIELD_SIG("/.docker/config.json"),
    NGX_HTTP_SHIELD_SIG("/.kube/config"),
    NGX_HTTP_SHIELD_SIG("/backup.sql"),
    NGX_HTTP_SHIELD_SIG("/dump.sql"),
    NGX_HTTP_SHIELD_SIG("/database.sql"),
    NGX_HTTP_SHIELD_SIG("/.git-credentials"),
    NGX_HTTP_SHIELD_SIG("/config/database.yml"),
    NGX_HTTP_SHIELD_SIG("/.env.production"),
    NGX_HTTP_SHIELD_SIG("/.env.local"),
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
    NGX_HTTP_SHIELD_SIG("/shell.jsp"),
    NGX_HTTP_SHIELD_SIG("/cmd.jsp"),
    NGX_HTTP_SHIELD_SIG("/tunnel.jsp"),
    NGX_HTTP_SHIELD_SIG("filesman"),
    NGX_HTTP_SHIELD_SIG("indoxploit"),
    NGX_HTTP_SHIELD_SIG("p0wny"),
    NGX_HTTP_SHIELD_SIG("weevely"),
    NGX_HTTP_SHIELD_SIG("antsword"),
    NGX_HTTP_SHIELD_SIG("behinder"),
    NGX_HTTP_SHIELD_SIG("regeorg"),
    NGX_HTTP_SHIELD_SIG("gel4y"),
    NGX_HTTP_SHIELD_SIG("aspxspy"),
};

/* ---- 25. Cloud metadata SSRF ------------------------------------------- */
static const ngx_http_shield_sig_t  ngx_http_shield_ssrf_meta[] = {
    NGX_HTTP_SHIELD_SIG("169.254.169.254"),
    NGX_HTTP_SHIELD_SIG("100.100.100.200"),       /* Alibaba Cloud metadata  */
    NGX_HTTP_SHIELD_SIG("192.0.0.192"),           /* Oracle Cloud metadata   */
    NGX_HTTP_SHIELD_SIG("metadata.google.internal"),
    NGX_HTTP_SHIELD_SIG("/latest/meta-data/"),
    NGX_HTTP_SHIELD_SIG("/latest/user-data"),
    NGX_HTTP_SHIELD_SIG("/latest/dynamic/instance-identity"),
    NGX_HTTP_SHIELD_SIG("/metadata/v1/"),
    NGX_HTTP_SHIELD_SIG("/metadata/instance"),    /* Azure IMDS              */
    NGX_HTTP_SHIELD_SIG("/computemetadata/v1/"),
    NGX_HTTP_SHIELD_SIG("/opc/v1/instance"),      /* Oracle IMDS             */
    NGX_HTTP_SHIELD_SIG("2852039166"),            /* decimal 169.254.169.254 */
    NGX_HTTP_SHIELD_SIG("0xa9fea9fe"),            /* hex 169.254.169.254     */
    NGX_HTTP_SHIELD_SIG("/latest/api/token"),     /* AWS IMDSv2 token endpoint */
    NGX_HTTP_SHIELD_SIG("/latest/meta-data/iam/security-credentials/"),
    NGX_HTTP_SHIELD_SIG("metadata-flavor: google"), /* GCP IMDS header form   */
    NGX_HTTP_SHIELD_SIG("metadata-flavor:google"),
};

/* ---- 26. NoSQL injection ----------------------------------------------- */
/* Only the operator forms that no legitimate query param carries verbatim --
 * bracketed MongoDB operators and server-side-JS $where. Plain values like a
 * param literally named "gt" are not matched. */
static const ngx_http_shield_sig_t  ngx_http_shield_nosql[] = {
    NGX_HTTP_SHIELD_SIG("[$ne]"),
    NGX_HTTP_SHIELD_SIG("[$gt]"),
    NGX_HTTP_SHIELD_SIG("[$lt]"),
    NGX_HTTP_SHIELD_SIG("[$regex]"),
    NGX_HTTP_SHIELD_SIG("[$where]"),
    NGX_HTTP_SHIELD_SIG("[$exists]"),
    NGX_HTTP_SHIELD_SIG("{\"$where\":"),
    NGX_HTTP_SHIELD_SIG("{\"$where\" :"),
    NGX_HTTP_SHIELD_SIG("$where:function"),
    NGX_HTTP_SHIELD_SIG("$func:"),
    NGX_HTTP_SHIELD_SIG("';return true;var"),
};

/* ---- 27. Server-side template injection -------------------------------- */
/* The arithmetic-probe and object-traversal forms attackers use to detect an
 * SSTI sink -- never a normal request value. */
static const ngx_http_shield_sig_t  ngx_http_shield_ssti[] = {
    NGX_HTTP_SHIELD_SIG("{{7*7}}"),
    NGX_HTTP_SHIELD_SIG("${7*7}"),
    NGX_HTTP_SHIELD_SIG("#{7*7}"),
    NGX_HTTP_SHIELD_SIG("*{7*7}"),
    NGX_HTTP_SHIELD_SIG("{{7*'7'}}"),
    NGX_HTTP_SHIELD_SIG("<%= 7*7"),
    NGX_HTTP_SHIELD_SIG("{{config"),
    NGX_HTTP_SHIELD_SIG("{{request"),
    NGX_HTTP_SHIELD_SIG("{{self"),
    NGX_HTTP_SHIELD_SIG("{{''.__class__"),
    NGX_HTTP_SHIELD_SIG("{{().__class__"),
    NGX_HTTP_SHIELD_SIG("${t(java"),
    NGX_HTTP_SHIELD_SIG("#set($"),
    NGX_HTTP_SHIELD_SIG("[[${"),                  /* Thymeleaf inline        */
};

/* ---- 28. Known n-day exploit paths ------------------------------------- */
/* Fixed request paths that only appear in mass-scan exploitation of specific
 * long-patched products. No legitimate client on a general host requests them. */
static const ngx_http_shield_sig_t  ngx_http_shield_exploit_path[] = {
    NGX_HTTP_SHIELD_SIG("/wls-wsat/"),               /* WebLogic 2017-10271  */
    NGX_HTTP_SHIELD_SIG("/mgmt/tm/util/bash"),       /* F5 CVE-2021-22986    */
    NGX_HTTP_SHIELD_SIG("/mgmt/shared/authn/login"), /* F5 CVE-2022-1388     */
    NGX_HTTP_SHIELD_SIG("/hipreport.esp"),           /* PAN-OS CVE-2024-3400 */
    NGX_HTTP_SHIELD_SIG("/remote/fgt_lang"),         /* Fortinet 2018-13379  */
    NGX_HTTP_SHIELD_SIG("/+cscoe+/"),                /* Cisco ASA path       */
    NGX_HTTP_SHIELD_SIG("/dana-na/"),                /* Pulse Secure         */
    NGX_HTTP_SHIELD_SIG("/cgi-bin/luci"),            /* OpenWrt/router       */
    NGX_HTTP_SHIELD_SIG("/boaform/admin/formlogin"), /* router botnet probe  */
    NGX_HTTP_SHIELD_SIG("/gponform/diag_form"),      /* GPON CVE-2018-10561  */
    NGX_HTTP_SHIELD_SIG("/hnap1/"),                  /* D-Link HNAP          */
    NGX_HTTP_SHIELD_SIG("/setup.cgi?next_file"),     /* Netgear             */
    NGX_HTTP_SHIELD_SIG("/solr/admin/cores"),        /* Solr RCE probes      */
    NGX_HTTP_SHIELD_SIG("/actuator/gateway/routes"), /* Spring Gateway RCE   */
    NGX_HTTP_SHIELD_SIG("/_ignition/execute-solution"), /* Laravel 2021-3129 */
    NGX_HTTP_SHIELD_SIG("/api/jsonws/invoke"),       /* Liferay 2020-7961    */
    NGX_HTTP_SHIELD_SIG("/console/css/%252e"),       /* WebLogic 2020-14882  */
    /* ProxyShell (CVE-2021-34473) — the bare Autodiscover path is what every
     * normal Outlook client requests, so only the path-confusion form that
     * carries the SSRF is a signature: a "?@" (or its encoded "%3f@") right
     * after autodiscover.json, which is what smuggles the backend host. */
    NGX_HTTP_SHIELD_SIG("autodiscover.json?@"),
    NGX_HTTP_SHIELD_SIG("autodiscover.json%3f@"),
    NGX_HTTP_SHIELD_SIG("/owa/auth/x."),             /* ProxyLogon probe     */
    NGX_HTTP_SHIELD_SIG("/vpns/portal/scripts"),     /* Citrix 2019-19781    */
    NGX_HTTP_SHIELD_SIG("/securityrealm/user/admin/descriptorbyname"), /* Jenkins */
    NGX_HTTP_SHIELD_SIG("/config/getuser?index="),   /* Zyxel 2020-29583     */
    NGX_HTTP_SHIELD_SIG("/tmui/login.jsp/..;/"),     /* F5 BIG-IP 2020-5902  */
    NGX_HTTP_SHIELD_SIG("/hsqldb%0a"),               /* F5 TMUI probe        */
    NGX_HTTP_SHIELD_SIG("/ui/vropspluginui/rest/services/uploadova"), /* vCenter 2021-21972 */
    NGX_HTTP_SHIELD_SIG("/ui/vropspluginui/rest/services/getstatus"),
    NGX_HTTP_SHIELD_SIG("/analytics/telemetry/ph/api/hyper/send"), /* vCenter 2021-22005 */
    /* Grafana CVE-2021-43798 is caught by the traversal category (../ under
     * /public/plugins/); a bare "/public/plugins/" matches legit plugin assets
     * and is therefore NOT listed here (would break t/05 FP guard). */
    NGX_HTTP_SHIELD_SIG("/webtools/control/xmlrpc"), /* OFBiz 2020-9496      */
    NGX_HTTP_SHIELD_SIG("/webtools/control/programexport"), /* OFBiz 2023-49070 */
    /* OFBiz requirePasswordChange=Y and Metabase /api/setup/validate are both
     * reachable on legitimate flows (password change / first-run install), so
     * neither is a standalone signature. Both are covered as AND-rules
     * (ofbiz_authbypass, metabase_jdbc_rce) -- paired with the gadget token
     * that makes them attack-only. */
    NGX_HTTP_SHIELD_SIG("/gwtest/formssso?event="),  /* Citrix 2023-3519     */
    NGX_HTTP_SHIELD_SIG("/vpn/../vpns/"),            /* Citrix 2019-19781    */
    NGX_HTTP_SHIELD_SIG("/newbm.pl"),                /* Citrix bookmark smuggle */
    NGX_HTTP_SHIELD_SIG("/remote/fgt_lang?lang=/../"), /* Fortinet 2018-13379 tail */
    NGX_HTTP_SHIELD_SIG("sslvpn_websession"),        /* Fortinet 2018-13379 target */
    NGX_HTTP_SHIELD_SIG("/api/v1/totp/user-backup-code/../"), /* Ivanti 2024-21887 */
    NGX_HTTP_SHIELD_SIG("/goform/set_limitclient_cfg"), /* router botnet probe */
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
    /* traversal also matches RAW: several signatures are encoded forms
     * (..%2f, ..%5c, .%%32%65) whose whole point is the still-encoded bytes. */
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_TRAVERSAL, "traversal",
        ngx_http_shield_traversal,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
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
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_NOSQL, "nosql",
        ngx_http_shield_nosql,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_SSTI, "ssti",
        ngx_http_shield_ssti,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
    NGX_HTTP_SHIELD_TABLE(NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH, "exploit_path",
        ngx_http_shield_exploit_path,
        NGX_HTTP_SHIELD_MATCH_DECODED | NGX_HTTP_SHIELD_MATCH_RAW),
};

#define NGX_HTTP_SHIELD_NCATEGORIES                                           \
    (sizeof(ngx_http_shield_categories) /                                     \
     sizeof(ngx_http_shield_categories[0]))

/* Structural categories carry names too, for shield_skip + logging. */
#define NGX_HTTP_SHIELD_NAME_HTTPOXY    "httpoxy"
#define NGX_HTTP_SHIELD_NAME_RANGE_DOS  "range_dos"
#define NGX_HTTP_SHIELD_NAME_CTRL_CHAR  "ctrl_char"


/* ---- AND-rules: categories that require several tokens to co-occur ------ */

/*
 * Some attacks are only distinguishable from legitimate traffic by a
 * COMBINATION of tokens. The path a Grafana path-traversal exploit uses is
 * "/public/plugins/" -- which is also how every Grafana instance serves its
 * plugin assets. The exploit is that path AND a traversal gadget. Listing
 * "/public/plugins/" as an ordinary signature would block the whole product;
 * omitting it leaves the exploit uncovered. The same shape appears for OFBiz
 * requirePasswordChange, Metabase's first-run setup endpoint, WordPress
 * xmlrpc method-volume abuse, and time-based SQLi via a bare "sleep(".
 *
 * An AND-rule expresses that: a set of terms that must ALL appear in the same
 * buffer before the rule's category fires.
 *
 * Rule terms are deliberately NOT ordinary signatures -- they live only here.
 * A term never sets a category bit in the automaton's out[] mask, so it can
 * never fire on its own, and the standalone-signature fast path (and its cost)
 * is untouched. Terms are matched by the same single automaton pass; each is
 * assigned a rule-term id whose bit is recorded in a side mask.
 *
 * Same-buffer only: every term of a rule must be found in one normalized
 * buffer. That covers every rule below (they are all single-URI patterns).
 * Cross-source AND (path in the URI, gadget in the body) is not expressible
 * and is not needed yet.
 */

/* Terms are grouped per rule; a term string may repeat across rules (it gets
 * its own id in each -- the sets are what matter, not term identity). */
typedef struct {
    ngx_http_shield_cat_e         cat;    /* category reported on a match    */
    const char                   *name;   /* rule label, for the error log   */
    const ngx_http_shield_sig_t  *terms;
    ngx_uint_t                    nterms;
    ngx_uint_t                    match;  /* DECODED and/or RAW              */
} ngx_http_shield_ruledef_t;

/* Grafana CVE-2021-43798: plugin asset path plus a traversal gadget. The path
 * alone is how Grafana serves plugin assets on every page load. */
static const ngx_http_shield_sig_t  ngx_http_shield_rule_grafana[] = {
    NGX_HTTP_SHIELD_SIG("/public/plugins/"),
    NGX_HTTP_SHIELD_SIG("../"),
};

/* Apache OFBiz CVE-2023-51467 auth bypass: the bypass parameter is only an
 * attack when it is steering a request at the webtools control endpoint.
 * requirePasswordChange=Y on its own is an ordinary password-change flow. */
static const ngx_http_shield_sig_t  ngx_http_shield_rule_ofbiz[] = {
    NGX_HTTP_SHIELD_SIG("requirepasswordchange=y"),
    NGX_HTTP_SHIELD_SIG("/webtools/control/"),
};

/* Metabase CVE-2023-38646 pre-auth RCE: the setup-validate endpoint is a real
 * first-run install endpoint. The attack carries an H2 JDBC connection string
 * with an INIT script -- that is the part no installer sends. */
static const ngx_http_shield_sig_t  ngx_http_shield_rule_metabase[] = {
    NGX_HTTP_SHIELD_SIG("/api/setup/validate"),
    NGX_HTTP_SHIELD_SIG("jdbc:h2:"),
};

/* Time-based SQL injection via a bare "sleep(". "sleep(" alone is ordinary
 * text in SQL tutorials, documentation and search queries -- it was removed as
 * a standalone signature for exactly that reason. Paired with a SQL gadget it
 * has no benign reading. */
static const ngx_http_shield_sig_t  ngx_http_shield_rule_sqli_sleep[] = {
    NGX_HTTP_SHIELD_SIG("sleep("),
    NGX_HTTP_SHIELD_SIG("select "),
};

/* No wp.getUsersBlogs rule. The obvious pairing -- wp.getUsersBlogs AND a
 * <methodCall> wrapper -- is worthless: <methodCall> is the XML-RPC envelope
 * EVERY client sends for EVERY method, so the rule would block the legitimate
 * call (t/05 TEST 24 catches exactly that). What distinguishes the brute-force
 * from a real client is request VOLUME, which no same-buffer term set can
 * express. The amplifier it rides on, system.multicall, is a standalone
 * signature and stays blocked. Left out until there is a term that actually
 * separates the two. */

#define NGX_HTTP_SHIELD_RULE(c, nm, arr, m)                                   \
    { (c), (nm), (arr), sizeof(arr) / sizeof((arr)[0]), (m) }

static const ngx_http_shield_ruledef_t  ngx_http_shield_rules[] = {
    NGX_HTTP_SHIELD_RULE(NGX_HTTP_SHIELD_CAT_TRAVERSAL, "grafana_plugin_lfi",
        ngx_http_shield_rule_grafana, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_RULE(NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH, "ofbiz_authbypass",
        ngx_http_shield_rule_ofbiz, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_RULE(NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH, "metabase_jdbc_rce",
        ngx_http_shield_rule_metabase, NGX_HTTP_SHIELD_MATCH_DECODED),
    NGX_HTTP_SHIELD_RULE(NGX_HTTP_SHIELD_CAT_SQLI, "sqli_time_based",
        ngx_http_shield_rule_sqli_sleep, NGX_HTTP_SHIELD_MATCH_DECODED),
};

#define NGX_HTTP_SHIELD_NRULES                                                \
    (sizeof(ngx_http_shield_rules) / sizeof(ngx_http_shield_rules[0]))


/* ---- Aho-Corasick automaton -------------------------------------------- */

/*
 * All signatures are matched in a SINGLE pass over each buffer, instead of one
 * linear sweep per signature. The old engine was O(n * m): ~500 sweeps per
 * buffer (391 signatures, six categories scanning both the raw and the decoded
 * copy). It was also defeated by its own prefilter -- the inner loop only
 * reached memcmp when the first byte matched, and 132 signature-passes begin
 * with '/', the most common byte in a URI.
 *
 * Aho-Corasick removes both problems: cost is O(n) in the buffer and no longer
 * depends on the number of signatures, so the table can grow for free and a
 * hostile all-'/' buffer costs the same as a benign one.
 *
 * Two automatons are built because categories disagree about which buffer they
 * apply to (MATCH_DECODED / MATCH_RAW). Each accepting state records the SET of
 * categories accepting there, as a bitmask over ngx_http_shield_cat_e -- the
 * same bit space as shield_skip, so the scan's accept test is a single
 * out[s] & ~skip. A hit in a category disabled via shield_skip is stepped over
 * and the scan continues -- per-location skip still works.
 *
 * The set must be a MASK, not a single id: one state can accept signatures from
 * several categories at once, either because they share a signature string or
 * because a short signature ends inside a longer one from another category
 * (out is unioned along fail links). Storing one id per state silently dropped
 * every category but the first -- a detection bypass, e.g. the traversal "../"
 * tail of an exploit_path signature going unreported.
 *
 * Built once at postconfiguration from cf->pool, then read-only for the life
 * of the cycle: no per-request allocation, no locking, safe to share.
 */

#define NGX_HTTP_SHIELD_AC_ALPHABET  256

/* Node indices are uint16_t. The full table builds to ~4k nodes, far under the
 * 65535 ceiling; ngx_http_shield_ac_build() enforces this and fails config
 * rather than overflowing, so adding signatures can never silently corrupt the
 * automaton. */
typedef uint16_t  ngx_http_shield_ac_state_t;

#define NGX_HTTP_SHIELD_AC_MAX_STATES  65535

/* out[] is a bitmask over ngx_http_shield_cat_e, so the category space must fit
 * in a uint64. shield_skip already assumes this; assert it once, here. */
typedef char ngx_http_shield_cat_fits_in_mask[
    (NGX_HTTP_SHIELD_CAT_N <= 64) ? 1 : -1];

/* Rule terms are numbered across ngx_http_shield_rules[] in declaration order
 * (rule 0's terms first, then rule 1's, ...). The id is a bit position in the
 * per-state rule mask, so the total number of terms must fit in a uint64. Ten
 * today; the assert makes an overflow a compile error rather than a silently
 * mis-evaluated rule. */
#define NGX_HTTP_SHIELD_NRULE_TERMS                                           \
    (sizeof(ngx_http_shield_rule_grafana)                                     \
       / sizeof(ngx_http_shield_rule_grafana[0])                              \
     + sizeof(ngx_http_shield_rule_ofbiz)                                     \
       / sizeof(ngx_http_shield_rule_ofbiz[0])                                \
     + sizeof(ngx_http_shield_rule_metabase)                                  \
       / sizeof(ngx_http_shield_rule_metabase[0])                             \
     + sizeof(ngx_http_shield_rule_sqli_sleep)                                \
       / sizeof(ngx_http_shield_rule_sqli_sleep[0]))

typedef char ngx_http_shield_rule_terms_fit_in_mask[
    (NGX_HTTP_SHIELD_NRULE_TERMS <= 64) ? 1 : -1];

typedef struct {
    ngx_http_shield_ac_state_t  *next;   /* [nstates][256] goto table        */
    uint64_t                    *out;    /* [nstates] accepting-category mask */
    ngx_uint_t                   nstates;

    /* [nstates] accepting rule-TERM mask, in the NGX_HTTP_SHIELD_NRULE_TERMS
     * bit space. Kept separate from out[] on purpose: a rule term must never
     * fire a category on its own, so it sets no bit in out[] and the standalone
     * fast path -- and its cost -- is exactly what it was. NULL if this
     * automaton carries no rule terms. */
    uint64_t                    *rout;

    /* Per-rule required-term masks, in the same bit space. A rule fires when
     * (seen & need[i]) == need[i]. Zero for rules not in this automaton, which
     * would match trivially, so ac_scan skips those explicitly. */
    uint64_t                     need[NGX_HTTP_SHIELD_NRULES];

    /* bit -> ngx_http_shield_categories[] row, for reporting a hit. Set to
     * NGX_HTTP_SHIELD_NCATEGORIES for categories with no table in this
     * automaton (never set in out[], so never looked up). */
    ngx_uint_t                   row[64];
} ngx_http_shield_ac_t;

#endif /* NGX_HTTP_SHIELD_PATTERNS_H_INCLUDED_ */
