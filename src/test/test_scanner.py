from core import threat_analyzer

def test_xss(capsys):
    test_url = "http://localhost:5000/"
    scanner = threat_analyzer.ThreatAnalyzer(test_url)
    scanner.scan()

    captured = capsys.readouterr()
    assert "Cross-Site Scripting (XSS)" in captured.out
    assert captured.err == ""

def test_sqli(capsys):
    test_url = "http://localhost:5000/"
    scanner = threat_analyzer.ThreatAnalyzer(test_url)
    scanner.scan()

    captured = capsys.readouterr()
    assert "SQL Injection" in captured.out
    assert captured.err == ""

def test_scanner(capsys):
    test_url = "https://juice-shop.herokuapp.com/"
    scanner = threat_analyzer.ThreatAnalyzer(test_url)
    scanner.scan()

    captured = capsys.readouterr()
    assert "[VULNERABILITY FOUND]" in captured.out
    assert captured.err == ""