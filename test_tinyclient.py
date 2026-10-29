#!/usr/bin/env python3
"""
test_tinyclient.py — Suite de tests unitaires pour Tiny Web Client.

Couvre : parsing d'URL, validation des entrées, protection CRLF,
parsing de la réponse HTTP, décodage chunked, construction de requête.

Lancer avec :  python3 -m unittest test_tinyclient.py -v
"""

import unittest

from tinyclient import (
    parse_url,
    validate_url_string,
    validate_path,
    build_request,
    parse_response,
    parse_status_code,
    decode_chunked,
    TinyClientError,
)


class TestParseUrl(unittest.TestCase):

    def test_url_http_simple(self):
        self.assertEqual(
            parse_url("http://example.com/index.html"),
            ("http", "example.com", 80, "/index.html"),
        )

    def test_url_https_default_path(self):
        self.assertEqual(
            parse_url("https://example.com"),
            ("https", "example.com", 443, "/"),
        )

    def test_url_custom_port(self):
        self.assertEqual(
            parse_url("http://example.com:8080/a/b"),
            ("http", "example.com", 8080, "/a/b"),
        )

    def test_url_unsupported_scheme_rejected(self):
        with self.assertRaises(TinyClientError):
            parse_url("ftp://example.com/")

    def test_url_missing_host_rejected(self):
        with self.assertRaises(TinyClientError):
            parse_url("http:///path")

    def test_url_invalid_port_rejected(self):
        with self.assertRaises(TinyClientError):
            parse_url("http://example.com:abc/")


class TestValidation(unittest.TestCase):

    def test_url_too_long_rejected(self):
        long_url = "http://example.com/" + ("a" * 3000)
        with self.assertRaises(TinyClientError):
            validate_url_string(long_url)

    def test_control_character_rejected(self):
        with self.assertRaises(TinyClientError):
            validate_url_string("http://example.com/\r\nX-Injected: evil")

    def test_valid_url_passes(self):
        # Ne doit lever aucune exception
        validate_url_string("http://example.com/index.html")


class TestCrlfInjection(unittest.TestCase):

    def test_crlf_in_path_rejected(self):
        with self.assertRaises(TinyClientError):
            validate_path("/page\r\nX-Injected: malicious-header")

    def test_clean_path_accepted(self):
        validate_path("/page?x=1")  # ne doit pas lever d'exception

    def test_build_request_rejects_crlf_in_custom_header(self):
        with self.assertRaises(TinyClientError):
            build_request(
                "GET", "example.com", "/",
                extra_headers={"X-Custom": "value\r\nX-Injected: evil"},
            )


class TestBuildRequest(unittest.TestCase):

    def test_request_contains_mandatory_headers(self):
        req = build_request("GET", "example.com", "/index.html").decode("ascii")
        self.assertIn("GET /index.html HTTP/1.1\r\n", req)
        self.assertIn("Host: example.com\r\n", req)
        self.assertIn("Connection: close\r\n", req)
        self.assertTrue(req.endswith("\r\n\r\n"))

    def test_post_request_includes_content_length(self):
        body = b'{"key": "value"}'
        req = build_request("POST", "example.com", "/api", body=body)
        self.assertIn(b"Content-Length: 16\r\n", req)
        self.assertTrue(req.endswith(body))


class TestParseResponse(unittest.TestCase):

    def test_parse_simple_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 13\r\n"
            b"\r\n"
            b"Hello, world!"
        )
        status_line, headers, body = parse_response(raw)
        self.assertEqual(status_line, "HTTP/1.1 200 OK")
        self.assertEqual(headers["Content-Type"], "text/html")
        self.assertEqual(headers["Content-Length"], "13")
        self.assertEqual(body, b"Hello, world!")

    def test_parse_status_code(self):
        self.assertEqual(parse_status_code("HTTP/1.1 404 Not Found"), 404)

    def test_parse_response_missing_separator_raises(self):
        with self.assertRaises(TinyClientError):
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html")


class TestChunkedDecoding(unittest.TestCase):

    def test_decode_simple_chunked_body(self):
        raw_body = b"7\r\nMozilla\r\n9\r\nDeveloper\r\n0\r\n\r\n"
        self.assertEqual(decode_chunked(raw_body), b"MozillaDeveloper")

    def test_decode_empty_chunked_body(self):
        raw_body = b"0\r\n\r\n"
        self.assertEqual(decode_chunked(raw_body), b"")

    def test_decode_malformed_chunk_size_raises(self):
        with self.assertRaises(TinyClientError):
            decode_chunked(b"ZZZ\r\ndata\r\n0\r\n\r\n")


if __name__ == "__main__":
    unittest.main()
