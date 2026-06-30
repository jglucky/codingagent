"""Tests for GitHub URL parsing."""

import unittest

from repo_scanner.github import GitHubCloneError, parse_github_url


class GitHubUrlTests(unittest.TestCase):
    def test_shorthand(self) -> None:
        repo = parse_github_url("snyk/goof")
        self.assertEqual(repo.owner, "snyk")
        self.assertEqual(repo.name, "goof")
        self.assertEqual(repo.url, "https://github.com/snyk/goof.git")

    def test_https_url(self) -> None:
        repo = parse_github_url("https://github.com/snyk/goof/")
        self.assertEqual(repo.owner, "snyk")
        self.assertEqual(repo.name, "goof")

    def test_invalid_url(self) -> None:
        with self.assertRaises(GitHubCloneError):
            parse_github_url("https://gitlab.com/foo/bar")


if __name__ == "__main__":
    unittest.main()