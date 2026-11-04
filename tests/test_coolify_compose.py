"""Keep the Coolify-managed profile in sync without adding test dependencies."""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("generate_coolify_compose", ROOT / "scripts/generate_coolify_compose.py")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class TestCoolifyCompose(unittest.TestCase):
    def test_generated_file_is_current(self):
        self.assertEqual((ROOT / "docker-compose.coolify.yml").read_text(), generator.render())

    def test_managed_file_matches_vendored_profile(self):
        rendered = generator.render()
        profile_line = rendered.split("        content: |\n", 1)[1].splitlines()[0]
        self.assertEqual(json.loads(profile_line), json.loads((ROOT / "docker/chromium-seccomp.json").read_text()))
        self.assertIn("source: ./chromium-seccomp.json", rendered)
        self.assertIn("seccomp=./chromium-seccomp.json", rendered)
        self.assertIn("read_only: true", rendered)

    def test_existing_oauth_volume_and_route_are_preserved(self):
        rendered = generator.render()
        self.assertIn("oauth-data:/data", rendered)
        self.assertIn("http://mcp:8080/mcp", rendered)
        self.assertIn("INSTALL_CAPTURE: 'true'", rendered)
        self.assertNotIn("unconfined", rendered)
        self.assertNotIn("/var/run/docker.sock", rendered)

    def test_commit_pin(self):
        commit = "a" * 40
        self.assertIn(f".git#{commit}'", generator.render(commit))

    def test_ref_cannot_inject_compose_content(self):
        for ref in ("master'", "master\nservices:", "$(command)", "", "main#other"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                generator.render(ref)


if __name__ == "__main__":
    unittest.main()
