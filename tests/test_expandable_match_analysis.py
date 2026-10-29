import unittest
import sqlite3
import hashlib
import json
from datetime import datetime
import app

class TestExpandableMatchAnalysis(unittest.TestCase):
    def setUp(self):
        self.app = app.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.created_report_ids = []

    def tearDown(self):
        if self.created_report_ids:
            conn = sqlite3.connect("lostfound.db")
            c = conn.cursor()
            id_list = ",".join(str(i) for i in self.created_report_ids)
            c.execute(f"DELETE FROM notified_matches WHERE lost_report_id IN ({id_list}) OR found_report_id IN ({id_list})")
            c.execute(f"DELETE FROM connection_requests WHERE source_report_id IN ({id_list}) OR target_report_id IN ({id_list})")
            c.execute(f"DELETE FROM reports WHERE id IN ({id_list})")
            conn.commit()
            conn.close()

    def _create_report(self, item_type, name, cat="Electronics", desc="", loc="Main Library", contact="9876543210", email="test@karunya.edu", owner="Guest", status="active", verified=1, claim_token=None):
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest() if claim_token else None
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, image, claim_token_hash, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
        """, (item_type, name, cat, desc, loc, contact, email, status, now, owner, token_hash, verified))
        rep_id = c.lastrowid
        conn.commit()
        conn.close()
        self.created_report_ids.append(rep_id)
        return rep_id

    def test_01_backend_breakdown_structure_and_symmetry(self):
        """Backend analyze_match_breakdown computes truthful weights, components, and is mathematically symmetrical."""
        # Strong match pair
        score_1, breakdown_1 = app.analyze_match_breakdown(
            "Apple MacBook Pro", "Electronics", "Space grey MacBook Pro laptop with stickers", "Library 2nd Floor",
            "Apple MacBook Pro", "Electronics", "Found space grey MacBook Pro with stickers", "Library 2nd Floor"
        )
        score_2, breakdown_2 = app.analyze_match_breakdown(
            "Apple MacBook Pro", "Electronics", "Found space grey MacBook Pro with stickers", "Library 2nd Floor",
            "Apple MacBook Pro", "Electronics", "Space grey MacBook Pro laptop with stickers", "Library 2nd Floor"
        )

        # Symmetry
        self.assertEqual(score_1, score_2)
        self.assertEqual(breakdown_1["score"], breakdown_2["score"])
        self.assertEqual(breakdown_1["score_pct"], breakdown_2["score_pct"])
        self.assertEqual(breakdown_1["summary_sentence"], breakdown_2["summary_sentence"])

        # Check required fields
        self.assertIn("summary_sentence", breakdown_1)
        self.assertIn("components", breakdown_1)
        self.assertIn("disclaimer", breakdown_1)
        self.assertIn("doesn't confirm ownership", breakdown_1["disclaimer"])

        # Verify natural summary sentence
        self.assertIn("This might match because the item", breakdown_1["summary_sentence"])
        self.assertIn("similar", breakdown_1["summary_sentence"])

        # Verify components list structure
        components = breakdown_1["components"]
        comp_names = [c["name"] for c in components]
        self.assertIn("Item description", comp_names)
        self.assertIn("Item title", comp_names)
        self.assertIn("Category", comp_names)
        self.assertIn("Location", comp_names)
        self.assertIn("Colour", comp_names)
        self.assertIn("Brand", comp_names)
        self.assertIn("Conflicting details", comp_names)

        # Check description component weights and contribution
        desc_comp = next(c for c in components if c["name"] == "Item description")
        self.assertEqual(desc_comp["weight"], "30%")
        self.assertIn("Strong similarity", desc_comp["similarity"])
        self.assertTrue(desc_comp["contribution"].startswith("+"))

        # Check category component
        cat_comp = next(c for c in components if c["name"] == "Category")
        self.assertEqual(cat_comp["weight"], "20%")
        self.assertEqual(cat_comp["similarity"], "Matches")
        self.assertEqual(cat_comp["contribution"], "+20%")

        # Check location component
        loc_comp = next(c for c in components if c["name"] == "Location")
        self.assertEqual(loc_comp["weight"], "10%")
        self.assertEqual(loc_comp["similarity"], "Similar")
        self.assertEqual(loc_comp["contribution"], "+10%")

        # Check conflict component when no conflict exists
        conf_comp = next(c for c in components if c["name"] == "Conflicting details")
        self.assertEqual(conf_comp["similarity"], "None detected")
        self.assertEqual(conf_comp["status"], "clean")

    def test_02_contradiction_penalty_and_plain_language_warning(self):
        """Contradictory matches cap the score truthfully and display plain-language warnings."""
        score, breakdown = app.analyze_match_breakdown(
            "Hydro Flask Water Bottle", "Water Bottles", "Bright blue Hydro Flask bottle with dent", "Sports Complex",
            "Hydro Flask Water Bottle", "Water Bottles", "Matte black Hydro Flask bottle with dent", "Sports Complex"
        )

        # Score capped strictly <= 22% due to conflicting colors
        self.assertLessEqual(score, 0.22)
        self.assertLessEqual(breakdown["score"], 22)

        # Contradiction warning in plain language
        contradictions = breakdown["contradictions"]
        self.assertTrue(len(contradictions) >= 1)
        self.assertTrue(any("Conflicting colors" in c for c in contradictions))
        self.assertTrue(any("colours don't match" in c for c in contradictions))

        # Check conflict component
        conf_comp = next(c for c in breakdown["components"] if c["name"] == "Conflicting details")
        self.assertEqual(conf_comp["similarity"], "Warning: conflicts detected")
        self.assertEqual(conf_comp["status"], "conflict")

    def test_03_default_card_and_expanded_analysis_html(self):
        """Matches page renders the clean default view and accessible 'Show Match Analysis' dropdown."""
        student_lost = "URK25CS7701"
        student_found = "URK25CS7702"

        rep_lost = self._create_report(
            "Lost Item", "Scientific Calculator", "Electronics",
            "Casio fx-991EX Classwiz scientific calculator with transparent slide cover", "Math Lab 101",
            "9876543201", "lost_calc@karunya.edu", student_lost
        )
        rep_found = self._create_report(
            "Found Item", "Scientific Calculator", "Electronics",
            "Casio fx-991EX Classwiz calculator found under desk", "Math Lab 101",
            "9876543202", "found_calc@karunya.edu", student_found
        )

        with self.client.session_transaction() as sess:
            sess["user"] = student_lost
            sess["role"] = "student"

        res = self.client.get("/matches")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()

        # 1. Default View elements
        self.assertIn("Possible Matches", html)
        self.assertIn("Match score:", html)
        self.assertIn("match-short-explanation", html)
        self.assertIn("This might match because the item", html)
        self.assertIn("View Details", html)
        self.assertIn("Explain Match", html)
        self.assertIn("Contact Finder", html)

        # 2. Expandable Dropdown elements
        self.assertIn("match-analysis-dropdown", html)
        self.assertIn("Show Match Analysis", html)
        self.assertIn("dropdown-chevron", html)
        self.assertIn("Score Component Breakdown:", html)
        self.assertIn("Item description", html)
        self.assertIn("Item title", html)
        self.assertIn("Category", html)
        self.assertIn("Location", html)
        self.assertIn("Conflicting details", html)
        self.assertIn("None detected", html)
        self.assertTrue("confirm ownership" in html)

        # 3. Verify no AI jargon in rendered HTML
        self.assertNotIn("TF-IDF vectors", html)
        self.assertNotIn("Cosine similarity", html)
        self.assertNotIn("token overlap", html)
        self.assertNotIn("heuristic penalties", html)
        self.assertNotIn("probability of ownership", html)

    def test_04_role_specific_symmetrical_view_found_owner(self):
        """Found item owner sees 'Reach Out to Owner' action and symmetrical natural summary."""
        student_lost = "URK25CS7703"
        student_found = "URK25CS7704"

        self._create_report(
            "Lost Item", "Leather Wallet", "Wallets",
            "Brown leather Tommy Hilfiger bifold wallet with campus card inside", "Auditorium",
            "9876543203", "lost_wallet@karunya.edu", student_lost
        )
        self._create_report(
            "Found Item", "Leather Wallet", "Wallets",
            "Brown leather Tommy Hilfiger wallet found on auditorium seat", "Auditorium",
            "9876543204", "found_wallet@karunya.edu", student_found
        )

        with self.client.session_transaction() as sess:
            sess["user"] = student_found
            sess["role"] = "student"

        res = self.client.get("/matches")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()

        self.assertIn("Your found item", html)
        self.assertIn("Reach Out to Owner", html)
        self.assertNotIn("Contact Finder", html)
        self.assertIn("Show Match Analysis", html)
        self.assertIn("Score Component Breakdown:", html)

    def test_05_api_match_explanation_json_and_privacy(self):
        """API /api/match_explanation returns rich breakdown without leaking private contact info."""
        student_lost = "URK25CS7705"
        student_found = "URK25CS7706"

        private_phone = "9876500099"
        private_email = "secret_contact@karunya.edu"

        rep_lost = self._create_report(
            "Lost Item", "Noise Cancelling Earbuds", "Electronics",
            "Black Sony WF-1000XM4 earbuds in black charging case", "Admin Block",
            private_phone, private_email, student_lost
        )
        rep_found = self._create_report(
            "Found Item", "Noise Cancelling Earbuds", "Electronics",
            "Found black Sony wireless earbuds near admin stairs", "Admin Block",
            "9876500088", "finder_secret@karunya.edu", student_found
        )

        with self.client.session_transaction() as sess:
            sess["user"] = student_lost
            sess["role"] = "student"

        res = self.client.get(f"/api/match_explanation?rep1_id={rep_lost}&rep2_id={rep_found}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Check API response fields
        self.assertIn("score", data)
        self.assertIn("score_pct", data)
        self.assertIn("summary_sentence", data)
        self.assertIn("components", data)
        self.assertIn("verification_clues", data)
        self.assertIn("disclaimer", data)

        # Strict privacy check: private phone, email, and register numbers must not leak in explanation payload
        payload_str = json.dumps(data)
        self.assertNotIn(private_phone, payload_str)
        self.assertNotIn(private_email, payload_str)
        self.assertNotIn(student_lost, payload_str)
        self.assertNotIn(student_found, payload_str)

if __name__ == "__main__":
    unittest.main()
