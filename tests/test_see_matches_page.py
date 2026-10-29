import unittest
import sqlite3
import hashlib
import json
from datetime import datetime
import app

class TestSeeMatchesPage(unittest.TestCase):
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

    def _create_report(self, item_type, name, cat="Accessories", desc="", loc="Campus Library", contact="", email="", owner="Guest", status="active", verified=1, claim_token=None):
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

    def test_01_navigation_tab_and_badge(self):
        """Phase A: Dedicated 'See Matches' navigation tab appears on all pages with match badge."""
        student = "URK25CS5501"
        other_student = "URK25CS5502"

        # Initially student has no reports -> See Matches tab has no badge or count 0
        with self.client.session_transaction() as sess:
            sess["user"] = student
            sess["role"] = "student"

        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 200)
        html_dash = res_dash.data.decode()
        self.assertIn("See Matches", html_dash)
        self.assertIn("All Reports", html_dash)
        self.assertIn("Report Item", html_dash)
        self.assertIn("My Reports", html_dash)

        # Create matching reports
        rep_lost = self._create_report(
            "Lost Item", "Apple iPad Air 5", "Electronics",
            "Space grey iPad in blue magnetic folio case", "Library Study Room 2",
            "9876543001", "student1@karunya.edu", student
        )
        rep_found = self._create_report(
            "Found Item", "Apple iPad Air 5", "Electronics",
            "Found space grey iPad with blue cover", "Library Study Room 2",
            "9876543002", "student2@karunya.edu", other_student
        )

        # Now when viewing dashboard, badge appears showing match count
        res_with_match = self.client.get("/dashboard")
        html_with_match = res_with_match.data.decode()
        self.assertIn("See Matches", html_with_match)
        self.assertIn("nav-badge", html_with_match)

    def test_02_all_reports_clean_public_catalogue(self):
        """Phase A: /reports contains public catalogue and filter, but NO personalized match dashboard."""
        student = "URK25CS5503"
        other_student = "URK25CS5504"

        self._create_report("Lost Item", "Sony Headphones", "Electronics", "Black Sony", "Gym", owner=student)
        self._create_report("Found Item", "Sony Headphones", "Electronics", "Black Sony", "Gym", owner=other_student)

        with self.client.session_transaction() as sess:
            sess["user"] = student
            sess["role"] = "student"

        res = self.client.get("/reports")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()

        # Public listings, search and filters are present
        self.assertIn("Campus Reports", html)
        self.assertIn("All Categories", html)
        self.assertIn("Active Lost Items", html)
        self.assertIn("Active Found Items", html)

        # Personalized match grid is NOT in All Reports
        self.assertNotIn("match-card-box", html)
        self.assertNotIn("AI Matches for Your Reports", html)

    def test_03_see_matches_server_side_filtering_and_roles(self):
        """Phase A & B: /matches shows only current user's matches with role-appropriate human-friendly wording."""
        lost_student = "URK25CS5505"
        found_student = "URK25CS5506"
        unrelated_student = "URK25CS5507"

        rep_lost = self._create_report(
            "Lost Item", "Casio G-Shock Watch", "Accessories",
            "Matte black G-Shock digital watch", "Sports Complex",
            "9876543003", "lost@karunya.edu", lost_student
        )
        rep_found = self._create_report(
            "Found Item", "Casio G-Shock Watch", "Accessories",
            "Black Casio G-Shock found near basketball court", "Sports Complex",
            "9876543004", "found@karunya.edu", found_student
        )

        # 1. Lost item reporter view
        with self.client.session_transaction() as sess:
            sess["user"] = lost_student
            sess["role"] = "student"
        res_lost = self.client.get("/matches")
        self.assertEqual(res_lost.status_code, 200)
        html_lost = res_lost.data.decode()

        self.assertIn("Possible Matches", html_lost)
        self.assertIn("Your lost item", html_lost)
        self.assertIn("Casio G-Shock Watch", html_lost)
        self.assertIn("Someone reported finding", html_lost)
        self.assertIn("Contact Finder", html_lost)
        self.assertIn("Explain Match", html_lost)
        self.assertIn("View Details", html_lost)
        # Verify no AI jargon in user-facing card
        self.assertNotIn("Hybrid TF-IDF NLP semantic matching", html_lost)
        self.assertNotIn("NLP Semantic Overlap", html_lost)
        self.assertNotIn("Cosine similarity", html_lost)

        # 2. Found item reporter view
        with self.client.session_transaction() as sess:
            sess["user"] = found_student
            sess["role"] = "student"
        res_found = self.client.get("/matches")
        self.assertEqual(res_found.status_code, 200)
        html_found = res_found.data.decode()

        self.assertIn("Possible Matches", html_found)
        self.assertIn("Your found item", html_found)
        self.assertIn("Someone may be looking for an item like this", html_found)
        self.assertIn("Reach Out to Owner", html_found)
        self.assertNotIn("Contact Finder", html_found)

        # 3. Unrelated student view -> sees friendly empty state
        with self.client.session_transaction() as sess:
            sess["user"] = unrelated_student
            sess["role"] = "student"
        res_unrel = self.client.get("/matches")
        self.assertEqual(res_unrel.status_code, 200)
        html_unrel = res_unrel.data.decode()
        self.assertIn("No matches yet!", html_unrel)
        self.assertNotIn("Casio G-Shock Watch", html_unrel)

    def test_04_guest_isolation_on_matches_page(self):
        """Phase A: Guest See Matches strictly isolates claimed reports and hides other pairs."""
        guest_token_1 = "testguesttoken111111111111111111"
        guest_owner_1 = "guest_00001111"
        other_guest_token = "testguesttoken222222222222222222"
        other_guest_owner = "guest_00002222"

        rep_g1 = self._create_report(
            "Lost Item", "Kindle Paperwhite", "Electronics",
            "Black Kindle e-reader in dark green case", "Cafeteria",
            "9876543005", "g1@example.com", guest_owner_1, claim_token=guest_token_1
        )
        rep_g2 = self._create_report(
            "Found Item", "Kindle Paperwhite", "Electronics",
            "Found black Kindle e-reader at lunch table", "Cafeteria",
            "9876543006", "g2@example.com", other_guest_owner, claim_token=other_guest_token
        )

        # Guest without claimed reports sees empty state
        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["claimed_reports"] = []
        res_empty = self.client.get("/matches")
        self.assertEqual(res_empty.status_code, 200)
        self.assertIn("No matches yet!", res_empty.data.decode())
        self.assertNotIn("Kindle Paperwhite", res_empty.data.decode())

        # Guest with claimed report rep_g1 sees their match
        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["claimed_reports"] = [rep_g1]
        res_g1 = self.client.get("/matches")
        self.assertEqual(res_g1.status_code, 200)
        html_g1 = res_g1.data.decode()
        self.assertIn("Kindle Paperwhite", html_g1)
        self.assertIn("Your lost item", html_g1)
        self.assertIn("Contact Finder", html_g1)

    def test_05_plain_language_explanation_modal_api(self):
        """Phase C: Explain Match API returns plain language attributes and no technical buzzwords."""
        student_a = "URK25CS5508"
        student_b = "URK25CS5509"

        rep_a = self._create_report(
            "Lost Item", "Gold Bracelet", "Jewellery",
            "Lost gold chain bracelet near Ladies Hostel", "Ladies Hostel",
            "9876543007", "a@karunya.edu", student_a
        )
        rep_b = self._create_report(
            "Found Item", "Gold Bracelet", "Jewellery",
            "Found small gold chain bracelet by the hostel gate", "Ladies Hostel",
            "9876543008", "b@karunya.edu", student_b
        )

        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"

        res = self.client.get(f"/api/match_explanation?rep1_id={rep_a}&rep2_id={rep_b}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Check plain language attributes
        self.assertIn("score_pct", data)
        self.assertIn("matching_attributes", data)
        attrs = " ".join(data["matching_attributes"])
        self.assertIn("Jewellery category", attrs)
        self.assertIn("gold", attrs)
        self.assertIn("descriptions share similar details", attrs)

        # Check disclaimer
        self.assertIn("disclaimer", data)
        self.assertIn("not proof that the item is yours", data["disclaimer"])

if __name__ == "__main__":
    unittest.main()
