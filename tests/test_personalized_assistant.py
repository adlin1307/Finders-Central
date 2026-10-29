import unittest
import sqlite3
import re
from datetime import datetime
import app

class TestPersonalizedAIAssistant(unittest.TestCase):
    def setUp(self):
        self.app = app.app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()
        self.created_report_ids = []

    def tearDown(self):
        if self.created_report_ids:
            conn = sqlite3.connect("lostfound.db")
            c = conn.cursor()
            id_list = ",".join(str(i) for i in self.created_report_ids)
            c.execute(f"DELETE FROM connection_requests WHERE source_report_id IN ({id_list}) OR target_report_id IN ({id_list})")
            c.execute(f"DELETE FROM reports WHERE id IN ({id_list})")
            conn.commit()
            conn.close()

    def _create_report(self, item_type, name, cat, desc, loc, contact, email, owner, verified=1):
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, image, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, '', ?)
        """, (item_type, name, cat, desc, loc, contact, email, now, owner, verified))
        rep_id = c.lastrowid
        conn.commit()
        conn.close()
        self.created_report_ids.append(rep_id)
        return rep_id

    def test_01_student_a_and_student_b_personalized_matches(self):
        """Student A reports lost item, Student B reports found item; both see reverse match, Student C sees neither"""
        student_a = "URK25CS1000"
        student_b = "URK25CS1003"
        student_c = "URK25CS1843"

        # Student A lost Dell XPS Laptop
        rep_a = self._create_report(
            "Lost Item", "Dell XPS 15 Laptop", "Electronics",
            "Midnight blue Dell XPS 15 with stickers on cover", "Main Library 2nd Floor",
            "9876543210", "student_a@karunya.edu", student_a, verified=1
        )
        # Student B found Dell XPS Laptop
        rep_b = self._create_report(
            "Found Item", "Dell XPS 15 Laptop", "Electronics",
            "Blue Dell XPS 15 found on library study desk", "Main Library 2nd Floor",
            "9876543211", "student_b@karunya.edu", student_b, verified=1
        )

        # 1. Student A views /matches -> sees personalized match
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_a = self.client.get("/matches")
        self.assertEqual(res_a.status_code, 200)
        html_a = res_a.data.decode()
        self.assertIn("Possible Matches", html_a)
        self.assertIn("Dell", html_a)
        self.assertIn("Your lost item", html_a)
        self.assertIn("Contact Finder", html_a)

        # Confirm All Reports (/reports) is clean and does not have the personalized match cards
        res_pub = self.client.get("/reports")
        self.assertEqual(res_pub.status_code, 200)
        html_pub = res_pub.data.decode()
        self.assertNotIn("match-card-box", html_pub)
        self.assertIn("Campus Reports", html_pub)

        # 2. Student B views /matches -> sees the reverse match
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        res_b = self.client.get("/matches")
        self.assertEqual(res_b.status_code, 200)
        html_b = res_b.data.decode()
        self.assertIn("Possible Matches", html_b)
        self.assertIn("Dell", html_b)
        self.assertIn("Your found item", html_b)
        self.assertIn("Reach Out to Owner", html_b)

        # 3. Student C (who has no active reports) views /matches -> sees friendly empty state
        with self.client.session_transaction() as sess:
            sess["user"] = student_c
            sess["role"] = "student"
        res_c = self.client.get("/matches")
        self.assertEqual(res_c.status_code, 200)
        html_c = res_c.data.decode()
        self.assertIn("No matches yet!", html_c)
        self.assertNotIn("match-card-box", html_c)
        self.assertIn("Add a report to get started", html_c)

        # 4. Student D (who owns a notebook report) views /matches -> sees only their own notebook matches, NOT Student A/B's Dell XPS
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1099"
            sess["role"] = "student"
        res_d = self.client.get("/matches")
        self.assertEqual(res_d.status_code, 200)
        html_d = res_d.data.decode()
        self.assertNotIn("Dell XPS 15 Laptop", html_d)

    def test_02_guest_personalized_matches(self):
        """Guest sees matches only for their claimed report; unrelated guest sees empty state"""
        guest_owner_1 = "guest_11223344"
        guest_owner_2 = "guest_55667788"

        rep_g1 = self._create_report(
            "Lost Item", "Red Fossil Leather Wallet", "Wallets / Purses",
            "Red leather wallet containing library card", "Cafeteria Dining Hall",
            "9123456789", "guest1@example.com", guest_owner_1, verified=0
        )
        rep_g2 = self._create_report(
            "Found Item", "Red Fossil Leather Wallet", "Wallets / Purses",
            "Red fossil wallet picked up near cafeteria cashier", "Cafeteria Dining Hall",
            "9123456780", "guest2@example.com", guest_owner_2, verified=0
        )

        # Guest 1 has rep_g1 in session claimed_reports -> views /matches
        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["claimed_reports"] = [rep_g1]
        res_g1 = self.client.get("/matches")
        self.assertEqual(res_g1.status_code, 200)
        html_g1 = res_g1.data.decode()
        self.assertIn("Red Fossil Leather Wallet", html_g1)
        self.assertIn("Your lost item", html_g1)
        self.assertIn("Contact Finder", html_g1)

        # Unrelated Guest 3 with empty session claimed_reports views /matches -> sees empty state
        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["claimed_reports"] = []
        res_g3 = self.client.get("/matches")
        self.assertEqual(res_g3.status_code, 200)
        html_g3 = res_g3.data.decode()
        self.assertNotIn("Red Fossil Leather Wallet", html_g3)
        self.assertIn("No matches yet!", html_g3)
        self.assertIn("Add a report to get started", html_g3)

    def test_03_api_match_explanation_authorization(self):
        """API match explanation endpoint verifies user ownership authorization"""
        student_a = "URK25CS1000"
        student_b = "URK25CS1003"
        student_c = "URK25CS1843"

        rep_a = self._create_report(
            "Lost Item", "Casio FX991 Calculator", "Stationery",
            "Silver and black scientific calculator", "Science Block 301",
            "9876543210", "student_a@karunya.edu", student_a, verified=1
        )
        rep_b = self._create_report(
            "Found Item", "Casio FX991 Calculator", "Stationery",
            "Scientific calculator found in science classroom", "Science Block 301",
            "9876543211", "student_b@karunya.edu", student_b, verified=1
        )

        # Student A is authorized
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_auth_a = self.client.get(f"/api/match_explanation?rep1_id={rep_a}&rep2_id={rep_b}")
        self.assertEqual(res_auth_a.status_code, 200)
        data_a = res_auth_a.get_json()
        self.assertIn("nlp_similarity_pct", data_a)
        self.assertIn("matching_attributes", data_a)

        # Student B is authorized
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        res_auth_b = self.client.get(f"/api/match_explanation?rep1_id={rep_a}&rep2_id={rep_b}")
        self.assertEqual(res_auth_b.status_code, 200)

        # Student C (owns neither report) is FORBIDDEN (403)
        with self.client.session_transaction() as sess:
            sess["user"] = student_c
            sess["role"] = "student"
        res_unauth = self.client.get(f"/api/match_explanation?rep1_id={rep_a}&rep2_id={rep_b}")
        self.assertEqual(res_unauth.status_code, 403)
        data_unauth = res_unauth.get_json()
        self.assertIn("Unauthorized", data_unauth.get("error", ""))

        # Anonymous Guest (no claims) is FORBIDDEN (403)
        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["claimed_reports"] = []
        res_guest_unauth = self.client.get(f"/api/match_explanation?rep1_id={rep_a}&rep2_id={rep_b}")
        self.assertEqual(res_guest_unauth.status_code, 403)

    def test_04_connect_action_flow(self):
        """Connect action submits connection request for exact matched pair"""
        student_a = "URK25CS1000"
        student_b = "URK25CS1003"

        rep_a = self._create_report(
            "Lost Item", "Sony Noise Cancelling Headphones", "Electronics",
            "Black over-ear Sony WH1000XM4 headphones", "Gymnasium",
            "9876543210", "student_a@karunya.edu", student_a, verified=1
        )
        rep_b = self._create_report(
            "Found Item", "Sony Headphones WH1000", "Electronics",
            "Black wireless Sony headphones found on bleachers", "Gymnasium",
            "9876543211", "student_b@karunya.edu", student_b, verified=1
        )

        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"

        # Student A sends connection request
        res = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a,
            "target_report_id": rep_b,
            "message": "I lost these headphones around 5pm near the bench.",
            "contact_info": "9876543210"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Verify request exists in database
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, status, requester_id, recipient_id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_a, rep_b))
        req = c.fetchone()
        conn.close()
        self.assertIsNotNone(req)
        self.assertEqual(req[1], "pending")
        self.assertEqual(req[2], student_a)
        self.assertEqual(req[3], student_b)

if __name__ == "__main__":
    unittest.main()
