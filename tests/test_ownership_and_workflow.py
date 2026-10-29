import unittest
import sqlite3
import hashlib
from datetime import datetime
import app

class TestOwnershipAndWorkflow(unittest.TestCase):
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

    def _create_report(self, item_type, name, cat, desc, loc, contact, email, owner, verified=1, claim_token=None):
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest() if claim_token else None
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, image, claim_token_hash, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, '', ?, ?)
        """, (item_type, name, cat, desc, loc, contact, email, now, owner, token_hash, verified))
        rep_id = c.lastrowid
        conn.commit()
        conn.close()
        self.created_report_ids.append(rep_id)
        return rep_id

    def test_01_student_a_lost_and_student_b_found_workflow(self):
        """Student A reports lost item, Student B reports found item. Both see correct contextual actions."""
        student_a = "URK25CS1000"
        student_b = "URK25CS1003"
        student_c = "URK25CS1843"

        # Student A lost Blue HP Pavilion Laptop
        rep_a = self._create_report(
            "Lost Item", "Blue HP Pavilion Laptop", "Electronics",
            "Blue HP laptop with scratch near trackpad", "ECE Lab 2",
            "9876543210", "student_a@karunya.edu", student_a, verified=1
        )
        # Student B found HP Pavilion Laptop
        rep_b = self._create_report(
            "Found Item", "HP Pavilion Laptop Blue", "Electronics",
            "Blue laptop found on workbench", "ECE Lab 2",
            "9876543211", "student_b@karunya.edu", student_b, verified=1
        )

        # 1. Student A sees correct potential match on /matches with finder-side request action
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_matches_a = self.client.get("/matches")
        self.assertEqual(res_matches_a.status_code, 200)
        html_matches_a = res_matches_a.data.decode()
        self.assertIn("Your lost item", html_matches_a)
        self.assertIn("Contact Finder", html_matches_a)

        # Public listing for rep_a on /reports must show 'Your Listed Report' not 'Got My Item Back' button
        res_a = self.client.get("/reports")
        self.assertEqual(res_a.status_code, 200)
        html_a = res_a.data.decode()
        self.assertIn("Your Listed Report", html_a)
        self.assertNotIn('action="/mark_returned/', html_a)

        # 2. Student B sees match on /matches with owner-side action
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        res_matches_b = self.client.get("/matches")
        self.assertEqual(res_matches_b.status_code, 200)
        html_matches_b = res_matches_b.data.decode()
        self.assertIn("Your found item", html_matches_b)
        self.assertIn("Reach Out to Owner", html_matches_b)

        # Public listing on /reports never shows 'This might be mine' for their found report
        res_b = self.client.get("/reports")
        self.assertEqual(res_b.status_code, 200)
        html_b = res_b.data.decode()
        self.assertNotIn("This might be mine — Request Connection with Report", html_b)

        # 3. Student C (unrelated) cannot manage or mark returned either report
        with self.client.session_transaction() as sess:
            sess["user"] = student_c
            sess["role"] = "student"
            sess["_csrf_token"] = "csrf_token_c"

        # Student C attempts unauthorized mark_returned on rep_a -> 403
        res_hack_a = self.client.post(f"/mark_returned/{rep_a}", data={"csrf_token": "csrf_token_c"})
        self.assertEqual(res_hack_a.status_code, 403)

        # Student C attempts unauthorized delete_report on rep_b -> 403
        res_hack_b = self.client.post(f"/delete_report/{rep_b}", data={"csrf_token": "csrf_token_c"})
        self.assertEqual(res_hack_b.status_code, 403)

        # 4. Student B cannot mark Student A's report as returned -> 403
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
            sess["_csrf_token"] = "csrf_token_b"
        res_b_marks_a = self.client.post(f"/mark_returned/{rep_a}", data={"csrf_token": "csrf_token_b"})
        self.assertEqual(res_b_marks_a.status_code, 403)

        # Confirm rep_a status is still active in database
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT status FROM reports WHERE id = ?", (rep_a,))
        self.assertEqual(c.fetchone()[0], "active")
        conn.close()

    def test_02_guest_claim_isolation_and_management(self):
        """Guest claim link resolves accurately, manages own report, cannot manage another guest report"""
        token_g1 = "valid_token_guest_1_32_chars_ok!"
        token_g2 = "valid_token_guest_2_32_chars_ok!"
        rep_g1 = self._create_report(
            "Lost Item", "Black Umbrella", "Others", "Compact black umbrella",
            "Campus Gate 1", "9000000001", "g1@example.com", "guest_1111", verified=0, claim_token=token_g1
        )
        rep_g2 = self._create_report(
            "Found Item", "Black Umbrella", "Others", "Foldable black umbrella",
            "Campus Gate 1", "9000000002", "g2@example.com", "guest_2222", verified=0, claim_token=token_g2
        )

        # 1. Guest 1 manages rep_g1 via token_g1
        res_manage = self.client.get(f"/guest/manage/{token_g1}")
        self.assertEqual(res_manage.status_code, 200)
        html_manage = res_manage.data.decode()
        self.assertIn("Black Umbrella", html_manage)
        self.assertIn(token_g1, html_manage)

        # 2. Guest 1 marks returned via token_g1
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "csrf_g1"
        res_ret = self.client.post(f"/guest/mark_returned/{token_g1}", data={"csrf_token": "csrf_g1"}, follow_redirects=True)
        self.assertEqual(res_ret.status_code, 200)

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT status FROM reports WHERE id = ?", (rep_g1,))
        self.assertEqual(c.fetchone()[0], "returned")
        conn.close()

        # 3. Invalid or wrong token cannot mark rep_g2 returned -> 403
        res_fake = self.client.post("/guest/mark_returned/invalid_fake_token_12345", data={"csrf_token": "csrf_g1"})
        self.assertEqual(res_fake.status_code, 403)

        # Confirm rep_g2 status is still active
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT status FROM reports WHERE id = ?", (rep_g2,))
        self.assertEqual(c.fetchone()[0], "active")
        conn.close()

    def test_03_opening_guest_claim_while_student_logged_in_preserves_session(self):
        """Opening a guest claim link while logged in as a student preserves student session and does not transfer ownership"""
        student = "URK25CS1004"
        token_guest = "guest_token_student_session_test"
        rep_guest = self._create_report(
            "Found Item", "Silver Watch", "Accessories", "Analog watch found in canteen",
            "Canteen", "9876543219", "guest@example.com", "guest_3333", verified=0, claim_token=token_guest
        )

        # Student is logged in
        with self.client.session_transaction() as sess:
            sess["user"] = student
            sess["role"] = "student"
            sess["claimed_reports"] = []

        # Student opens guest claim URL
        res = self.client.get(f"/guest/claim/{token_guest}", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()

        # 1. Student identity is preserved (user pill in header still shows student)
        self.assertIn(student, html)
        self.assertIn("Guest Report Claim", html)

        # 2. Student did not acquire student ownership of this guest report
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT owner FROM reports WHERE id = ?", (rep_guest,))
        self.assertEqual(c.fetchone()[0], "guest_3333")
        conn.close()

        # 3. Student cannot mark returned this guest report via student /mark_returned route
        with self.client.session_transaction() as sess:
            sess["user"] = student
            sess["role"] = "student"
            sess["_csrf_token"] = "csrf_stud"
        res_hack = self.client.post(f"/mark_returned/{rep_guest}", data={"csrf_token": "csrf_stud"})
        self.assertEqual(res_hack.status_code, 403)

if __name__ == "__main__":
    unittest.main()
