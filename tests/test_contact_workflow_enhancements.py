import unittest
import sqlite3
import hashlib
import json
from datetime import datetime
import app

class TestContactWorkflowEnhancements(unittest.TestCase):
    """
    Focused test suite verifying:
    1. 'I Found This / Reach Out' explains on-platform connection request (not an email)
    2. Request submission confirms server save, shows clear feedback and status
    3. Accept & Decline actions redirect cleanly without raw 403 errors
    4. Accepted connections reveal email & phone (or 'Not provided') across student-student,
       student-guest, guest-student, and guest-guest scenarios, protecting privacy
    5. Guest claim links work independently of student logins without mutating ownership
    """

    def setUp(self):
        self.app = app.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.created_report_ids = []

    def tearDown(self):
        if self.created_report_ids:
            try:
                conn = sqlite3.connect("lostfound.db", timeout=10)
                c = conn.cursor()
                id_list = ",".join(str(i) for i in self.created_report_ids)
                c.execute(f"DELETE FROM connection_requests WHERE source_report_id IN ({id_list}) OR target_report_id IN ({id_list})")
                c.execute(f"DELETE FROM reports WHERE id IN ({id_list})")
                conn.commit()
                conn.close()
            except Exception:
                pass

    def _create_report(self, item_type, name, cat="Electronics", desc="", loc="Campus",
                       contact="", email="", owner="Guest", status="active", verified=1, claim_token=None):
        conn = sqlite3.connect("lostfound.db", timeout=10)
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

    def _create_connection_request(self, src_id, tgt_id, req_type="student", req_id="URK25CS1001",
                                   rec_type="student", rec_id="URK25CS1002", status="pending",
                                   message="Clue", response_note="", contact_info=""):
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        now = datetime.now().strftime("%d %b %Y, %I:%M %p")
        c.execute("""
            INSERT INTO connection_requests (
                source_report_id, target_report_id, requester_type, requester_id,
                recipient_type, recipient_id, status, message, response_note,
                contact_info, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (src_id, tgt_id, req_type, req_id, rec_type, rec_id, status, message, response_note, contact_info, now, now))
        cr_id = c.lastrowid
        conn.commit()
        conn.close()
        return cr_id

    # -------------------------------------------------------------------------
    # 1. UI Copy Clarification: On-Platform Request (Not an Email)
    # -------------------------------------------------------------------------
    def test_01_reach_out_copy_explains_on_platform_not_email(self):
        """Verifies that buttons and modals explain on-platform connection (not an email)."""
        lost_id = self._create_report("Lost Item", "Blue Umbrella", "Others", "Left in library", "Library", owner="URK25CS3001")
        found_id = self._create_report("Found Item", "Blue Rain Umbrella", "Others", "Found 2nd floor", "Library", owner="URK25CS3002")

        # 1. Check /reports page
        res = self.client.get("/reports")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()

        self.assertIn("🤝 I Found This / Reach Out", html)
        self.assertIn("Sends an on-platform connection request (not an email)", html)
        self.assertIn("On-Platform Request:", html)
        self.assertIn("This sends a connection request directly inside Finder's Central (not an email)", html)

        # 2. Check /matches page for an authenticated student
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3001"
            sess["role"] = "student"
        res_matches = self.client.get("/matches")
        self.assertEqual(res_matches.status_code, 200)
        matches_html = res_matches.data.decode()
        self.assertIn("Sends an on-platform connection request (not an email)", matches_html)
        self.assertIn("On-Platform Request:", matches_html)
        self.assertIn("This sends a connection request directly inside Finder's Central (not an email)", matches_html)

    # -------------------------------------------------------------------------
    # 2. Submission Feedback and Server-Side Save Confirmation
    # -------------------------------------------------------------------------
    def test_02_request_submission_confirms_db_save_and_status(self):
        """Submission confirms record exists in SQLite before displaying success."""
        rep_lost = self._create_report("Lost Item", "Scientific Calculator", "Others", "fx-991EX", "Hall A", "9876500001", "owner1@karunya.edu", "URK25CS3010")
        rep_found = self._create_report("Found Item", "Casio Scientific Calculator", "Others", "Classroom desk", "Hall A", "9876500002", "owner2@karunya.edu", "URK25CS3020")

        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3010"
            sess["role"] = "student"
            sess["_csrf_token"] = "valid_csrf_token"

        res = self.client.post("/request_connection", data={
            "csrf_token": "valid_csrf_token",
            "source_report_id": rep_lost,
            "target_report_id": rep_found,
            "message": "It has my initials CK etched lightly on the back casing.",
            "contact_info": "9876500001"
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 200)
        html = res.data.decode()
        self.assertIn("Request sent! We&#39;ll let you know when they respond.", html)

        # Verify DB directly: connection_request was saved and status is pending
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        c.execute("""
            SELECT id, status, message, requester_id, recipient_id
            FROM connection_requests
            WHERE source_report_id = ? AND target_report_id = ?
        """, (rep_lost, rep_found))
        saved = c.fetchone()
        conn.close()

        self.assertIsNotNone(saved)
        self.assertEqual(saved[1], "pending")
        self.assertEqual(saved[2], "It has my initials CK etched lightly on the back casing.")
        self.assertEqual(saved[3], "URK25CS3010")
        self.assertEqual(saved[4], "URK25CS3020")

    # -------------------------------------------------------------------------
    # 3. Accept and Decline Actions Redirect Cleanly Without Raw 403
    # -------------------------------------------------------------------------
    def test_03_accept_and_decline_redirect_cleanly_student(self):
        """Student accept and decline actions update state and redirect cleanly with flash message."""
        rep_src = self._create_report("Lost Item", "Water Bottle Hydro", "Others", owner="URK25CS3031")
        rep_tgt = self._create_report("Found Item", "Hydro Flask Bottle", "Others", owner="URK25CS3032")

        # Create pending connection request using helper
        req_id = self._create_connection_request(
            rep_src, rep_tgt,
            req_type="student", req_id="URK25CS3031",
            rec_type="student", rec_id="URK25CS3032",
            status="pending", message="Verification clue here"
        )

        # Target owner URK25CS3032 accepts the request
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3032"
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"

        res_accept = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "test_csrf_token",
            "response_note": "Meet me outside the student union at 3pm."
        }, follow_redirects=True)

        self.assertEqual(res_accept.status_code, 200)
        html = res_accept.data.decode()
        self.assertIn("Connection accepted! Contact details are now available to both of you.", html)
        self.assertIn("Connection accepted! You can now coordinate the return securely.", html)
        self.assertNotIn("403 Forbidden", html)

        # Check DB status
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        c.execute("SELECT status, response_note FROM connection_requests WHERE id = ?", (req_id,))
        row = c.fetchone()
        conn.close()
        self.assertEqual(row[0], "accepted")
        self.assertEqual(row[1], "Meet me outside the student union at 3pm.")

        # Test Decline on a second request
        req_id_2 = self._create_connection_request(
            rep_src, rep_tgt,
            req_type="student", req_id="URK25CS3031",
            rec_type="student", rec_id="URK25CS3032",
            status="pending", message="Second clue"
        )

        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3032"
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"

        res_decline = self.client.post(f"/connection_request/{req_id_2}/decline", data={
            "csrf_token": "test_csrf_token"
        }, follow_redirects=True)
        self.assertEqual(res_decline.status_code, 200)
        html_decline = res_decline.data.decode()
        self.assertIn("Request declined.", html_decline)
        self.assertNotIn("403 Forbidden", html_decline)

        # Check DB status
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        c.execute("SELECT status FROM connection_requests WHERE id = ?", (req_id_2,))
        row_dec = c.fetchone()
        conn.close()
        self.assertEqual(row_dec[0], "declined")

    # -------------------------------------------------------------------------
    # 4. Authorization & Security: Unauthorized Actions Do Not Show Raw 403 White Screen
    # -------------------------------------------------------------------------
    def test_04_unauthorized_user_redirected_safely_no_raw_crash(self):
        """Unauthorized user attempting to accept or decline another user's request is safely rejected."""
        rep_src = self._create_report("Lost Item", "Keyring with 3 keys", "Others", owner="URK25CS3041")
        rep_tgt = self._create_report("Found Item", "Brass keys on red ring", "Others", owner="URK25CS3042")

        req_id = self._create_connection_request(
            rep_src, rep_tgt,
            req_type="student", req_id="URK25CS3041",
            rec_type="student", rec_id="URK25CS3042",
            status="pending", message="Clue"
        )

        # URK25CS3099 (uninvolved third-party) tries to accept
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3099"
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"

        res = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "test_csrf_token"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        html = res.data.decode()
        self.assertIn("You do not have permission to manage this connection request.", html)
        self.assertNotIn("Werkzeug", html)

        # Confirm request status remains pending
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        c.execute("SELECT status FROM connection_requests WHERE id = ?", (req_id,))
        self.assertEqual(c.fetchone()[0], "pending")
        conn.close()

    # -------------------------------------------------------------------------
    # 5. Contact Info Revealed on Accepted Requests Across All User Types
    #    With "Not provided" Fallback for Missing Phone or Email
    # -------------------------------------------------------------------------
    def test_05_contact_reveal_with_not_provided_fallback_student_and_guest(self):
        """
        Tests revealed contact info across:
        - Student-Student
        - Student-Guest
        - Missing email/phone displays 'Not provided'
        - Unauthorized users cannot see private contact details
        """
        # A: Student with full contact info
        rep_student = self._create_report("Lost Item", "Leather Wallet", "Others",
                                          contact="9876543210", email="student_wallet@karunya.edu",
                                          owner="URK25CS3050")

        # B: Guest with phone but NO email (empty string)
        guest_token = "guest_token_abc_12345678901234567890"
        rep_guest = self._create_report("Found Item", "Black Leather Wallet", "Others",
                                        contact="9123456780", email="",
                                        owner="Guest", claim_token=guest_token)

        # Create and accept connection request: Student requested Guest
        req_id = self._create_connection_request(
            rep_student, rep_guest,
            req_type="student", req_id="URK25CS3050",
            rec_type="guest", rec_id="guest",
            status="accepted", message="Has an old library card inside",
            response_note="Come pick it up at the gate"
        )

        # 1. Requester (Student) views their My Reports page
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3050"
            sess["role"] = "student"

        res_student_view = self.client.get("/my_reports")
        self.assertEqual(res_student_view.status_code, 200)
        html_student = res_student_view.data.decode()

        # Student should see Guest's phone
        self.assertIn("9123456780", html_student)
        # Guest had no email, so student should see "Not provided"
        self.assertIn("Not provided", html_student)

        # 2. Recipient (Guest) views via their private claim link
        res_guest_view = self.client.get(f"/guest/manage/{guest_token}")
        self.assertEqual(res_guest_view.status_code, 200)
        html_guest = res_guest_view.data.decode()

        # Guest should see Student's full contact info
        self.assertIn("9876543210", html_guest)
        self.assertIn("student_wallet@karunya.edu", html_guest)

        # 3. Public / unauthenticated visitor views /reports: MUST NOT reveal contact info
        res_public = self.client.get("/reports")
        html_pub = res_public.data.decode()
        self.assertNotIn("student_wallet@karunya.edu", html_pub)
        self.assertNotIn("9123456780", html_pub)

    def test_06_guest_to_guest_connection_accept_via_token(self):
        """Guest accepts incoming connection request from another guest using claim token."""
        guest_tok_1 = "guest_tok_requester_12345678901234"
        guest_tok_2 = "guest_tok_recipient_12345678901234"

        rep_guest_src = self._create_report("Lost Item", "AirPods Pro Case", "Electronics",
                                            contact="", email="requester_guest@example.com",
                                            owner="Guest", claim_token=guest_tok_1)
        rep_guest_tgt = self._create_report("Found Item", "AirPods Case White", "Electronics",
                                            contact="9998887776", email="",
                                            owner="Guest", claim_token=guest_tok_2)

        req_id = self._create_connection_request(
            rep_guest_src, rep_guest_tgt,
            req_type="guest", req_id="guest",
            rec_type="guest", rec_id="guest",
            status="pending", message="Case has a green silicone sleeve"
        )

        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test_csrf_token"

        # Recipient guest accepts using their claim token
        res_accept = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "test_csrf_token",
            "claim_token": guest_tok_2,
            "response_note": "Meet at front gate reception"
        }, follow_redirects=True)

        self.assertEqual(res_accept.status_code, 200)
        html = res_accept.data.decode()
        self.assertIn("Connection accepted! Contact details are now available to both of you.", html)
        self.assertIn("Connection accepted! You can now coordinate the return securely.", html)
        self.assertNotIn("403 Forbidden", html)

        # Requester's phone was missing, so Guest 2's page should show "Not provided" for phone
        self.assertIn("Not provided", html)
        self.assertIn("requester_guest@example.com", html)

    # -------------------------------------------------------------------------
    # 6. Guest Claim Links Work Independently of Student Logins
    # -------------------------------------------------------------------------
    def test_07_guest_claim_link_with_active_student_session_preserves_isolation(self):
        """
        Opening a guest claim link while logged in as a student:
        - Does NOT overwrite student login
        - Does NOT convert guest report ownership to the student
        - Displays isolation notice
        """
        student_id = "URK25CS3080"
        guest_token = "guest_isolated_token_1234567890123"

        guest_rep_id = self._create_report("Found Item", "Gym Bag Blue", "Others",
                                           contact="9111222333", email="guest_visitor@example.com",
                                           owner="Guest", claim_token=guest_token)

        # Student logs in
        with self.client.session_transaction() as sess:
            sess["user"] = student_id
            sess["role"] = "student"

        # Logged-in student opens the guest claim link
        res_claim = self.client.get(f"/guest/claim/{guest_token}", follow_redirects=True)
        self.assertEqual(res_claim.status_code, 200)
        html = res_claim.data.decode()

        # 1. Confirm page shows isolation notice with the student ID
        self.assertIn("Your student account", html)
        self.assertIn(student_id, html)
        self.assertIn("remains active and securely isolated", html)

        # 2. Check session: user is still the student
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("user"), student_id)
            self.assertEqual(sess.get("role"), "student")

        # 3. Check database: report owner is STILL 'Guest', not the student
        conn = sqlite3.connect("lostfound.db", timeout=10)
        c = conn.cursor()
        c.execute("SELECT owner, verified FROM reports WHERE id = ?", (guest_rep_id,))
        owner, verified = c.fetchone()
        conn.close()

        self.assertEqual(owner, "Guest")
        self.assertEqual(verified, 1)

    # -------------------------------------------------------------------------
    # 7. Invalid CSRF on Accept/Decline Returns Friendly Error, Not Raw 403
    # -------------------------------------------------------------------------
    def test_08_invalid_or_missing_csrf_returns_friendly_error(self):
        """Invalid or missing CSRF token returns 400 Bad Request with friendly error page, not raw crash."""
        rep_src = self._create_report("Lost Item", "Lab Manual", "Books", owner="URK25CS3061")
        rep_tgt = self._create_report("Found Item", "Chemistry Lab Manual", "Books", owner="URK25CS3062")

        req_id = self._create_connection_request(
            rep_src, rep_tgt,
            req_type="student", req_id="URK25CS3061",
            rec_type="student", rec_id="URK25CS3062",
            status="pending", message="Section B manual"
        )

        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS3062"
            sess["role"] = "student"
            sess["_csrf_token"] = "correct_csrf_token"

        # Missing / invalid CSRF token
        res = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "tampered_invalid_token",
            "response_note": "I have it"
        })
        self.assertEqual(res.status_code, 400)
        html = res.data.decode()
        self.assertIn("Security Verification Failed", html)
        self.assertIn("invalid or missing CSRF session token", html)
        self.assertNotIn("403 Forbidden", html)


if __name__ == "__main__":
    unittest.main()
