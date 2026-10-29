import unittest
import sqlite3
import hashlib
import json
from datetime import datetime
import app

class TestConnectionWorkflow(unittest.TestCase):
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
            c.execute(f"DELETE FROM connection_requests WHERE source_report_id IN ({id_list}) OR target_report_id IN ({id_list})")
            c.execute(f"DELETE FROM reports WHERE id IN ({id_list})")
            conn.commit()
            conn.close()

    def _create_report(self, item_type, name, cat="Electronics", desc="", loc="Campus", contact="", email="", owner="Guest", status="active", verified=1, claim_token=None):
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

    def test_01_request_submission_feedback_and_clue_preservation(self):
        """Connection request submission shows clear feedback flash and preserves entered clue on validation failure"""
        student_a = "URK25CS2001"
        student_b = "URK25CS2002"

        rep_a = self._create_report("Lost Item", "Sony Headphones WH1000", "Electronics", "Black Sony headphones", "Library 3rd floor", "9876543201", "student_a@karunya.edu", student_a)
        rep_b = self._create_report("Found Item", "Sony Noise Cancelling Headphones", "Electronics", "Found near study carrel", "Library 3rd floor", "9876543202", "student_b@karunya.edu", student_b)

        # 1. Validation failure: missing verification clue (tested with follow_redirects=False to verify session state)
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        res_fail = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a,
            "target_report_id": rep_b,
            "message": "",
            "contact_info": "9876543201"
        }, follow_redirects=False)
        self.assertEqual(res_fail.status_code, 302)

        # Confirm entered contact info was preserved in session before being popped by template
        with self.client.session_transaction() as sess:
            form_data = sess.get("connect_form_data")
            self.assertIsNotNone(form_data)
            self.assertEqual(form_data.get("contact_info"), "9876543201")

        # Now follow redirect to /reports and verify flash error and preserved field in HTML
        res_follow = self.client.get(res_fail.headers["Location"])
        html_follow = res_follow.data.decode()
        self.assertIn("Please provide an identifying clue", html_follow)
        self.assertIn("9876543201", html_follow)

        # 2. Successful submission: flashes clear success message
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        res_success = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a,
            "target_report_id": rep_b,
            "message": "It has a small scratch on the right hinge and custom black foam pads.",
            "contact_info": "9876543201"
        }, follow_redirects=True)
        self.assertEqual(res_success.status_code, 200)
        html_success = res_success.data.decode()
        self.assertIn("Request sent! We&#39;ll let you know when they respond.", html_success)
        self.assertIn("PENDING RECIPIENT", html_success)

    def test_02_validation_blocks_self_request_duplicates_and_ineligible(self):
        """Prevents self-requests, duplicate requests, and requests on returned items"""
        student_a = "URK25CS2003"
        student_b = "URK25CS2004"

        # Reports owned by same student
        rep_a_lost = self._create_report("Lost Item", "Calculator Casio fx991", "Others", "Silver casio", "Exam Hall", "9876543203", "a@karunya.edu", student_a)
        rep_a_found = self._create_report("Found Item", "Casio fx991 Calculator", "Others", "Silver casio", "Exam Hall", "9876543203", "a@karunya.edu", student_a)

        # 1. Self-request blocked
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        res_self = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a_lost,
            "target_report_id": rep_a_found,
            "message": "Trying to connect to my own item"
        }, follow_redirects=True)
        html_self = res_self.data.decode()
        self.assertIn("Cannot send a connection request between reports owned by the same person", html_self)

        # 2. Ineligible (returned) report blocked
        rep_b_returned = self._create_report("Found Item", "Casio Calculator", "Others", "Returned calculator", "Exam Hall", "9876543204", "b@karunya.edu", student_b, status="returned")
        res_ret = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a_lost,
            "target_report_id": rep_b_returned,
            "message": "Connecting to returned item"
        }, follow_redirects=True)
        html_ret = res_ret.data.decode()
        self.assertIn("Connection requests can only be sent for active, unreturned reports", html_ret)

        # 3. Duplicate request blocked
        rep_b_active = self._create_report("Found Item", "Casio fx991 Active", "Others", "Active calculator", "Exam Hall", "9876543204", "b@karunya.edu", student_b)
        # Send first request
        res1 = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a_lost,
            "target_report_id": rep_b_active,
            "message": "Valid first request"
        }, follow_redirects=True)
        self.assertIn("Request sent! We&#39;ll let you know when they respond.", res1.data.decode())

        # Try sending second duplicate request
        res_dup = self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a_lost,
            "target_report_id": rep_b_active,
            "message": "Duplicate attempt"
        }, follow_redirects=True)
        self.assertIn("already pending", res_dup.data.decode())

    def test_03_student_to_student_acceptance_and_contact_reveal(self):
        """Student A requests connection, Student B accepts, both see permitted contact info, third-party C is forbidden"""
        student_a = "URK25CS2010"
        student_b = "URK25CS2011"
        student_c = "URK25CS2012"  # Third party

        phone_a = "9876543210"
        email_a = "student_a_unique@karunya.edu"
        phone_b = "9876543211"
        email_b = "student_b_unique@karunya.edu"

        rep_a = self._create_report("Lost Item", "Dell XPS 15 Laptop", "Electronics", "Silver Dell laptop with stickers", "Computer Lab 4", phone_a, email_a, student_a)
        rep_b = self._create_report("Found Item", "Dell XPS Silver Laptop", "Electronics", "Dell laptop found on bench 3", "Computer Lab 4", phone_b, email_b, student_b)

        # Student A sends request
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a,
            "target_report_id": rep_b,
            "message": "Has an Ubuntu sticker and 32GB RAM tag.",
            "contact_info": "Urgent, available on WhatsApp: " + phone_a
        }, follow_redirects=True)

        # Find request ID
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, status FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_a, rep_b))
        req_row = c.fetchone()
        conn.close()
        self.assertIsNotNone(req_row)
        req_id = req_row[0]
        self.assertEqual(req_row[1], "pending")

        # Prior to acceptance: neither party's unmasked contact info is visible in /my_reports
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        res_b_pending = self.client.get("/my_reports")
        html_b_pending = res_b_pending.data.decode()
        self.assertIn("PENDING REVIEW", html_b_pending)
        self.assertNotIn(phone_a, html_b_pending)
        self.assertNotIn(email_a, html_b_pending)

        # Calling secure contact endpoint while pending returns 403
        res_contact_pending = self.client.get(f"/connection_request/{req_id}/contact")
        self.assertEqual(res_contact_pending.status_code, 403)

        # Student B accepts request
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        res_accept = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "test_csrf_token",
            "response_note": "Sticker matches! Come to Lab 4 office between 2-4 PM."
        }, follow_redirects=True)
        self.assertEqual(res_accept.status_code, 200)
        html_b_accepted = res_accept.data.decode()
        self.assertIn("Connection accepted! You can now coordinate the return securely.", html_b_accepted)
        self.assertIn("ACCEPTED", html_b_accepted)

        # Student B now sees Student A's contact info
        self.assertIn(phone_a, html_b_accepted)
        self.assertIn(email_a, html_b_accepted)

        # Student A visits /my_reports and now sees Student B's contact info and response note
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_a_accepted = self.client.get("/my_reports")
        html_a_accepted = res_a_accepted.data.decode()
        self.assertIn("ACCEPTED!", html_a_accepted)
        self.assertIn(phone_b, html_a_accepted)
        self.assertIn(email_b, html_a_accepted)
        self.assertIn("Come to Lab 4 office between 2-4 PM.", html_a_accepted)

        # Authorized API contact access returns 200 for Student A and Student B
        res_api_a = self.client.get(f"/connection_request/{req_id}/contact")
        self.assertEqual(res_api_a.status_code, 200)
        data_a = json.loads(res_api_a.data.decode())
        self.assertEqual(data_a["partner_contact"], phone_b)
        self.assertEqual(data_a["partner_email"], email_b)

        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        res_api_b = self.client.get(f"/connection_request/{req_id}/contact")
        self.assertEqual(res_api_b.status_code, 200)
        data_b = json.loads(res_api_b.data.decode())
        self.assertEqual(data_b["partner_contact"], phone_a)
        self.assertEqual(data_b["partner_email"], email_a)

        # Third party Student C (unrelated) gets HTTP 403 on API and sees nothing in /my_reports
        with self.client.session_transaction() as sess:
            sess["user"] = student_c
            sess["role"] = "student"
        res_api_c = self.client.get(f"/connection_request/{req_id}/contact")
        self.assertEqual(res_api_c.status_code, 403)

        res_c_reports = self.client.get("/my_reports")
        html_c = res_c_reports.data.decode()
        self.assertNotIn(phone_a, html_c)
        self.assertNotIn(phone_b, html_c)

    def test_04_student_to_guest_and_guest_to_student_flows(self):
        """Cross-role connections work with guest claim tokens and isolate contact details"""
        student_a = "URK25CS2020"
        guest_token = "guest_claim_token_flow_test_32!"
        guest_owner = "guest_workflow_owner_456"

        phone_student = "9876543220"
        email_student = "student_a_cross@karunya.edu"
        phone_guest = "9876543221"
        email_guest = "guest_cross@example.com"

        rep_student = self._create_report("Lost Item", "RayBan Aviator Sunglasses", "Accessories", "Gold frame aviators", "Cafeteria", phone_student, email_student, student_a)
        rep_guest = self._create_report("Found Item", "Aviator Sunglasses Gold", "Accessories", "Found on cafeteria table", "Cafeteria", phone_guest, email_guest, guest_owner, claim_token=guest_token)

        # Student A requests connection targeting Guest report
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_student,
            "target_report_id": rep_guest,
            "message": "It has green gradient G-15 lenses and tiny scratch on left bridge."
        }, follow_redirects=True)

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_student, rep_guest))
        req_id = c.fetchone()[0]
        conn.close()

        # Guest opens guest manage page
        res_manage = self.client.get(f"/guest/manage/{guest_token}")
        self.assertEqual(res_manage.status_code, 200)
        self.assertIn("PENDING REVIEW", res_manage.data.decode())

        # Guest accepts connection request using claim token
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test_csrf_token"
        res_g_accept = self.client.post(f"/guest/connection_request/{req_id}/accept", data={
            "csrf_token": "test_csrf_token",
            "claim_token": guest_token,
            "response_note": "Matches! Meet me at Security Office at 1 PM."
        }, follow_redirects=True)
        self.assertEqual(res_g_accept.status_code, 200)
        html_g_accepted = res_g_accept.data.decode()
        self.assertIn("Connection accepted! You can now coordinate the return securely.", html_g_accepted)
        self.assertIn(phone_student, html_g_accepted)
        self.assertIn(email_student, html_g_accepted)

        # Student A in /my_reports now sees Guest contact info
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_s_accepted = self.client.get("/my_reports")
        html_s_accepted = res_s_accepted.data.decode()
        self.assertIn(phone_guest, html_s_accepted)
        self.assertIn(email_guest, html_s_accepted)
        self.assertIn("Meet me at Security Office at 1 PM.", html_s_accepted)

        # Random unauthenticated guest with different or invalid token gets 403 on API
        with self.client.session_transaction() as sess:
            sess.clear()
        res_bad_guest = self.client.get(f"/connection_request/{req_id}/contact?token=wrong_guest_token_1234567890123")
        self.assertEqual(res_bad_guest.status_code, 403)

        # Verified guest with valid token gets 200 on API
        res_good_guest = self.client.get(f"/connection_request/{req_id}/contact?token={guest_token}")
        self.assertEqual(res_good_guest.status_code, 200)
        data_g = json.loads(res_good_guest.data.decode())
        self.assertEqual(data_g["partner_contact"], phone_student)

    def test_05_declined_request_keeps_contacts_strictly_withheld(self):
        """Declining a request sets status to DECLINED and never exposes phone or email to either party"""
        student_a = "URK25CS2030"
        student_b = "URK25CS2031"

        phone_a = "9876543230"
        email_a = "student_a_decline@karunya.edu"
        phone_b = "9876543231"
        email_b = "student_b_decline@karunya.edu"

        rep_a = self._create_report("Lost Item", "Fitbit Charge 5", "Electronics", "Black band fitbit", "Gym", phone_a, email_a, student_a)
        rep_b = self._create_report("Found Item", "Fitness Tracker Black", "Electronics", "Found in locker room", "Gym", phone_b, email_b, student_b)

        # Student A sends request
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        self.client.post("/request_connection", data={
            "csrf_token": "test_csrf_token",
            "source_report_id": rep_a,
            "target_report_id": rep_b,
            "message": "It is a Fitbit."
        }, follow_redirects=True)

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_a, rep_b))
        req_id = c.fetchone()[0]
        conn.close()

        # Student B declines request
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
            sess["_csrf_token"] = "test_csrf_token"
        res_dec = self.client.post(f"/connection_request/{req_id}/decline", data={"csrf_token": "test_csrf_token"}, follow_redirects=True)
        self.assertEqual(res_dec.status_code, 200)
        html_dec_b = res_dec.data.decode()
        self.assertIn("DECLINED", html_dec_b)
        self.assertIn("Contact details remain strictly withheld", html_dec_b)
        self.assertNotIn(phone_a, html_dec_b)
        self.assertNotIn(email_a, html_dec_b)

        # Student A sees DECLINED and contact info is withheld
        with self.client.session_transaction() as sess:
            sess["user"] = student_a
            sess["role"] = "student"
        res_dec_a = self.client.get("/my_reports")
        html_dec_a = res_dec_a.data.decode()
        self.assertIn("DECLINED", html_dec_a)
        self.assertIn("Contact details are not shared", html_dec_a)
        self.assertNotIn(phone_b, html_dec_a)
        self.assertNotIn(email_b, html_dec_a)

        # Secure contact endpoint returns 403 Forbidden for both
        self.assertEqual(self.client.get(f"/connection_request/{req_id}/contact").status_code, 403)
        with self.client.session_transaction() as sess:
            sess["user"] = student_b
            sess["role"] = "student"
        self.assertEqual(self.client.get(f"/connection_request/{req_id}/contact").status_code, 403)

    def test_06_public_all_reports_does_not_expose_unmasked_contacts(self):
        """Public /reports cards show safe masked labels and do not expose unmasked contact details"""
        phone_secret = "9876543299"
        email_secret = "confidential_person@karunya.edu"
        rep_id = self._create_report("Lost Item", "Confidential Notebook", "Books", "Notebook with project ideas", "Admin Block", phone_secret, email_secret, "URK25CS2099")

        # Unauthenticated visitor requests /reports
        res_pub = self.client.get("/reports")
        self.assertEqual(res_pub.status_code, 200)
        html_pub = res_pub.data.decode()

        # Secret contact details must NOT appear in public HTML
        self.assertNotIn(phone_secret, html_pub)
        self.assertNotIn(email_secret, html_pub)
        self.assertIn("Confidential Notebook", html_pub)

if __name__ == "__main__":
    unittest.main()
