import unittest
import sqlite3
import re
import io
from PIL import Image
import os
import hashlib
from datetime import datetime, timedelta

import app

class FinderRescueTestSuite(unittest.TestCase):
    def setUp(self):
        self.app = app.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.created_report_ids = []
        self.created_request_ids = []
        self.created_user_ids = []

    def tearDown(self):
        # Clean up only the test records created during this test
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        if self.created_request_ids:
            c.execute(f"DELETE FROM connection_requests WHERE id IN ({','.join(map(str, self.created_request_ids))})")
        if self.created_report_ids:
            c.execute(f"DELETE FROM reports WHERE id IN ({','.join(map(str, self.created_report_ids))})")
            c.execute(f"DELETE FROM notified_matches WHERE lost_report_id IN ({','.join(map(str, self.created_report_ids))}) OR found_report_id IN ({','.join(map(str, self.created_report_ids))})")
        if self.created_user_ids:
            c.execute(f"DELETE FROM users WHERE id IN ({','.join(map(str, self.created_user_ids))})")
        conn.commit()
        conn.close()

    def test_01_reporter_label_pii_masking(self):
        """Phase 3: Verify safe reporter labels protect student and guest identity"""
        # Jinja filter registrations
        self.assertIn("reporter_label", app.app.jinja_env.filters)
        self.assertIn("reporter_label_filter", app.app.jinja_env.filters)
        self.assertIn("mask_phone", app.app.jinja_env.filters)
        self.assertIn("mask_phone_filter", app.app.jinja_env.filters)
        self.assertIn("mask_email", app.app.jinja_env.filters)
        self.assertIn("mask_email_filter", app.app.jinja_env.filters)

        # Student register number
        self.assertEqual(app.reporter_label("URK25CS1004"), "Verified Student (***1004)")
        self.assertEqual(app.reporter_label_filter("URK25CS1004"), "Verified Student (***1004)")
        self.assertEqual(app.reporter_label("URK25CS1099"), "Verified Student (***1099)")
        # Guest alias
        self.assertEqual(app.reporter_label("guest_64c2d0e7ece9"), "Campus Visitor (Guest-ece9)")
        self.assertEqual(app.reporter_label("Guest"), "Campus Visitor")
        # Empty fallback
        self.assertEqual(app.reporter_label(""), "Campus Community Member")

        # Phone masking
        self.assertEqual(app.mask_phone("9876543210"), "******3210")
        self.assertEqual(app.mask_phone_filter("9876543210"), "******3210")
        # Email masking
        self.assertEqual(app.mask_email("student@karunya.edu"), "s***t@karunya.edu")
        self.assertEqual(app.mask_email_filter("student@karunya.edu"), "s***t@karunya.edu")

    def test_02_report_submission_student_no_image(self):
        """Phase 2: Verify student lost report submission without image"""
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "valid_csrf_token"

        resp = self.client.post("/report", data={
            "csrf_token": "valid_csrf_token",
            "item_type": "Lost Item",
            "item_name": "Test Scientific Calculator FX991",
            "category": "Electronics",
            "description": "Casio scientific calculator with initials on back",
            "location": "Math Department Lab",
            "contact": "9876543210",
            "email": "student@college.edu"
        }, follow_redirects=False)

        # Should either redirect to /reports or render match_found
        self.assertIn(resp.status_code, [200, 302])

        # Verify database record
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, item_name, owner, verified, status FROM reports WHERE item_name = 'test scientific calculator fx991'")
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.created_report_ids.append(row[0])
        self.assertEqual(row[2], "URK25CS1004")
        self.assertEqual(row[3], 1)
        self.assertEqual(row[4], "active")

    def test_03_report_submission_guest_with_image(self):
        """Phase 2: Verify guest found report submission with valid image and claim link"""
        # Create a tiny in-memory test PNG
        img = Image.new("RGB", (30, 30), color="blue")
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        with self.client.session_transaction() as sess:
            sess["user"] = "Guest"
            sess["_csrf_token"] = "guest_csrf_token"

        resp = self.client.post("/report", data={
            "csrf_token": "guest_csrf_token",
            "item_type": "Found Item",
            "item_name": "Test Keyring with 3 Keys",
            "category": "Accessories",
            "description": "Silver keyring found on bench",
            "location": "Sports Ground",
            "contact": "9123456780",
            "email": "visitor@example.com",
            "image": (img_bytes, "test_keys.png")
        }, content_type="multipart/form-data", follow_redirects=False)

        self.assertIn(resp.status_code, [200, 302])

        # Verify database record
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, item_name, owner, claim_token_hash, verified, image FROM reports WHERE item_name = 'test keyring with 3 keys'")
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.created_report_ids.append(row[0])
        self.assertTrue(row[2].startswith("guest_"))
        self.assertIsNotNone(row[3]) # claim_token_hash present
        self.assertTrue(len(row[5]) > 0) # image filename stored

    def test_04_report_custom_category_submission(self):
        """Phase 2: Custom category specification works smoothly"""
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "custom_cat_token"

        resp = self.client.post("/report", data={
            "csrf_token": "custom_cat_token",
            "item_type": "Lost Item",
            "item_name": "Test Lab Coat",
            "category": "Other",
            "other_category": "Lab Equipment",
            "description": "White chemistry lab coat",
            "location": "Chemistry Block",
            "contact": "9876543210",
            "email": "student@college.edu"
        }, follow_redirects=False)

        self.assertIn(resp.status_code, [200, 302])

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, category FROM reports WHERE item_name = 'test lab coat'")
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.created_report_ids.append(row[0])
        self.assertEqual(row[1], "Lab Equipment")

    def test_05_report_validation_errors_retain_data(self):
        """Phase 2: Validation errors return 400 and preserve form data"""
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "val_token"

        # Invalid phone (too short)
        resp = self.client.post("/report", data={
            "csrf_token": "val_token",
            "item_type": "Lost Item",
            "item_name": "Test Laptop Sleeve",
            "category": "Electronics",
            "description": "Grey neoprene sleeve",
            "location": "Audi",
            "contact": "12345", # invalid
            "email": "student@college.edu"
        })

        self.assertEqual(resp.status_code, 400)
        self.assertIn("10-digit mobile phone number", resp.data.decode())
        self.assertIn("Test Laptop Sleeve", resp.data.decode()) # data preserved

    def test_06_ai_tfidf_nlp_similarity_and_contradiction(self):
        """Phase 6 & 7: Verify TF-IDF NLP similarity and Explainable Match Assistant"""
        # Exact/high overlap
        t1 = "Apple AirPods Pro with white wireless charging case"
        t2 = "AirPods Pro lost white charging case earbuds"
        sim = app.calculate_tfidf_cosine_similarity(t1, t2)
        self.assertGreater(sim, 0.25)

        # Contradiction check: blue vs black water bottle
        score, explanation = app.analyze_match_breakdown(
            "blue water bottle", "Water Bottles", "Milton blue flask", "Library",
            "black water bottle", "Water Bottles", "Black plastic bottle", "Library"
        )
        # Contradiction should cap score strictly <= 0.22 (22%)
        self.assertLessEqual(score, 0.22)
        self.assertTrue(any("Conflicting colors" in c for c in explanation["contradictions"]))
        self.assertIn("disclaimer", explanation)

        # High match without contradiction
        score2, explanation2 = app.analyze_match_breakdown(
            "AirPods Pro", "Electronics", "White AirPods Pro earbuds", "CTC III",
            "AirPods Pro", "Electronics", "Found white airpods near CTC III", "Near CTC III"
        )
        self.assertGreaterEqual(score2, 0.70)
        self.assertTrue(len(explanation2["matching_attributes"]) >= 2)
        self.assertTrue(len(explanation2["verification_clues"]) >= 1)

    def test_07_match_connection_request_end_to_end(self):
        """Phase 4: Full connection request lifecycle (Create, Pending, Accept, Outgoing update)"""
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

        # Create Report A (Lost by student URK25CS1003)
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Lost Item', 'test purple umbrella', 'Accessories', 'Lost purple umbrella', 'Library', '9876543210', 's1@college.edu', 'active', ?, 'URK25CS1003', 1)
        """, (now_str,))
        rep_a_id = c.lastrowid
        self.created_report_ids.append(rep_a_id)

        # Create Report B (Found by student URK25CS1004)
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Found Item', 'test purple umbrella', 'Accessories', 'Found purple umbrella', 'Library entrance', '9876543211', 's2@college.edu', 'active', ?, 'URK25CS1004', 1)
        """, (now_str,))
        rep_b_id = c.lastrowid
        self.created_report_ids.append(rep_b_id)
        conn.commit()
        conn.close()

        # Step 1: Owner of Report A (URK25CS1003) requests connection with Report B
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1003"
            sess["_csrf_token"] = "conn_csrf"

        req_resp = self.client.post("/request_connection", data={
            "csrf_token": "conn_csrf",
            "source_report_id": rep_a_id,
            "target_report_id": rep_b_id,
            "message": "It has my name tag on the handle inside.",
            "contact_info": "Phone: 9876543210"
        }, follow_redirects=False)
        self.assertEqual(req_resp.status_code, 302)

        # Verify request created in DB
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, status, message, recipient_id, contact_info FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_a_id, rep_b_id))
        req_row = c.fetchone()
        conn.close()

        self.assertIsNotNone(req_row)
        req_id = req_row[0]
        self.created_request_ids.append(req_id)
        self.assertEqual(req_row[1], "pending")
        self.assertEqual(req_row[3], "URK25CS1004")

        # Step 2: Recipient (URK25CS1004) sees it in My Reports
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
        my_rep_resp = self.client.get("/my_reports")
        self.assertEqual(my_rep_resp.status_code, 200)
        self.assertIn("It has my name tag on the handle inside.", my_rep_resp.data.decode())
        # Private contact info MUST NOT be visible while pending
        self.assertNotIn("Phone: 9876543210", my_rep_resp.data.decode())

        # Step 3: Recipient accepts request with coordination note
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "accept_csrf"

        accept_resp = self.client.post(f"/connection_request/{req_id}/accept", data={
            "csrf_token": "accept_csrf",
            "response_note": "Meet me at Library Counter at 4 PM"
        }, follow_redirects=False)
        self.assertEqual(accept_resp.status_code, 302)

        # Step 4: Verify accepted state and sender's view in Outgoing Requests
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT status, response_note FROM connection_requests WHERE id = ?", (req_id,))
        updated_req = c.fetchone()
        conn.close()
        self.assertEqual(updated_req[0], "accepted")
        self.assertEqual(updated_req[1], "Meet me at Library Counter at 4 PM")

        # Sender sees the coordination note in Outgoing requests
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1003"
        sender_resp = self.client.get("/my_reports")
        self.assertIn("Meet me at Library Counter at 4 PM", sender_resp.data.decode())

    def test_08_connection_request_self_request_prevented(self):
        """Phase 4: Self-requests and requests on same item are prevented"""
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Lost Item', 'test self item', 'Books', 'desc', 'loc', '9876543210', 's@c.edu', 'active', ?, 'URK25CS1004', 1)
        """, (now_str,))
        rep1 = c.lastrowid
        self.created_report_ids.append(rep1)

        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Found Item', 'test self item', 'Books', 'desc', 'loc', '9876543210', 's@c.edu', 'active', ?, 'URK25CS1004', 1)
        """, (now_str,))
        rep2 = c.lastrowid
        self.created_report_ids.append(rep2)
        conn.commit()
        conn.close()

        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "self_token"

        resp = self.client.post("/request_connection", data={
            "csrf_token": "self_token",
            "source_report_id": rep1,
            "target_report_id": rep2,
            "message": "Testing self request"
        }, follow_redirects=False)

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep1, rep2))
        row = c.fetchone()
        conn.close()

        # No request should have been inserted
        self.assertIsNone(row)

    def test_09_guest_claim_link_and_authorization(self):
        """Phase 4: Guest claim recovery and management authorization"""
        token = "test_guest_token_1234567890abcdef"
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        expires_at = (datetime.now() + timedelta(days=30)).isoformat()
        now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, claim_token_hash, claim_token_expires_at, verified)
            VALUES ('Lost Item', 'test guest ring', 'Jewellery', 'Silver band', 'Hostel', '9876543210', 'guest@example.com', 'active', ?, 'guest_abc123', ?, ?, 0)
        """, (now_str, token_hash, expires_at))
        rep_id = c.lastrowid
        self.created_report_ids.append(rep_id)
        conn.commit()
        conn.close()

        # Access claim link
        resp = self.client.get(f"/guest/claim/{token}", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Test Guest Ring", resp.data.decode())

        # Verify report was marked verified
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT verified FROM reports WHERE id = ?", (rep_id,))
        self.assertEqual(c.fetchone()[0], 1)
        conn.close()

    def test_10_api_match_explanation(self):
        """Phase 7: Explainable Match Assistant API endpoint returns JSON reasoning when authorized"""
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["role"] = "student"
        resp = self.client.get("/api/match_explanation?rep1_id=1&rep2_id=2")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("score_pct", data)
        self.assertIn("matching_attributes", data)
        self.assertIn("verification_clues", data)
        self.assertIn("nlp_similarity_pct", data)
        self.assertIn("disclaimer", data)

    def test_11_connection_request_decline_and_returned_ineligible(self):
        """Phase 4: Test declining a connection request and rejecting returned items"""
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

        # Create active lost report for URK25CS1003
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Lost Item', 'test decline item', 'Books', 'Lost notebook', 'Lab', '9876543210', 's1@c.edu', 'active', ?, 'URK25CS1003', 1)
        """, (now_str,))
        rep_lost = c.lastrowid
        self.created_report_ids.append(rep_lost)

        # Create already returned found report for URK25CS1004
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Found Item', 'test decline item', 'Books', 'Found notebook', 'Lab', '9876543211', 's2@c.edu', 'returned', ?, 'URK25CS1004', 1)
        """, (now_str,))
        rep_returned = c.lastrowid
        self.created_report_ids.append(rep_returned)

        # Create active found report for URK25CS1004
        c.execute("""
            INSERT INTO reports (item_type, item_name, category, description, location, contact, email, status, timestamp, owner, verified)
            VALUES ('Found Item', 'test decline item', 'Books', 'Found notebook', 'Lab', '9876543211', 's2@c.edu', 'active', ?, 'URK25CS1004', 1)
        """, (now_str,))
        rep_active_found = c.lastrowid
        self.created_report_ids.append(rep_active_found)

        conn.commit()
        conn.close()

        # Attempt to connect to already RETURNED report -> Must be rejected
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1003"
            sess["_csrf_token"] = "test_decline_token"

        resp_ret = self.client.post("/request_connection", data={
            "csrf_token": "test_decline_token",
            "source_report_id": rep_lost,
            "target_report_id": rep_returned,
            "message": "Trying to connect to returned item"
        }, follow_redirects=False)

        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_lost, rep_returned))
        self.assertIsNone(c.fetchone()) # Not created

        # Now connect to active found report
        self.client.post("/request_connection", data={
            "csrf_token": "test_decline_token",
            "source_report_id": rep_lost,
            "target_report_id": rep_active_found,
            "message": "Valid request to decline"
        }, follow_redirects=False)

        c.execute("SELECT id FROM connection_requests WHERE source_report_id = ? AND target_report_id = ?", (rep_lost, rep_active_found))
        req_row = c.fetchone()
        conn.close()
        self.assertIsNotNone(req_row)
        req_id = req_row[0]
        self.created_request_ids.append(req_id)

        # Recipient declines request
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS1004"
            sess["_csrf_token"] = "decline_csrf"

        decline_resp = self.client.post(f"/connection_request/{req_id}/decline", data={
            "csrf_token": "decline_csrf"
        }, follow_redirects=False)
        self.assertEqual(decline_resp.status_code, 302)

        # Verify status is declined
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT status FROM connection_requests WHERE id = ?", (req_id,))
        self.assertEqual(c.fetchone()[0], "declined")
        conn.close()

    def test_12_public_reports_page_privacy(self):
        """Phase 3: Verify /reports renders safely without exposing full student IDs or raw guest tokens"""
        resp = self.client.get("/reports")
        self.assertEqual(resp.status_code, 200)
        content = resp.data.decode()

        # No Jinja runtime template errors
        self.assertNotIn("TemplateRuntimeError", content)
        self.assertNotIn("No filter named", content)

        # Suggested Matches link present
        self.assertIn("See Matches", content)

        # Check reporter label formatting
        self.assertIn("Verified Student (***", content)
        self.assertIn("Campus Visitor", content)

        # Raw student IDs should not be in reporter labels
        self.assertNotIn("Reported by: URK25CS1004", content)
        self.assertNotIn("Reported by: URK25CS1003", content)

if __name__ == "__main__":
    unittest.main()
