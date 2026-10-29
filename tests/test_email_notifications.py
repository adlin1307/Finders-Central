import unittest
from unittest.mock import patch, MagicMock
import sqlite3
import hashlib
import json
import socket
import smtplib
from datetime import datetime
import app

class TestEmailNotifications(unittest.TestCase):
    def setUp(self):
        self.app = app.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.created_report_ids = []
        # Reset cache before tests
        app._EMAIL_STATUS_CACHE = {"checked_at": 0, "status": None}

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
        app._EMAIL_STATUS_CACHE = {"checked_at": 0, "status": None}
        self.app.config.pop("_MOCK_EMAIL_STATUS", None)

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

    def test_01_configuration_and_timeout_settings(self):
        """Verifies SMTP settings and bounded network timeouts are properly configured."""
        self.assertEqual(self.app.config.get("MAIL_SERVER"), "smtp.gmail.com")
        self.assertEqual(self.app.config.get("MAIL_PORT"), 587)
        self.assertTrue(self.app.config.get("MAIL_USE_TLS"))
        self.assertGreater(float(self.app.config.get("MAIL_TIMEOUT", 0)), 0)

    def test_02_status_helper_unconfigured_when_credentials_missing(self):
        """Email status helper accurately reports unconfigured when username/password is missing."""
        orig_user = self.app.config.get("MAIL_USERNAME")
        orig_pass = self.app.config.get("MAIL_PASSWORD")
        try:
            self.app.config["MAIL_USERNAME"] = None
            self.app.config["MAIL_PASSWORD"] = None
            status = app.get_email_service_status(force_recheck=True)
            self.assertEqual(status["status"], "unconfigured")
            self.assertFalse(status["configured"])
            self.assertFalse(status["can_send"])
            self.assertIn("unconfigured", status["message"].lower())
        finally:
            self.app.config["MAIL_USERNAME"] = orig_user
            self.app.config["MAIL_PASSWORD"] = orig_pass

    @patch("smtplib.SMTP")
    def test_03_status_helper_connection_failure(self, mock_smtp):
        """Email status helper accurately reports connection failure when socket/DNS fails."""
        mock_smtp.side_effect = socket.gaierror(8, "nodename nor servname provided, or not known")
        status = app.get_email_service_status(force_recheck=True)
        self.assertEqual(status["status"], "connection_failed")
        self.assertTrue(status["configured"])
        self.assertFalse(status["can_send"])
        self.assertIn("temporarily unavailable", status["message"].lower())

    @patch("smtplib.SMTP")
    def test_04_status_helper_auth_failure(self, mock_smtp):
        """Email status helper accurately reports auth failure when credentials rejected."""
        instance = MagicMock()
        instance.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
        mock_smtp.return_value = instance

        status = app.get_email_service_status(force_recheck=True)
        self.assertEqual(status["status"], "auth_failed")
        self.assertTrue(status["configured"])
        self.assertFalse(status["can_send"])
        self.assertIn("authentication failed", status["message"].lower())

    @patch("smtplib.SMTP")
    def test_05_status_helper_active_verified(self, mock_smtp):
        """Email status helper accurately reports active when SMTP handshake and auth succeed."""
        instance = MagicMock()
        mock_smtp.return_value = instance

        status = app.get_email_service_status(force_recheck=True)
        self.assertEqual(status["status"], "active")
        self.assertTrue(status["configured"])
        self.assertTrue(status["can_send"])
        self.assertIn("active", status["label"].lower())

    def test_06_template_rendering_consistent_email_status(self):
        """Verifies templates render dynamically without contradictory development mode warnings."""
        # 1. When active
        self.app.config["_MOCK_EMAIL_STATUS"] = {
            "status": "active",
            "label": "Campus Email Service Active",
            "configured": True,
            "can_send": True,
            "message": "Automated campus email notifications are fully active."
        }
        res_active = self.client.get("/reports")
        self.assertEqual(res_active.status_code, 200)
        self.assertNotIn("development mode", res_active.get_data(as_text=True).lower())
        self.assertIn("Campus Email Service Active", res_active.get_data(as_text=True))

        # 2. When connection is unavailable
        self.app.config["_MOCK_EMAIL_STATUS"] = {
            "status": "connection_failed",
            "label": "Mail Service Unavailable",
            "configured": True,
            "can_send": False,
            "message": "Campus mail relay connection is temporarily unavailable."
        }
        res_offline = self.client.get("/reports")
        self.assertEqual(res_offline.status_code, 200)
        self.assertNotIn("development mode", res_offline.get_data(as_text=True).lower())
        self.assertIn("Direct Local Client & On-Platform Coordination", res_offline.get_data(as_text=True))

    @patch("app.send_notification_email")
    def test_07_role_specific_lost_and_found_notifications(self, mock_send):
        """Verifies symmetrical, role-appropriate copy for both lost and found reporters."""
        mock_send.return_value = True

        lost_owner = "URK25CS7001"
        found_owner = "URK25CS7002"
        lost_email = "lost_owner@karunya.edu"
        found_email = "found_owner@karunya.edu"

        lost_id = self._create_report(
            "Lost Item", "Black Fossil Leather Wallet", "Accessories",
            "Lost my black fossil leather wallet with cards", "Library 2nd floor",
            "9876543210", lost_email, lost_owner
        )
        found_id = self._create_report(
            "Found Item", "Black Fossil Leather Wallet", "Accessories",
            "Found black fossil leather wallet on reading table", "Library 2nd floor",
            "9876543211", found_email, found_owner
        )

        lost_tuple = (lost_id, "Lost Item", "Black Fossil Leather Wallet", "Accessories",
                      "Lost my black fossil leather wallet", "Library 2nd floor",
                      "9876543210", lost_email, "active", "", lost_owner)
        found_tuple = (found_id, "Found Item", "Black Fossil Leather Wallet", "Accessories",
                       "Found black fossil leather wallet", "Library 2nd floor",
                       "9876543211", found_email, "active", "", found_owner)

        matches = [{
            "report": found_tuple,
            "score": 92,
            "score_pct": "92%",
            "explanation": {"overall_score": 92}
        }]

        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")

        # Expect 2 dispatched emails
        self.assertEqual(mock_send.call_count, 2)

        calls = mock_send.call_args_list
        emails_sent = {c[0][0]: {"subject": c[0][1], "body": c[0][2]} for c in calls}

        # 1. Lost owner notification
        self.assertIn(lost_email, emails_sent)
        lost_msg = emails_sent[lost_email]
        self.assertEqual(lost_msg["subject"], "👀 Wait… someone found something like yours!")
        self.assertIn("Someone reported a found item that could match what you lost", lost_msg["body"])
        self.assertIn(f"#report-{found_id}", lost_msg["body"])
        self.assertIn("Fingers crossed! ✨", lost_msg["body"])

        # 2. Found owner notification
        self.assertIn(found_email, emails_sent)
        found_msg = emails_sent[found_email]
        self.assertEqual(found_msg["subject"], "🔎 Someone might be looking for what you found!")
        self.assertIn("Someone reported losing an item that could match what you found", found_msg["body"])
        self.assertIn(f"#report-{lost_id}", found_msg["body"])
        self.assertIn("No pressure until the details line up. 💙", found_msg["body"])

        # 3. Verify deduplication table recorded both
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT recipient_email FROM notified_matches WHERE lost_report_id = ? AND found_report_id = ?", (lost_id, found_id))
        recipients = [row[0] for row in c.fetchall()]
        conn.close()
        self.assertIn(lost_email, recipients)
        self.assertIn(found_email, recipients)

    @patch("app.send_notification_email")
    def test_08_deduplication_prevents_duplicate_notifications(self, mock_send):
        """Verifies that running notify_matches twice does not send duplicate emails."""
        mock_send.return_value = True

        lost_id = self._create_report("Lost Item", "AirPods Pro White", "Electronics", "White case", "Cafeteria", "9000000001", "lost_airpods@karunya.edu", "URK25CS8001")
        found_id = self._create_report("Found Item", "AirPods Pro White", "Electronics", "Found airpods in white case", "Cafeteria", "9000000002", "found_airpods@karunya.edu", "URK25CS8002")

        lost_tuple = (lost_id, "Lost Item", "AirPods Pro White", "Electronics", "", "Cafeteria", "", "lost_airpods@karunya.edu", "active", "", "URK25CS8001")
        found_tuple = (found_id, "Found Item", "AirPods Pro White", "Electronics", "", "Cafeteria", "", "found_airpods@karunya.edu", "active", "", "URK25CS8002")

        matches = [{"report": found_tuple, "score": 88, "score_pct": "88%", "explanation": {}}]

        # First run: dispatches 2 emails
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")
        self.assertEqual(mock_send.call_count, 2)

        # Second run: deduplication suppresses all emails
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")
        self.assertEqual(mock_send.call_count, 2)

    @patch("app.send_notification_email")
    def test_09_notification_suppressed_for_same_owner(self, mock_send):
        """Verifies no notifications sent if both items belong to the same owner."""
        owner = "URK25CS9001"
        lost_id = self._create_report("Lost Item", "Silver Watch", "Accessories", "Silver watch", "Gym", "9111111111", "same_owner@karunya.edu", owner)
        found_id = self._create_report("Found Item", "Silver Watch", "Accessories", "Silver watch", "Gym", "9111111111", "same_owner@karunya.edu", owner)

        lost_tuple = (lost_id, "Lost Item", "Silver Watch", "Accessories", "", "Gym", "", "same_owner@karunya.edu", "active", "", owner)
        found_tuple = (found_id, "Found Item", "Silver Watch", "Accessories", "", "Gym", "", "same_owner@karunya.edu", "active", "", owner)

        matches = [{"report": found_tuple, "score": 95, "score_pct": "95%", "explanation": {}}]
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")
        self.assertEqual(mock_send.call_count, 0)

    @patch("app.send_notification_email")
    def test_10_notification_suppressed_for_low_similarity(self, mock_send):
        """Verifies no notifications sent if match score is below 70% threshold."""
        lost_id = self._create_report("Lost Item", "Black Umbrella", "Other", "", "Bus Stop", "9222222221", "owner1@karunya.edu", "URK25CS9002")
        found_id = self._create_report("Found Item", "Blue Water Bottle", "Other", "", "Bus Stop", "9222222222", "owner2@karunya.edu", "URK25CS9003")

        lost_tuple = (lost_id, "Lost Item", "Black Umbrella", "Other", "", "Bus Stop", "", "owner1@karunya.edu", "active", "", "URK25CS9002")
        found_tuple = (found_id, "Found Item", "Blue Water Bottle", "Other", "", "Bus Stop", "", "owner2@karunya.edu", "active", "", "URK25CS9003")

        # Score 65% is below AUTO_NOTIFY_THRESHOLD (70%)
        matches = [{"report": found_tuple, "score": 65, "score_pct": "65%", "explanation": {}}]
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")
        self.assertEqual(mock_send.call_count, 0)

    @patch("app.send_notification_email")
    def test_11_notification_suppressed_for_inactive_reports(self, mock_send):
        """Verifies no notifications sent if one of the reports is resolved/returned."""
        lost_id = self._create_report("Lost Item", "Scientific Calculator", "Electronics", "", "Block 3", "9333333331", "calc_lost@karunya.edu", "URK25CS9004", status="returned")
        found_id = self._create_report("Found Item", "Scientific Calculator", "Electronics", "", "Block 3", "9333333332", "calc_found@karunya.edu", "URK25CS9005", status="active")

        lost_tuple = (lost_id, "Lost Item", "Scientific Calculator", "Electronics", "", "Block 3", "", "calc_lost@karunya.edu", "returned", "", "URK25CS9004")
        found_tuple = (found_id, "Found Item", "Scientific Calculator", "Electronics", "", "Block 3", "", "calc_found@karunya.edu", "active", "", "URK25CS9005")

        matches = [{"report": found_tuple, "score": 90, "score_pct": "90%", "explanation": {}}]
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")
        self.assertEqual(mock_send.call_count, 0)

    @patch("app.send_notification_email")
    def test_12_single_email_sent_when_other_party_has_no_email(self, mock_send):
        """Verifies notification is sent to party with valid email even if other party has none."""
        mock_send.return_value = True

        lost_id = self._create_report("Lost Item", "Blue Hydro Flask", "Accessories", "", "Auditorium", "9444444441", "hydro_lost@karunya.edu", "URK25CS9006")
        found_id = self._create_report("Found Item", "Blue Hydro Flask", "Accessories", "", "Auditorium", "9444444442", "", "URK25CS9007")

        lost_tuple = (lost_id, "Lost Item", "Blue Hydro Flask", "Accessories", "", "Auditorium", "", "hydro_lost@karunya.edu", "active", "", "URK25CS9006")
        found_tuple = (found_id, "Found Item", "Blue Hydro Flask", "Accessories", "", "Auditorium", "", "", "active", "", "URK25CS9007")

        matches = [{"report": found_tuple, "score": 85, "score_pct": "85%", "explanation": {}}]
        app.notify_matches(lost_tuple, matches, db_path="lostfound.db")

        # Only 1 email should be dispatched to hydro_lost@karunya.edu
        self.assertEqual(mock_send.call_count, 1)
        self.assertEqual(mock_send.call_args[0][0], "hydro_lost@karunya.edu")

    @patch("app.send_notification_email")
    def test_13_report_submission_persists_when_smtp_fails(self, mock_send):
        """Verifies report submission succeeds and is committed to database even when SMTP crashes."""
        mock_send.side_effect = Exception("SMTP Connection Timeout")

        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS9008"
            sess["_csrf_token"] = "csrf_test_9008"

        res = self.client.post("/report", data={
            "csrf_token": "csrf_test_9008",
            "item_type": "Lost Item",
            "item_name": "HP Laptop Charger 65W",
            "category": "Electronics",
            "description": "Black HP 65W charger with barrel pin",
            "location": "Computer Lab 4",
            "contact": "9555555555",
            "email": "hp_owner@karunya.edu"
        }, follow_redirects=True)

        self.assertIn(res.status_code, (200, 302))

        # Assert report was written to database despite email failure
        conn = sqlite3.connect("lostfound.db")
        c = conn.cursor()
        c.execute("SELECT id, status FROM reports WHERE LOWER(item_name) = 'hp laptop charger 65w'")
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.created_report_ids.append(row[0])
        self.assertEqual(row[1], "active")

    def test_14_diagnostics_endpoint_security_and_json(self):
        """Verifies access control and JSON responses on /admin/test-email."""
        # 1. Unauthorized remote request
        res_unauth = self.client.get("/admin/test-email", environ_base={"REMOTE_ADDR": "198.51.100.1"})
        self.assertEqual(res_unauth.status_code, 403)

        # 2. Authorized student session
        with self.client.session_transaction() as sess:
            sess["user"] = "URK25CS9009"

        res_auth = self.client.get("/admin/test-email", headers={"Accept": "application/json"})
        self.assertEqual(res_auth.status_code, 200)
        data = json.loads(res_auth.get_data(as_text=True))
        self.assertIn("overall_status", data)
        self.assertIn("config", data)
        self.assertIn("dns", data)
        self.assertIn("connection", data)
        self.assertIn("auth", data)
        # Ensure password is never exposed
        self.assertNotIn("password", data["config"])
        self.assertTrue(data["config"]["password_configured"])

if __name__ == "__main__":
    unittest.main()
