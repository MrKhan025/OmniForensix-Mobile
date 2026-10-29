"""Synthetic mobile forensic evidence fixtures for deterministic pytest execution."""

from __future__ import annotations

import plistlib
import sqlite3
from datetime import datetime
from pathlib import Path
import pytest


@pytest.fixture()
def synthetic_evidence_dir(tmp_path: Path) -> Path:
    """Create a synthetic Android + iOS logical extraction directory with SQLite DBs and plists."""
    ev_dir = tmp_path / "evidence_dump"
    android_dir = ev_dir / "android"
    ios_dir = ev_dir / "ios"
    android_dir.mkdir(parents=True)
    ios_dir.mkdir(parents=True)

    # 1. Android mmssms.db
    sms_db = android_dir / "mmssms.db"
    conn = sqlite3.connect(sms_db)
    conn.execute(
        """CREATE TABLE sms (
            _id INTEGER PRIMARY KEY,
            thread_id INTEGER,
            address TEXT,
            date INTEGER,
            date_sent INTEGER,
            read INTEGER,
            type INTEGER,
            body TEXT,
            service_center TEXT
        );"""
    )
    conn.execute(
        "INSERT INTO sms VALUES (1, 10, '+15550199', 1700000000000, 1700000000000, 1, 1, "
        "'Urgent alert: http://verify-bank-alert.top/login', '+15550000');"
    )
    conn.commit()
    conn.close()

    # 2. Android contacts2.db (calls)
    calls_db = android_dir / "contacts2.db"
    conn = sqlite3.connect(calls_db)
    conn.execute(
        """CREATE TABLE calls (
            _id INTEGER PRIMARY KEY,
            number TEXT,
            date INTEGER,
            duration INTEGER,
            type INTEGER,
            name TEXT,
            geocoded_location TEXT
        );"""
    )
    conn.execute(
        "INSERT INTO calls VALUES (1, '+15550199', 1700000500000, 145, 1, 'Unknown Caller', 'New York, NY');"
    )
    conn.commit()
    conn.close()

    # 3. Android Chrome History
    chrome_db = android_dir / "chrome_history.db"
    conn = sqlite3.connect(chrome_db)
    conn.execute(
        """CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            typed_count INTEGER,
            last_visit_time INTEGER
        );"""
    )
    # 13344480000000000 WebKit microseconds == 2023-11-14T22:13:20Z
    conn.execute(
        "INSERT INTO urls VALUES (1, 'https://c2-stalker-sync.net/beacon', 'Sync Portal', 3, 0, 13344480000000000);"
    )
    conn.commit()
    conn.close()

    # 4. Android packages.xml with stalkerware package
    packages_xml = android_dir / "packages.xml"
    packages_xml.write_text(
        """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<packages>
    <package name="com.mspy.tracker" codePath="/data/app/com.mspy.tracker-1" it="18bcfe56800" installer="adb" version="42">
        <perms>
            <item name="android.permission.READ_SMS" granted="true" />
            <item name="android.permission.ACCESS_FINE_LOCATION" granted="true" />
        </perms>
    </package>
</packages>""",
        encoding="utf-8",
    )

    # 5. iOS sms.db
    ios_sms_db = ios_dir / "sms.db"
    conn = sqlite3.connect(ios_sms_db)
    conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);")
    conn.execute(
        """CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY,
            guid TEXT,
            text TEXT,
            service TEXT,
            is_from_me INTEGER,
            date INTEGER,
            date_read INTEGER,
            handle_id INTEGER
        );"""
    )
    conn.execute("INSERT INTO handle VALUES (1, 'user@icloud.com');")
    # 721692800 Mac Absolute Seconds == 2023-11-14T22:13:20Z
    conn.execute(
        "INSERT INTO message VALUES (1, 'GUID-100', 'Meeting confirmed at 9 PM', 'iMessage', 0, 721692800000000000, 0, 1);"
    )
    conn.commit()
    conn.close()

    # 6. iOS CallHistory.storedata
    ios_call_db = ios_dir / "CallHistory.storedata"
    conn = sqlite3.connect(ios_call_db)
    conn.execute(
        """CREATE TABLE ZCALLRECORD (
            Z_PK INTEGER PRIMARY KEY,
            ZADDRESS BLOB,
            ZDURATION REAL,
            ZDATE REAL,
            ZORIGINATED INTEGER,
            ZANSWERED INTEGER,
            ZSERVICE_PROVIDER TEXT
        );"""
    )
    conn.execute(
        "INSERT INTO ZCALLRECORD VALUES (1, X'2b3135353530393939', 62.5, 721693000.0, 1, 1, 'com.apple.Telephony');"
    )
    conn.commit()
    conn.close()

    # 7. iOS com.apple.wifi.plist
    wifi_plist = ios_dir / "com.apple.wifi.plist"
    with wifi_plist.open("wb") as fh:
        plistlib.dump(
            {
                "List of known networks": [
                    {
                        "SSID_STR": "Corp-Guest-5G",
                        "BSSID": "aa:bb:cc:dd:ee:ff",
                        "lastJoined": datetime(2023, 11, 14, 22, 30, 0),
                        "enabled": True,
                    }
                ]
            },
            fh,
            fmt=plistlib.FMT_BINARY,
        )


    # 8. Android WhatsApp msgstore.db & wa.db
    wa_msg_db = android_dir / "msgstore.db"
    conn = sqlite3.connect(wa_msg_db)
    conn.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);")
    conn.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER);")
    conn.execute(
        """CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            chat_row_id INTEGER,
            from_me INTEGER,
            timestamp INTEGER,
            text_data TEXT,
            message_type INTEGER
        );"""
    )
    conn.execute("INSERT INTO jid VALUES (1, '15550123@s.whatsapp.net');")
    conn.execute("INSERT INTO chat VALUES (1, 1);")
    conn.execute("INSERT INTO message VALUES (101, 1, 1, 1700001000000, 'WhatsApp wire transfer details sent', 0);")
    conn.commit()
    conn.close()

    wa_contacts_db = android_dir / "wa.db"
    conn = sqlite3.connect(wa_contacts_db)
    conn.execute(
        """CREATE TABLE wa_contacts (
            _id INTEGER PRIMARY KEY,
            jid TEXT,
            display_name TEXT,
            number TEXT,
            status TEXT,
            status_timestamp INTEGER
        );"""
    )
    conn.execute("INSERT INTO wa_contacts VALUES (1, '15550123@s.whatsapp.net', 'Target Broker', '+15550123', 'Available', 1700000000000);")
    conn.commit()
    conn.close()

    # 9. iOS WhatsApp ChatStorage.sqlite
    ios_wa_db = ios_dir / "ChatStorage.sqlite"
    conn = sqlite3.connect(ios_wa_db)
    conn.execute("CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZPARTNERNAME TEXT, ZCONTACTJID TEXT);")
    conn.execute(
        """CREATE TABLE ZWAMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZCHATSESSION INTEGER,
            ZISFROMME INTEGER,
            ZMESSAGEDATE REAL,
            ZTEXT TEXT,
            ZFROMJID TEXT,
            ZTOJID TEXT
        );"""
    )
    conn.execute("INSERT INTO ZWACHATSESSION VALUES (1, 'Alice Witness', '15550888@s.whatsapp.net');")
    conn.execute(
        "INSERT INTO ZWAMESSAGE VALUES (1, 1, 0, 721693200.0, 'Encrypted drop coordinates attached', '15550888@s.whatsapp.net', 'me@s.whatsapp.net');"
    )
    conn.commit()
    conn.close()

    # 10. Telegram cache4.db
    tg_db = android_dir / "cache4.db"
    conn = sqlite3.connect(tg_db)
    conn.execute("CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, status INTEGER);")
    conn.execute(
        """CREATE TABLE messages_v2 (
            mid INTEGER PRIMARY KEY,
            uid INTEGER,
            date INTEGER,
            out INTEGER,
            read_state INTEGER,
            data BLOB
        );"""
    )
    conn.execute("INSERT INTO users VALUES (777000, 'Telegram Handler', 1);")
    conn.execute(
        "INSERT INTO messages_v2 VALUES (501, 777000, 1700002000, 0, 1, X'000068747470733a2f2f63322d7374616c6b65722d73796e632e6e65742f7061796c6f616400');"
    )
    conn.commit()
    conn.close()

    # 11. Signal signal.db
    sig_db = android_dir / "signal.db"
    conn = sqlite3.connect(sig_db)
    conn.execute(
        """CREATE TABLE recipient (
            _id INTEGER PRIMARY KEY,
            e164 TEXT,
            system_joined_name TEXT,
            profile_given_name TEXT
        );"""
    )
    conn.execute(
        """CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            thread_id INTEGER,
            from_recipient_id INTEGER,
            date_sent INTEGER,
            date_received INTEGER,
            body TEXT,
            expires_in INTEGER
        );"""
    )
    conn.execute("INSERT INTO recipient VALUES (1, '+15550777', 'Bob Informant', 'Bob');")
    conn.execute(
        "INSERT INTO message VALUES (1, 1, 1, 1700003000000, 1700003001000, 'Signal ephemeral message check', 60000);"
    )
    conn.commit()
    conn.close()

    return ev_dir
