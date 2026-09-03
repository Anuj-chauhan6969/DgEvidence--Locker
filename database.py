"""
database.py – Full database layer for DgEvidenceLocker
Tables: users, evidence, cases, audit_logs, delete_requests, otp_store
"""
import sqlite3
import hashlib
import os
import shutil
import datetime

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

DB_NAME = 'evidence_locker.db'
BACKUP_DIR = 'backups'

# ── Admin seed credentials (change after first login) ──────────────────────
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@dgevidencelocker.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Administrator')


def get_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


class UserDatabase:
    def __init__(self, db_name=DB_NAME):
        global DB_NAME
        DB_NAME = db_name
        print(f'[db] Initializing Database: {DB_NAME} (bcrypt available: {BCRYPT_AVAILABLE})')
        self.db_name = db_name
        self._init_database()
        self._seed_admin()
        self._auto_backup()

    # ── Schema ──────────────────────────────────────────────────────────────
    def _init_database(self):
        conn = get_conn()
        cur = conn.cursor()

        cur.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL,
                email       TEXT    UNIQUE NOT NULL,
                mobile      TEXT    DEFAULT '',
                password    TEXT    NOT NULL,
                role        TEXT    NOT NULL DEFAULT 'user',
                is_active   INTEGER NOT NULL DEFAULT 1,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS cases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                case_id     TEXT    UNIQUE NOT NULL,
                name        TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                status      TEXT    NOT NULL DEFAULT 'pending',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id     TEXT    UNIQUE NOT NULL,
                user_id         INTEGER NOT NULL,
                case_ref        TEXT    DEFAULT '',
                original_name   TEXT    NOT NULL,
                stored_filename TEXT    NOT NULL,
                file_type       TEXT    NOT NULL,
                file_size       INTEGER NOT NULL DEFAULT 0,
                sha256_hash     TEXT    NOT NULL,
                is_encrypted    INTEGER NOT NULL DEFAULT 1,
                status          TEXT    NOT NULL DEFAULT 'pending',
                title           TEXT    DEFAULT '',
                description     TEXT    DEFAULT '',
                category        TEXT    DEFAULT '',
                tags            TEXT    DEFAULT '',
                priority        TEXT    DEFAULT 'medium',
                location        TEXT    DEFAULT '',
                collected_at    TEXT    DEFAULT '',
                uploaded_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                security_question TEXT,
                security_answer_hash TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until    TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS otp_store (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT    NOT NULL,
                otp         TEXT    NOT NULL,
                purpose     TEXT    NOT NULL DEFAULT 'login',
                expires_at  TIMESTAMP NOT NULL,
                used        INTEGER NOT NULL DEFAULT 0,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS delete_requests (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id     TEXT    NOT NULL,
                user_id         INTEGER NOT NULL,
                reason          TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'pending',
                admin_note      TEXT    DEFAULT '',
                requested_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at     TIMESTAMP,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
                FOREIGN KEY (user_id)     REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                action      TEXT    NOT NULL,
                target      TEXT    DEFAULT '',
                details     TEXT    DEFAULT '',
                ip_address  TEXT    DEFAULT '',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')

        # ── Migrations (Safe ALTER TABLE) ──────────────────────────────────
        try:
            conn.execute("ALTER TABLE evidence ADD COLUMN security_question TEXT")
        except: pass
        try:
            conn.execute("ALTER TABLE evidence ADD COLUMN security_answer_hash TEXT")
        except: pass
        try:
            conn.execute("ALTER TABLE evidence ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        except: pass
        try:
            conn.execute("ALTER TABLE evidence ADD COLUMN locked_until TIMESTAMP")
        except: pass

        conn.commit()
        conn.close()

    # ── Auto-backup ──────────────────────────────────────────────────────────
    def _auto_backup(self):
        if not os.path.exists(self.db_name):
            return
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        dest = os.path.join(BACKUP_DIR, f'backup_{ts}.db')
        try:
            shutil.copy2(self.db_name, dest)
            # Keep only last 10 backups
            backups = sorted(
                [f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')],
                reverse=True
            )
            for old in backups[10:]:
                os.remove(os.path.join(BACKUP_DIR, old))
        except Exception as e:
            print(f'[db] Backup warning: {e}')

    # ── Password helpers ─────────────────────────────────────────────────────
    def _hash_password(self, password: str) -> str:
        if BCRYPT_AVAILABLE:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        # fallback: SHA-256 (upgrade later)
        return 'sha256:' + hashlib.sha256(password.encode()).hexdigest()

    def _check_password(self, password: str, stored: str) -> bool:
        if BCRYPT_AVAILABLE and not stored.startswith('sha256:'):
            try:
                return bcrypt.checkpw(password.encode(), stored.encode())
            except Exception:
                return False
        # legacy / fallback
        return stored == 'sha256:' + hashlib.sha256(password.encode()).hexdigest()

    # ── Admin seed ───────────────────────────────────────────────────────────
    def _seed_admin(self):
        if not ADMIN_PASSWORD:
            print('[db] ADMIN_PASSWORD is not configured; skipping admin seed.')
            return
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT id FROM users WHERE role = "admin"')
        if not cur.fetchone():
            hashed = self._hash_password(ADMIN_PASSWORD)
            cur.execute(
                'INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)',
                (ADMIN_USERNAME, ADMIN_EMAIL, hashed, 'admin')
            )
            conn.commit()
            print(f'[db] Admin seeded: {ADMIN_EMAIL}')
        conn.close()

    # ── OTP ─────────────────────────────────────────────────────────────────
    def store_otp(self, email: str, otp: str, purpose: str = 'login') -> bool:
        conn = get_conn()
        try:
            expires = datetime.datetime.now() + datetime.timedelta(minutes=5)
            # Invalidate previous OTPs for same email+purpose
            conn.execute(
                'UPDATE otp_store SET used=1 WHERE email=? AND purpose=? AND used=0',
                (email, purpose)
            )
            conn.execute(
                'INSERT INTO otp_store (email,otp,purpose,expires_at) VALUES (?,?,?,?)',
                (email, otp, purpose, expires.strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] store_otp error: {e}')
            return False
        finally:
            conn.close()
        return False

    def verify_otp(self, email: str, otp: str, purpose: str = 'login') -> bool:
        conn = get_conn()
        try:
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cur = conn.execute(
                '''SELECT id FROM otp_store
                   WHERE email=? AND otp=? AND purpose=?
                     AND used=0 AND expires_at > ?
                   ORDER BY id DESC LIMIT 1''',
                (email, otp, purpose, now)
            )
            row = cur.fetchone()
            if row:
                conn.execute('UPDATE otp_store SET used=1 WHERE id=?', (row['id'],))
                conn.commit()
                return True
            return False
        except Exception:
            return False
        finally:
            conn.close()
        return False

    def get_all_otps(self, limit: int = 100):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT * FROM otp_store ORDER BY created_at DESC LIMIT ?',
                (limit,)
            )
            return cur.fetchall()
        finally:
            conn.close()

    def delete_otp(self, otp_id: int) -> bool:
        conn = get_conn()
        try:
            conn.execute('DELETE FROM otp_store WHERE id=?', (otp_id,))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def clear_all_otps(self) -> bool:
        conn = get_conn()
        try:
            conn.execute('DELETE FROM otp_store')
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def store_delete_confirmation_otp(self, delete_request_id: int, otp: str) -> bool:
        """Store OTP specifically for delete confirmation."""
        conn = get_conn()
        try:
            # Store with special purpose for delete confirmation
            # Use SQLite datetime('now') + 30 days to avoid local/UTC confusion
            conn.execute(
                '''INSERT INTO otp_store (email,otp,purpose,expires_at) 
                   SELECT u.email, ?, 'delete_confirm', datetime('now', '+30 days')
                   FROM delete_requests dr
                   JOIN users u ON u.id = dr.user_id
                   WHERE dr.id=?''',
                (otp, delete_request_id)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] store_delete_confirmation_otp error: {e}')
            return False
        finally:
            conn.close()

    def verify_delete_confirmation_otp(self, delete_request_id: int, otp: str) -> bool:
        """Verify OTP for delete confirmation."""
        conn = get_conn()
        try:
            # Use SQLite datetime('now') for comparison to match storage logic
            cur = conn.execute(
                '''SELECT otp_store.id FROM otp_store
                   INNER JOIN users ON users.email = otp_store.email
                   INNER JOIN delete_requests ON delete_requests.user_id = users.id
                   WHERE delete_requests.id=? AND otp_store.otp=? 
                     AND otp_store.purpose='delete_confirm' AND otp_store.used=0 
                     AND otp_store.expires_at > datetime('now')
                   ORDER BY otp_store.id DESC LIMIT 1''',
                (delete_request_id, otp)
            )
            row = cur.fetchone()
            if row:
                conn.execute('UPDATE otp_store SET used=1 WHERE id=?', (row['id'],))
                conn.commit()
                return True
            return False
        except Exception as e:
            print(f'[db] verify_delete_confirmation_otp error: {e}')
            return False
        finally:
            conn.close()

    # ── Users ────────────────────────────────────────────────────────────────
    def add_user(self, username: str, email: str, password: str,
                 mobile: str = '', role: str = 'user', silent: bool = False) -> bool:
        conn = get_conn()
        try:
            hashed = self._hash_password(password)
            conn.execute(
                'INSERT INTO users (username,email,password,mobile,role) VALUES (?,?,?,?,?)',
                (username, email, hashed, mobile, role)
            )
            conn.commit()
            if not silent:
                print(f'[db] User added: {email}')
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            print(f'[db] add_user error: {e}')
            return False
        finally:
            conn.close()
        return False

    def verify_user(self, email: str, password: str):
        """Returns (username, role) tuple or None."""
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT id, username, password, role, is_active FROM users WHERE email=?',
                (email,)
            )
            row = cur.fetchone()
            if row and row['is_active'] and self._check_password(password, row['password']):
                return row['id'], row['username'], row['role']
            return None
        finally:
            conn.close()

    def get_user_by_email(self, email: str):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT id,username,email,mobile,role,created_at FROM users WHERE email=?',
                (email,)
            )
            return cur.fetchone()
        finally:
            conn.close()

    def get_user_by_id(self, user_id: int):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT id,username,email,mobile,role,created_at FROM users WHERE id=?',
                (user_id,)
            )
            return cur.fetchone()
        finally:
            conn.close()

    def get_all_users(self):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT id,username,email,mobile,role,is_active,created_at FROM users ORDER BY created_at DESC'
            )
            return cur.fetchall()
        finally:
            conn.close()

    def update_profile(self, user_id: int, username: str, mobile: str) -> bool:
        conn = get_conn()
        try:
            conn.execute(
                'UPDATE users SET username=?, mobile=? WHERE id=?',
                (username, mobile, user_id)
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def update_password(self, user_id: int, new_password: str) -> bool:
        conn = get_conn()
        try:
            hashed = self._hash_password(new_password)
            conn.execute('UPDATE users SET password=? WHERE id=?', (hashed, user_id))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def toggle_user_active(self, user_id: int) -> bool:
        conn = get_conn()
        try:
            conn.execute(
                'UPDATE users SET is_active = 1 - is_active WHERE id=?',
                (user_id,)
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def delete_user(self, user_id: int) -> bool:
        conn = get_conn()
        try:
            # Foreign keys (cases, evidence) should cascade or be handled
            # Since FKs are ON, we can delete the user
            conn.execute('DELETE FROM users WHERE id=?', (user_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] delete_user error: {e}')
            return False
        finally:
            conn.close()

    # ── Cases ────────────────────────────────────────────────────────────────
    def create_case(self, user_id: int, name: str, description: str = '') -> str | None:
        import uuid
        case_id = 'CASE-' + str(uuid.uuid4())[:8].upper()
        conn = get_conn()
        try:
            conn.execute(
                'INSERT INTO cases (user_id,case_id,name,description) VALUES (?,?,?,?)',
                (user_id, case_id, name, description)
            )
            conn.commit()
            return case_id
        except Exception as e:
            print(f'[db] create_case error: {e}')
            return None
        finally:
            conn.close()

    def get_cases(self, user_id: int):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT * FROM cases WHERE user_id=? ORDER BY created_at DESC',
                (user_id,)
            )
            return cur.fetchall()
        finally:
            conn.close()

    def get_all_cases(self):
        conn = get_conn()
        try:
            cur = conn.execute(
                '''SELECT c.*, u.username FROM cases c
                   JOIN users u ON u.id = c.user_id
                   ORDER BY c.created_at DESC'''
            )
            return cur.fetchall()
        finally:
            conn.close()

    def update_case_status(self, case_id: str, status: str) -> bool:
        conn = get_conn()
        try:
            conn.execute('UPDATE cases SET status=? WHERE case_id=?', (status, case_id))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    # ── Evidence ─────────────────────────────────────────────────────────────
    def add_evidence(self, user_id: int, evidence_id: str, case_ref: str,
                     original_name: str, stored_filename: str, file_type: str,
                     file_size: int, sha256_hash: str, title: str = '',
                     description: str = '', category: str = '', tags: str = '',
                     priority: str = 'medium', location: str = '',
                     collected_at: str = '', security_question: str = '',
                     security_answer: str = '') -> bool:
        conn = get_conn()
        try:
            security_answer_hash = self._hash_password(security_answer.strip().lower()) if security_answer else None

            conn.execute('''
                INSERT INTO evidence
                  (evidence_id,user_id,case_ref,original_name,stored_filename,
                   file_type,file_size,sha256_hash,title,description,
                   category,tags,priority,location,collected_at,
                   security_question, security_answer_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (evidence_id, user_id, case_ref, original_name, stored_filename,
                  file_type, file_size, sha256_hash, title, description,
                  category, tags, priority, location, collected_at,
                  security_question, security_answer_hash))
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] add_evidence error: {e}')
            return False
        finally:
            conn.close()

    def get_evidence_by_user(self, user_id: int):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT * FROM evidence WHERE user_id=? ORDER BY uploaded_at DESC',
                (user_id,)
            )
            return cur.fetchall()
        finally:
            conn.close()

    def get_all_evidence(self):
        conn = get_conn()
        try:
            cur = conn.execute(
                '''SELECT e.*, u.username FROM evidence e
                   JOIN users u ON u.id = e.user_id
                   ORDER BY e.uploaded_at DESC'''
            )
            return cur.fetchall()
        finally:
            conn.close()

    def get_evidence_by_id(self, evidence_id: str):
        conn = get_conn()
        try:
            cur = conn.execute(
                'SELECT * FROM evidence WHERE evidence_id=?',
                (evidence_id,)
            )
            return cur.fetchone()
        finally:
            conn.close()

    def update_evidence_status(self, evidence_id: str, status: str) -> bool:
        conn = get_conn()
        try:
            conn.execute('UPDATE evidence SET status=? WHERE evidence_id=?', (status, evidence_id))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def delete_evidence_record(self, evidence_id: str) -> bool:
        conn = get_conn()
        try:
            conn.execute('DELETE FROM evidence WHERE evidence_id = ?', (evidence_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] delete_evidence error: {e}')
            return False
        finally:
            conn.close()

    def record_failed_attempt(self, evidence_id: str):
        conn = get_conn()
        try:
            conn.execute('''
                UPDATE evidence 
                SET failed_attempts = failed_attempts + 1,
                    locked_until = CASE 
                        WHEN failed_attempts + 1 >= 3 THEN datetime('now', '+24 hours')
                        ELSE locked_until 
                    END
                WHERE evidence_id = ?
            ''', (evidence_id,))
            conn.commit()
        except Exception as e:
            print(f'[db] record_failed_attempt error: {e}')
        finally:
            conn.close()

    def reset_failed_attempts(self, evidence_id: str):
        conn = get_conn()
        try:
            conn.execute('''
                UPDATE evidence 
                SET failed_attempts = 0, locked_until = NULL 
                WHERE evidence_id = ?
            ''', (evidence_id,))
            conn.commit()
        except Exception as e:
            print(f'[db] reset_failed_attempts error: {e}')
        finally:
            conn.close()

    def is_evidence_locked(self, evidence_id: str) -> tuple[bool, str | None]:
        """Returns (is_locked, locked_until_str)"""
        conn = get_conn()
        try:
            row = conn.execute('SELECT locked_until FROM evidence WHERE evidence_id = ?', (evidence_id,)).fetchone()
            if row and row['locked_until']:
                try:
                    locked_until = datetime.datetime.strptime(row['locked_until'], '%Y-%m-%d %H:%M:%S')
                    if locked_until > datetime.datetime.now():
                        return True, row['locked_until']
                except:
                    # Fallback for different formats
                    return True, row['locked_until']
            return False, None
        except Exception as e:
            print(f'[db] is_evidence_locked error: {e}')
            return False, None
        finally:
            conn.close()

    def verify_security_answer(self, evidence_id: str, answer: str) -> bool:
        conn = get_conn()
        try:
            row = conn.execute('SELECT security_answer_hash FROM evidence WHERE evidence_id = ?', (evidence_id,)).fetchone()
            if not row or not row['security_answer_hash'] or not answer:
                print(f'[DEBUG] db: No hash or no answer for {evidence_id}')
                return False
            
            processed_answer = answer.strip().lower()
            stored_hash = row['security_answer_hash']
            match = self._check_password(processed_answer, stored_hash)
            
            print(f'[DEBUG] db verification: ev_id={evidence_id}')
            print(f'        processed_input="{processed_answer}"')
            print(f'        stored_hash="{stored_hash}"')
            print(f'        match_result={match}')
            
            return match
        except Exception as e:
            print(f'[db] verify_security_answer error: {e}')
            return False
        finally:
            conn.close()

    def search_evidence(self, user_id: int, query: str = '', file_type: str = '',
                        date_from: str = '', date_to: str = ''):
        conn = get_conn()
        try:
            sql = 'SELECT * FROM evidence WHERE user_id=?'
            params = [user_id]
            if query:
                sql += ' AND (evidence_id LIKE ? OR title LIKE ? OR tags LIKE ? OR description LIKE ? OR case_ref LIKE ?)'
                q = f'%{query}%'
                params += [q, q, q, q, q]
            if file_type:
                sql += ' AND file_type=?'
                params.append(file_type)
            if date_from:
                sql += ' AND DATE(uploaded_at) >= ?'
                params.append(date_from)
            if date_to:
                sql += ' AND DATE(uploaded_at) <= ?'
                params.append(date_to)
            sql += ' ORDER BY uploaded_at DESC'
            cur = conn.execute(sql, params)
            return cur.fetchall()
        finally:
            conn.close()

    # ── Delete Requests ──────────────────────────────────────────────────────
    def create_delete_request(self, evidence_id: str, user_id: int, reason: str) -> bool:
        conn = get_conn()
        try:
            # Only one pending per evidence
            cur = conn.execute(
                'SELECT id FROM delete_requests WHERE evidence_id=? AND status="pending"',
                (evidence_id,)
            )
            if cur.fetchone():
                return False  # already pending
            conn.execute(
                'INSERT INTO delete_requests (evidence_id,user_id,reason) VALUES (?,?,?)',
                (evidence_id, user_id, reason)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] create_delete_request error: {e}')
            return False
        finally:
            conn.close()

    def get_delete_requests(self, status: str = None):
        conn = get_conn()
        try:
            where_clause = "WHERE dr.status=?" if status else ""
            params = (status,) if status else ()
            
            # Try full join first
            try:
                query = f'''
                    SELECT dr.*, e.original_name, e.stored_filename, u.username, u.email
                    FROM delete_requests dr
                    JOIN evidence e ON e.evidence_id = dr.evidence_id
                    JOIN users u    ON u.id = dr.user_id
                    {where_clause} ORDER BY dr.requested_at DESC
                '''
                cur = conn.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
            except Exception as e:
                print(f"[DB DEBUG] get_delete_requests JOIN failed: {e}")
                # Fallback to simple query
                query = f'''
                    SELECT dr.*, '' as original_name, '' as stored_filename, '' as username, '' as email
                    FROM delete_requests dr
                    {where_clause} ORDER BY dr.requested_at DESC
                '''
                cur = conn.execute(query, params)
                results = [dict(row) for row in cur.fetchall()]
                
                # Fetch related info manually
                for r in results:
                    try:
                        ev_cur = conn.execute('SELECT original_name, stored_filename FROM evidence WHERE evidence_id=?', (r['evidence_id'],))
                        ev = ev_cur.fetchone()
                        if ev:
                            r['original_name'] = ev['original_name']
                            r['stored_filename'] = ev['stored_filename']
                        
                        u_cur = conn.execute('SELECT username, email FROM users WHERE id=?', (r['user_id'],))
                        u = u_cur.fetchone()
                        if u:
                            r['username'] = u['username']
                            r['email'] = u['email']
                    except: pass
                return results
        finally:
            conn.close()

    def get_user_delete_requests(self, user_id: int):
        conn = get_conn()
        try:
            print(f"[DB DEBUG] Getting delete requests for user_id: {user_id}")
            
            # First try the simple query without joins
            try:
                cur = conn.execute(
                    '''SELECT dr.*, e.original_name, e.stored_filename, u.username, u.email
                       FROM delete_requests dr
                       JOIN evidence e ON e.evidence_id = dr.evidence_id
                       JOIN users u    ON u.id = dr.user_id
                       WHERE dr.user_id=? ORDER BY dr.requested_at DESC''',
                    (user_id,)
                )
                results = [dict(row) for row in cur.fetchall()]
                print(f"[DB DEBUG] Successfully retrieved {len(results)} delete requests with full join")
                return results
            except Exception as join_error:
                print(f"[DB DEBUG] JOIN query failed: {join_error}")
                print(f"[DB DEBUG] Trying simple query without joins...")
                
                # Fallback to simple query
                cur = conn.execute(
                    '''SELECT dr.*, '' as original_name, '' as stored_filename, '' as username, '' as email
                       FROM delete_requests dr
                       WHERE dr.user_id=? ORDER BY dr.requested_at DESC''',
                    (user_id,)
                )
                results = [dict(row) for row in cur.fetchall()]
                print(f"[DB DEBUG] Retrieved {len(results)} delete requests with simple query")
                
                # Try to get evidence info separately
                for result in results:
                    try:
                        ev_cur = conn.execute(
                            'SELECT original_name, stored_filename FROM evidence WHERE evidence_id=?',
                            (result['evidence_id'],)
                        )
                        ev_info = ev_cur.fetchone()
                        if ev_info:
                            result['original_name'] = ev_info['original_name']
                            result['stored_filename'] = ev_info['stored_filename']
                    except:
                        pass  # Keep default values if evidence lookup fails
                
                # Try to get user info separately
                try:
                    user_cur = conn.execute(
                        'SELECT username, email FROM users WHERE id=?',
                        (user_id,)
                    )
                    user_info = user_cur.fetchone()
                    if user_info:
                        for result in results:
                            result['username'] = user_info['username']
                            result['email'] = user_info['email']
                except:
                    pass  # Keep default values if user lookup fails
                
                return results
                
        except Exception as e:
            print(f"[DB DEBUG] ERROR in get_user_delete_requests: {e}")
            return []
        finally:
            conn.close()

    def update_delete_request_status(self, request_id: int, status: str, admin_note: str = '') -> bool:
        """Update delete request status without deleting evidence."""
        conn = get_conn()
        try:
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                'UPDATE delete_requests SET status=?,admin_note=?,resolved_at=? WHERE id=?',
                (status, admin_note, now, request_id)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f'[db] update_delete_request_status error: {e}')
            return False
        finally:
            conn.close()

    def resolve_delete_request(self, request_id: int, approved: bool, admin_note: str = '') -> str | None:
        """Returns evidence stored_filename (to delete file) if approved, else None."""
        # For this specific operation, we MUST disable foreign keys BEFORE starting any work
        # because delete_requests references evidence_id, blocking its deletion.
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=OFF') 
        
        try:
            # Join with evidence to get stored_filename
            cur = conn.execute('''
                SELECT dr.*, e.stored_filename 
                FROM delete_requests dr
                JOIN evidence e ON e.evidence_id = dr.evidence_id
                WHERE dr.id=?
            ''', (request_id,))
            req = cur.fetchone()
            
            if not req:
                return None

            status = 'approved' if approved else 'rejected'
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn.execute(
                'UPDATE delete_requests SET status=?,admin_note=?,resolved_at=? WHERE id=?',
                (status, admin_note, now, request_id)
            )
            
            if approved:
                # Delete evidence file
                stored = req['stored_filename']
                evidence_path = os.path.join(os.path.dirname(__file__), 'uploads', stored)
                try:
                    os.remove(evidence_path)
                except FileNotFoundError:
                    pass
                except Exception as ef:
                    print(f'[db] File removal error: {ef}')
                
                # Remove evidence record (This is where FK usually blocks us)
                conn.execute('DELETE FROM evidence WHERE evidence_id=?', (req['evidence_id'],))
            
            conn.commit()
            return stored if approved else None
        except Exception as e:
            print(f'[db] resolve_delete_request exception: {e}')
            return None
        finally:
            conn.close()

    # ── Audit Logs ───────────────────────────────────────────────────────────
    def log_audit(self, user_id, action: str, target: str = '', details: str = '',
                  ip_address: str = ''):
        conn = get_conn()
        try:
            conn.execute(
                'INSERT INTO audit_logs (user_id, action, target, details, ip_address) VALUES (?, ?, ?, ?, ?)',
                (user_id, action, target, details, ip_address)
            )
            conn.commit()
        except Exception as e:
            print(f'[db] log_audit error: {e}')
        finally:
            conn.close()


    def get_audit_logs(self, user_id: int = None, limit: int = 200):
        conn = get_conn()
        try:
            if user_id:
                cur = conn.execute(
                    '''SELECT al.*, u.username FROM audit_logs al
                       LEFT JOIN users u ON u.id = al.user_id
                       WHERE al.user_id=? ORDER BY al.created_at DESC LIMIT ?''',
                    (user_id, limit)
                )
            else:
                cur = conn.execute(
                    '''SELECT al.*, u.username FROM audit_logs al
                       LEFT JOIN users u ON u.id = al.user_id
                       ORDER BY al.created_at DESC LIMIT ?''',
                    (limit,)
                )
            return cur.fetchall()
        finally:
            conn.close()

    def delete_audit_log(self, log_id: int) -> bool:
        conn = get_conn()
        try:
            conn.execute('DELETE FROM audit_logs WHERE id=?', (log_id,))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()
        return False

    def clear_all_audit_logs(self) -> bool:
        conn = get_conn()
        try:
            conn.execute('DELETE FROM audit_logs')
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()
        return False

    # ── Stats ────────────────────────────────────────────────────────────────
    def get_user_stats(self, user_id: int) -> dict:
        conn = get_conn()
        try:
            ev = conn.execute('SELECT COUNT(*), SUM(file_size) FROM evidence WHERE user_id=?', (user_id,)).fetchone()
            cs = conn.execute('SELECT COUNT(*) FROM cases WHERE user_id=?', (user_id,)).fetchone()
            pending = conn.execute('SELECT COUNT(*) FROM evidence WHERE user_id=? AND status="pending"', (user_id,)).fetchone()
            return {
                'total_evidence': ev[0] or 0,
                'storage_bytes': ev[1] or 0,
                'total_cases': cs[0] or 0,
                'pending_review': pending[0] or 0,
            }
        finally:
            conn.close()

    def get_admin_stats(self) -> dict:
        conn = get_conn()
        try:
            users      = conn.execute('SELECT COUNT(*) FROM users WHERE role="user"').fetchone()[0]
            total_ev   = conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
            pending_ev = conn.execute('SELECT COUNT(*) FROM evidence WHERE status="pending"').fetchone()[0]
            delete_req = conn.execute('SELECT COUNT(*) FROM delete_requests WHERE status="pending"').fetchone()[0]
            total_cases= conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0]
            return {
                'total_users': users,
                'total_evidence': total_ev,
                'pending_evidence': pending_ev,
                'pending_delete_requests': delete_req,
                'total_cases': total_cases,
            }
        finally:
            conn.close()

    # ── Legacy compatibility ─────────────────────────────────────────────────
    def get_user(self, email: str):
        return self.get_user_by_email(email)


# ── Module-level singleton ───────────────────────────────────────────────────
db = UserDatabase()
