import traceback
try:
    from app import app
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_id'] = 1
        sess['otp_verified'] = True
    print("Testing /evidence/verify-answer")
    r = c.post('/evidence/verify-answer', data={'evidence_id': 'EV-3334FCCD-C3B', 'answer': 'black'})
    print("Status:", r.status_code)
    print("Body:", r.get_data(as_text=True))
except Exception as e:
    traceback.print_exc()
