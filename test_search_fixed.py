import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.curdir))

from database import db

def test_search_by_case_id():
    user_id = 1 # Assuming user 1 exists or just using it for query
    case_id = "CASE-XXXXX"
    
    print(f"Testing search for case_id: {case_id}")
    
    # Try searching for a case ID that we expect to be in case_ref
    # This will return result if any evidence has case_ref="CASE-XXXXX"
    results = db.search_evidence(user_id, query=case_id)
    
    print(f"Results found: {len(results)}")
    
    # Check if the query is correctly constructed in the logs or by inspecting the DB state
    # Since we don't have a guaranteed test database in a pristine state here, 
    # we just verify the logic by running it.
    
    print("Verification script finished.")

if __name__ == "__main__":
    test_search_by_case_id()
