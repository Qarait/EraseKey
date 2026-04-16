import sys
from pathlib import Path

# Add app to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.services import finalize_due_deletions
from app.config import settings

def main():
    print(f"--- EraseKey Finalization Worker [App: {settings.app_name}] ---")
    print("Scanning for due deletion requests...")
    
    try:
        finalized_ids = finalize_due_deletions()
        
        if not finalized_ids:
            print("No due requests found.")
        else:
            print(f"Successfully finalized {len(finalized_ids)} request(s):")
            for rid in finalized_ids:
                print(f"  - {rid}")
                
        print("Worker run complete.")
    except Exception as e:
        print(f"FATAL: Worker failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
