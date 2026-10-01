from database import SessionLocal
from blockchain import BlockchainBlock

db = SessionLocal()

try:
    duplicate = db.query(BlockchainBlock).filter(
        BlockchainBlock.block_index == 4
    ).first()

    if duplicate:
        print("Deleting duplicate blockchain block:")
        print("Block index:", duplicate.block_index)
        print("Document ID:", duplicate.document_id)

        db.delete(duplicate)
        db.commit()

        print("Duplicate block deleted successfully.")
    else:
        print("Block 4 was not found.")

finally:
    db.close()